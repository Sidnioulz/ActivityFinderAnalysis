"""An action performed by an Application at a specific time."""

from enum import Enum
from Application import Application
from SqlEvent import SqlEvent
from File import File, EventFileFlags
from utils import urlToUnixPath, int16
from constants import POSIX_OPEN_RE, POSIX_FOPEN_RE, POSIX_FDOPEN_RE, \
                      POSIX_OPENDIR_RE, \
                      O_ACCMODE, O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, \
                      O_TRUNC, O_DIRECTORY
import sys
import re
from os.path import normpath as np


class EventSource(Enum):
    """Supported sources for events: Zeitgeist or PreloadLogger."""

    unknown = 0
    zeitgeist = 1
    preloadlogger = 2
    cmdline = 3


class EventType(Enum):
    """Supported types of events, from Zeitgeist or PreloadLogger."""

# create, destroy, read, write, designation, programmatic,

    invalid = -1
    unknown = 0

    filecreate = 1
    filemove = 2
    filecopy = 3
    fileread = 4
    filewrite = 5
    filereadwrite = 6
    filedelete = 7
    filelink = 8
    filesymlink = 9

    applaunch = 20
    appstart = 21


class Event(object):
    """An action performed by an Application at a specific time.

    Representation of an action performed by an Application, e.g. a system call
    or usage of a Desktop API. Actions are performed at a specific time, and
    target subjects (e.g. Files or other Applications).
    """

    time = 0       # type: int; when the event occurred
    evtype = None  # type: EventType; type of the event
    evflags = EventFileFlags.no_flags  # type: EventFileFlags
    actor = None   # type: Application; responsible for performing the event
    source = EventSource.unknown  # type: EventSource; source of the event
    subjects = []  # type: list; other entities affected by the event
    data = None    # binary data specific to each Event. Read the code...
    data_app = None  # binary data specific to each Event's actor.

    posixOpenRe = re.compile(POSIX_OPEN_RE)
    posixFopenRe = re.compile(POSIX_FOPEN_RE)
    posixFDopenRe = re.compile(POSIX_FDOPEN_RE)
    posixOpendirRe = re.compile(POSIX_OPENDIR_RE)

    def __init__(self,
                 actor: Application,
                 time: int=0,
                 zgEvent: list=None,
                 syscallStr: str=None,
                 cmdlineStr: str=None):
        """Construct an Event, using a Zeitgeist or PreloadLogger log entry."""
        super(Event, self).__init__()

        # Initialise actor and time of occurrence
        if not actor:
            raise ValueError("Events must be performed by a valid "
                             "Application.")
        if not time:
            raise ValueError("Events must have a time of occurrence.")
        self.actor = actor
        self.time = time

        self.type = EventType.unknown
        self.evflags = EventFileFlags.no_flags
        self.data = []

        # Verify there's only one source
        if not zgEvent and not syscallStr and not cmdlineStr:
            raise ValueError("Events cannot be empty: please provide a log "
                             "entry from Zeitgeist or PreloadLogger, or a "
                             "command line to analyse.")

        if (zgEvent and (syscallStr or cmdlineStr)) or \
           (syscallStr and cmdlineStr):
            raise ValueError("Events can only be parsed from a single log "
                             "entry: please provide either a Zeitgeist or a "
                             "PreloadLogger entry or a command line, but not "
                             "multiple sources.")

        if zgEvent:
            self.source = EventSource.zeitgeist
            self.parseZeitgeist(zgEvent)
        elif syscallStr:
            self.source = EventSource.preloadlogger
            self.parseSyscall(syscallStr)
        elif cmdlineStr:
            self.source = EventSource.cmdline
            # TODO mark designation read/create!

    def setDataSyscallFile(self, path: str, ftype: str=''):
        """Set data to a single file (for simple file events)."""
        self.data = [File(path=path, ftype=ftype)]

    def setDataSyscallFD(self, fd: int):
        """Set list of FDs that this Event links to its acting Application."""
        self.data_app = [fd]

    def setDataZGFiles(self, zge: SqlEvent):
        """Set data to a list of files (for simple file events)."""
        self.data = []
        for subj in zge.subjects:
            if subj.uri.startswith("file://"):
                f = File(path=urlToUnixPath(subj.uri),
                         ftype=subj.mimetype)
                self.data.append(f)

    def setDataZGFilesDual(self, zge: SqlEvent):
        """Set data to a list of file couples (for copy/move events)."""
        self.data = []
        for subj in zge.subjects:
            if subj.uri.startswith("file://"):
                fold = File(path=urlToUnixPath(subj.uri),
                            ftype=subj.mimetype)
                fnew = File(path=urlToUnixPath(subj.current_uri),
                            ftype=subj.mimetype)
                self.data.append((fold, fnew))

    def parseZeitgeist(self, zge: SqlEvent):
        """Process a Zeitgeist event to initialise this Event."""
        self.dbgdata = zge
        self.evflags |= EventFileFlags.designation

        # File creation (or file write on a file that was incorrectly detected
        # as non-existent; this is solved later on in the simulator).
        if zge.interpretation in (
             'activity://gui-toolkit/gtk2/FileChooser/FileCreate',
             'activity://gui-toolkit/gtk3/FileChooser/FileCreate'):
            self.evtype = EventType.filecreate
            self.evflags |= EventFileFlags.create
            self.evflags |= EventFileFlags.write
            self.setDataZGFiles(zge)

        # File read.
        elif zge.interpretation in (
             'activity://gui-toolkit/gtk2/FileChooser/FileAccess',
             'activity://gui-toolkit/gtk3/FileChooser/FileAccess'):
            self.evtype = EventType.fileread
            self.evflags |= EventFileFlags.read
            self.setDataZGFiles(zge)

        # File write.
        elif zge.interpretation in (
             'activity://gui-toolkit/gtk2/FileChooser/FileModify',
             'activity://gui-toolkit/gtk3/FileChooser/FileModify'):
            self.evtype = EventType.filewrite
            self.evflags |= EventFileFlags.write
            self.setDataZGFiles(zge)

        # File deletion; we don't treat trashed files as 'moved' to trash
        # because we don't know their exact path in the trash.
        elif zge.interpretation in (
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#TrashEvent',
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#DeleteEvent'):
            self.evtype = EventType.filedelete
            self.evflags |= EventFileFlags.write
            self.evflags |= EventFileFlags.destroy
            self.setDataZGFiles(zge)

        # File move; we record the information flow between both files, so
        # that's not a deletion + creation.
        elif zge.interpretation in (
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#MoveEvent',):
            self.evtype = EventType.filemove
            self.evflags |= EventFileFlags.move
            self.setDataZGFilesDual(zge)

        # File copy; similar to file move
        elif zge.interpretation in (
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#CopyEvent',):
            self.evtype = EventType.filecopy
            self.evflags |= EventFileFlags.copy
            self.setDataZGFilesDual(zge)

        else:
            # TODO continue
            self.type = EventType.invalid

    def _openRejectError(self, syscall, path, flags, error):
        """Print a warning that a syscall failed and invalidate the Event."""
        # Don't log failed syscalls, but inform the reader
        print("Info: system call %s(%s, %d) from Application %s:%d "
              "failed with error %d, and will not be logged." % (
               syscall, path, flags,
               self.actor.getDesktopId(), self.actor.getPid(),
               error),
              file=sys.stderr)
        self.type = EventType.invalid

    def _openFopenParseFlags(self, flags):
        """Parse flags for open syscalls (and for fopen, as PL maps them)."""
        if flags & O_CREAT:
            self.evflags |= EventFileFlags.create
            self.evtype = EventType.filecreate

        if flags & O_TRUNC:
            self.evflags |= EventFileFlags.overwrite
            self.evtype = EventType.filecreate

        if flags & O_ACCMODE == O_WRONLY:
            self.evflags |= EventFileFlags.write
            self.evtype = EventType.filewrite

        if flags & O_ACCMODE == O_RDONLY:
            self.evflags |= EventFileFlags.read
            self.evtype = EventType.fileread

        if flags & O_ACCMODE == O_RDWR:
            self.evflags |= EventFileFlags.write
            self.evflags |= EventFileFlags.read
            self.evtype = EventType.filereadwrite

    def parsePOSIXOpen(self, syscall: str, content: str):
        """Process a POSIX open() or similar system call."""
        # Process the event's content
        res = Event.posixOpenRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            if syscall not in ('openat', 'openat64', 'mkdirat'):
                print("Error: POSIX open* system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.type = EventType.invalid
                return
            else:
                print("TODO: find RE parser for: ", syscall, "***", content)
                print("TODO: init @fdref@ with fd value")
                sys.exit(1)  # TODO
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 5:
                print("Error: POSIX open* system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.type = EventType.invalid
                return

            # Assign relevant variables
            func = (str, int, int, int, str)
            (filename, fd, flags, error, cwd) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator
        path = filename if filename.startswith('/') else np(cwd+'/'+filename)

        # Inject reference to system call if relevant, but as openat is
        # sometimes open with a NULL fd parameter, it can happen that fdref is
        # not defined, and that's fine.
        if syscall in ('openat', 'openat64', 'mkdirat'):
            try:
                path = ("@fdref%d@" % fdref) + path  # FIXME syntax
            except NameError:
                pass

        # Now, save the File that will be processed by the simulator
        if syscall in ('mkdirat', 'mkdir') or flags & O_DIRECTORY:
            self.setDataSyscallFile(path, 'inode/directory')
        else:
            self.setDataSyscallFile(path)
        self.setDataSyscallFD(fd)

        # Don't log failed syscalls, but inform the reader
        if error < 0:
            self._openRejectError(syscall, path, flags, error)
            return

        # creat() is a specialised open(), and mkdir() also 'creates' a file
        if syscall in ('creat', 'mkdir'):
            flags = O_WRONLY | O_CREAT | O_TRUNC

        # Parse flags
        self._openFopenParseFlags(flags)

    def parsePOSIXFopen(self, syscall: str, content: str):
        """Process a POSIX fopen() or freopen() system call."""
        # Process the event's content
        res = Event.posixFopenRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX fopen/freopen system call was not logged "
                  "properly: %s" % content, file=sys.stderr)
            self.type = EventType.invalid
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 5:
                print("Error: POSIX fopen/freopen system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.type = EventType.invalid
                return

            # Assign relevant variables
            func = (str, int16, int, int, str)
            (filename, fd, flags, error, cwd) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = filename if filename.startswith('/') else np(cwd+'/'+filename)
        self.setDataSyscallFile(path)
        self.setDataSyscallFD(fd)

        # Don't log failed syscalls, but inform the reader
        if error < 0:
            self._openRejectError(syscall, path, flags, error)
            return

        # Parse flags
        self._openFopenParseFlags(flags)

    def parsePOSIXFDopen(self, syscall: str, content: str):
        """Process a POSIX fdopen() or fdopendir() system call."""

        # FIXME DEBUG
        if syscall in ('fdopendir',):
            print("CHECK SYNTAX: ", syscall, content)   # TODO
            sys.exit(1)

        # Process the event's content
        content = content.strip()
        res = Event.posixFDopenRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX fdopen/fdopendir system call was not "
                  "logged properly: %s" % content, file=sys.stderr)
            self.type = EventType.invalid
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 4:
                print("Error: POSIX fdopen/fdopendir system call was not "
                      "logged properly: %s" % content, file=sys.stderr)
                self.type = EventType.invalid
                return

            # Assign relevant variables
            func = (int, str, int16, int, int, str)
            (fdref, fd, flags, error) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = ("@fdref%d@" % fdref)  # FIXME syntax

        # Don't log failed syscalls, but inform the reader
        if error < 0:
            self._openRejectError(syscall, path, flags, error)
            return

        # Now, save the File that will be processed by the simulator
        if syscall in ('fdopendir') or flags & O_DIRECTORY:
            self.setDataSyscallFile(path, 'inode/directory')
        else:
            self.setDataSyscallFile(path)
        self.setDataSyscallFD(fd)

        # Parse flags
        self._openFopenParseFlags(flags)

    def parsePOSIXOpendir(self, syscall: str, content: str):
        """Process a POSIX opendir() system call."""
        # Process the event's content
        res = Event.posixOpendirRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX opendir system call was not logged "
                  "properly: %s" % content, file=sys.stderr)
            self.type = EventType.invalid
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 4:
                print("Error: POSIX opendir system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.type = EventType.invalid
                return

            # Assign relevant variables
            func = (str, int16, int, str)
            (filename, fd, error, cwd) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = filename if filename.startswith('/') else np(cwd+'/'+filename)
        self.setDataSyscallFile(path, 'inode/directory')
        self.setDataSyscallFD(fd)

        # Opendir requires the directory to exist, and is a read access
        flags = O_RDONLY

        # Don't log failed syscalls, but inform the reader
        if error < 0:
            self._openRejectError(syscall, path, flags, error)
            return

        # Parse flags
        self._openFopenParseFlags(flags)

    def parseSyscall(self, syscallStr: str):
        """Process a system call string to initialise this Event."""

        self.dbgdata = syscallStr
        self.evflags |= EventFileFlags.programmatic

        # Extract the system call name
        sep = 0
        sep1 = syscallStr.find('|')
        sep2 = syscallStr.find('\n')
        if sep1 != -1 and sep2 != -1:
            sep = min(sep1, sep2)
        else:
            sep = sep1 if sep1 != -1 else sep2

        syscall = syscallStr[:sep] if sep else syscallStr
        content = syscallStr[sep+1:] if sep else ''

        # Variants of the open() system call
        if syscall in ('creat', 'open', 'openat',
                       'open64', 'openat64', 'mkdir', 'mkdirat'):
            self.parsePOSIXOpen(syscall, content)
        # Variants of the fopen() system calls
        elif syscall in ('fopen', 'freopen'):
            self.parsePOSIXFopen(syscall, content)
        # Variants of the fdopen() system calls
        elif syscall in ('fdopen', 'fdopendir'):
            self.parsePOSIXFDopen(syscall, content)
        # opendir()
        elif syscall in ('opendir',):
            self.parsePOSIXOpendir(syscall, content)

        else:
            # TODO continue
            self.type = EventType.invalid

    def getTime(self):
        """Return the Event's time of occurrence."""
        return self.time

    def getType(self):
        """Return the Event's type."""
        return self.evtype

    def getFileFlags(self):
        """Return the Event's flags related to files."""
        return self.evflags

    def getActor(self):
        """Return the Application that performed this Event."""
        return self.actor

    def getData(self):
        """Return the Event's custom data."""
        return self.data
