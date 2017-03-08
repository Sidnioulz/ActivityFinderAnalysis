"""An action performed by an Application at a specific time."""
from enum import Enum
from Application import Application
from SqlEvent import SqlEvent
from File import File, EventFileFlags, FileStub
from utils import urlToUnixPath, int16, debugEnabled, intersection, \
                  checkExcludedFilesEnabled
from constants import POSIX_OPEN_RE, POSIX_FOPEN_RE, POSIX_FDOPEN_RE, \
                      POSIX_OPENDIR_RE, POSIX_UNLINK_RE, POSIX_CLOSE_RE, \
                      POSIX_FCLOSE_RE, POSIX_RENAME_RE, POSIX_DUP_RE, \
                      O_ACCMODE, O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, \
                      O_TRUNC, O_DIRECTORY, FD_OPEN, FD_CLOSE, \
                      POSIX_FDOPENDIR_RE
from UserConfigLoader import UserConfigLoader
import sys
import re
from os.path import normpath as np

excludedEvents = 0
excludedFiles = set()
excludedApps = dict()
exclItemsRORW = dict()


def dbgPrintExcludedEvents():
    """Print excluded Events/Files, if asked to. Used for debugging."""
    global excludedApps
    global excludedEvents
    global excludedFiles

    dids = dict()
    print("\n\nINSTANCES")
    for app, count in sorted(excludedApps.items(), key=lambda x: x[0].uid()):
        print("%s: %d" % (app.uid(), count))
        dd = dids.get(app.desktopid) or (0, 0)
        dids[app.desktopid] = (dd[0] + count, dd[1] + 1)

    print("\n\nDESKTOP IDS")
    for did, count in sorted(dids.items()):
        print("%s: %d files across %d instances" % (did, count[0], count[1]))

    print("\n\nTOTAL EXCLUSIONS: %d files, %d events" % (
           len(excludedFiles), excludedEvents))

    print("\n\nTOTAL FILES ALSO ACCESSED BY EXCLUDED LISTS")
    for uid, rorws in exclItemsRORW.items():
        mustBePrinted = False
        for e, rorw in rorws.items():
            if rorw[1]:
                mustBePrinted = True
                break

        if not mustBePrinted:
            continue

        print("APP: %s" % uid)
        for e, rorw in rorws.items():
            print(e, rorw)

    sys.exit(0)


class EventSource(Enum):
    """Supported sources for events: Zeitgeist or PreloadLogger."""

    unknown = 0
    zeitgeist = 1
    preloadlogger = 2
    cmdline = 3


class Event(object):
    """An action performed by an Application at a specific time.

    Representation of an action performed by an Application, e.g. a system call
    or usage of a Desktop API. Actions are performed at a specific time, and
    target subjects (e.g. Files or other Applications).
    """

    posixOpenRe = re.compile(POSIX_OPEN_RE)
    posixFopenRe = re.compile(POSIX_FOPEN_RE)
    posixFDopenRe = re.compile(POSIX_FDOPEN_RE)
    posixFDopendirRe = re.compile(POSIX_FDOPENDIR_RE)
    posixOpendirRe = re.compile(POSIX_OPENDIR_RE)
    posixUnlinkRe = re.compile(POSIX_UNLINK_RE)
    posixCloseRe = re.compile(POSIX_CLOSE_RE)
    posixFcloseRe = re.compile(POSIX_FCLOSE_RE)
    posixRenameRe = re.compile(POSIX_RENAME_RE)
    posixDupRe = re.compile(POSIX_DUP_RE)

    def __init__(self,
                 actor: Application=None,
                 time: int=0,
                 zgEvent: list=None,
                 syscallStr: str=None,
                 cmdlineStr: str=None):
        """Construct an Event, using a Zeitgeist or PreloadLogger log entry."""
        super(Event, self).__init__()
        # Initialise actor and time of occurrence
        if not time:
            raise ValueError("Events must have a time of occurrence.")
        self.actor = actor  # type: Application; responsible for the event
        self.time = time    # type: int; when the event occurred

        self.evflags = EventFileFlags.no_flags  # type: EventFileFlags
        self.source = EventSource.unknown       # type: EventSource

        self.data = []        # binary data specific to each Event.
        self.data_app = []    # binary data specific to each Event's actor.

        # Dummy actors are useful for making dummy events for time comparison.
        if not actor:
            return

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
            self.parseCommandLine(cmdlineStr)

        if checkExcludedFilesEnabled():
            self.checkIfExcluded()

    def markInvalid(self):
        """Mark an Event as being invalid, by deleting its flags."""
        self.evflags = EventFileFlags.no_flags
        self.actor = None
        self.data = None
        self.data_app = None

    def isInvalid(self):
        """Tell if an Event is invalid by checking it has flags."""
        return self.evflags == EventFileFlags.no_flags

    def checkIfExcluded(self):
        """Check if Event concerns an excluded File, invalidate Event if so."""

        def _hasExcludedFile(self):
            if not self.data:
                return False

            global excludedApps
            global excludedEvents
            global excludedFiles
            global exclItemsRORW

            def _userFile(p, userHome):
                hasParent = True
                hidden = False
                path = p
                while hasParent and not hidden:
                    path = File.getParentNameFromName(path)
                    hasParent = True if path else False

                    if hasParent:
                        lastDir = path.rfind('/')
                        if lastDir >= 0:
                            hidden = len(path) > lastDir+1 and \
                                path[lastDir+1] == '.'
                        else:
                            hidden = path[0] == '.'

                if hidden or p.startswith(userHome+"/."):
                    return False

                if not p.startswith("/media") and \
                        not p.startswith("/mnt") and \
                        not p.startswith(userHome):
                    return False

                return True

            if checkExcludedFilesEnabled():
                if self.actor.uid() not in exclItemsRORW:
                    eI = dict()
                    userConf = UserConfigLoader.get()
                    excl = userConf.getExcludedHomeDirs()
                    for e in excl:
                        eI[e] = [0, 0, 0, 0, set(), set()]
                    exclItemsRORW[self.actor.uid()] = eI

            userConf = UserConfigLoader.get()
            userHome = userConf.getHomeDir()
            excl = userConf.getExcludedHomeDirs()

            if isinstance(self.data[0], FileStub):
                paths = list((f.path for f in self.data))
            elif isinstance(self.data[0], str):
                paths = self.data
            elif isinstance(self.data[0], tuple):
                if isinstance(self.data[0][0], FileStub):
                    paths = list((f.path for t in self.data for f in t))
                elif isinstance(self.data[0][0], str):
                    paths = list((f for t in self.data for f in t))

            else:
                print(type(self.data[0]))

            i = []
            ro = self.evflags & EventFileFlags.read
            for p in paths:
                found = False
                for e in excl:
                    if p.startswith(e):
                        found = True
                        i.append(p)
                        if checkExcludedFilesEnabled():
                            eI = exclItemsRORW[self.actor.uid()]
                            for eKey, rorw in eI.items():
                                if eKey == e:
                                    rorw[0 if ro else 1] += 1
                                else:
                                    rorw[2 if ro else 3] += 1
                                eI[eKey] = rorw
                                exclItemsRORW[self.actor.uid()] = eI

                if checkExcludedFilesEnabled() and not found \
                        and _userFile(p, userHome):
                    eI = exclItemsRORW[self.actor.uid()]
                    for eKey, rorw in eI.items():
                        rorw[4 if ro else 5].add(p)
                        eI[eKey] = rorw
                        exclItemsRORW[self.actor.uid()] = eI

            if i:
                if checkExcludedFilesEnabled():
                    excludedEvents += 1
                    for path in i:
                        excludedFiles.add(path)
                    aC = excludedApps.get(self.actor) or 0
                    excludedApps[self.actor] = aC + 1
                return True

            return False

        if _hasExcludedFile(self):
            self.markInvalid()

    def parseCommandLine(self, cmdlineStr: str):
        """Parse a command line to record acts of designation onto Files."""
        # Attn: we can't just split the command-line because spaces did not get
        # escaped! So we have to match the file names to the whole string and
        # hope for a match. Files with a relative path cannot be matched thus.
        # # Split command-line
        # g = space.split(cmdlineStr.strip())
        #
        # # Collect all files
        # self.data = []
        # del g[0]
        # for component in g:
        #     # Remove the very likely app parameter
        #     if component.startswith('-'):
        #         continue
        #
        #     f = File(path=component, tstart=self.time)
        #     self.data.append(f)
        self.data = cmdlineStr

        # Tell the EventStore this is an act of designation
        self.evflags |= EventFileFlags.designationcache

        # Command-lines indicate designation for any future processing
        self.evflags |= EventFileFlags.designation
        self.evflags |= EventFileFlags.read
        self.evflags |= EventFileFlags.write
        self.evflags |= EventFileFlags.create
        self.evflags |= EventFileFlags.overwrite
        self.evflags |= EventFileFlags.destroy

    def setDataSyscallFile(self, path: str, ftype: str=''):
        """Set data to a single file (for simple file events)."""
        self.data = [FileStub(path, ftype)]

    def setDataSyscallFD(self, fd: int, path: str, fdType):
        """Set list of FDs that this Event links to its acting Application."""
        self.data_app.append((fd, path, fdType))

    def setDataSyscallFilesDual(self, oldpath: str, newpath: str):
        """Set data to a list of file couples (for copy/move events)."""
        fold = FileStub(oldpath, None)
        fnew = FileStub(newpath, None)
        self.data = [(fold, fnew)]

    def setDataZGFiles(self, zge: SqlEvent):
        """Set data to a list of files (for simple file events)."""
        self.data = []
        for subj in zge.subjects:
            if subj.uri.startswith("file://"):
                f = FileStub(urlToUnixPath(subj.uri), subj.mimetype)
                self.data.append(f)

    def setDataZGFilesDual(self, zge: SqlEvent):
        """Set data to a list of file couples (for copy/move events)."""
        self.data = []
        for subj in zge.subjects:
            if subj.uri.startswith("file://"):
                fold = FileStub(urlToUnixPath(subj.uri), subj.mimetype)
                fnew = FileStub(urlToUnixPath(subj.current_uri), subj.mimetype)
                self.data.append((fold, fnew))

    def parseZeitgeist(self, zge: SqlEvent):
        """Process a Zeitgeist event to initialise this Event."""
        # self.dbgdata = zge
        self.evflags |= EventFileFlags.designation

        # File creation (or file write on a file that was incorrectly detected
        # as non-existent; this is solved later on in the simulator).
        if zge.interpretation in (
             'activity://gui-toolkit/gtk2/FileChooser/FileCreate',
             'activity://gui-toolkit/gtk3/FileChooser/FileCreate'):
            self.evflags |= EventFileFlags.create
            self.evflags |= EventFileFlags.write
            self.setDataZGFiles(zge)

        # File read.
        elif zge.interpretation in (
             'activity://gui-toolkit/gtk2/FileChooser/FileAccess',
             'activity://gui-toolkit/gtk3/FileChooser/FileAccess'):
            self.evflags |= EventFileFlags.read
            self.setDataZGFiles(zge)

        # File write.
        elif zge.interpretation in (
             'activity://gui-toolkit/gtk2/FileChooser/FileModify',
             'activity://gui-toolkit/gtk3/FileChooser/FileModify'):
            self.evflags |= EventFileFlags.write
            self.setDataZGFiles(zge)

        # File deletion; we don't treat trashed files as 'moved' to trash
        # because we don't know their exact path in the trash.
        elif zge.interpretation in (
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#TrashEvent',
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#DeleteEvent'):
            self.evflags |= EventFileFlags.write
            self.evflags |= EventFileFlags.destroy
            self.setDataZGFiles(zge)

        # File move; we record the information flow between both files, so
        # that's not a deletion + creation.
        elif zge.interpretation in (
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#MoveEvent',):
            self.evflags |= EventFileFlags.move
            self.setDataZGFilesDual(zge)

        # File copy; similar to file move
        elif zge.interpretation in (
             'http://www.zeitgeist-project.com/ontologies/2010/01/27/'
             'zg#CopyEvent',):
            self.evflags |= EventFileFlags.copy
            self.setDataZGFilesDual(zge)

        else:
            # TODO continue
            self.markInvalid()

    def _rejectError(self, syscall, path, flags, error):
        """Print a warning that a syscall failed and invalidate the Event."""
        # Don't log failed syscalls, but inform the reader
        if debugEnabled():
            print("Info: system call %s(%s, %d) from Application %s:%d "
                  "failed with error %d, and will not be logged." % (
                   syscall, path, flags,
                   self.actor.desktopid, self.actor.pid,
                   error),
                  file=sys.stderr)

        self.markInvalid()

    def _openFopenParseFlags(self, flags):
        """Parse flags for open syscalls (and for fopen, as PL maps them)."""
        if flags & O_CREAT:
            self.evflags |= EventFileFlags.create

        if flags & O_TRUNC:
            self.evflags |= EventFileFlags.overwrite

        if flags & O_ACCMODE == O_WRONLY:
            self.evflags |= EventFileFlags.write

        if flags & O_ACCMODE == O_RDONLY:
            self.evflags |= EventFileFlags.read

        if flags & O_ACCMODE == O_RDWR:
            self.evflags |= EventFileFlags.write
            self.evflags |= EventFileFlags.read

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
                self.markInvalid()
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
                self.markInvalid()
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
                path = ("@fdref:%d@appref:%s@" % (
                         fdref, self.getActor().uid())) + path
            except NameError:
                pass

        # Don't log failed syscalls, but inform the reader
        if error < 0 or fd == -1:
            self._rejectError(syscall, path, flags, error)
            return

        # Now, save the File that will be processed by the simulator
        if syscall in ('mkdirat', 'mkdir') or flags & O_DIRECTORY:
            self.setDataSyscallFile(path, 'inode/directory')
        else:
            self.setDataSyscallFile(path)
        self.setDataSyscallFD(fd, path, FD_OPEN)

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
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 5:
                print("Error: POSIX fopen/freopen system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (str, int16, int, int, str)
            (filename, fd, flags, error, cwd) = map(lambda f, d: f(d), func, g)

        # Ignore abstract sockets
        if filename.startswith('@/'):
            # print("Info: opening of abstract socket '%s' will be ignored." %
            #       filename)
            self.markInvalid()
            return

        # Build path to be used by simulator, and save the corresponding File
        path = filename if filename.startswith('/') else np(cwd+'/'+filename)

        # Don't log failed syscalls, but inform the reader
        if error < 0 or fd == -1:
            self._rejectError(syscall, path, flags, error)
            return

        # Set paths once we know the call succeeded
        self.setDataSyscallFile(path)
        self.setDataSyscallFD(fd, path, FD_OPEN)

        # Parse flags
        self._openFopenParseFlags(flags)

    def parsePOSIXFDopendir(self, syscall: str, content: str):
        """Process a POSIX fdopendir() system call."""
        # Process the event's content
        content = content.strip()
        res = Event.posixFDopendirRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX fdopendir system call was not "
                  "logged properly: %s" % content, file=sys.stderr)
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 3:
                print("Error: POSIX fdopendir system call was not "
                      "logged properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (int, int16, int)
            (fdref, fd, error) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = ("@fdref:%d@appref:%s@" % (fdref, self.getActor().uid()))

        # Opendir requires the directory to exist, and is a read access
        flags = O_RDONLY

        # Don't log failed syscalls, but inform the reader
        if error < 0 or fd == -1:
            self._rejectError(syscall, path, flags, error)
            return

        # Set paths once we know the call succeeded
        self.setDataSyscallFile(path, 'inode/directory')
        self.setDataSyscallFD(fd, path, FD_OPEN)

        # Parse flags
        self._openFopenParseFlags(flags)

    def parsePOSIXFDopen(self, syscall: str, content: str):
        """Process a POSIX fdopen() system call."""

        # Process the event's content
        content = content.strip()
        res = Event.posixFDopenRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX fdopen system call was not "
                  "logged properly: %s" % content, file=sys.stderr)
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 4:
                print("Error: POSIX fdopen system call was not "
                      "logged properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (int, int16, int, int)
            (fdref, fd, flags, error) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = ("@fdref:%d@appref:%s@" % (fdref, self.getActor().uid()))

        # Don't log failed syscalls, but inform the reader
        if error < 0 or fd == -1:
            self._rejectError(syscall, path, flags, error)
            return

        # Now, save the File that will be processed by the simulator
        if flags & O_DIRECTORY:
            self.setDataSyscallFile(path, 'inode/directory')
        else:
            self.setDataSyscallFile(path)
        self.setDataSyscallFD(fd, path, FD_OPEN)

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
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 4:
                print("Error: POSIX opendir system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (str, int16, int, str)
            (filename, fd, error, cwd) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = filename if filename.startswith('/') else np(cwd+'/'+filename)

        # Opendir requires the directory to exist, and is a read access
        flags = O_RDONLY

        # Don't log failed syscalls, but inform the reader
        if error < 0 or fd == -1:
            self._rejectError(syscall, path, flags, error)
            return

        # Set paths once we know the call succeeded
        self.setDataSyscallFile(path, 'inode/directory')
        self.setDataSyscallFD(fd, path, FD_OPEN)

        # Parse flags
        self._openFopenParseFlags(flags)

    def parsePOSIXUnlink(self, syscall: str, content: str):
        """Process a POSIX unlink() system call."""
        # Process the event's content
        res = Event.posixUnlinkRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX unlink system call was not logged "
                  "properly: %s" % content, file=sys.stderr)
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 3:
                print("Error: POSIX unlink system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (str, int, str)
            (filename, error, cwd) = map(lambda f, d: f(d), func, g)

        # Build path to be used by simulator, and save the corresponding File
        path = filename if filename.startswith('/') else np(cwd+'/'+filename)
        if syscall in ('rmdir',):
            self.setDataSyscallFile(path, 'inode/directory')
        else:
            self.setDataSyscallFile(path)

        # Don't log failed syscalls, but inform the reader
        if error != 0:
            if syscall in ('rmdir',) and error == 39:
                return  # silently, ENOTEMPTY happens all the time
            elif syscall in ('unlink',) and error == 2:
                return  # silently, ENOENT happens often with cache cleanups
            else:
                self._rejectError(syscall, path, 0, error)
                return

        self.evflags |= EventFileFlags.write
        self.evflags |= EventFileFlags.destroy

    def parsePOSIXClose(self, syscall: str, content: str):
        """Process a POSIX close() or fclose() or closedir() system call."""
        # Process the event's content
        if syscall == 'close':
            res = Event.posixCloseRe.match(content)
        else:
            res = Event.posixFcloseRe.match(content)

        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX close* system call was not logged "
                  "properly: %s" % content, file=sys.stderr)
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 2:
                print("Error: POSIX close* system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (int if syscall == 'close' else int16, int)
            (fd, error) = map(lambda f, d: f(d), func, g)

        # Don't log failed syscalls, but inform the reader
        if error < 0 or fd == -1:
            self._rejectError(syscall, None, 0, error)
            return

        # Build path to be used by simulator, and save the corresponding File
        self.setDataSyscallFD(fd, None, FD_CLOSE)

    def parsePOSIXRename(self, syscall: str, content: str):
        """Process a POSIX rename() system call."""

        # FIXME DEBUG
        if syscall in ('renameat', 'renameat2',):
            print("CHECK SYNTAX: ", syscall, content)   # TODO
            sys.exit(1)

        # Process the event's content
        res = Event.posixRenameRe.match(content)

        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX rename system call was not logged "
                  "properly: %s" % content, file=sys.stderr)
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 6:
                print("Error: POSIX rename system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (str, str, str, int, int, str)
            (old, ocwd, new, flags, error, ncwd) = map(
                lambda f, d: f(d), func, g)

        # Don't log failed syscalls, but inform the reader
        if error < 0:
            self._rejectError(syscall, None, 0, error)
            return

        # Build paths to be used by simulator, and save the corresponding File
        oldpath = old if old.startswith('/') else np(ocwd+'/'+old)
        newpath = new if new.startswith('/') else np(ncwd+'/'+new)

        self.evflags |= EventFileFlags.copy
        self.setDataSyscallFilesDual(oldpath, newpath)

    def parsePOSIXDup(self, syscall: str, content: str):
        """Process a POSIX dup*() system call.

        WARNING: Do not tamper with the way the error code is processed, it was
        incorrectly stored in PreloadLogger. We thus cannot know when there was
        an error and we must assume that the operation was always correct.
        """

        # Process the event's content
        res = Event.posixDupRe.match(content)
        try:
            g = res.groups()
        except(AttributeError) as e:
            print("Error: POSIX dup* system call was not logged "
                  "properly: %s" % content, file=sys.stderr)
            self.markInvalid()
            return
        else:
            # Check the syscall was well formed and we have everything we need
            if len(g) != 5:
                print("Error: POSIX dup* system call was not logged "
                      "properly: %s" % content, file=sys.stderr)
                self.markInvalid()
                return

            # Assign relevant variables
            func = (int, str, int, str, str)
            (oldfd, oldcwd, newfd, __, newcwd) = \
                map(lambda f, d: f(d), func, g)

        # No error checking in this syscall due to a bug in PreloadLogger.
        if -1 in (oldfd, newfd):
            self._rejectError(syscall, ("%d/%d" % (oldfd, newfd)), 0, -1)
            return

        # Ignore duplications of FD 0, 1 or 2. Note that this is weak, a better
        # approach would be for Application.resolveFD to detect when a FD
        # references the stdin/out/err descriptors, and only then to abort
        # the current Event. This is much harder architecturally, though.
        if oldfd in (0, 1, 2) or newfd in (0, 1, 2):
            self.markInvalid()
            return

        # Close the file descriptor at the previous address, for dup2 and dup3.
        if syscall in ('dup2', 'dup3'):
            if oldfd != newfd:
                self.setDataSyscallFD(newfd, None, FD_CLOSE)
            else:
                self._rejectError(syscall, str(newfd), 0, 0)
                return

        # Build path to be used by simulator, and save the corresponding File
        newpath = ("@fdref:%d@appref:%s@" % (oldfd, self.getActor().uid()))
        self.setDataSyscallFD(newfd, newpath, FD_OPEN)

        self.evflags |= EventFileFlags.read
        self.setDataSyscallFile(newpath)

    def parseSyscall(self, syscallStr: str):
        """Process a system call string to initialise this Event."""

        # self.dbgdata = syscallStr
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
        elif syscall in ('fdopen',):
            self.parsePOSIXFDopen(syscall, content)
        # Variants of the fdopendir() system calls
        elif syscall in ('fdopendir',):
            self.parsePOSIXFDopendir(syscall, content)
        # folder opening
        elif syscall in ('opendir',):
            self.parsePOSIXOpendir(syscall, content)
        # file deletion
        elif syscall in ('unlink', 'remove', 'rmdir'):
            self.parsePOSIXUnlink(syscall, content)
        # file descriptor closing
        elif syscall in ('close', 'fclose', 'closedir'):
            self.parsePOSIXClose(syscall, content)
        # file renaming
        elif syscall in ('rename', 'renameat', 'renameat2', ):
            self.parsePOSIXRename(syscall, content)
        # file description duplication
        elif syscall in ('dup', 'dup2', 'dup3', ):
            self.parsePOSIXDup(syscall, content)
        else:
            # TODO continue
            self.markInvalid()

    def getTime(self):
        """Return the Event's time of occurrence."""
        return self.time

    def getFileFlags(self):
        """Return the Event's flags related to files."""
        return self.evflags

    def getActor(self):
        """Return the Application that performed this Event."""
        return self.actor

    def getData(self):
        """Return the Event's custom data."""
        return self.data

    def getSource(self):
        """Return the source of the Event (zeitgeist, preload-logger, etc.)."""
        return self.source
