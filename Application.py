"""A runtime instance of a Linux Desktop application."""

from xdg import DesktopEntry
from constants import DESKTOPPATHS, DESKTOPIDRE
import re


class Application(object):
    """A runtime instance of a Linux Desktop application.

    Representation of a UNIX process, along with information on the Desktop
    application it is expected to belong to (using XDG Desktop Specification).
    Applications are identified by their XDG Desktop identifier, or by the path
    to their executable.
    """

    init = False              # type: bool
    desktopid = None          # type: str; final id of the app after init
    desktopidoriginal = None  # type: str; original id when App was c'ted
    interpreterid = None      # type: str; id of interpreter, e.g. java, python
    path = None               # type: str; path to executable
    pid = 0                   # type: int; UNIX process ID
    tstart = 0                # type: int; when the app is known to exist
    tend = 0                  # type: int; when it's known to cease existing
    cmdline = ''              # type: str; complete command line, when known
    events = []               # type: list
    windows = []              # type: list
    documents = []            # type: list
    states = []               # type: list
    uris = []                 # type: list
    ipc = []                  # type: list
    parent = None             # type: Application
    children = []             # type: list
    desktopre = re.compile(DESKTOPIDRE)

    def __init__(self,
                 desktopid: str=None,
                 path: str=None,
                 pid: int=0,
                 tstart: int=0,
                 tend: int=0,
                 interpreterid: str=None):
        """Construct an Application, using a desktopid or a path."""
        super(Application, self).__init__()
        if desktopid:
            self.desktopid = desktopid.lower()
            self.__initFromDesktopID()
        elif path:
            self.path = path
            self.__initFromPath()
        else:
            raise ValueError("A binary path or a Desktop id are needed to "
                             "instantiate an Application.")

        self.pid = pid
        self.tstart = tstart
        self.tend = tend
        self.interpreterid = interpreterid.lower() if interpreterid else None

    def __initFromDesktopID(self):
        """Initialise an application using an XDG desktop identifier."""
        if self.desktopid is None:
            return

        if self.desktopid.startswith("application://"):
            defile = self.desktopid[14:]
        else:
            defile = self.desktopid

        if not self.desktopid.endswith(".desktop"):
            defile += ".desktop"

        self.desktopidoriginal = defile

        de = DesktopEntry.DesktopEntry()
        foundPath = False
        for path in DESKTOPPATHS:
            depath = path + defile
            try:
                # TODO: resolve symlink on depath and use that link target
                de.parse(depath)
                res = Application.desktopre.match(depath)
                try:
                    self.desktopid = res.groups()[0].lower()
                except(ValueError, KeyError) as e:
                    self.desktopid = depath.lower()
                foundPath = True
                break
            except DesktopEntry.ParsingError as e:
                pass

        if not foundPath:
            self.desktopid = None
            return

        if not self.path:
            # TODO get path from Exec/TryExec for de entry
            pass

        # TODO continue
        self.init = True

    def __initFromPath(self):
        """Initialise an Application based on the path of its executable.

        Scans the XDG desktop entries' Exec and TryExec paths to find an
        appropriate Desktop id.
        """
        # TODO
        # first, literal pass through Exec
        # second, resolve PATH to only get the executable name
        # third, TryExec, literal
        # forth, TryExec, name
        raise NotImplementedError

    def isInitialised(self):
        """Check if an Application is initialised."""
        return self.init

    def getDesktopId(self):
        """Return the Application's .desktop entry identifier."""
        return self.desktopid

    def hasSameDesktopId(self, other, resolveInterpreter: bool=False):
        """Check whether a desktop id is equivalent to the current object's.

        other -- either another Application or a string containing the desktop
        id to compare.
        resolveInterpreter -- also compare interpreterid, in which case only
        Application instances can be given to :other: (default False).
        """
        if hasattr(other, 'desktopid') and hasattr(other, 'interpreterid'):
            otherId = other.desktopid
            otherInterpreter = other.interpreterid
        elif resolveInterpreter:
            raise AttributeError("This function can only resolve interpreters "
                                 "if you pass it an Application instance, not "
                                 "a string.")
        else:
            otherId = other.lower()

        try:
            res = Application.desktopre.match(otherId)
            otherName = res.groups()[0]
        except (ValueError, KeyError) as e:
            return False
        else:
            if self.desktopid == otherName:
                return True
            elif resolveInterpreter and self.interpreterid == otherName:
                return True
            elif resolveInterpreter and self.desktopid == otherInterpreter:
                return True
            else:
                return False

    def getPid(self):
        """Return the Application's pid."""
        return self.pid

    def getTimeOfStart(self):
        """Return the Application's time of start."""
        return self.tstart

    def getTimeOfEnd(self):
        """Return the Application's time of end."""
        return self.tend

    def setTimeOfStart(self, val):
        """Set the Application's time of start to the passed value."""
        self.tstart = val

    def setTimeOfEnd(self, val):
        """Set the Application's time of end to the passed value."""
        self.tend = val

    def merge(self, other):
        """Merge another Application with the current one.

        Both Applications must have the same PID and initialisation status, and
        an equivalent Desktop id (or the interpreterid of one Application must
        be equal to the other's desktopid). The merged Application will take
        any parameters from :other: that it was missing, and will also update
        its times of start and end to cover the period when both instances were
        running.
        """
        if not isinstance(other, Application):
            raise ValueError("Only other Application instances can be merged.")

        if self.init != other.init:
            raise ValueError("Initialised Applications cannot be merged with "
                             "uninitialised ones.")

        if self.pid != other.pid:
            raise ValueError("Only Applications with the same PID can be "
                             "merged.")

        if self.desktopid != other.desktopid:
            if self.interpreterid == other.desktopid:
                pass
            elif self.desktopid == other.interpreterid:
                self.desktopid = other.desktopid
                self.interpreterid = other.interpreterid
                pass
            else:
                raise ValueError("Only Applications with the same Desktop id "
                                 "can be merged.")

        if (not self.path) and other.path:
            self.path = other.path
        if (not self.cmdline) and other.cmdline:
            self.cmdline = other.cmdline
        if (not self.desktopidoriginal) and other.desktopidoriginal:
            self.desktopidoriginal = other.desktopidoriginal

        self.setTimeOfStart(min(other.getTimeOfStart(),
                                self.getTimeOfStart()))
        self.setTimeOfEnd(max(other.getTimeOfEnd(),
                              self.getTimeOfEnd()))
        self.events += list(set(other.events) - set(self.events))

    def setCommandLine(self, cmd):
        """Set the command line used to start this Application."""
        self.cmdline = cmd

    def getCommandLine(self):
        """Return the command line used to start this Application."""
        return self.cmdline

    def addEvent(self, event):
        """Add an event to this Application for future modelling."""
        self.events.append(event)

    def getAllEvents(self):
        """Return this Application's events."""
        for event in self.events:
            yield event

    def takeAllEvents(self):
        """Return this Application's events and clears them."""
        ev = self.events
        self.events = []
        return ev

    def clearEvents(self):
        """Clear all events to be modellined for this Application."""
        self.events = []
