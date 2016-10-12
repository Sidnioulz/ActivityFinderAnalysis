from xdg import DesktopEntry
from constants import DESKTOPPATHS


class Application(object):
    init = False      # type: bool
    desktopid = None  # type: str
    path = None       # type: str
    pid = 0           # type: int
    tstart = 0        # type: int
    tend = 0          # type: int
    cmdline = ''      # type: str
    events = []       # type: list
    syscalls = []     # type: list
    windows = []      # type: list
    documents = []    # type: list
    states = []       # type: list
    uris = []         # type: list
    ipc = []          # type: list
    parent = None     # type: Application
    children = []     # type: list

    """ The representation of a Linux Desktop app, identified by its Desktop
        id, or by the path to its executable. """
    def __init__(self,
                 desktopid: str=None,
                 path: str=None,
                 pid: int=0,
                 tstart: int=0,
                 tend: int=0):
        super(Application, self).__init__()
        if desktopid:
            self.desktopid = desktopid
            self.__initFromDesktopID()

        elif path:
            self.path = path
            self.__initFromPath()

        self.pid = pid
        self.tstart = tstart
        self.tend = tend

    """ Initialise an application from the XDG desktop identifier given by
        Zeitgeist (e.g. application://eog.desktop). """
    def __initFromDesktopID(self):
        if self.desktopid is None:
            return
        de = DesktopEntry.DesktopEntry()

        if self.desktopid.startswith("application://"):
            defile = self.desktopid[14:]
        else:
            defile = self.desktopid

        foundPath = False
        for path in DESKTOPPATHS:
            depath = path + defile
            try:
                de.parse(depath)
                self.desktopid = depath
                foundPath = True
                break
            except DesktopEntry.ParsingError as e:
                pass

        if not foundPath:
            self.desktopid = None
            # TODO print error?
            return

        # TODO continue
        self.init = True

    """ Check if an Application is initialised. """
    def isInitialised(self):
        return self.init

    """ Return the Application's .desktop entry identifier """
    def getDesktopId(self):
        return self.desktopid

    """ Return the Application's pid """
    def getPid(self):
        return self.pid

    """ Return the Application's time of start """
    def getTimeOfStart(self):
        return self.tstart

    """ Return the Application's time of end """
    def getTimeOfEnd(self):
        return self.tend

    """ Sets the Application's time of start to the passed value """
    def setTimeOfStart(self, val):
        self.tstart = val

    """ Sets the Application's time of end to the passed value  """
    def setTimeOfEnd(self, val):


        self.tend = val
    """ Merges another application with the current one. """
    def merge(self, other):
        # TODO validate actor
        # TODO validate pid
        # TODO validate path
        self.setTimeOfStart(min(other.getTimeOfStart(),
                                self.getTimeOfStart()))
        self.setTimeOfEnd(max(other.getTimeOfEnd(),
                              self.getTimeOfEnd()))
        self.events += list(set(other.events) - set(self.events))

    """ Adds an event to this Application for future modelling. """
    def addEvent(self, event):
        if event not in self.events:
            self.events.append(event)

    """ Clears all events to be modellined for this Application. """
    def clearEvents(self):
        self.events = []
