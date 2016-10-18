"""An action performed by an Application at a specific time."""

from enum import Enum
from Application import Application
# from utils import timestampZgPrint
# from constants import EV_TIMESTAMP, EV_INTERPRETATION_URI


class EventSource(Enum):
    """Supported sources for events: Zeitgeist or PreloadLogger."""

    unknown = 0
    zeitgeist = 1
    preloadlogger = 2
    cmdline = 3


class EventType(Enum):
    """Supported types of events, from Zeitgeist or PreloadLogger."""

    unknown = 0

    filecreate = 1
    filemove = 2
    filecopy = 3
    fileread = 4
    filewrite = 5
    filedelete = 6
    filelink = 7
    filesymlink = 8

    applaunch = 9
    appstart = 10


class Event(object):
    """An action performed by an Application at a specific time.

    Representation of an action performed by an Application, e.g. a system call
    or usage of a Desktop API. Actions are performed at a specific time, and
    target subjects (e.g. Files or other Applications).
    """

    time = 0       # type: int; when the event occurred
    evtype = None  # type: EventType; type of the event
    actor = None   # type: list; actor responsible for performing the event
    source = EventSource.unknown  # type: EventSource; source of the event
    subjects = []  # type: list; other entities affected by the event

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
            # TODO Parse event! woop woop
            # print("NEW EVENT: AT %s -- %s from ZG" % (
            #        timestampZgPrint(self.time), zgEvent[EV_INTERPRETATION_URI])
            #       )

        elif syscallStr:
            self.source = EventSource.preloadlogger
            syscall = None
            content = None
            bits = syscallStr.split(sep='|')
            try:
                syscall = bits[0]
                content = bits[1]
            except(TypeError, KeyError) as e:
                raise ValueError("An invalid system call was passed to Event, "
                                 "aborting: %s" % syscallStr)
            # TODO pass syscall and content to a dispatcher for handlers
            # print("NEW EVENT: AT %s -- %s from PL" % (
            #        timestampZgPrint(self.time), syscall)
            #       )
        elif cmdlineStr:
            self.source = EventSource.cmdline
            # TODO
            # print("NEW EVENT: AT %s -- %s from CMD" % (
            #        timestampZgPrint(self.time), syscall)
            #       )

    def getTime(self):
        """Return the Event's time of occurrence."""
        return self.time

    def getActor(self):
        """Return the Application that performed this Event."""
        return self.actor
