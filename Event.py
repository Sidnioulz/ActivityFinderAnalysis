"""An action performed by an Application at a specific time."""

from enum import Enum
from Application import Application
from utils import timestampZgPrint
from constants import EV_TIMESTAMP, EV_INTERPRETATION_URI


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


class Event(object):
    """An action performed by an Application at a specific time.

    Representation of an action performed by an Application, e.g. a system call
    or usage of a Desktop API. Actions are performed at a specific time, and
    target subjects (e.g. Files or other Applications).
    """

    time = 0       # type: int; when the event occurred
    evtype = None  # type: EventType; type of the event
    actor = None   # type: list; actor responsible for performing the event
    subjects = []  # type: list; other entities affected by the event

    def __init__(self,
                 actor: Application,
                 time: int=0,
                 zgEvent: list=None,
                 syscallStr: str=None):
        """Construct an Event, using a Zeitgeist or PreloadLogger log entry."""
        super(Event, self).__init__()

        if not actor:
            raise ValueError("Events must be performed by a valid "
                             "Application.")

        if not zgEvent and not syscallStr:
            raise ValueError("Events cannot be empty: please provide a log "
                             "entry from Zeitgeist or PreloadLogger to "
                             "analyse.")

        if zgEvent and syscallStr:
            raise ValueError("Events can only be parsed from a single log "
                             "entry: please provide either a Zeitgeist or a "
                             "PreloadLogger entry, but not both.")

        self.time = time
        self.actor = actor

        if zgEvent:
            self.time = zgEvent[EV_TIMESTAMP] if not self.time else self.time
            # TODO Parse event! woop woop
            print("NEW EVENT: AT %s -- %s from ZG" % (
                   timestampZgPrint(self.time), zgEvent[EV_INTERPRETATION_URI])
                  )

        elif syscallStr:
            syscall = None
            content = None
            bits = syscallStr.split(sep='|')
            try:
                self.time = bits[0] * 100-100 if not self.time else self.time
                syscall = bits[1]
                content = bits[2]
            except(TypeError, KeyError) as e:
                raise ValueError("An invalid system call was passed to Event, "
                                 "aborting: %s" % syscallStr)
            # TODO pass syscall and content to a dispatcher for handlers
            print("NEW EVENT: AT %s -- %s from PL" % (
                   timestampZgPrint(self.time), syscall)
                  )

    def getTime(self):
        """Return the Event's time of occurrence."""
        return self.time

    def getActor(self):
        """Return the Application that performed this Event."""
        return self.actor
