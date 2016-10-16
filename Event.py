"""An action performed by an Application at a specific time."""

from enum import Enum
from Application import Application


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
                 time: int,
                 actor: Application,
                 zgStr: str=None,
                 syscallStr: str=None):
        """Construct an Event, using a Zeitgeist or PreloadLogger log entry."""
        super(Event, self).__init__()

        if not time:
            raise ValueError("Events must have a valid time of occurrence.")
        if not actor:
            raise ValueError("Events must be performed by a valid "
                             "Application.")

        if not zgStr and not syscallStr:
            raise ValueError("Events cannot be empty: please provide a log "
                             "entry from Zeitgeist or PreloadLogger to "
                             "analyse.")
        if zgStr and syscallStr:
            raise ValueError("Events can only be parsed from a single log "
                             "entry: please provide either a Zeitgeist or a "
                             "PreloadLogger entry, but not both.")

        self.time = time
        self.actor = actor

        # TODO parse sources, get type and subjects this way

    def getTime(self):
        """Return the Event's time of occurrence."""
        return self.time

    def getActor(self):
        """Return the Application that performed this Event."""
        return self.actor
