"""A cache for acts of designation used in an EventStore simulation."""
from Event import Event
from File import EventFileFlags
from Application import Application
from blist import sortedlist
from utils import time2Str


class DesignationCacheItem(object):
    """An act of designation for one Application over some Files."""

    actor = None     # type: Application
    decision = None  # type: EventFileFlags
    tstart = 0       # type: start time
    tend = 0         # type: expiration time
    # files = []       # type: list
    files = ''       # type: str

    def __init__(self,
                 actor: Application,
                 evflags: EventFileFlags,
                 tstart: int,
                 # files: list,
                 files: str,
                 duration: int=-1):
        """Construct a DesignationCacheItem."""
        super(DesignationCacheItem, self).__init__()
        self.actor = actor
        self.evflags = evflags
        self.tstart = tstart
        self.tend = tstart + duration if duration != -1 else 0
        self.files = files
        pass


class DesignationCache(object):
    """A cache for acts of designation used in an EventStore simulation.

    This class caches acts of designation (see EventFileFlags.designation) for
    Applications on Files. It tells whether designation is provided, when from
    and until when, and for what types of Events. The EventStore then adjusts
    the designation and programmatic flags of Events within this time window
    for the relevant Files and Applications.
    """

    def __init__(self):
        """Construct a DesignationCache."""
        super(DesignationCache, self).__init__()
        self.store = dict()

    def addItem(self, event: Event, duration: int=-1):
        """Add a new item to the designation cache."""
        item = DesignationCacheItem(actor=event.getActor(),
                                    evflags=event.getFileFlags(),
                                    files=event.data,
                                    tstart=event.time,
                                    duration=duration)
        l = self.store.get(event.getActor().uid()) or \
            sortedlist(key=lambda i: i.tstart)
        l.add(item)
        self.store[event.getActor().uid()] = l

    def checkForDesignation(self, event: Event, files: list, cwd: str=None):
        """Check for acts of designation that match an Event and its Files.

        Browse the DesignationCache to find acts of designation that match the
        actor of an Event, and a list of Files. If some files are matched, and
        if the act has a different designation / programmatic flag than the
        Event, this function returns updated EventFileFlags for each matching
        File, so that the EventStore simulator records prior acts of
        designation for these Files.

        Returns a list of (File, EventFileFlags) tuples.
        """
        l = self.store.get(event.getActor().uid()) or []
        lChanged = False

        # Check latest acts of designation first, and loop till we're done.
        res = []
        for (actIdx, act) in enumerate(reversed(l)):
            # If there are no files left, we can exit.
            if not len(files):
                break

            # If we reach events that have expired, we can get rid of them.
            if act.tend and act.tend < event.time:
                del l[actIdx]
                lChanged = True
                continue

            # Compare the event's flags to the act's.
            crossover = event.getFileFlags() & act.evflags

            #  The event and act already have the same authorisation type.
            if crossover & (EventFileFlags.designation |
                            EventFileFlags.programmatic):
                continue

            # The flags for which the act applies don't match all event flags.
            accesses = event.getFileFlags() & ~(EventFileFlags.designation |
                                                EventFileFlags.programmatic)
            if crossover != accesses:
                continue

            # From now on we build a return value with new flags for files that
            # match the act of designation.
            auths = act.evflags & (EventFileFlags.designation |
                                   EventFileFlags.programmatic)
            newFlags = EventFileFlags.no_flags
            newFlags |= accesses
            newFlags |= auths

            # Now find Files that match the act of designation's own Files
            for (fIdx, f) in enumerate(files):
                if f.getName() in act.files:
                    print("Info: Event '%s' performed on %s by App '%s' on "
                          "File '%s' is turned into a %s event based on an "
                          "act of designation performed on %s." % (
                           event.getFileFlags(),
                           time2Str(event.getTime()),
                           event.getActor().uid(),
                           f.getName(),
                           "designation" if newFlags &
                           EventFileFlags.designation else "programmatic",
                           time2Str(act.tstart)))
                    res.append((f, newFlags))
                    del files[fIdx]
        # Now that we've checked all acts of designation for this Application,
        # check if some files have not matched any act. We return those with
        # the original event flags.
        else:
            for f in files:
                res.append((f, event.getFileFlags()))

        # If we've removed expired acts, we should update the store.
        if lChanged:
            self.store[event.getActor().uid()] = l

        return res
