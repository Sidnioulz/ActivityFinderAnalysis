"""A cache for acts of designation used in an EventStore simulation."""
from Event import Event, EventSource, EventType
from File import EventFileFlags
from Application import Application
from blist import sortedlist
from utils import time2Str


class DesignationCacheItem(object):
    """An act of designation for one Application over some Files."""

    def __init__(self,
                 actor: Application,
                 evflags: EventFileFlags,
                 tstart: int,
                 files: list=[],
                 cmdline: str='',
                 duration: int=-1):
        """Construct a DesignationCacheItem."""
        super(DesignationCacheItem, self).__init__()
        self.actor = actor
        self.evflags = evflags
        self.tstart = tstart
        self.tend = tstart + duration if duration != -1 else 0
        self.files = files or []
        self.cmdline = cmdline


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
        self.pidwatches = set()

    def addItem(self, event: Event, start: int=-1, duration: int=-1):
        """Add a new item to the designation cache."""
        # Zeitgeist Events mean designation is granted to syscalls.
        if event.source == EventSource.zeitgeist:
            if event.getType() == EventType.invalid:
                return

            if start == -1 or duration == -1:
                raise ValueError("Zeitgeist Events need a start and a duration"
                                 " to be stored in the DesignationCache: %s" %
                                 event)
            files = []
            if event.getType() in (EventType.filemove, EventType.filecopy):
                for (src, dest) in event.data:
                    files.append(src)
                    files.append(dest)
            else:
                for f in event.data:
                    files.append(f)
            item = DesignationCacheItem(actor=event.getActor(),
                                        evflags=event.getFileFlags(),
                                        files=files,
                                        tstart=start,
                                        duration=duration)
        # Files passed to an app launch command-line can be freely accessed.
        elif event.source == EventSource.cmdline:
            item = DesignationCacheItem(actor=event.getActor(),
                                        evflags=event.getFileFlags(),
                                        cmdline=event.data,
                                        tstart=event.time,
                                        duration=duration)
        l = self.store.get(event.getActor().uid()) or \
            sortedlist(key=lambda i: i.tstart)
        l.add(item)
        self.store[event.getActor().uid()] = l

    def addPidWatch(self, pid):
        self.pidwatches.add(pid)

    def checkForDesignation(self, event: Event, files: list):
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

        if event.actor.pid in self.pidwatches:
            print(event.source, event.actor.uid())

        # Bypass Zeitgeist events as they're all by designation.
        if event.getSource() == EventSource.zeitgeist:
            l = []

        # Check latest acts of designation first, and loop till we're done.
        res = []
        for (actIdx, act) in enumerate(reversed(l)):
            # If there are no files left, we can exit.
            if not len(files):
                break

            # If we reach events that have expired, we can get rid of them.
            if act.tend and act.tend < event.time:
                # FIXME review how this index is calculated (l is reversed!)
                # del l[actIdx]
                # lChanged = True
                continue

            # We can't yet rely on this designation cache item.
            if act.tstart > event.time:
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
                # print("Debug: an act of designation was found for Event %s,"
                #       " but the access flags don't match. Event: %s. Act:"
                #       " %s" % (event, accesses, crossover))
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
                if f.getName() in act.cmdline:
                    # print("Info: Event '%s' performed on %s by App '%s' on "
                    #       "File '%s' is turned into a %s event based on an "
                    #       "act of designation performed on %s." % (
                    #        event.getFileFlags(),
                    #        time2Str(event.getTime()),
                    #        event.getActor().uid(),
                    #        f.getName(),
                    #        "designation" if newFlags &
                    #        EventFileFlags.designation else "programmatic",
                    #        time2Str(act.tstart)))
                    res.append((f, newFlags))
                    del files[fIdx]
                elif f.getName() in [x.getName() for x in act.files]:
                    print("Info: Event '%s' performed on %s by App '%s' on "
                          "File '%s' is turned into a %s event based on an "
                          "Zeitgeit event performed on %s." % (
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
