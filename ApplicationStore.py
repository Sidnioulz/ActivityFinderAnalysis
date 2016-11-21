"""A place to store and merge fragments of Application instances."""
from utils import time2Str
from Application import Application
from Event import Event
from constants import APPMERGEWINDOW
import sys


class ApplicationStore(object):
    """A place to store Applications as they are being built from multiple sources.

    ApplicationStore is a store for Application objects. When inserting a new
    Application which is already present, both instances will be merged in the
    store, ensuring all events are kept. The store  provides lookup methods to
    retrieve the actual applications once all data sources have been inserted
    into the store.
    """
    __app_store = None

    @staticmethod
    def get():
        """Return the ApplicationStore for the entire application."""
        if not ApplicationStore.__app_store:
            ApplicationStore.__app_store = ApplicationStore()
        return ApplicationStore.__app_store

    @staticmethod
    def reset():
        ApplicationStore.__app_store = None

    def __init__(self):
        """Construct an ApplicationStore."""
        super(ApplicationStore, self).__init__()
        self.clear()

    def clear(self):
        """Empty the ApplicationStore."""
        self.pidStore = dict()   # type: dict
        self.nameStore = dict()  # type: dict
        self.nameStoreClean = True

    def _mergePidList(self, pid, pids: list):
        """Ensure a time-sorted PID list has its similar neighbours merged."""
        newPids = []

        # Check if the previous item has the same id and finished late enough.
        mergeTarget = None
        for (index, app) in enumerate(pids):
            if not mergeTarget:
                mergeTarget = app
                newPids.append(app)
                continue

            if mergeTarget.hasSameDesktopId(app, resolveInterpreter=True) and \
                    (mergeTarget.getTimeOfEnd() + APPMERGEWINDOW >
                     app.getTimeOfStart()):
                mergeTarget.merge(app)
                newPids[-1] = mergeTarget
            else:
                mergeTarget = app
                newPids.append(app)

        return newPids

    def _mergePidItem(self, pids: list, checkupIndex: int):
        """Merge an app with identical neighbours in a time-sorted PID list."""
        finalApp = pids[checkupIndex]

        # Check if the previous item has the same id and finished late enough.
        prevIndex = checkupIndex - 1
        if prevIndex >= 0:
            currentApp = pids[checkupIndex]
            prevApp = pids[prevIndex]

            if prevApp.hasSameDesktopId(currentApp, resolveInterpreter=True) \
                    and (prevApp.getTimeOfEnd() + APPMERGEWINDOW >
                         currentApp.getTimeOfStart()):
                # Merge the currently-being-checked app into the previous one.
                prevApp.merge(currentApp)
                pids[prevIndex] = prevApp

                # Eliminate the leftover and point to the newly merged app.
                del pids[checkupIndex]
                checkupIndex = prevIndex
                finalApp = prevApp

        # Then check if the next app has the same id and started early enough.
        nextIndex = checkupIndex + 1
        if nextIndex < len(pids):
            currentApp = pids[checkupIndex]
            nextApp = pids[nextIndex]

            if currentApp.hasSameDesktopId(nextApp, resolveInterpreter=True) \
                    and (currentApp.getTimeOfEnd() + APPMERGEWINDOW >
                         nextApp.getTimeOfStart()):
                currentApp.merge(nextApp)
                pids[checkupIndex] = currentApp
                del pids[nextIndex]
                finalApp = currentApp

        return (pids, finalApp)

    def insert(self, app: Application):
        """Insert an Application in the store."""
        finalApp = None

        if app.getPid() == 0:
            raise ValueError("Applications must have a valid PID.")

        if not app.getDesktopId():
            raise ValueError("Applications must have a Desktop identifier.")

        tstart = app.getTimeOfStart()
        tend = app.getTimeOfEnd()
        if tstart > tend:
            raise ValueError("Applications must have valid times of start and "
                             "end.")

        # Get the list of instances for this PID, and find this app's place.
        pids = self.pidStore.get(app.getPid(), list())  # type: list

        neighbourCheckupIndex = -1
        for (index, bpp) in enumerate(pids):
            bstart = bpp.getTimeOfStart()
            bend = bpp.getTimeOfEnd()

            # other item before ours, keep moving
            if (bend < tstart):
                continue

            # other item after ours, we found our position
            if (bstart > tend):
                pids.insert(index, app)
                neighbourCheckupIndex = index
                break

            # time period conflict, merge apps if same id or alert of a problem
            if (bend >= tstart) or (bstart <= tend):
                if app.hasSameDesktopId(bpp, resolveInterpreter=True):
                    bpp.merge(app)
                    pids[index] = bpp
                    neighbourCheckupIndex = index
                else:
                    # TODO: split the larger Application, if there is one, else
                    # abandon the ship.
                    print("Error: Applications %s and %s overlap on PID %d" % (
                         app.getDesktopId(), bpp.getDesktopId(), app.getPid()),
                         file=sys.stderr)

                    raise ValueError("Applications %s and %s have the same PID"
                                     " (%d) and their runtimes overlap:\n"
                                     "\t%s \t %s\n\t%s \t %s\nbut they have"
                                     " different identities. This is a bug in"
                                     " the collected data." % (
                                       app.getDesktopId(),
                                       bpp.getDesktopId(),
                                       app.getPid(),
                                       time2Str(app.getTimeOfStart()),
                                       time2Str(app.getTimeOfEnd()),
                                       time2Str(bpp.getTimeOfStart()),
                                       time2Str(bpp.getTimeOfEnd())))
                break
        # app is the last item on the list!
        else:
            pids.append(app)
            finalApp = app

        # Now, we check if the neighbours to the newly inserted Application
        # have the same Desktop ID. If they do, and if they are within a given
        # proximity window, we merge the items. This is needed to help Events
        # from Zeitgeist and PreloadLogger to synchronise.
        if neighbourCheckupIndex >= 0:
            (pids, finalApp) = self._mergePidItem(pids, neighbourCheckupIndex)

        self.pidStore[app.getPid()] = pids
        self.nameStoreClean = False
        return finalApp

    def resolveInterpreters(self):
        """Ensure all interpreted apps have their known interpreter set.

        Identify desktopids for which an interpreterid is known, and ensure all
        Applications with that desktopid have it set. Then, re-merge all apps
        in the store to eliminate past inconsistencies."""

        interpretersAdded = 0
        instancesEliminated = 0

        # First, get all the interpreters from the apps.
        interpreters = dict()
        if not self.nameStoreClean:
            self._regenNameStore()
        for (desktopid, apps) in self.nameStore.items():
            for app in apps:
                if app.interpreterid:
                    interpreters[desktopid] = app.interpreterid
                    break

        # Update all apps in the pidStore.
        for (pid, apps) in self.pidStore.items():
            listLen = len(apps)
            changed = False
            for (index, app) in enumerate(apps):
                if not app.interpreterid:
                    app.interpreterid = interpreters.get(app.desktopid)
                    changed = True
                    interpretersAdded += 1
            self.pidStore[pid] = self._mergePidList(pid, apps) if changed \
                else apps
            instancesEliminated += listLen - len(self.pidStore[pid])

        # Ensure the name store is up-to-date again
        self._regenNameStore()

        return (interpretersAdded, instancesEliminated)

    def sendEventsToStore(self):
        """Send Applications' events to the EventStore with a correct actor."""
        for (pid, apps) in self.pidStore.items():
            for app in apps:
                app.sendEventsToStore()

    def _regenNameStore(self):
        """Regenerate the desktopid index of this ApplicationStore."""
        self.nameStore = dict()

        for (pid, apps) in self.pidStore.items():
            for app in apps:
                desktopList = self.nameStore.get(app.desktopid) or []
                desktopList.append(app)
                self.nameStore[app.desktopid] = desktopList

        self.nameStoreClean = True

    def getAppLaunchEvents(self):
        """Return Events that embed info obtained from Apps' command lines."""
        allApps = []
        events = []

        for pid, apps in self.pidStore.items():
            for app in apps:
                allApps.append(app)

        for app in allApps:
            cmd = app.getCommandLine()
            if cmd:
                event = Event(actor=app,
                              time=app.getTimeOfStart(),
                              cmdlineStr=cmd)
                events.append(event)

        return events

    def lookupUid(self, uid: str):
        """Return the only Application that has the given UID."""
        try:
            func = (str, int, int)
            (desktopid, pid, tstart) = map(lambda f, d: f(d), func,
                                           uid.split(":"))
            ret = self.lookupPidTimestamp(pid, tstart)
            if ret and ret.desktopid == desktopid:
                return ret
            else:
                return None
        except(ValueError, KeyError):
            return None

    def lookupPid(self, pid: int):
        """Lookup Applications that have had the given PID."""
        try:
            return self.pidStore[pid]
        except(KeyError):
            return None

    def lookupDesktopId(self, desktopId: str, limit: int=0):
        """Lookup Applications that have the given Desktop identifier."""
        if not self.nameStoreClean:
            self._regenNameStore()

        apps = self.nameStore.get(desktopId) or []
        if limit:
            return apps[:limit]
        else:
            return apps

    def lookupPidTimestamp(self, pid, timestamp):
        """Return the only Application that had given PID at the given time."""
        try:
            pids = self.pidStore[pid]
        except(KeyError):
            return None
        else:
            for app in pids:
                if (timestamp >= app.getTimeOfStart() and
                        timestamp <= app.getTimeOfEnd()):
                    return app

            return None
