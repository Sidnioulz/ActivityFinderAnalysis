"""A place to store and merge fragments of Application instances."""
from utils import time2Str
from Application import Application
from Event import Event
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

    def insert(self, app: Application):
        """Insert an Application in the store."""
        # print("Insert %s:%d into store" % (app.getDesktopId(), app.getPid()))
        if app.getPid() == 0:
            raise ValueError("Applications must have a valid PID.")

        if not app.getDesktopId():
            raise ValueError("Applications must have a Desktop identifier.")

        tstart = app.getTimeOfStart()
        tend = app.getTimeOfEnd()
        if tstart > tend:
            raise ValueError("Applications must have valid times of start and "
                             "end.")

        pids = self.pidStore.get(app.getPid(), list())  # type: list

        for (index, bpp) in enumerate(pids):
            bstart = bpp.getTimeOfStart()
            bend = bpp.getTimeOfEnd()

            # other item before ours, keep moving
            if (bend < tstart):
                continue

            # other item after ours, we found our position
            if (bstart > tend):
                pids.insert(index, app)
                break

            # time period conflict, merge apps if same id or alert of a problem
            if (bend >= tstart) or (bstart <= tend):
                if app.hasSameDesktopId(bpp, resolveInterpreter=True):
                    bpp.merge(app)
                    pids[index] = bpp
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
                                       bpp.getDesktopId(),
                                       app.getDesktopId(),
                                       app.getPid(),
                                       time2Str(app.getTimeOfStart()),
                                       time2Str(app.getTimeOfEnd()),
                                       time2Str(bpp.getTimeOfStart()),
                                       time2Str(bpp.getTimeOfEnd())))
                break
        # app is the last item on the list!
        else:
            pids.append(app)

        self.pidStore[app.getPid()] = pids

        # Update the name store
        apps = self.nameStore.get(app.getDesktopId()) or []
        apps.append(app)
        self.nameStore[app.getDesktopId()] = apps

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
