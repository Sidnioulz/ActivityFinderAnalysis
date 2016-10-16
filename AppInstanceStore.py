"""A place to store and merge fragments of Application instances."""
from utils import timestampZgPrint
from Application import Application
import sys


class AppInstanceStore(object):
    """A place to store Applications as they are being built from multiple sources.

    AppInstanceStore is a store for Application objects. When inserting a new
    Application which is already present, both instances will be merged in the
    store, ensuring all events are kept. The store  provides lookup methods to
    retrieve the actual applications once all data sources have been inserted
    into the store.
    """

    def __init__(self):
        """Construct an AppInstanceStore."""
        super(AppInstanceStore, self).__init__()
        self.clear()

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
                                       timestampZgPrint(app.getTimeOfStart()),
                                       timestampZgPrint(app.getTimeOfEnd()),
                                       timestampZgPrint(bpp.getTimeOfStart()),
                                       timestampZgPrint(bpp.getTimeOfEnd())))
                break
        # app is the last item on the list!
        else:
            pids.append(app)

        self.pidStore[app.getPid()] = pids

    def clear(self):
        self.pidStore = dict()   # type: dict
        self.nameStore = dict()  # type: dict

    def lookupPid(self, pid):
        """TODO."""
        # TODO
        return self.pidStore[pid]

    def lookupPidTimestamp(self, pid, timestamp):
        """TODO."""
        # TODO
        pids = self.pidStore[pid]
        for app in pids:
            if (timestamp >= app.getTimeOfStart() and
                    timestamp <= app.getTimeOfEnd()):
                return app

        return None

    def lookupPidActor(self, pid, actor):
        """TODO."""
        # TODO
        pass
