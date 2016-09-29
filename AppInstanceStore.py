from utils import timestampZgPrint
import sys


class AppInstanceStore(object):
    pidStore = dict()   # type: dict
    nameStore = dict()  # type: dict

    """ AppInstanceStore is a store for AppInstance objects. It detects issues
    when inserting a new AppInstance, and provides lookup methods."""
    def __init__(self):
        super(AppInstanceStore, self).__init__()

    def insert(self, app):
        # print("Insert %s:%d into store" % (app.getDesktopId(), app.getPid()))
        if app.getPid() == 0:
            return  # TODO except

        if not app.getDesktopId():
            return  # TODO except

        tstart = app.getTimeOfStart()
        tend = app.getTimeOfEnd()
        if tstart > tend:
            return  # TODO except

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
                if (app.getDesktopId() == bpp.getDesktopId()):
                    bpp.merge(app)
                    pids[index] = bpp
                else:
                    print("Error: Applications %s and %s overlap on PID %d" % (
                         app.getDesktopId(), bpp.getDesktopId(), app.getPid()),
                         file=sys.stderr)

                    raise ValueError("Applications %s and %s have the same PID"
                                     " (%d) and their runtimes (%s-%s and "
                                     " %s-%s) overlap, but they have different"
                                     " identities. This is a bug in the "
                                     "collected data." % (
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

        # si liste vide, rajoute

        # si inst. av. autre acteur au milieu du range de newapp, THROW Error
        # situation compliquee : evenements exacts doivent etre recuperes de
        # toutes les sources pour recalculer les instances

        # si instance avec meme acteur overlap: mettre a jour instance dans le
        # store, puis "informer" le caller que l'objet est mis a jour

    def lookupPid(self, pid):
        return self.pidStore[pid]

    def lookupPidTimestamp(self, pid, timestamp):
        pids = self.pidStore[pid]
        for app in pids:
            if (timestamp >= app.getTimeOfStart() and
                    timestamp <= app.getTimeOfEnd()):
                return app

        return None

    def lookupPidActor(self, pid, actor):
        pass
