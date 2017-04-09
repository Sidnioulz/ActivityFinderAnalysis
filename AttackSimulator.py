"""An attack simulator that estimates the propagation of malware."""
from AccessListCache import AccessListCache
from Application import Application
from ApplicationStore import ApplicationStore
from File import File
from FileStore import FileStore
from PolicyEngine import Policy
from utils import debugEnabled, tprnt, time2Str
from collections import deque
import random
import sys


class Attack(object):
    """A compact representation of an attack's origin point."""

    def __init__(self, time: int, source, appMem: bool = True):
        """Construct an AttackSimulator."""
        super(Attack, self).__init__()
        self.time = time
        self.source = source
        self.appMemory = appMem
    # TODO


class AttackSimulator(object):
    """An attack simulator that estimates the propagation of malware."""

    def __init__(self, seed: int=0):
        """Construct an AttackSimulator."""
        super(AttackSimulator, self).__init__()
        random.seed(a=seed)

        # TODO choose if file or app is source of atk
        # TODO examine range, pick one source
        # TODO examine live time of source, consider if random atk or if source fundamentally corrupt from start
        # TODO call atk function
        # TODO write output to file

    def _runAttackRound(self, attack: Attack, pol: Policy):
        acCache = AccessListCache.get()
        fileStore = FileStore.get()
        appStore = ApplicationStore.get()
        (acListApp, acListInst) = acCache.getAccessListFromPolicy(pol)

        seen = set()  # Already seen targets.
        spreadTimes = dict()  # Times from which the attack can spread.

        toSpread = deque()
        toSpread.append(attack.source)
        spreadTimes[attack.source] = attack.time

        # Statistics counters.
        appCount = 0
        fileCount = 0

        if debugEnabled():
            tprnt("Launching attack on %s at time %s %s app memory." %
                  (attack.source if isinstance(attack.source, File) else
                   attack.source.uid(),
                   time2Str(attack.time),
                   "with" if attack.appMemory else "without"))
                  

        # As long as there are reachable targets, loop.
        while toSpread:
            current = toSpread.pop()
            currentTime = spreadTimes[current]

            # When the attack spreads to a File.
            if isinstance(current, File):
                fileCount += 1
                if debugEnabled():
                    tprnt("File added @%d: %s" % (currentTime, current))

                # Add followers.
                for f in current.follow:
                    if f.time > currentTime:
                        follower = fileStore.getFile(f.inode)
                        toSpread.append(follower)
                        spreadTimes[follower] = f.time

                # Add future accesses.
                for acc in current.accesses:
                    if acc.time > currentTime and \
                            (pol.accessAllowedByPolicy(current, acc) or
                             pol.fileOwnedByApp(current, acc) or
                             pol.allowedByPolicy(current, acc.actor)):
                        toSpread.append(acc.actor)
                        spreadTimes[acc.actor] = acc.time

            # When the attack spreads to an app instance.
            elif isinstance(current, Application):
                appCount += 1
                if debugEnabled():
                    tprnt("App added @%d: %s" % (currentTime, current.uid()))

                # Add files accessed by the app.
                for accFile in acListInst.get(current.uid()) or []:
                    for acc in accFile.accesses:
                        if acc.actor == current and \
                                (pol.accessAllowedByPolicy(accFile, acc) or
                                 pol.fileOwnedByApp(accFile, acc) or
                                 pol.allowedByPolicy(accFile, current)) \
                                 and acc.time > currentTime:
                            toSpread.append(accFile)
                            spreadTimes[accFile] = acc.time
                
                # Add future versions of the app.
                if attack.appMemory:
                      for app in appStore.lookupDesktopId(current.desktopid):
                          if app.tstart > currentTime:
                                  toSpread.append(app)
                                  spreadTimes[app] = app.tstart

            else:
                print("Error: attack simulator attempting to parse an unknown"
                      " object (%s)" % type(current), file=sys.stderr)
            
            seen.add(current)
            # IF FILE
            # IF APP
            # TODO add all accessed files AFTER ATTACK TIME to the list
            # TODO 
            
        return (appCount, fileCount)
    
    
    def performAttack(self, pol: Policy, appStartingPoints=[], fileStartingPoints=[]):
        pass
        
