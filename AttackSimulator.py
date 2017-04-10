"""An attack simulator that estimates the propagation of malware."""
from AccessListCache import AccessListCache
from Application import Application
from ApplicationStore import ApplicationStore
from File import File
from FileStore import FileStore
from PolicyEngine import Policy
from UserConfigLoader import UserConfigLoader
from utils import debugEnabled, tprnt, time2Str
from collections import deque
import random
import sys
import re
import os
import statistics


class Attack(object):
    """A compact representation of an attack's origin point."""

    def __init__(self, source, time: int, appMem: bool = True):
        """Construct an AttackSimulator."""
        super(Attack, self).__init__()
        self.time = time
        self.source = source
        self.appMemory = appMem


class AttackSimulator(object):
    """An attack simulator that estimates the propagation of malware."""

    passCount = 100

    def __init__(self, seed: int=0):
        """Construct an AttackSimulator."""
        super(AttackSimulator, self).__init__()
        random.seed(a=seed)

    def _runAttackRound(self,
                        attack: Attack,
                        policy: Policy):
        """Run an attack round with a set source and time."""
        acCache = AccessListCache.get()
        fileStore = FileStore.get()
        appStore = ApplicationStore.get()
        (acListApp, acListInst) = acCache.getAccessListFromPolicy(policy)

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
                            (policy.accessAllowedByPolicy(current, acc) or
                             policy.fileOwnedByApp(current, acc) or
                             policy.allowedByPolicy(current, acc.actor)):
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
                                (policy.accessAllowedByPolicy(accFile, acc) or
                                 policy.fileOwnedByApp(accFile, acc) or
                                 policy.allowedByPolicy(accFile, current)) \
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
            
        return (appCount, fileCount)
    
    
    def performAttack(self,
                      policy: Policy,
                      attackName: str="none",
                      startingApps: list=[],
                      filePattern: str=None):
        fileStore = FileStore.get()
        appStore = ApplicationStore.get()

        msg = "\n\n## Performing attack '%s'\n" % attackName
        
        # First, check if the proposed attack pattern is applicable to the
        # current participant. If not, return.
        startingPoints = []

        # Case where an app is at the origin of an attack.
        if startingApps:
            msg += ("Simulating attack starting from an app among %s.\n" %
                    startingApps)
            tprnt("Simulating '%s' attack starting from an app among %s." %
                  (attackName, startingApps))
            for did in startingApps:
                for app in appStore.lookupDesktopId(did):
                    startingPoints.append(app)

            if not startingPoints:
                tprnt("No such app found, aborting attack simulation.")
                return msg

        # Case where a file is at the origin of the attack.
        elif filePattern:
            msg += ("Simulating attack starting from a file matching %s.\n" % 
                    filePattern)
            tprnt("Simulating '%s' attack starting from a file matching %s." % 
                  (attackName, filePattern))

            userConf = UserConfigLoader.get()
            home = userConf.getHomeDir() or "/MISSING-HOME-DIR"
            desk = userConf.getSetting("XdgDesktopDir") or "~/Desktop"
            down = userConf.getSetting("XdgDownloadsDir") or "~/Downloads"
            user = userConf.getSetting("Username") or "user"
            host = userConf.getSetting("Hostname") or "localhost"
            filePattern = filePattern.replace('@XDG_DESKTOP_DIR@', desk)
            filePattern = filePattern.replace('@XDG_DOWNLOADS_DIR@', desk)
            filePattern = filePattern.replace('@USER@', user)
            filePattern = filePattern.replace('@HOSTNAME@', host)
            filePattern = filePattern.replace('~', home)
            fileRe = re.compile(filePattern)

            for f in fileStore:
                if fileRe.match(f.path):
                    startingPoints.append(f)

            if not startingPoints:
                tprnt("No such file found, aborting attack simulation.")
                return msg
        else:
            tprnt("No starting point defined, aborting attack simulation.")
            return msg

        # Now, roll the attack.
        msg += ("%d starting points found. Performing %d rounds of attacks."
                "\n\n" % (len(startingPoints), AttackSimulator.passCount))
        tprnt("%d starting points found. Performing %d rounds of attacks." %
              (len(startingPoints), AttackSimulator.passCount))

        apps = []
        files = []
        sums = []
        for i in range(0, AttackSimulator.passCount):
            source = startingPoints[random.randrange(0, len(startingPoints))]
            # Files corrupt from the start, apps become corrupt randomly.
            time = source.tstart if isinstance(source, File) else \
                random.randrange(source.tstart, source.tend)
            attack = Attack(source=source, time=time, appMem=True)
            print(attack.source)
            (appCount, fileCount) = self._runAttackRound(attack, policy)
            
            msg += ("Pass %d:\tattack on %s at time %s %s app memory.\n"
                    "        \t%d apps infected; %d files infected.\n\n" %
                    (i + 1,
                     attack.source if isinstance(attack.source, File) else
                     attack.source.uid(),
                     time2Str(attack.time),
                     "with" if attack.appMemory else "without",
                     appCount,
                     fileCount))
            tprnt("Pass %d: %d apps infected; %d files infected" % (i+1,
                                                                    appCount,
                                                                    fileCount))
            apps.append(appCount)
            files.append(fileCount)
            sums.append(appCount + fileCount)

        medLocationL = statistics.median_low(sums)
        medLocationH = statistics.median_high(sums)
        if medLocationL != medLocationH:
            idxL = sums.index(medLocationL)
            idxH = sums.index(medLocationH)
            medApps = (apps[idxL] + apps[idxH]) / 2
            medFiles = (files[idxL] + files[idxH]) / 2
        else:
            idx = sums.index(medLocationH)
            medApps = apps[idx]
            medFiles = files[idx]
      
        avgFiles = sum(files) / len(files)
        avgApps = sum(apps) / len(apps)

        minIdx = min(sums)
        minFiles = files[minIdx]
        minApps = apps[minIdx]
        maxIdx = max(sums)
        maxFiles = files[maxIdx]
        maxApps = apps[maxIdx]

        msg += "\nMin: %d apps infected; %d files infected\n" % (
                minApps, minFiles)
        msg += "Max: %d apps infected; %d files infected\n" % (
                maxApps, maxFiles)
        msg += "Avg: %d apps infected; %d files infected\n" % (
                avgApps, avgFiles)
        msg += "Med: %d apps infected; %d files infected\n\n" % (
                medApps, medFiles)

        return msg

    def runAttacks(self,
                   policy: Policy,
                   outputDir: str=None):
        """Run all registered attacks for a Policy."""
        outputDir = policy.getOutputDir(parent=outputDir) if \
            policy else outputDir

        msg = ""

        # Downloaded virus in movie via torrent app.
        msg += self.performAttack(policy,
                                  "virus-photo",
                                  filePattern="^.*?\.jpg$")
        
        # Downloaded virus in movie via torrent app.
        msg += self.performAttack(policy,
                                  "torrent-virus-movie",
                                  filePattern="^.*?\.(mov|flv|avi|wav|mp4|qt|asf|swf|mpg|wmv|h264|webm|mkv|3gp|mpg4)$")

        # TODO
        msg += self.performAttack(policy, "NAME HERE", filePattern="/tmp/.*")
        
        # TODO
        msg += self.performAttack(policy, "NAME HERE", filePattern="/tmp/.*")

        path = outputDir + "/attacks.out"
        os.makedirs(File.getParentNameFromName(path), exist_ok=True)
        with open(path, "w") as f:
            print(msg, file=f)

