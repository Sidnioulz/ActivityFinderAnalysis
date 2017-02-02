"""An engine for running algorithms that implement an access control policy."""
from File import File, FileAccess, EventFileFlags
from FileStore import FileStore
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, OWNED_PATH_ACCESS, \
                      ILLEGAL_ACCESS
from utils import debugEnabled, graphEnabled, hasIntersection, pyre
from blist import sortedlist
import os
import statistics
import re


class PolicyScores(object):
    """Usability scores for Policies."""

    def __init__(self):
        """Construct a PolicyScores."""
        super(PolicyScores, self).__init__()
        # ACCESS SCORES.
        self.desigAccess = 0
        self.ownedPathAccess = 0
        self.policyAccess = 0
        self.illegalAccess = 0

        # USABILITY COSTS.
        # Cost of configuring access control policies prior to any usage
        self.configCost = 0

        # Interruptions to an interaction (security confirmation dialogs)
        self.grantingCost = 0   # Cost of granting access to a file on the spot
        self.cumulGrantingCost = 0  # Cumulative number of illegal accesses
        self.isolationCost = 0  # Cost of separating an instance from its state
        self.splittingCost = 0  # Cost of splitting a process into 2 instances

        # Costs to reach optimal partitioning on information flow graph.
        self.graphGrantingCost = 0
        self.graphIsolationCost = 0
        self.graphSplittingCost = 0

        # For each app, we keep a record of how many files they have accessed
        # compared to how many files they are allowed to access. This ratio
        # allows us to compare the overentitlements between policies. The per-
        # app ratio is relevant to overentitlement in general, the per-instance
        # ratio is useful for discussing the potential immediate consequences
        # of a benign app being exploited (notwithstanding app statefulness).
        self.overEntitlements = [set(), set()]

    def __eq__(self, other):
        """Compare this PolicyScores to :other:."""
        if not isinstance(other, self.__class__):
            raise TypeError("Cannot increment a PolicyScores with something "
                            "other than another PolicyScores.")

        return \
            self.desigAccess == other.desigAccess and \
            self.ownedPathAccess == other.ownedPathAccess and \
            self.policyAccess == other.policyAccess and \
            self.illegalAccess == other.illegalAccess and \
            self.configCost == other.configCost and \
            self.grantingCost == other.grantingCost and \
            self.cumulGrantingCost == other.cumulGrantingCost and \
            self.isolationCost == other.isolationCost and \
            self.splittingCost == other.splittingCost and \
            self.graphGrantingCost == other.graphGrantingCost and \
            self.graphIsolationCost == other.graphIsolationCost and \
            self.graphSplittingCost == other.graphSplittingCost and \
            self.overEntitlements[0] == other.overEntitlements[0] and \
            self.overEntitlements[1] == other.overEntitlements[1]

    def __iadd__(self, other):
        """Add the scores from :other: to this PolicyScores."""
        if not isinstance(other, self.__class__):
            raise TypeError("Cannot increment a PolicyScores with something "
                            "other than another PolicyScores.")

        self.desigAccess += other.desigAccess
        self.ownedPathAccess += other.ownedPathAccess
        self.policyAccess += other.policyAccess
        self.illegalAccess += other.illegalAccess
        self.configCost += other.configCost
        self.grantingCost += other.grantingCost
        self.cumulGrantingCost += other.cumulGrantingCost
        self.isolationCost += other.isolationCost
        self.splittingCost += other.splittingCost
        self.graphGrantingCost += other.graphGrantingCost
        self.graphIsolationCost += other.graphIsolationCost
        self.graphSplittingCost += other.graphSplittingCost

        self.overEntitlements[0] = \
            self.overEntitlements[0].union(list(other.overEntitlements[0]))
        self.overEntitlements[1] = \
            self.overEntitlements[1].union(list(other.overEntitlements[1]))

        return self

    def printScores(self,
                    outputDir: str=None,
                    filename: str=None,
                    userHome: str=None,
                    extraText: str=None,
                    quiet: bool=False):
        """Print the access, cost and security scores of this PolicyScores."""

        msg = ("Accesses:\n")
        msg += ("\t* by designation: %d\n" % self.desigAccess)
        msg += ("\t* file owned by app: %d\n" % self.ownedPathAccess)
        msg += ("\t* policy-allowed: %d\n" % self.policyAccess)
        msg += ("\t* illegal: %d\n" % self.illegalAccess)

        msg += ("\nCosts:\n")
        msg += ("\t* configuration: %d\n" % self.configCost)
        msg += ("\t* granting: %d\n" % self.grantingCost)
        msg += ("\t* cumulative granting: %d\n" % self.cumulGrantingCost)
        msg += ("\t* isolating apps: %d\n" % self.isolationCost)
        msg += ("\t* splitting apps: %d\n" % self.splittingCost)

        msg += ("\nCosts to optimal graph configuration:\n")
        msg += ("\t* g-granting: %d\n" % self.graphGrantingCost)
        msg += ("\t* g-isolating apps: %d\n" % self.graphIsolationCost)
        msg += ("\t* g-splitting apps: %d\n" % self.graphSplittingCost)

        msg += ("\nSecurity over-entitlements:\n")
        msg += ("\t* %d files used / %d reachable\n" % (
                (len(self.overEntitlements[0]),
                 len(self.overEntitlements[1]))))

        sysFiles = [set(), set()]
        userFiles = [set(), set()]
        for i in (0, 1):
            for file in self.overEntitlements[i]:
                if file.isUserDocument(userHome, allowHiddenFiles=True):
                    userFiles[i].add(file)
                else:
                    sysFiles[i].add(file)

        msg += ("\t* %d user documents used / %d reachable\n" % (
                (len(userFiles[0]), len(userFiles[1]))))

        msg += ("\t* %d system files used / %d reachable\n" % (
                (len(sysFiles[0]), len(sysFiles[1]))))

        if extraText:
            msg += extraText

        if not quiet:
            print(msg)

        if outputDir:
            filename = outputDir + '/' + filename
            os.makedirs(File.getParentNameFromName(filename),
                        exist_ok=True)
            with open(filename, "a") as f:
                print(msg, file=f)

        return [len(userFiles[0]), len(userFiles[1])]


class Policy(object):
    """Virtual pure parent class for policy algorithms."""

    def __init__(self,
                 name: str):
        """Construct a Policy."""
        super(Policy, self).__init__()
        self.name = name
        self.userConf = UserConfigLoader.get()
        self.appPathCache = dict()
        self.clearScores()

    def clearScores(self):
        """Initialise scores to zero before processing FileAccesses."""
        # General score (usability, overEntitlements, access counts)
        self.s = PolicyScores()

        # Scores per Application instance, and per Application
        self.perAppScores = dict()
        self.perInstanceScores = dict()

        # Scores for each individual File
        self.perFileScores = dict()

        # Security clusters
        self.clusters = None
        self.clustersInst = None
        self.accessLists = None
        self.exclScores = None
        self.exclScoresInst = None
        self.exclScoresPerApp = None

    def getOutputDir(self, parent: str=None):
        if parent:
            return parent + "/Policy - %s" % self.name
        else:
            return "/tmp/Policy - %s" % self.name

    def printScores(self,
                    outputDir: str,
                    printClusters: bool=False):
        """Print general scores, scores per app, instance and file."""

        # Make sure the score directory is built
        if outputDir:
            scoreDir = self.getOutputDir(parent=outputDir)

            if not os.path.exists(outputDir):
                raise FileNotFoundError("Output directory given to the "
                                        "PolicyEngine does not exist: %s" %
                                        outputDir)
            os.makedirs(scoreDir, exist_ok=True)
        else:
            scoreDir = None

        # Security scores first as they increment splittingCost in some apps.
        print("\nINFORMATION FLOW CLUSTERS")
        self.printSecurityClusters(outputDir=scoreDir,
                            printClusters=printClusters)
        print("-------------------")

        # Application scores.
        totalOEDists = []
        totalOECount = 0
        systemS = PolicyScores()
        desktopS = PolicyScores()
        userappS = PolicyScores()
        appStore = ApplicationStore.get()
        userHome = self.userConf.getHomeDir()
        for desktopid in sorted(self.perAppScores.keys()):
            dists = []
            count = 0

            # Loop through application instances and print their scores.
            apps = appStore.lookupDesktopId(desktopid)
            for app in sorted(apps, key=lambda a: a.uid()):
                iScore = self.perInstanceScores.get(app.uid())
                if iScore:
                    r = iScore.printScores(outputDir=scoreDir,
                                           filename="App - %s - Instance %s."
                                           "score" % (desktopid,
                                                      app.uid()),
                                           userHome=userHome,
                                           quiet=True)

                    count += 1
                    dists += [r]

            props = list((d[0] / d[1] if d[1] else 0) for d in dists)
            if props:
                minOE = min(props)
                maxOE = max(props)
                avgOE = sum(props) / count
                medOE = statistics.median(props)
                totalOEDists += dists
                totalOECount += count

                extraText = "\nAPP INSTANCE STATS SORTED BY UID\n" \
                            "Distribution of over-entitlements: %s\n" \
                            "Over-entitlement proportions: %s\n" \
                            "Min: %f\n" \
                            "Max: %f\n" \
                            "Average: %f\n" \
                            "Median: %f\n" % (
                             str(dists), str(props), minOE, maxOE, avgOE,
                             medOE)
            else:
                extraText = None

            oneInst = appStore.lookupDesktopId(desktopid, limit=1)
            extraText += "\n\nAPPTYPE: %s" % oneInst[0].getAppType()

            # And then save the app's score file with the extra statistics.
            score = self.perAppScores[desktopid]
            score.printScores(outputDir=scoreDir,
                              filename="App - %s.score" % desktopid,
                              userHome=userHome,
                              extraText=extraText,
                              quiet=True)

            # Identify if the application is of desktop/system/DE type.
            if apps:
                if apps[0].isSystemApp():
                    systemS += score
                elif apps[0].isDesktopApp():
                    desktopS += score
                elif apps[0].isUserlandApp():
                    userappS += score

        # Score for each type of application.
        print("-------------------")
        print("\nALL SYSTEM APPS")
        systemS.printScores(outputDir=scoreDir,
                            filename="SystemApps.score",
                            userHome=userHome)
        print("\nALL DESKTOP APPS")
        desktopS.printScores(outputDir=scoreDir,
                             filename="DesktopApps.score",
                             userHome=userHome)
        print("\nALL USER APPS")
        userappS.printScores(outputDir=scoreDir,
                             filename="UserlandApps.score",
                             userHome=userHome)
        print("-------------------")

        # File scores.
        systemF = PolicyScores()
        userDocF = PolicyScores()
        userHome = self.userConf.getHomeDir()
        fileStore = FileStore.get()
        for key in sorted(fileStore.nameStore, key=lambda s: s.lower()):
            files = fileStore.nameStore[key]
            lastCnt = 0
            for last in reversed(files):
                outfilename = last.getName() + \
                              (".prev.%d" % lastCnt if lastCnt else "") + \
                              ".%s.score" % self.name
                lastCnt += 1

                score = self.perFileScores.get(last.inode)
                if not score:  # File didn't have any legal/valid access.
                    continue

                # print("\n\nFile: %s:%s" % (last.inode, outfilename))
                score.printScores(outputDir=outputDir,
                                  filename=outfilename,
                                  userHome=userHome,
                                  quiet=True)

                if last.isUserDocument(userHome, allowHiddenFiles=True):
                    userDocF += score
                else:
                    systemF += score
        print("\nALL SYSTEM FILES")
        systemF.printScores(outputDir=scoreDir,
                            filename="SystemFiles.score",
                            userHome=userHome)
        print("\nALL USER DOCUMENTS")
        userDocF.printScores(outputDir=scoreDir,
                             filename="UserDocFiles.score",
                             userHome=userHome)
        print("-------------------")

        # General scores.
        print("\nGENERAL SCORES")
        props = list((d[0] / d[1] if d[1] else 0) for d in totalOEDists)
        if props:
            minOE = min(props)
            maxOE = max(props)
            avgOE = sum(props) / totalOECount
            medOE = statistics.median(props)
            extraText = "Min: %f\n" \
                        "Max: %f\n" \
                        "Average: %f\n" \
                        "Median: %f\n" % (minOE, maxOE, avgOE, medOE)
        else:
            extraText = "No over-entitlements statistics are available for " \
                        "policies where all non-designation accesses were " \
                        "denied."

        self.s.printScores(outputDir=scoreDir,
                           filename="general.score",
                           userHome=userHome,
                           extraText=extraText)
        print("\n\n\n")

    def incrementScore(self,
                       score: str,
                       file: File,
                       actor: Application,
                       increment: int=1):
        """Increment a given score for the Policy, File and Application."""
        if file and not isinstance(file, File):
            raise TypeError("Policy.incrementScore needs a File parameter, "
                            "received a %s." % file.__class__.__name__)
        if actor and not isinstance(actor, Application):
            raise TypeError("Policy.incrementScore needs an Application "
                            "parameter, received a %s." %
                            actor.__class__.__name__)

        # Global score
        try:
            attr = self.s.__getattribute__(score)
        except (AttributeError):
            raise AttributeError("This Policy doesn't have a scored named %s" %
                                 score)
        else:
            attr += increment
            self.s.__setattr__(score, attr)

        # App score
        if actor:
            iScore = self.perInstanceScores.get(actor.uid()) or PolicyScores()
            attr = iScore.__getattribute__(score)
            attr += increment
            iScore.__setattr__(score, attr)
            self.perInstanceScores[actor.uid()] = iScore

            aScore = self.perAppScores.get(actor.getDesktopId()) or \
                PolicyScores()
            attr = aScore.__getattribute__(score)
            attr += increment
            aScore.__setattr__(score, attr)
            self.perAppScores[actor.getDesktopId()] = aScore

        # File score
        if file:
            fScore = self.perFileScores.get(file.inode) or PolicyScores()
            attr = fScore.__getattribute__(score)
            attr += increment
            fScore.__setattr__(score, attr)
            self.perFileScores[file.inode] = fScore

    def incrementOverEntitlement(self,
                                 file: File,
                                 actor: Application,
                                 accessed: bool):
        """Increment an overentitlement score for a File and Application."""
        if file and not isinstance(file, File):
            raise TypeError("Policy.incrementOverEntitlement needs a File "
                            "parameter, received a %s." %
                            file.__class__.__name__)
        if actor and not isinstance(actor, Application):
            raise TypeError("Policy.incrementOverEntitlement needs an "
                            "Application parameter, received a %s." %
                            actor.__class__.__name__)
        if not file:
            raise AttributeError("Policy.incrementOverEntitlement needs a "
                                 "file parameter.")
        if not actor:
            raise AttributeError("Policy.incrementOverEntitlement needs an "
                                 "actor parameter.")

        # Global score
        self.s.overEntitlements[0 if accessed else 1].add(file)

        # Per instance score
        iScore = self.perInstanceScores.get(actor.uid()) or \
            PolicyScores()
        iScore.overEntitlements[0 if accessed else 1].add(file)
        self.perInstanceScores[actor.uid()] = iScore

        # Per app score
        aScore = self.perAppScores.get(actor.getDesktopId()) or \
            PolicyScores()
        aScore.overEntitlements[0 if accessed else 1].add(file)
        self.perAppScores[actor.getDesktopId()] = aScore

    def generateOwnedPaths(self, actor: Application):
        """Return the paths where an Application can fully write Files."""
        if actor not in self.appPathCache:
            paths = []
            home = self.userConf.getHomeDir() or "/MISSING-HOME-DIR"
            desk = self.userConf.getSetting("XdgDesktopDir") or "~/Desktop"
            user = self.userConf.getSetting("Username") or "user"
            host = self.userConf.getSetting("Hostname") or "localhost"
            did = re.escape(actor.desktopid)

            # Full privileges in one's home!
            rwf = (EventFileFlags.read | EventFileFlags.write |
                   EventFileFlags.overwrite | EventFileFlags.destroy |
                   EventFileFlags.create | EventFileFlags.move |
                   EventFileFlags.copy)
            paths.append((re.compile('^%s/\.%s' % (home, did)), rwf))
            paths.append((re.compile('^%s/\.cache/%s' % (home, did)), rwf))
            paths.append((re.compile('^%s/\.config/%s' % (home, did)), rwf))
            paths.append((re.compile('^%s/\.local/share/%s' % (home, did)),
                         rwf))
            paths.append((re.compile('^%s/\.local/share/+(mime/|recently\-'
                         'used\.xbel)' % (home)), rwf))
            paths.append((re.compile('^/run/user/[0-9]+/dconf/user$'), rwf))
            paths.append((re.compile('^/dev/null$'), rwf))

            # Append the app-specific home paths
            appSpecificRWPaths = actor.getSetting('RWPaths',
                                                  type='string list') or []
            for path in appSpecificRWPaths:
                path = path.replace('@XDG_DESKTOP_DIR@', desk)
                path = path.replace('@USER@', user)
                path = path.replace('@HOSTNAME@', host)
                path = path.replace('~', home)
                paths.append((re.compile(path), rwf))

            # Sticky bit in /tmp: one can touch what they created
            paths.append((re.compile('^/tmp/'), EventFileFlags.create))
            paths.append((re.compile('^/var/tmp/'), EventFileFlags.create))

            # Read-only / copy-only installed files
            rof = (EventFileFlags.read | EventFileFlags.copy)
            paths.append((re.compile('^/etc/%s' % did), rof))
            paths.append((re.compile('^/usr/include/%s' % did), rof))
            paths.append((re.compile('^/usr/lib/%s' % did), rof))
            paths.append((re.compile('^/usr/share/%s' % did), rof))
            paths.append((re.compile('^/usr/lib/pkgconfig/%s\.pc' % did), rof))
            paths.append((re.compile('^/usr/share/GConf/gsettings/%s\..*' %
                          did), rof))
            paths.append((re.compile('^/usr/share/appdata/%s\.appdata\.xml' %
                          did), rof))
            paths.append((re.compile('^/usr/share/appdata/%s(\-.*)?\.'
                          'metainfo\.xml' % did), rof))
            paths.append((re.compile('^/usr/share/applications/(.*\.)?%s\.'
                          'desktop' % did), rof))
            paths.append((re.compile('^/usr/share/icons/.*%s\.(png|svg)' %
                          did), rof))
            paths.append((re.compile('^/usr/share/dbus-1/services/.*\.%s\.'
                          'service' % did), rof))
            paths.append((re.compile('^/usr/share/gtk-doc/html/%s' % did),
                          rof))
            paths.append((re.compile('^/usr/share/help/.*/%s' % did), rof))
            paths.append((re.compile('^/usr/share/locale/.*/LC_MESSAGES/%s\.mo'
                          % did), rof))
            paths.append((re.compile('^/usr/share/man/man1/%s\.1\.gz' % did),
                         rof))
            paths.append((re.compile('^/usr/local/%s' % did), rof))
            paths.append((re.compile('^/opt/%s' % did), rof))
            paths.append((re.compile('^%s/\.X(defaults|authority)' % (home)),
                         rof))
            paths.append((re.compile('^%s/\.ICEauthority' % (home)), rof))
            paths.append((re.compile('^%s/\.config/(pango/pangorc|dconf/user|'
                                     'user-dirs.dirs)' % (home)), rof))
            paths.append((re.compile('^%s/\.local/share/applications(/|/mime'
                                     'info\.cache|/mimeapps\.list)?$' %
                                     (home)), rof))
            paths.append((re.compile('%s/\.icons/.*?/(index\.theme|cursors/)' %
                         (home)), rof))
            paths.append((re.compile('%s/\.(config/)?enchant/' % (home)), rof))
            paths.append((re.compile('^/usr/share/myspell'), rof))

            # Interpretor-specific files
            if ((actor.getInterpreterId() and
                 pyre.match(actor.getInterpreterId())) or
                    pyre.match(actor.getDesktopId())):
                paths.append((re.compile('^/usr/lib/python2\.7/.*\.pyc'), rwf))
            # If I ever support Vala: /usr/share/(vala|vala-0.32)/vapi/%s*

            # Append the app-specific system paths
            appSpecificROPaths = actor.getSetting('ROPaths',
                                                  type='string list') or []
            for path in appSpecificROPaths:
                path = path.replace('@XDG_DESKTOP_DIR@', desk)
                path = path.replace('@USER@', user)
                path = path.replace('@HOSTNAME@', host)
                path = path.replace('~', home)
                paths.append((re.compile(path), rof))

            self.appPathCache[actor] = paths

        return self.appPathCache[actor]

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return None

    def _accFunCondDesignation(self,
                               f: File,
                               acc: FileAccess,
                               composed: bool,
                               data):
        """Calculate condition for DESIGNATION_ACCESS to be returned."""
        return acc.evflags & EventFileFlags.designation

    def _accFunCondPolicy(self,
                          f: File,
                          acc: FileAccess,
                          composed: bool,
                          data):
        """Calculate condition for POLICY_ACCESS to be returned."""
        (allowed, __) = self.allowedByPolicy(f, acc.actor)
        return allowed

    def _accFunSimilarAccessCond(self,
                                 f: File,
                                 acc: FileAccess,
                                 composed: bool,
                                 data):
        """Calculate condition for grantingCost to be incremented."""
        return not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                          appWide=self.appWideRecords())

    def accessFunc(self,
                   engine: 'PolicyEngine',
                   f: File,
                   acc: FileAccess,
                   composed: bool=False):
        """Assess the usability score of a FileAccess."""
        data = self._accFunPreCompute(f, acc)

        if not composed:
            # Designation accesses are considered cost-free.
            if self._accFunCondDesignation(f, acc, composed, data):
                self.incrementScore('desigAccess', f, acc.actor)
                self.updateDesignationState(f, acc, data)
                return DESIGNATION_ACCESS

            # Some files are allowed because they clearly belong to the app
            ownedPaths = self.generateOwnedPaths(acc.actor)
            for (path, evflags) in ownedPaths:
                if path.match(f.getName()) and \
                        acc.allowedByFlagFilter(evflags, f):
                    self.incrementScore('ownedPathAccess', f, acc.actor)
                    return OWNED_PATH_ACCESS

        # Check for legality coming from the acting app's policy.
        if self._accFunCondPolicy(f, acc, composed, data):
            if not composed:
                self.incrementScore('policyAccess', f, acc.actor)
                self.updateAllowedState(f, acc, data)
            return POLICY_ACCESS

        if not composed:
            # We could not justify the access, increase the usabiltiy cost.
            self.incrementScore('illegalAccess', f, acc.actor)

            # If a prior interruption granted access, don't overcount.
            self.incrementScore('cumulGrantingCost', f, acc.actor)
            if self._accFunSimilarAccessCond(f, acc, composed, data):
                self.incrementScore('grantingCost', f, acc.actor)
            f.recordAccessCost(acc, ILLEGAL_ACCESS,
                               appWide=self.appWideRecords())
            self.updateIllegalState(f, acc, data)
        return ILLEGAL_ACCESS

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        raise NotImplementedError

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        pass

    def updateAllowedState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on POLICY_ACCESS."""
        pass

    def updateIllegalState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on ILLEGAL_ACCESS."""
        pass

    def matchExclusionPattern(self, pattern: str, file: File):
        """Check if a File's path matches an exclusion pattern.

        Check if a File's patch matches an exclusion pattern, and if so, return
        the matched pattern in the File's path. Else, return None.
        """
        exp = self.exclRegEx[pattern]
        res = exp.match(file.getName())
        if res:
            return res.group(0)
        return None

    def calculateExclViolations(self):
        """Calculate cross-overs between exclusion lists for each cluster."""

        # Get, and compile, the exclusion lists from the user.
        self.exclList = self.userConf.getSecurityExclusionLists()
        self.exclRegEx = dict()
        for list in self.exclList:
            for path in list:
                self.exclRegEx[path] = re.compile('^'+path)

        def _calculate(clusters):
            """Calculate the cross-overs for a given cluster."""
            # Each cluster has its own list of scores.
            exclScores = [None] * len(clusters)

            for (cIndex, cluster) in enumerate(clusters):
                # Each list of mutually exclusive patterns has its scores.
                clusterScores = [dict() for _ in range(len(self.exclList))]

                # We check for each file and list which patterns files match.
                for file in cluster:
                    # Go through each list of patterns.
                    for (eIndex, excl) in enumerate(self.exclList):

                        # Go through each pattern and look for a match.
                        for (pIndex, pattern) in enumerate(excl):
                            matched = self.matchExclusionPattern(pattern, file)
                            if not matched:
                                continue

                            # print("path: %s\tmatch: %s\tfile: %s" % (
                            #     pattern, matched, file.getName()
                            # ))
                            exclFiles = clusterScores[eIndex].get(matched) \
                                or [pattern]
                            exclFiles.append(file)
                            clusterScores[eIndex][matched] = exclFiles

                exclScores[cIndex] = clusterScores

            return exclScores

        def _calculateApps(lists):
            appExclScores = dict()
            for (app, files) in lists.items():
                # Each list of mutually exclusive patterns has its scores.
                clusterScores = [dict() for _ in range(len(self.exclList))]

                for file in files:
                    # Go through each list of patterns.
                    for (eIndex, excl) in enumerate(self.exclList):

                        # Go through each pattern and look for a match.
                        for (pIndex, pattern) in enumerate(excl):
                            matched = self.matchExclusionPattern(pattern, file)
                            if not matched:
                                continue

                            # print("path: %s\tmatch: %s\tfile: %s" % (
                            #     pattern, matched, file.getName()
                            # ))
                            exclFiles = clusterScores[eIndex].get(matched) \
                                or [pattern]
                            exclFiles.append(file)
                            clusterScores[eIndex][matched] = exclFiles

                appExclScores[app] = clusterScores

            return appExclScores

        self.exclScores = _calculate(self.clusters)
        self.exclScoresInst = _calculate(self.clustersInst)
        self.exclScoresPerApp = _calculateApps(self.accessLists)
        # TODO: presence of user Secure Files in clusters, and size thereof

    def printSecurityClusters(self,
                              outputDir: str=None,
                              quiet: bool=False,
                              printClusters: bool=False):
        """Print information about information flow clusters."""
        # if not self.clusters or not self.clusters:
        if not self.clusters:
            raise ValueError("Clusters must be built with "
                             ":buildSecurityClusters: before they can be "
                             "printed for Policy '%s'." % self.name)

        def _printClusters(clusters):
            """Print cluster basic statistics."""
            clusterCount = len(clusters)
            lenDist = list(len(c) for c in clusters)
            avg = sum(lenDist) / len(clusters)
            median = statistics.median(lenDist)
            minLen = min(lenDist)
            maxLen = max(lenDist)

            msg = ("Number of clusters: %d\n" % clusterCount)
            msg += ("Average length:     %d\n" % avg)
            msg += ("Median length:      %d\n" % median)
            msg += ("Smallest cluster:   %d\n" % minLen)
            msg += ("Largest cluster:    %d\n" % maxLen)
            msg += ("Cluster distribution: [")
            for l in sorted(lenDist):
                msg += "%d, " % l
            msg.rstrip(", ")
            msg += "]\n"

            return msg

        def _printExclViolations(exclScores):
            """Print cross-overs of exclusion lists in each cluster."""
            if not self.exclList:
                return ""

            msg = ""
            violationCount = 0

            for (eIndex, listScores) in enumerate(exclScores):
                msg += ("Exclusion list #%d: %s\n" % (
                        eIndex+1,
                        self.exclList[eIndex].__str__()))

                matchSum = set()
                for (path, match) in listScores.items():
                    matchSum.add(match[0])
                    msg += ("  %s (pattern %s): %d files matched\n" % (
                             path,
                             match[0],
                             len(match)-1))

                if len(matchSum) > 1:
                    violationCount += 1
                    msg += (" %d exclusive paths matched. Security "
                            "violation!\n" % len(matchSum))
                elif len(matchSum) == 1:
                    msg += (" 1 exclusive path matched.\n")
                else:
                    msg += (" No exclusive paths matched.\n")
                msg += "\n"
            msg += "\n"

            return (msg, violationCount)

        def _printClusterExclViolations(clusters, exclScores):
            """Print cross-overs of exclusion lists in each cluster."""
            if not self.exclList:
                return ""

            msg = ""
            violationCount = 0

            for (cIndex, cluster) in enumerate(clusters):
                msg += ("Cluster #%d (%d files):\n" % (cIndex+1,
                                                       len(cluster)))
                for f in sorted(cluster, key=lambda key: key.getName()):
                    msg += ("  %s\n" % f.getName())
                msg += "\n"

                (ret, cnt) = _printExclViolations(exclScores[cIndex])
                msg += ret
                violationCount += cnt
            msg += "\n"

            msg += ("# of clusters violating exclusion lists: %d" %
                    violationCount)

            return msg

        def _writeClusters(clusters, scores, forMsg, filename):
            """Write the output of the print function to a file and stdout."""
            msg = ("\nCONNECTED FILE CLUSTERS FOR %s\n" % forMsg)
            msg += _printClusters(clusters)
            msg += _printClusterExclViolations(clusters, scores)

            if not quiet and printClusters:
                print(msg)

            if outputDir:
                filename = outputDir + '/' + filename
                os.makedirs(File.getParentNameFromName(filename),
                            exist_ok=True)
                with open(filename, "a") as f:
                    print(msg, file=f)

        def _writeApps(appExclScores):
            """Write the output of the print function to a file and stdout."""
            appStore = ApplicationStore.get()
            if not quiet:
                print("\nEXCLUSION LIST SCORES FOR USER APP INSTANCES\n")
            for (app, exclScores) in sorted(appExclScores.items()):
                (msg, cnt) = _printExclViolations(exclScores)

                if cnt:
                    appUid = app[app.find("Instance ")+len("Instance "):
                                 -len(".score")]
                    inst = appStore.lookupUid(appUid)
                    if inst:
                        self.incrementScore('splittingCost', None, inst, cnt)

                if not quiet:
                    print("\n%s:" % app)
                    print(msg)

                if outputDir:
                    filename = outputDir + '/' + app + ".exclscore"
                    os.makedirs(File.getParentNameFromName(filename),
                                exist_ok=True)
                    with open(filename, "a") as f:
                        print(msg, file=f)

        _writeClusters(self.clusters, self.exclScores,
                       "APPLICATIONS AND USER DOCUMENTS",
                       "clustersPerApp.securityscore")
        _writeClusters(self.clustersInst, self.exclScoresInst,
                       "APPLICATION INSTANCES AND USER DOCUMENTS",
                       "clustersPerAppInstance.securityscore")
        _writeApps(self.exclScoresPerApp)

    def buildSecurityClusters(self,
                              engine: 'PolicyEngine',
                              userDocumentsOnly: bool=False):
        """Build clusters of files with information flows to one another."""
        # First, build clusters of files co-accessed by every single app.
        accessListsApp = dict()
        accessListsInst = dict()
        userHome = self.userConf.getHomeDir()
        for f in engine.fileStore:
            # Ignore folders without accesses (auto-created by factory).
            if f.isFolder() and not f.hasAccesses():
                continue

            # Only take user documents if asked to.
            if userDocumentsOnly and not \
                    f.isUserDocument(userHome=userHome, allowHiddenFiles=True):
                continue

            for acc in f.getAccesses():
                if not acc.actor.isUserlandApp():
                    continue

                (policyAllowed, __) = self.allowedByPolicy(f, acc.actor)
                if policyAllowed or acc.isByDesignation():
                    instanceLabel = "App - %s - Instance %s.score" % (
                                     acc.actor.getDesktopId(),
                                     acc.actor.uid())
                    l = accessListsApp.get(acc.actor.desktopid) or set()
                    l.add(f)
                    accessListsApp[acc.actor.desktopid] = l
                    l = accessListsInst.get(instanceLabel) or set()
                    l.add(f)
                    accessListsInst[instanceLabel] = l

        # Then, merge clusters that share an item.
        def _clusters(accessLists):
            clusters = []

            for (app, l) in accessLists.items():
                mergeSet = []

                # Single out all the clusters that share an item with l.
                for (index, cluster) in enumerate(clusters):
                    if hasIntersection(l, cluster):
                        mergeSet.append(index)

                # Pop them all out (in reverse order to keep indexes
                # consistant), and feed them to a set's union operator in
                # order to unify all the list contents into a single set.
                newCluster = set(list(l)).union(
                    *(clusters.pop(index) for index in
                        reversed(sorted(mergeSet))))
                clusters.append(newCluster)

            return clusters

        # Return our final list of clusters.
        return (_clusters(accessListsApp),
                _clusters(accessListsInst),
                accessListsInst)

    def calculateOverentitlements(self, engine: 'PolicyEngine'):
        """Calculate over-entitlements for each app."""

        for app in engine.appStore:
            for f in engine.fileStore:
                # Ignore folders without accesses (auto-created by factory).
                if f.isFolder() and not f.hasAccesses():
                    continue

                (policyAllowed, __) = self.allowedByPolicy(f, app)

                # File allowed by the policy
                if policyAllowed:
                    self.incrementOverEntitlement(f, app, False)

                    # File accessed by the app
                    accesses = f.getAccesses()
                    for acc in accesses:
                        if acc.actor == app:
                            self.incrementOverEntitlement(f, app, True)
                            break

    def securityRun(self, engine: 'PolicyEngine'):
        """Assess the quality of the security provided by a Policy."""

        # Build clusters of files with information flows to one another.
        # (self.clusters, self.accessLists) = \
        #     self.buildSecurityClusters(engine)
        (self.clusters, self.clustersInst, self.accessLists) = \
            self.buildSecurityClusters(engine, userDocumentsOnly=True)

        # Calculate exclusion list violations in clusters and apps.
        self.calculateExclViolations()

        # Calculate over-entitlements for each app.
        self.calculateOverentitlements(engine)

    def appWideRecords(self):
        """Return True if access records are across instances, False else."""
        return False

    def appsHaveMemory(self):
        """Return True if Applications have a memory across instances."""
        return True

    def globalConfigCost(self):
        """Return True if the Policy has a global config cost for all apps."""
        return False

    def configCostCarryover(self):
        """Apply the global config cost to all sub PolicyScores."""
        """Increment a given score for the Policy, File and Application."""

        gbScore = self.s.configCost

        for (key, score) in self.perInstanceScores.items():
            score.configCost = gbScore
            self.perInstanceScores[key] = score

        for (key, score) in self.perAppScores.items():
            score.configCost = gbScore
            self.perAppScores[key] = score

        for (key, score) in self.perFileScores.items():
            score.configCost = gbScore
            self.perFileScores[key] = score


class PolicyEngine(object):
    """An engine for running algorithms that implement a file AC policy."""

    def __init__(self):
        """Construct a PolicyEngine."""
        super(PolicyEngine, self).__init__()
        self.appStore = ApplicationStore.get()
        self.fileStore = FileStore.get()

    def runPolicy(self,
                  policy: Policy=None,
                  outputDir: str=None,
                  quiet: bool=False,
                  printClusters: bool=False):
        """Run a Policy over all the Files, and print the resulting scores."""
        if not policy:
            return

        # Sort all accesses by time before we can simulate usability scores.
        self.illegalAppStore = dict()
        accesses = sortedlist(key=lambda i: i[0].time)
        for file in self.fileStore:
            for acc in file.getAccesses():
                accesses.add((acc, file))

        # Then, calculate usability scores of each file access.
        for (acc, file) in accesses:
            ret = policy.accessFunc(self, file, acc)
            if ret == ILLEGAL_ACCESS and debugEnabled():
                t = self.illegalAppStore.get(acc.actor.desktopid) or set()
                t.add(file.getName()+("\tWRITE" if acc.evflags &
                                      EventFileFlags.write else "\tREAD"))
                self.illegalAppStore[acc.actor.desktopid] = t

        # Clean up files for the next policy run, and clear up some RAM.
        for file in self.fileStore:
            file.clearAccessCosts()
        del accesses

        # If there is a global config cost, ensure all sub-scores remember it.
        if policy.globalConfigCost():
            policy.configCostCarryover()

        # And security scores of each app
        policy.securityRun(self)

        # Graph printing, if enabled.
        if graphEnabled():
            from GraphEngine import GraphEngine
            engine = GraphEngine()
            engine.runGraph(policy=policy)

        if not quiet:
            policy.printScores(outputDir, printClusters=printClusters)

        if debugEnabled() and not quiet:
            for key in sorted(self.illegalAppStore):
                if key == 'catfish':  # too noisy
                    continue
                for file in sorted(self.illegalAppStore[key]):
                    print("%s: %s" % (key, file))
