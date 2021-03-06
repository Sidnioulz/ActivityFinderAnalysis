"""An engine for running algorithms that implement an access control policy."""
from AccessListCache import AccessListCache
from LibraryManager import LibraryManager
from File import File, FileAccess, EventFileFlags
from FileStore import FileStore
from FileFactory import FileFactory
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, OWNED_PATH_ACCESS, \
                      ILLEGAL_ACCESS
from utils import debugEnabled, graphEnabled, hasIntersection, pyre, \
                  printClustersEnabled, scoreEnabled
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
        self.overEntitlements = [0, 0, 0, 0]

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
            self.overEntitlements[1] == other.overEntitlements[1] and \
            self.overEntitlements[2] == other.overEntitlements[2] and \
            self.overEntitlements[3] == other.overEntitlements[3]

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

        # Warning: It makes no sense to sum over-entitlements now they're just
        # counters. There will be files counted twice for sure.
        self.overEntitlements[0] += other.overEntitlements[0]
        self.overEntitlements[1] += other.overEntitlements[1]
        self.overEntitlements[2] += other.overEntitlements[2]
        self.overEntitlements[3] += other.overEntitlements[3]

        return self

    def __str__(self):
        """Print this PolicyScores object."""
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
                (self.overEntitlements[0],
                 self.overEntitlements[1])))

        msg += ("\t* %d user documents used / %d reachable\n" % (
                (self.overEntitlements[2],
                 self.overEntitlements[3])))

        return msg

    def printScores(self,
                    outputDir: str=None,
                    filename: str=None,
                    extraText: str=None,
                    quiet: bool=False):
        """Print the access, cost and security scores of this PolicyScores."""
        msg = self.__str__()

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

        return [self.overEntitlements[2], self.overEntitlements[3]]


class Policy(object):
    """Virtual pure parent class for policy algorithms."""

    appPathCache = dict()
    fileOwnedCache = dict()
    scopeCache = dict()

    def __init__(self,
                 name: str):
        """Construct a Policy."""
        super(Policy, self).__init__()
        self.name = name
        self.userConf = UserConfigLoader.get()
        self.libMgr = LibraryManager.get()
        self.scope = None
        self.unscopedDefDesignated = True
        self.unscopedDefAllowed = True
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
        self.perFileUserAppScores = dict()

        # Scores for libraries
        self.perLibScores = dict()

        # Security clusters
        self.clusters = None
        self.clustersInst = None
        self.accessLists = None
        self.exclScores = dict()
        self.exclScoresInst = dict()
        self.exclScoresPerApp = dict()

        self.scoreDir = None

    def getLastAccessDecisionStrength(self):
        """Tell if last access decision is valid enough for Folder policies."""
        return True

    def getOutputDir(self, parent: str=None):
        if parent:
            return parent + "/Policy - %s" % self.name
        else:
            return "/tmp/Policy - %s" % self.name

    def makeOutputDir(self,
                      outputDir: str):
        """Create the output directory for this policy to be printed."""

        # Make sure the score directory is built
        if outputDir:
            self.scoreDir = self.getOutputDir(parent=outputDir)

            if not os.path.exists(outputDir):
                raise FileNotFoundError("Output directory given to the "
                                        "PolicyEngine does not exist: %s" %
                                        outputDir)
            os.makedirs(self.scoreDir, exist_ok=True)
        else:
            self.scoreDir = None

    def printScores(self,
                    outputDir: str,
                    printClusters: bool=False):
        """Print general scores, scores per app, instance and file."""

        # Security scores first as they increment splittingCost in some apps.
        if printClustersEnabled():
            print("\nINFORMATION FLOW CLUSTERS")
            self.printSecurityClusters(outputDir=self.scoreDir,
                                printClusters=printClusters)
            print("-------------------")

        # Application scores.
        print("\nOVERENTITLEMENTS AND USABILITY SCORES")
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
                    r = iScore.printScores(outputDir=self.scoreDir,
                                           filename="App - %s - Instance %s."
                                           "score" % (desktopid,
                                                      app.uid()),
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

                extraText = "\n(reminder: no OE scores for apps.\n\n)\n" \
                            "\nAPP INSTANCE STATS SORTED BY UID\n" \
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
            score.printScores(outputDir=self.scoreDir,
                              filename="App - %s.score" % desktopid,
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
        systemS.printScores(outputDir=self.scoreDir,
                            filename="SystemApps.score")
        print("\nALL DESKTOP APPS")
        desktopS.printScores(outputDir=self.scoreDir,
                             filename="DesktopApps.score")
        print("\nALL USER APPS")
        userappS.printScores(outputDir=self.scoreDir,
                             filename="UserlandApps.score")
        print("-------------------")

        # File scores.
        systemF = PolicyScores()
        userDocF = PolicyScores()
        userDocUserAppF = PolicyScores()
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

                # NOTE: Disabled for performance reasons.
                # print("\n\nFile: %s:%s" % (last.inode, outfilename))
                # score.printScores(outputDir=outputDir,
                #                   filename=outfilename,
                #                   quiet=True)

                isDoc = last.isUserDocument(userHome, allowHiddenFiles=True)
                if isDoc:
                    userDocF += score
                else:
                    systemF += score

                score = self.perFileUserAppScores.get(last.inode)
                if score and isDoc:
                    userDocUserAppF += score

        print("\nALL SYSTEM FILES")
        systemF.printScores(outputDir=self.scoreDir,
                            filename="SystemFiles.score")
        print("\nMEDIA LIBRARY SCORES")
        for (libName, libScore) in self.perLibScores.items():
            libScore.printScores(outputDir=self.scoreDir,
                                 filename="Library%s.score" % (
                                  libName.capitalize() if libName
                                  else "Unclassified"))
        print("\nALL USER DOCUMENTS")
        userDocF.printScores(outputDir=self.scoreDir,
                             filename="UserDocFiles.score")
        print("\nUSER DOCUMENTS ACCESSED BY USER APPLICATIONS")
        userDocUserAppF.printScores(outputDir=self.scoreDir,
                                    filename="UserDocUserAppFiles.score")
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

        self.s.printScores(outputDir=self.scoreDir,
                           filename="general.score",
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

            aScore = self.perAppScores.get(actor.desktopid) or \
                PolicyScores()
            attr = aScore.__getattribute__(score)
            attr += increment
            aScore.__setattr__(score, attr)
            self.perAppScores[actor.desktopid] = aScore

        # File score
        if file:
            fScore = self.perFileScores.get(file.inode) or PolicyScores()
            attr = fScore.__getattribute__(score)
            attr += increment
            fScore.__setattr__(score, attr)
            self.perFileScores[file.inode] = fScore

            if actor and actor.isUserlandApp():
                fScore = self.perFileUserAppScores.get(file.inode) or \
                    PolicyScores()
                attr = fScore.__getattribute__(score)
                attr += increment
                fScore.__setattr__(score, attr)
                self.perFileUserAppScores[file.inode] = fScore

            # Library score
            libName = self.libMgr.getLibraryForFile(file,
                                                    LibraryManager.Custom)
            lScore = self.perLibScores.get(libName) or PolicyScores()
            attr = lScore.__getattribute__(score)
            attr += increment
            lScore.__setattr__(score, attr)
            self.perLibScores[libName] = lScore


    def incrementOverEntitlement(self,
                                 file: File,
                                 actor: Application,
                                 accessed: bool,
                                 isUserDoc: bool):
        """Increment an overentitlement score for a File and Application."""
        # Global score
        if not actor:
            self.s.overEntitlements[0 if accessed else 1] += 1
            if isUserDoc:
                self.s.overEntitlements[2 if accessed else 3] += 1

        # Per instance score
        else:
            iScore = self.perInstanceScores.get(actor.uid()) or \
                PolicyScores()
            iScore.overEntitlements[0 if accessed else 1] += 1
            if isUserDoc:
                iScore.overEntitlements[2 if accessed else 3] += 1
            self.perInstanceScores[actor.uid()] = iScore

    def fileOwnedByApp(self, f: File, acc: FileAccess):
        """Return True if a File is owned by an Application."""
        decision = False

        if (f, acc) not in Policy.fileOwnedCache:
            ownedPaths = self.generateOwnedPaths(acc.actor)
            for (path, evflags) in ownedPaths:
                if path.match(f.getName()) and acc.allowedByFlagFilter(evflags, f):
                    decision = True

            Policy.fileOwnedCache[(f, acc)] = decision

        return Policy.fileOwnedCache[(f, acc)]

    def generateOwnedPaths(self, actor: Application):
        """Return the paths where an Application can fully write Files."""
        if actor not in Policy.appPathCache:
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
                    pyre.match(actor.desktopid)):
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

            Policy.appPathCache[actor] = paths

        return Policy.appPathCache[actor]

    def inScope(self, f: File):
        """Check if a File is in scope for this Policy."""
        key = (f, self.scope)

        if key not in Policy.scopeCache:
            dec = False
            for s in self.scope:
                if f.path.startswith(s):
                    dec = True
                    break
            Policy.scopeCache[key] = dec
            return dec

        else:
            return Policy.scopeCache[key]

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return None

    def _uaccFunCondDesignation(self,
                                f: File,
                                acc: FileAccess,
                                composed: bool,
                                data):
        """Calculate condition for DESIGNATION_ACCESS to be returned."""
        return acc.evflags & EventFileFlags.designation

    def _accFunCondDesignation(self,
                               f: File,
                               acc: FileAccess,
                               composed: bool,
                               data):
        """Calculate condition for DESIGNATION_ACCESS to be returned."""
        if self.scope is None or self.inScope(f) or self.unscopedDefDesignated:
            return self._uaccFunCondDesignation(f, acc, composed, data)
        else:
            return False

    def _uaccFunCondPolicy(self,
                           f: File,
                           acc: FileAccess,
                           composed: bool,
                           data):
        """Calculate condition for POLICY_ACCESS to be returned."""
        return self.allowedByPolicy(f, acc.actor)

    def _accFunCondPolicy(self,
                          f: File,
                          acc: FileAccess,
                          composed: bool,
                          data):
        """Calculate condition for POLICY_ACCESS to be returned."""
        if self.scope is None or self.inScope(f):
            return self._uaccFunCondPolicy(f, acc, composed, data)
        else:
            return self.unscopedDefAllowed

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
            if self.fileOwnedByApp(f, acc):
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

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        raise NotImplementedError

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        if self.scope is None or self.inScope(f):
            return self._allowedByPolicy(f, app)
        else:
            return self.unscopedDefAllowed

    def accessAllowedByPolicy(self, f: File, acc: FileAccess):
        """Tell if a File can be accessed by an Application."""
        return self._accFunCondDesignation(f, acc, False, None)

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        pass

    def updateAllowedState(self, f: File, acc: FileAccess, data=None, strong=True):
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
        res = exp.match(file.path)
        if res:
            return res.group(0)
        return None

    def calculateExclViolations(self):
        """Calculate cross-overs between exclusion lists for each cluster."""

        # Get, and compile, the exclusion lists from the user.
        self.exclLists = self.userConf.getSecurityExclusionLists()
        self.exclRegEx = dict()
        for (exclistType, exclLists) in self.exclLists.items():
            for exclList in exclLists:
                for path in exclList:
                    self.exclRegEx[path] = re.compile('^'+path)

        def _calculate(clusters, listName, exclList):
            """Calculate the cross-overs for a given cluster."""
            # Each cluster has its own list of scores.
            exclScores = [None] * len(clusters)

            for (cIndex, cluster) in enumerate(clusters):
                # Each list of mutually exclusive patterns has its scores.
                clusterScores = [dict() for _ in range(len(exclList))]

                # We check for each file and list which patterns files match.
                for file in cluster:
                    # Go through each list of patterns.
                    for (eIndex, excl) in enumerate(exclList):

                        # Go through each pattern and look for a match.
                        for (pIndex, pattern) in enumerate(excl):
                            matched = self.matchExclusionPattern(pattern,
                                                                 file)
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

        def _calculateApps(lists, listName, exclList):
            appExclScores = dict()
            for (app, files) in lists.items():
                # Each list of mutually exclusive patterns has its scores.
                clusterScores = [dict() for _ in range(len(exclList))]

                for file in files:
                    # Go through each list of patterns.
                    for (eIndex, excl) in enumerate(exclList):

                        # Go through each pattern and look for a match.
                        for (pIndex, pattern) in enumerate(excl):
                            matched = self.matchExclusionPattern(pattern,
                                                                 file)
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

        for (listName, exclList) in self.exclLists.items():
            self.exclScores[listName] = \
                _calculate(self.clusters, listName, exclList)
            self.exclScoresInst[listName] = \
                _calculate(self.clustersInst, listName, exclList)
            self.exclScoresPerApp[listName] = \
                _calculateApps(self.accessLists, listName, exclList)

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

        def _printExclViolations(exclScores, exclType):
            """Print cross-overs of exclusion lists in each cluster."""
            if not self.exclLists:
                return ""

            msg = ""
            violationCount = 0

            for (eIndex, listScores) in enumerate(exclScores):
                msg += ("Exclusion list #%d: %s\n" % (
                        eIndex+1,
                        self.exclLists[exclType][eIndex].__str__()))

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

        def _printClusterExclViolations(clusters, exclScores, exclType):
            """Print cross-overs of exclusion lists in each cluster."""
            if not self.exclLists.get(exclType):
                return ""

            msg = ""
            violationCount = 0

            for (cIndex, cluster) in enumerate(clusters):
                msg += ("Cluster #%d (%d files):\n" % (cIndex+1,
                                                       len(cluster)))
                for f in sorted(cluster, key=lambda key: key.getName()):
                    msg += ("  %s\n" % f.getName())
                msg += "\n"

                (ret, cnt) = _printExclViolations(exclScores[cIndex], exclType)
                msg += ret
                violationCount += cnt
            msg += "\n"

            msg += ("# of clusters violating exclusion lists: %d" %
                    violationCount)

            return msg

        def _writeClusters(clusters, scores, exclType, forMsg, filename):
            """Write the output of the print function to a file and stdout."""
            msg = ("\nCONNECTED FILE CLUSTERS FOR %s\n" % forMsg)
            msg += _printClusters(clusters)
            msg += _printClusterExclViolations(clusters, scores, exclType)

            if not quiet and printClusters:
                print(msg)

            if outputDir:
                filename = outputDir + '/' + filename + "." + exclType + \
                    ".securityscore"
                os.makedirs(File.getParentNameFromName(filename),
                            exist_ok=True)
                with open(filename, "a") as f:
                    print(msg, file=f)

        def _writeApps(appExclScores, exclType):
            """Write the output of the print function to a file and stdout."""
            appStore = ApplicationStore.get()
            if not quiet:
                print("\nEXCLUSION LIST SCORES FOR USER APP INSTANCES\n")
            for (app, exclScores) in sorted(appExclScores.items()):
                (msg, cnt) = _printExclViolations(exclScores, exclType)

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
                    filename = outputDir + '/' + app + \
                        "." + exclType + ".exclscore"
                    os.makedirs(File.getParentNameFromName(filename),
                                exist_ok=True)
                    with open(filename, "a") as f:
                        print(msg, file=f)

        for (exclType, exclScores) in self.exclScores.items():
            _writeClusters(self.clusters, exclScores, exclType,
                           "APPLICATIONS AND USER DOCUMENTS",
                           "clustersPerAppExcl")
        for (exclType, exclScoresInst) in self.exclScoresInst.items():
            _writeClusters(self.clustersInst, exclScoresInst, exclType,
                           "APPLICATION INSTANCES AND USER DOCUMENTS",
                           "clustersPerAppInstanceExcl")
        for (exclType, exclScoresPerApp) in self.exclScoresPerApp.items():
            _writeApps(exclScoresPerApp, exclType)

    def buildSecurityClusters(self,
                              engine: 'PolicyEngine',
                              quiet: bool=False):
        """Build clusters of files with information flows to one another."""
        # First, build clusters of files co-accessed by every single app.
        if not quiet:
            print("\t\tBuilding lists of co-accessed files per application...")
        accessListsApp = dict()
        accessListsInst = dict()
        userHome = self.userConf.getHomeDir()
        for f in engine.fileStore:
            # Ignore folders without accesses (auto-created by factory).
            if f.isFolder() and not f.hasAccesses():
                continue

            # Only take user documents if asked to.
            if not f.isUserDocument(userHome=userHome, allowHiddenFiles=True):
                continue

            for acc in f.getAccesses():
                if not acc.actor.isUserlandApp():
                    continue

                if self.allowedByPolicy(f, acc.actor) or \
                        self.accessAllowedByPolicy(f, acc):
                    instanceLabel = "App - %s - Instance %s.score" % (
                                     acc.actor.desktopid,
                                     acc.actor.uid())
                    l = accessListsApp.get(acc.actor.desktopid) or set()
                    l.add(f)
                    accessListsApp[acc.actor.desktopid] = l
                    l = accessListsInst.get(instanceLabel) or set()
                    l.add(f)
                    accessListsInst[instanceLabel] = l


        alCache = AccessListCache.get()
        accessListsLinks = alCache.getLinkList()

        # Then, merge clusters that share an item.
        def _clusters(accessLists, links):
            clusters = []

            iterList = list(accessLists.values()) + links
            for l in iterList:
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
        if not quiet:
            print("\t\tMerging lists into clusters...")
        self.clusters = _clusters(accessListsApp, accessListsLinks)
        self.clustersInst = _clusters(accessListsInst, accessListsLinks)
        self.accessLists = accessListsInst

    # @profile
    def calculateOverentitlements(self,
                                  engine: 'PolicyEngine',
                                  quiet: bool=False):
        """Calculate over-entitlements for each app."""

        userHome = self.userConf.getHomeDir()
        total = len(engine.appStore) * len(engine.fileStore)
        threshold = int(total / 100)
        currentPct = 0
        currentCnt = 0

        for f in engine.fileStore:
            # Ignore folders without accesses (auto-created by factory).
            if f.isFolder() and not f.hasAccesses():
                continue

            wasAllowed = False
            wasAccessed = False

            uDoc = f.isUserDocument(userHome, allowHiddenFiles=True)
            allowedApps = []
            for app in engine.appStore:
                currentCnt += 1
                if currentCnt == threshold:
                    currentCnt = 0
                    currentPct += 1
                    if not (currentPct % 5) and not quiet:
                        print("\t\t... (%d%% done)" % currentPct)

                # File allowed by the policy
                if self.allowedByPolicy(f, app):
                    wasAllowed = True
                    allowedApps.append(app)
                    self.incrementOverEntitlement(f, app, False, uDoc)

            # File accessed by the app
            for acc in f.getAccesses():
                if acc.actor in allowedApps:
                    wasAccessed = True
                    self.incrementOverEntitlement(f, acc.actor, True, uDoc)
                    break

            if wasAllowed:
                self.incrementOverEntitlement(f, None, False, uDoc)
            if wasAccessed:
                self.incrementOverEntitlement(f, None, True, uDoc)

    def securityRun(self, engine: 'PolicyEngine', quiet: bool=False):
        """Assess the quality of the security provided by a Policy."""

        # Build clusters of files with information flows to one another.
        if not quiet:
            print("\tBuilding security clusters...")
        self.buildSecurityClusters(engine, quiet=quiet)

        # Calculate exclusion list violations in clusters and apps.
        if not quiet:
            print("\tCalculating exclusion list violations...")
        self.calculateExclViolations()

        # Calculate over-entitlements for each app.
        if not quiet:
            print("\tCalculating over-entitlements...")
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

        for (key, score) in self.perFileUserAppScores.items():
            score.configCost = gbScore
            self.perFileUserAppScores[key] = score

        for (key, score) in self.perLibScores.items():
            score.configCost = gbScore
            self.perLibScores[key] = score


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

        total = len(accesses)
        threshold = int(total / 100)
        currentPct = 0
        currentCnt = 0
        # Then, calculate usability scores of each file access.
        if not quiet:
            print("Starting usability computations...")

        for (acc, file) in accesses:
            currentCnt += 1
            if currentCnt == threshold:
                currentCnt = 0
                currentPct += 1
                if not (currentPct % 5) and not quiet:
                    print("\t... (%d%% done)" % currentPct)

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
        if not quiet:
            print("Carrying config costs over to app instances...")
        if policy.globalConfigCost():
            policy.configCostCarryover()

        # Make the output directory as we will produce output files!
        if not quiet:
            print("Creating output directory...")
        policy.makeOutputDir(outputDir)

        # Graph printing, if enabled.
        if graphEnabled():
            if not quiet:
                print("Starting graph computations...")
            from GraphEngine import GraphEngine
            engine = GraphEngine.get()
            engine.runGraph(policy=policy, outputDir=outputDir)

        # We were only running the access function to prepare for attack
        # simulation (which requires allowedByPolicy to be initialised) or for
        # graph simulation.
        if not scoreEnabled():
            return

        # And security scores of each app
        if not quiet:
            print("Starting security computations...")
        policy.securityRun(self, quiet=quiet)

        if not quiet:
            policy.printScores(outputDir, printClusters=printClusters)

        if debugEnabled() and not quiet:
            for key in sorted(self.illegalAppStore):
                if key == 'catfish':  # too noisy
                    continue
                for file in sorted(self.illegalAppStore[key]):
                    print("%s: %s" % (key, file))
