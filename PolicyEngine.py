"""An engine for running algorithms that implement an access control policy."""
from File import File, FileAccess, EventFileFlags
from FileStore import FileStore
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, OWNED_PATH_ACCESS, \
                      ILLEGAL_ACCESS
from utils import debugEnabled, hasIntersection, pyre
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

        # Cost of launching an app/file in a special way
        self.anticipationCost = 0

        # Interruptions to an interaction (security confirmation dialogs)
        self.grantingCost = 0   # Cost of granting access to a file on the spot
        self.grantingOwnedCost = 0   # For debug: past owned files now illegal
        self.grantingDesigCost = 0   # For debug: past desig files now illegal
        self.grantingPolicyCost = 0   # For debug: past pol files now illegal
        self.cumulGrantingCost = 0  # Cumulative number of illegal accesses
        self.splittingCost = 0  # Cost of splitting a process into 2 instances

        # Interaction overheads when handling multiple instances of an app
        self.overheadCost = 0

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
        self.anticipationCost += other.anticipationCost
        self.grantingCost += other.grantingCost
        self.grantingOwnedCost += other.grantingOwnedCost
        self.grantingDesigCost += other.grantingDesigCost
        self.grantingPolicyCost += other.grantingPolicyCost
        self.cumulGrantingCost += other.cumulGrantingCost
        self.splittingCost += other.splittingCost
        self.overheadCost += other.overheadCost

        return self

    def printScores(self,
                    outputDir: str=None,
                    filename: str=None,
                    quiet: bool=False):
        """Print the access and cost scores of this PolicyScores."""

        msg = ("Accesses:\n")
        msg += ("\t* by designation: %d\n" % self.desigAccess)
        msg += ("\t* file owned by app: %d\n" % self.ownedPathAccess)
        msg += ("\t* policy-allowed: %d\n" % self.policyAccess)
        msg += ("\t* illegal: %d\n" % self.illegalAccess)

        msg += ("\nCosts:")
        msg += ("\t* configuration: %d\n" % self.configCost)
        msg += ("\t* anticipation: %d\n" % self.anticipationCost)
        msg += ("\t* granting: %d\n" % self.grantingCost)
        if debugEnabled():
            msg += ("\t*TEST illegal w/ past owned path: %d\n" %
                    self.grantingOwnedCost)
            msg += ("\t*TEST illegal w/ past designation: %d\n" %
                    self.grantingDesigCost)
            msg += ("\t*TEST illegal w/ past policy-allowed: %d\n" %
                    self.grantingPolicyCost)
        msg += ("\t* cumulative granting: %d\n" % self.cumulGrantingCost)
        msg += ("\t* splitting apps: %d\n" % self.splittingCost)
        msg += ("\t* overhead: %d\n" % self.overheadCost)

        if not quiet:
            print(msg)

        if outputDir:
            os.makedirs(outputDir + '/' +
                        File.getParentName(filename),
                        exist_ok=True)
            with open(outputDir + '/' + filename, "a") as f:
                print(msg, file=f)


class SecurityScores(object):
    """Security scores for Policies."""

    def __init__(self):
        """Construct a SecurityScores."""
        super(SecurityScores, self).__init__()
        # For each desktopid, maintain a list. This list contains a number per
        # instance of the Application, which represents the number of logically
        # separated units that have been accessed by the instance. An average
        # score of 1 means that there was no instance which accessed two such
        # isolation units. Scores are only incremented for legal accesses,
        # which is what differentiates the policies from one another.
        self.implicitSeparations = []  # TODO

        # For each app, we keep a record of how many files they have accessed
        # compared to how many files they are allowed to access. This ratio
        # allows us to compare the overentitlements between policies. The per-
        # app ratio is relevant to overentitlement in general, the per-instance
        # ratio is useful for discussing the potential immediate consequences
        # of a benign app being exploited (notwithstanding app statefulness).
        self.overEntitlements = [set(), set()]

    def __eq__(self, other):
        """Compare this SecurityScores to :other:."""
        if not isinstance(other, self.__class__):
            raise TypeError("Cannot increment a SecurityScores with something "
                            "other than another SecurityScores.")

        return self.implicitSeparations == other.implicitSeparations and \
            self.overEntitlements[0] == other.overEntitlements[0] and \
            self.overEntitlements[1] == other.overEntitlements[1]

    def __iadd__(self, other):
        """Add the scores from :other: to this SecurityScores."""
        if not isinstance(other, self.__class__):
            raise TypeError("Cannot increment a SecurityScores with something "
                            "other than another SecurityScores.")

        self.implicitSeparations += other.implicitSeparations
        self.overEntitlements[0] = \
            self.overEntitlements[0].union(list(other.overEntitlements[0]))
        self.overEntitlements[1] = \
            self.overEntitlements[1].union(list(other.overEntitlements[1]))

        return self

    def printScores(self,
                    outputDir: str=None,
                    filename: str=None,
                    userHome: str=None,
                    quiet: bool=False):
        """Print the security scores."""

        msg = ("Security over-entitlements:\n")
        msg += ("\t* %d files used / %d reachable\n" % (
                (len(self.overEntitlements[0]), len(self.overEntitlements[1]))))

        sysFiles = [set(), set()]
        userFiles = [set(), set()]
        for i in (0,1):
            for file in self.overEntitlements[i]:
                if file.isUserDocument(userHome):
                    userFiles[i].add(file)
                else:
                    sysFiles[i].add(file)

        msg += ("\t* %d user documents used / %d reachable\n" % (
                (len(userFiles[0]), len(userFiles[1]))))

        msg += ("\t* %d system files used / %d reachable\n" % (
                (len(sysFiles[0]), len(sysFiles[1]))))

        if not quiet:
            print(msg)

        if outputDir:
            os.makedirs(outputDir + '/' +
                        File.getParentName(filename),
                        exist_ok=True)
            with open(outputDir + '/' + filename, "a") as f:
                print(msg, file=f)


class Policy(object):
    """Virtual pure parent class for policy algorithms."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str):
        """Construct a Policy."""
        super(Policy, self).__init__()
        self.name = name
        self.userConf = userConf
        self.appPathCache = dict()
        self.clearScores()

    def clearScores(self):
        """Initialise scores to zero before processing FileAccesses."""
        # Usability general score
        self.s = PolicyScores()

        # Scores per Application instance, and per Application
        self.perAppScores = dict()
        self.perInstanceScores = dict()

        # Scores for each individual File
        self.perFileScores = dict()

        # Security score, and security clusters
        self.ss = SecurityScores()
        self.perAppSecurityScores = dict()
        self.perInstanceSecurityScores = dict()
        self.clusters = []
        self.clustersPerInstance = []
        # TODO more security scores

    def printScores(self,
                    outputDir: str,
                    printClusters: bool=False):
        """Print general scores, scores per app, instance and file."""

        # Make sure the score directory is built
        if outputDir:
            scoreDir = outputDir + "/Policy - %s" % self.name

            if not os.path.exists(outputDir):
                raise FileNotFoundError("Output directory given to the "
                                        "PolicyEngine does not exist: %s" %
                                        outputDir)
            os.makedirs(scoreDir, exist_ok=False)
        else:
            scoreDir = None

        print("\n#####################~  USABILITY  ~#####################")

        # Score for each application individually
        systemS = PolicyScores()
        desktopS = PolicyScores()
        userappS = PolicyScores()
        appStore = ApplicationStore.get()
        for desktopid in sorted(self.perAppScores.keys()):
            score = self.perAppScores[desktopid]
            # print("\n\nApp: %s" % desktopid)
            score.printScores(outputDir=scoreDir,
                              filename="App - %s.score" % desktopid,
                              quiet=True)

            # Loop through application instances and print their scores.
            apps = appStore.lookupDesktopId(desktopid, limit=1)
            for app in apps:
                iScore = self.perInstanceScores.get(app)
                if iScore:
                    iScore.printScores(outputDir=scoreDir,
                                       filename="App - %s - Instance %s.score"
                                        % (desktopid, app.uid()),
                                       quiet=True)

            # Identify if the application is of desktop/system/DE type.
            if apps:
                if apps[0].isSystemApp():
                    systemS += score
                elif apps[0].isDesktopApp():
                    desktopS += score
                elif apps[0].isUserlandApp():
                    userappS += score

        # Score for each type of application
        print("-------------------")
        print("\nALL SYSTEM APPS")
        systemS.printScores(outputDir=scoreDir,
                            filename="SystemApps.score")
        print("\nALL DESKTOP APPS")
        desktopS.printScores(outputDir=scoreDir,
                             filename="DesktopApps.score")
        print("\nALL USER APPS")
        userappS.printScores(outputDir=scoreDir,
                             filename="UserlandApps.score")
        print("-------------------")

        # File scores
        systemF = PolicyScores()
        userDocF = PolicyScores()
        userHome = self.userConf.getSetting("HomeDir")
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
                                  quiet=True)

                if last.isUserDocument(userHome):
                    userDocF += score
                else:
                    systemF += score
        print("\nALL SYSTEM FILES")
        systemF.printScores(outputDir=scoreDir,
                            filename="SystemFiles.score")
        print("\nALL USER DOCUMENTS")
        userDocF.printScores(outputDir=scoreDir,
                             filename="UserDocFiles.score")
        print("-------------------")

        # General score
        print("\nGENERAL SCORES")
        self.s.printScores(outputDir=scoreDir,
                           filename="general.score")
        print("-------------------")
        print("\n\n\n")

        print("\n#####################~  SECURITY  ~#####################")
        # Security score for each application individually
        appStore = ApplicationStore.get()
        for desktopid in sorted(self.perAppSecurityScores.keys()):
            score = self.perAppSecurityScores[desktopid]
            score.printScores(outputDir=scoreDir,
                              filename="App - %s.securityscore" % desktopid,
                              userHome=userHome,
                              quiet=True)

            # Loop through application instances and print their scores.
            apps = appStore.lookupDesktopId(desktopid, limit=1)
            for app in apps:
                iScore = self.perInstanceSecurityScores.get(app.uid())
                if iScore:
                    iScore.printScores(outputDir=scoreDir,
                                       filename="App - %s - Instance %s.securi"
                                       "tyscore" % (desktopid, app.uid()),
                                       userHome=userHome,
                                       quiet=True)

        # Security - general score
        print("\nSECURITY OVERENTITLEMENT SCORES")
        self.ss.printScores(outputDir=scoreDir,
                            filename="general.securityscore",
                            userHome=userHome)
        print("-------------------")

        print("\nINFORMATION FLOW CLUSTERS")
        self.printSecurityClusters(outputDir=scoreDir,
                                   printClusters=printClusters)
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
        self.ss.overEntitlements[0 if accessed else 1].add(file)

        # Per instance score
        iScore = self.perInstanceSecurityScores.get(actor.uid()) or \
            SecurityScores()
        iScore.overEntitlements[0 if accessed else 1].add(file)
        self.perInstanceSecurityScores[actor.uid()] = iScore

        # Per app score
        aScore = self.perAppSecurityScores.get(actor.getDesktopId()) or \
            SecurityScores()
        aScore.overEntitlements[0 if accessed else 1].add(file)
        self.perAppSecurityScores[actor.getDesktopId()] = aScore

    def generateOwnedPaths(self, actor: Application):
        """Return the paths where an Application can fully write Files."""
        if actor not in self.appPathCache:
            paths = []
            home = self.userConf.getSetting("HomeDir") or "/MISSING-HOME-DIR"
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

    def accessFunc(self, engine: 'PolicyEngine', f: File, acc: FileAccess):
        """Assess the usability score of a FileAccess."""
        # Designation accesses are considered cost-free.
        if acc.evflags & EventFileFlags.designation:
            self.incrementScore('desigAccess', f, acc.actor)
            f.recordAccessCost(acc, DESIGNATION_ACCESS)
            return DESIGNATION_ACCESS

        # Some files are allowed because they clearly belong to the app
        ownedPaths = self.generateOwnedPaths(acc.actor)
        for (path, evflags) in ownedPaths:
            if path.match(f.getName()) and acc.allowedByFlagFilter(evflags, f):
                self.incrementScore('ownedPathAccess', f, acc.actor)
                f.recordAccessCost(acc, OWNED_PATH_ACCESS)
                return OWNED_PATH_ACCESS

        # Check for legality coming from the acting app's policy.
        (allowed, __) = self.allowedByPolicy(f, acc.actor)
        if allowed:
            self.incrementScore('policyAccess', f, acc.actor)
            f.recordAccessCost(acc, POLICY_ACCESS)
            return POLICY_ACCESS

        # We could not justify the access, increase the usabiltiy cost.
        self.incrementScore('illegalAccess', f, acc.actor)

        # If a prior interruption granted access, don't overcount.
        self.incrementScore('cumulGrantingCost', f, acc.actor)
        if not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS):
            self.incrementScore('grantingCost', f, acc.actor)
        if f.hadPastSimilarAccess(acc, OWNED_PATH_ACCESS):
            self.incrementScore('grantingOwnedCost', f, acc.actor)
        if f.hadPastSimilarAccess(acc, DESIGNATION_ACCESS):
            self.incrementScore('grantingDesigCost', f, acc.actor)
        if f.hadPastSimilarAccess(acc, POLICY_ACCESS):
            self.incrementScore('grantingPolicyCost', f, acc.actor)
        f.recordAccessCost(acc, ILLEGAL_ACCESS)
        return ILLEGAL_ACCESS

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        raise NotImplementedError

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

    def calculateClusterCrossovers(self):
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

        self.exclScores = _calculate(self.clusters)
        self.exclScoresPerInstance = _calculate(self.clustersPerInstance)
        self.exclScoreDocs = _calculate(self.clusterDocs)
        self.exclScoreDocsPerInstance = _calculate(self.clusterDocsPerInstance)
        # TODO: presence of user Secure Files in clusters, and size thereof

    def makeSecurityClusterIndexes(self, outputDir: str):
        """TODO"""
        pass  # TODO

    def printSecurityClusters(self,
                              outputDir: str=None,
                              quiet: bool=False,
                              printClusters: bool=False):
        """Print information about information flow clusters."""
        if not self.clusters or not self.clustersPerInstance:
            raise ValueError("Clusters must be built with "
                             ":buildSecurityClusters: before they can be "
                             "printed for Policy '%s'." % self.name)

        def _print(clusters):
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

        def _printCrossovers(clusters, exclScores):
            """Print cross-overs of exclusion lists in each cluster."""
            if not self.exclList:
                return ""

            msg = ""

            for (cIndex, cluster) in enumerate(clusters):
                msg += ("Cluster #%d (%d files):\n" % (cIndex+1, len(cluster)))
                if printClusters:
                    for f in sorted(cluster, key=lambda key: key.getName()):
                        msg += ("  %s\n" % f.getName())
                    msg += ("\n")

                for (eIndex, listScores) in enumerate(exclScores[cIndex]):
                    msg += ("Exclusion list #%d: %s\n" % (
                            eIndex+1,
                            self.exclList[eIndex].__str__()))

                    matchSum = set()
                    for (path, match) in listScores.items():
                        msg += ("  %s (pattern %s): %d files matched\n" % (
                                 path,
                                 match[0],
                                 len(match)-1))
                        matchSum.add(match[0])

                    if len(matchSum) > 1:
                        msg += (" %d exclusive paths matched. Security "
                                "violation!\n" % len(matchSum))
                    elif len(matchSum) == 1:
                        msg += (" 1 exclusive path matched.\n")
                    else:
                        msg += (" No exclusive paths matched.\n")
                    msg += "\n"
                msg += "\n"
            msg += "\n"

            return msg

        def _write(clusters, scores, forMsg, filename):
            """Write the output of the print function to a file and stdout."""
            msg = ("\nCONNECTED FILE CLUSTERS FOR %s\n" % forMsg)
            msg += _print(clusters)
            msg += _printCrossovers(clusters, scores)

            if not quiet:
                print(msg)

            if outputDir:
                os.makedirs(outputDir + '/' +
                            File.getParentName(filename),
                            exist_ok=True)
                with open(outputDir + '/' + filename, "a") as f:
                    print(msg, file=f)

        _write(self.clusters, self.exclScores,
               "APPLICATIONS", "clustersPerApp.securityscore")
        _write(self.clustersPerInstance, self.exclScoresPerInstance,
               "APP INSTANCES", "clustersPerInstance.securityscore")
        _write(self.clusterDocs, self.exclScoreDocs,
               "APPLICATIONS AND USER DOCUMENTS",
               "clustersPerAppAndUserDocs.securityscore")
        _write(self.clusterDocsPerInstance, self.exclScoreDocsPerInstance,
               "APP INSTANCES AND USER DOCUMENTS",
               "clustersPerInstanceAndUserDocs.securityscore")

    def buildSecurityClusters(self,
                              engine: 'PolicyEngine',
                              userDocumentsOnly: bool=False):
        """Build clusters of files with information flows to one another."""
        # First, build clusters of files co-accessed by every single app.
        accessLists = dict()
        accessListsInstance = dict()
        userHome = self.userConf.getSetting("HomeDir")
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
                    # TODO: for policies that have one sandbox per app, use
                    # desktopID. for other policies, use instance uid()
                    # For policies with multiple sandboxes, find a good place
                    # to calculate duplicationCost! e.g. writes to owned path
                    # files -> duplication. This also means the allowedByPolicy
                    # function should exclude owned files (as some will be
                    # legitimately duplicated).
                    l = accessLists.get(acc.actor.getDesktopId()) or set()
                    l.add(f)
                    accessLists[acc.actor.getDesktopId()] = l
                    l = accessListsInstance.get(acc.actor.uid()) or set()
                    l.add(f)
                    accessListsInstance[acc.actor.uid()] = l

        # Then, merge clusters that share an item.
        clusters = []
        for (app, l) in accessLists.items():
            mergeSet = []

            # Single out all the clusters that share an item with l.
            for (index, cluster) in enumerate(clusters):
                if hasIntersection(l, cluster):
                    mergeSet.append(index)

            # Pop them all out (in reverse order to keep indexes consistant),
            # and feed them to a set's union operator in order to unify all the
            # list contents into a single set.
            newCluster = set(list(l)).union(
                *(clusters.pop(index) for index in reversed(sorted(mergeSet))))
            clusters.append(newCluster)

        # Then, merge clusters that share an item.
        clustersInstance = []
        for (app, l) in accessListsInstance.items():
            mergeSet = []

            # Single out all the clusters that share an item with l.
            for (index, cluster) in enumerate(clustersInstance):
                if hasIntersection(l, cluster):
                    mergeSet.append(index)

            # Pop them all out (in reverse order to keep indexes consistant),
            # and feed them to a set's union operator in order to unify all the
            # list contents into a single set.
            newCluster = set(list(l)).union(
                *(clustersInstance.pop(index) for index in
                  reversed(sorted(mergeSet))))
            clustersInstance.append(newCluster)

        # Return our final list of clusters.
        return (clusters, clustersInstance)

    def securityRun(self, engine: 'PolicyEngine'):
        """Assess the quality of the security provided by a Policy."""

        # Build clusters of files with information flows to one another.
        (self.clusters, self.clustersPerInstance) = \
            self.buildSecurityClusters(engine)
        (self.clusterDocs, self.clusterDocsPerInstance) = \
            self.buildSecurityClusters(engine, userDocumentsOnly=True)

        self.calculateClusterCrossovers()

        # Calculate over-entitlements for each app.
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

        # Calculate usability scores of each file access
        self.illegalAppStore = dict()
        for file in self.fileStore:
            for acc in file.getAccesses():
                ret = policy.accessFunc(self, file, acc)
                if ret == ILLEGAL_ACCESS and debugEnabled():
                    t = self.illegalAppStore.get(acc.actor.desktopid) or set()
                    t.add(file.getName()+("\tWRITE" if acc.evflags &
                                          EventFileFlags.write else "\tREAD"))
                    self.illegalAppStore[acc.actor.desktopid] = t
            file.clearAccessCosts()

        # And security scores of each app
        policy.securityRun(self)

        if not quiet:
            policy.printScores(outputDir, printClusters=printClusters)

        if debugEnabled() and not quiet:
            for key in sorted(self.illegalAppStore):
                if key == 'catfish':  # too noisy
                    continue
                for file in sorted(self.illegalAppStore[key]):
                    print("%s: %s" % (key, file))
