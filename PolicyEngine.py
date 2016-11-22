"""An engine for running algorithms that implement an access control policy."""
from File import File, FileAccess, EventFileFlags
from FileStore import FileStore
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from constants import ILLEGAL_ACCESS
from utils import debugEnabled
import os


class PolicyScores(object):
    """docstring for PolicyScores."""
    def __init__(self):
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
        self.interruptionCost = 0
        self.grantingCost = 0   # Granting access to a file on the spot
        self.cumulGrantCost = 0  # Increase even w/ past illegal access counted
        self.splittingCost = 0  # Running two instances of a process

        # Interaction overheads when handling multiple instances of an app
        self.overheadCost = 0

        # Scores per Application instance, and per Application
        self.perAppScores = dict()
        self.perinstanceScores = dict()

        # SECURITY COSTS.
        # TODO validate these proposed scores
        self.userSecViolations = 0
        self.instanceExposure = 0
        self.appExposure = 0

    def __iadd__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("Cannot increment a PolicyScores with something "
                            "other than another PolicyScores.")

        self.desigAccess += other.desigAccess
        self.ownedPathAccess += other.ownedPathAccess
        self.policyAccess += other.policyAccess
        self.illegalAccess += other.illegalAccess
        self.configCost += other.configCost
        self.anticipationCost += other.anticipationCost
        self.interruptionCost += other.interruptionCost
        self.grantingCost += other.grantingCost
        self.cumulGrantCost += other.cumulGrantCost
        self.splittingCost += other.splittingCost
        self.overheadCost += other.overheadCost
        self.userSecViolations += other.userSecViolations
        self.instanceExposure += other.instanceExposure
        self.appExposure += other.appExposure

        return self

    def printScores(self,
                    outputDir: str=None,
                    filename: str=None,
                    quiet: bool=False):
        """Print the access, cost and security scores of this PolicyScores."""

        msg = ("Accesses:\n")
        msg += ("\t* by designation: %d\n" % self.desigAccess)
        msg += ("\t* file owned by app: %d\n" % self.ownedPathAccess)
        msg += ("\t* policy-allowed: %d\n" % self.policyAccess)
        msg += ("\t* illegal: %d\n" % self.illegalAccess)

        msg += ("\nCosts:")
        msg += ("\t* configuration: %d\n" % self.configCost)
        msg += ("\t* anticipation: %d\n" % self.anticipationCost)
        msg += ("\t* interruption: %d\n" % self.interruptionCost)
        msg += ("\t\t* granting: %d\n" % self.grantingCost)
        msg += ("\t\t* cumulative granting: %d\n" % self.cumulGrantCost)
        msg += ("\t\t* splitting apps: %d\n" % self.splittingCost)
        msg += ("\t* overhead: %d\n" % self.overheadCost)

        msg += ("\nSecurity:\n")
        msg += ("TODO")

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
        self.clearScores()

    def clearScores(self):
        """Initialise scores to zero before processing FileAccesses."""
        self.s = PolicyScores()

        # Scores per Application instance, and per Application
        self.perAppScores = dict()
        self.perInstanceScores = dict()

        # Scores for each individual File
        self.perFileScores = dict()

    def printScores(self, outputDir: str):
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

        # Score for each application individually
        systemS = PolicyScores()
        desktopS = PolicyScores()
        userappS = PolicyScores()
        for desktopid in sorted(self.perAppScores.keys()):
            score = self.perAppScores[desktopid]
            # print("\n\nApp: %s" % desktopid)
            score.printScores(scoreDir, "App - %s.score" % desktopid,
                              quiet=True)

            appStore = ApplicationStore.get()
            apps = appStore.lookupDesktopId(desktopid, limit=1)
            if apps:
                # TODO loop and append
                if apps[0].isSystemApp():
                    systemS += score
                elif apps[0].isDesktopApp():
                    desktopS += score
                elif apps[0].isUserlandApp():
                    userappS += score

        # Score for each type of application
        print("-------------------")
        print("\nALL SYSTEM APPS")
        systemS.printScores(scoreDir, "SystemApps.score")
        print("\nALL DESKTOP APPS")
        desktopS.printScores(scoreDir, "DesktopApps.score")
        print("\nALL USER APPS")
        userappS.printScores(scoreDir, "UserlandApps.score")
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
                score.printScores(outputDir, outfilename, quiet=True)

                if last.isUserDocument(userHome):
                    userDocF += score
                else:
                    systemF += score
        print("\nALL SYSTEM FILES")
        systemF.printScores(scoreDir, "SystemFiles.score")
        print("\nALL USER DOCUMENTS")
        userDocF.printScores(scoreDir, "UserDocFiles.score")
        print("-------------------")

        # General score
        print("\nGENERAL SCORES:")
        self.s.printScores(scoreDir, "general.score")
        print("-------------------")
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
                            file.__class__.__name__)

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

    def accessFunc(self, engine: 'PolicyEngine', f: File, acc: FileAccess):
        """Assess the security and usability score of a FileAccess."""
        raise NotImplementedError


class PolicyEngine(object):
    """An engine for running algorithms that implement a file AC policy."""

    def __init__(self):
        """Construct a PolicyEngine."""
        super(PolicyEngine, self).__init__()
        self.appStore = ApplicationStore.get()
        self.fileStore = FileStore.get()

    def runPolicy(self, policy: Policy=None, outputDir: str=None):
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

        policy.printScores(outputDir)

        if debugEnabled():
            for key in sorted(self.illegalAppStore):
                if key == 'catfish':  # too noisy
                    continue
                for file in sorted(self.illegalAppStore[key]):
                    print("%s: %s" % (key, file))
