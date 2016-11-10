"""An engine for running algorithms that implement an access control policy."""

from File import File, FileAccess, EventFileFlags
from FileStore import FileStore
from ApplicationStore import ApplicationStore
from constants import ILLEGAL_ACCESS
from utils import debugEnabled


class Policy(object):
    """Virtual pure parent class for policy algorithms."""

    def __init__(self, name: str):
        """Construct a Policy."""
        super(Policy, self).__init__()
        self.name = name
        self.clearScores()

    def clearScores(self):
        """Initialise scores to zero before processing FileAccesses."""
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
        # TODO: separate costs on hidden (config) files and documents
        self.interruptionCost = 0
        self.grantingCost = 0   # Granting access to a file on the spot
        self.cumulGrantCost = 0  # Increase even w/ past illegal access counted
        self.splittingCost = 0  # Running two instances of a process

        # Interaction overheads when handling multiple instances of an app
        self.overheadCost = 0

        # SECURITY COSTS.
        # TODO validate these proposed scores
        self.userSecViolations = 0
        self.instanceExposure = 0
        self.appExposure = 0

    def printScores(self):
        """Print all scores."""
        print("Accesses:")
        print("\t* by designation: %d" % self.desigAccess)
        print("\t* file owned by app: %d" % self.ownedPathAccess)
        print("\t* policy-allowed: %d" % self.policyAccess)
        print("\t* illegal: %d" % self.illegalAccess)

        print("\nCosts:")
        print("\t* configuration: %d" % self.configCost)
        print("\t* anticipation: %d" % self.anticipationCost)
        print("\t* interruption: %d" % self.interruptionCost)
        print("\t\t* granting: %d" % self.grantingCost)
        print("\t\t* cumulative granting: %d" % self.cumulGrantCost)
        print("\t\t* splitting apps: %d" % self.splittingCost)
        print("\t* overhead: %d" % self.overheadCost)

        print("\nSecurity:")
        print("TODO")

    def accessFunc(self, engine: 'PolicyEngine', f: File, acc: FileAccess):
        """Assess the security and usability score of a FileAccess."""
        raise NotImplementedError


class PolicyEngine(object):
    """An engine for running algorithms that implement a file AC policy."""

    def __init__(self,
                 appStore: ApplicationStore,
                 fileStore: FileStore):
        """Construct a PolicyEngine."""
        super(PolicyEngine, self).__init__()
        self.appStore = appStore
        self.fileStore = fileStore

    def runPolicy(self, policy: Policy=None):
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

        policy.printScores()

        if debugEnabled():
            for key in sorted(self.illegalAppStore):
                if key == 'catfish':  # too noisy
                    continue
                for file in sorted(self.illegalAppStore[key]):
                    print("%s: %s" % (key, file))
