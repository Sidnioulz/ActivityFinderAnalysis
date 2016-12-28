"""Policy where every access is allowed."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from PolicyEngine import Policy, PolicyEngine
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS


class UnsecurePolicy(Policy):
    """Policy where every access is allowed."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='UnsecurePolicy'):
        """Construct a UnsecurePolicy."""
        super(UnsecurePolicy, self).__init__(userConf, name)

    def accessFunc(self, engine: PolicyEngine, f: File, acc: FileAccess):
        """Assess the usability score of a FileAccess."""
        # Designation accesses are considered cost-free.
        if acc.evflags & EventFileFlags.designation:
            self.incrementScore('desigAccess', f, acc.actor)
            f.recordAccessCost(acc, DESIGNATION_ACCESS)
            return DESIGNATION_ACCESS

        # Check for legality coming from the acting app's policy.
        self.incrementScore('policyAccess', f, acc.actor)
        f.recordAccessCost(acc, POLICY_ACCESS)
        return POLICY_ACCESS

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return (True, None)
