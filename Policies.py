"""Policy where every access is allowed."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from PolicyEngine import Policy, PolicyEngine
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS
import sys


class OneLibraryPolicy(Policy):
    """Libraries made up of a single location. One library set per app."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='OneLibraryPolicy'):
        """Construct a OneLibraryPolicy."""
        super(OneLibraryPolicy, self).__init__(userConf, name)

        self.appPolicyCache = dict()

        self.documentsLibrary = dict()
        self.imageLibrary = dict()
        self.musicLibrary = dict()
        self.videoLibrary = dict()

        self.loadUserLibraryPreferences(userConf)

    def loadUserLibraryPreferences(self, userConf: UserConfigLoader):
        """Load user's library and folder names."""
        self.documentsLibrary[userConf.getSetting('XdgDocumentsDir')] = 0
        self.imageLibrary[userConf.getSetting('XdgImageDir')] = 0
        self.musicLibrary[userConf.getSetting('XdgMusicDir')] = 0
        self.videoLibrary[userConf.getSetting('XdgVideoDir')] = 0

    def getAppPolicy(self, actor: Application):
        """Return the library capabilities policy for one Application."""
        if actor not in self.appPolicyCache:
            policies = actor.getSetting('LibraryCaps',
                                        type='string list') or []
            self.appPolicyCache[actor] = policies

        return self.appPolicyCache[actor]

    def allowedByPolicy(self, file: File, actor: Application):
        """Tell if a File is allowed to be accessed by a Policy."""
        policies = self.getAppPolicy(actor)
        for pol in policies:
            try:
                attr = self.__getattribute__(pol+"Library")
            except (AttributeError):
                pass
            else:
                for (path, cost) in attr.items():
                    if(file.getName().startswith(path)):
                        return (True, cost)

        return (False, 0)


class CompoundLibraryPolicy(OneLibraryPolicy):
    """Libraries made up of compound locations. One library set per app."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='CompoundLibraryPolicy'):
        """Construct a CompoundLibraryPolicy."""
        super(CompoundLibraryPolicy, self).__init__(userConf, name)

    def loadUserLibraryPreferences(self, userConf: UserConfigLoader):
        super(CompoundLibraryPolicy, self).loadUserLibraryPreferences(userConf)

        """Load user's extra libraries."""
        confCost = 0
        for d in userConf.getSetting('ExtraDocumentsDirs',
                                     defaultValue=[],
                                     type='string list'):
            self.documentsLibrary[d] = 1
            confCost += 1
        for d in userConf.getSetting('ExtraImageDirs',
                                     defaultValue=[],
                                     type='string   list'):
            self.imageLibrary[d] = 1
            confCost += 1
        for d in userConf.getSetting('ExtraMusicDirs',
                                     defaultValue=[],
                                     type='string   list'):
            self.musicLibrary[d] = 1
            confCost += 1
        for d in userConf.getSetting('ExtraVideoDirs',
                                     defaultValue=[],
                                     type='string   list'):
            self.videoLibrary[d] = 1
            confCost += 1

        # Record the cost of configuring the policy
        self.incrementScore('configCost', None, None, increment=confCost)


class FileTypePolicy(Policy):
    """Policy where accesses are allowed by on files' file types."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='FileTypePolicy'):
        """Construct a FileTypePolicy."""
        super(FileTypePolicy, self).__init__(userConf, name)
        self.unsupportedExts = set()
        self.appLibCapsCache = dict()
        self.appMimeTypesCache = dict()

    def getAppLibCaps(self, actor: Application):
        """Return the library capabilities policy for one Application."""
        if actor not in self.appLibCapsCache:
            policies = actor.getSetting('LibraryCaps',
                                        type='string list') or []
            self.appLibCapsCache[actor] = policies

        return self.appLibCapsCache[actor]

    def getAppAllowedTypes(self, actor: Application):
        """Return the handled MIME types for one Application."""
        if actor not in self.appMimeTypesCache:
            allowedTypes = actor.getSetting('MimeType',
                                        type='string list')
            self.appMimeTypesCache[actor] = allowedTypes

        return self.appMimeTypesCache[actor]

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        allowedTypes = self.getAppAllowedTypes(app)

        if not allowedTypes:
            libCaps = self.getAppLibCaps(app)
            if libCaps:
                print("Warning: application '%s' with library capabilities "
                      " '%s' does not handle any MIME types. This is an "
                      "omissin from the writers of the app's .desktop file." %
                      (app.desktopid, libCaps))
            return (False, 0)

        fileType = f.getType()
        if not fileType:
            dot = f.getFileName().rfind(".")
            slash = f.getFileName().rfind("/")
            if dot != -1 and dot > slash+1:
                ext = f.getFileName()[dot+1:]
                self.unsupportedExts.add(ext)

        return (fileType in allowedTypes, 0)

    def abortIfUnsupportedExtensions(self):
        if len(self.unsupportedExts):
            print("Unsupported file extensions for FileTypePolicy:",
                  file=sys.stderr)
            for ext in self.unsupportedExts:
                print("\t* %s" % ext,
                      file=sys.stderr)
            sys.exit(0)


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
        return (True, 0)
