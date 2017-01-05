"""Policy definitions."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from PolicyEngine import Policy, PolicyEngine
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, ILLEGAL_ACCESS, \
                      OWNED_PATH_ACCESS
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


class DesignationPolicy(Policy):
    """Policy where only accesses by designation are allowed."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='DesignationPolicy'):
        """Construct a DesignationPolicy."""
        super(DesignationPolicy, self).__init__(userConf, name)

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return (False, 0)


class FolderPolicy(Policy):
    """Policy where whole folders can be accessed after a designation event."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='FolderPolicy'):
        """Construct a FolderPolicy."""
        super(FolderPolicy, self).__init__(userConf, name)
        self.designatedFoldersCache = dict()
        self.illegalFoldersCache = dict()

    def accessFunc(self,
                   engine: PolicyEngine,
                   f: File,
                   acc: FileAccess,
                   composed: bool=False):
        """Assess the usability score of a FileAccess."""
        folder = File.getParentName(f.getName())

        if not composed:
            # Designation accesses are considered cost-free.
            if acc.evflags & EventFileFlags.designation:
                self.incrementScore('desigAccess', f, acc.actor)
                f.recordAccessCost(acc, DESIGNATION_ACCESS)
                self.addToCache(self.designatedFoldersCache, folder, acc.actor)
                return DESIGNATION_ACCESS

            # Some files are allowed because they clearly belong to the app
            ownedPaths = self.generateOwnedPaths(acc.actor)
            for (path, evflags) in ownedPaths:
                if path.match(f.getName()) and \
                        acc.allowedByFlagFilter(evflags, f):
                    self.incrementScore('ownedPathAccess', f, acc.actor)
                    f.recordAccessCost(acc, OWNED_PATH_ACCESS)
                    return OWNED_PATH_ACCESS

        # Files in the same folder as a designated file are allowed.
        if self.folderInCache(self.designatedFoldersCache, folder, acc.actor):
            if not composed:
                self.incrementScore('policyAccess', f, acc.actor)
                f.recordAccessCost(acc, POLICY_ACCESS)
            return POLICY_ACCESS

        if not composed:
            # We could not justify the access, increase the usabiltiy cost.
            self.incrementScore('illegalAccess', f, acc.actor)

            # If a prior interruption granted access, don't overcount.
            self.incrementScore('cumulGrantingCost', f, acc.actor)
            if (not self.folderInCache(self.illegalFoldersCache, folder,
                    acc.actor)
                    and not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS)):
                self.incrementScore('grantingCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, OWNED_PATH_ACCESS):
                self.incrementScore('grantingOwnedCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, DESIGNATION_ACCESS):
                self.incrementScore('grantingDesigCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, POLICY_ACCESS):
                self.incrementScore('grantingPolicyCost', f, acc.actor)
            f.recordAccessCost(acc, ILLEGAL_ACCESS)
        self.addToCache(self.illegalFoldersCache, folder, acc.actor)
        return ILLEGAL_ACCESS

    def addToCache(self, cache: dict, folder: str, app: Application):
        """Record that a folder has been previously accessed by an app."""
        if not folder:
            return
        s = cache.get(app.uid()) or set()
        s.add(folder)
        cache[app.uid()] = s

    def folderInCache(self, cache: dict, folder: str, app: Application):
        """Tell if a folder has been previously accessed by an app."""
        if not folder:
            return False
        s = cache.get(app.uid()) or set()
        return folder in s

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        folder = File.getParentName(f.getName())
        if self.folderInCache(self.designatedFoldersCache, folder, app):
            return (True, 0)
        else:
            return (False, 0)


class OneFolderPolicy(FolderPolicy):
    """Policy where apps can access a single folder only."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='OneFolderPolicy'):
        """Construct a OneFolderPolicy."""
        super(OneFolderPolicy, self).__init__(userConf, name)
        self.designatedFoldersCache = dict()
        self.illegalFoldersCache = dict()

    def appHasFolderCached(self, app: Application):
        """Tell if a folder has been previously accessed by an app."""
        s = self.designatedFoldersCache.get(app.uid())
        return s is not None

    def accessFunc(self,
                   engine: PolicyEngine,
                   f: File,
                   acc: FileAccess,
                   composed: bool=False):
        """Assess the usability score of a FileAccess."""
        folder = File.getParentName(f.getName())

        if not composed:
            # This time we only allow one any access at first, so we don't
            # allow further accesses from other folders, even by designation.
            if not self.appHasFolderCached(acc.actor) and \
                    (acc.evflags & EventFileFlags.designation):
                self.incrementScore('desigAccess', f, acc.actor)
                f.recordAccessCost(acc, DESIGNATION_ACCESS, appWide=True)
                self.addToCache(self.designatedFoldersCache, folder, acc.actor)
                return DESIGNATION_ACCESS

            # Some files are allowed because they clearly belong to the app
            ownedPaths = self.generateOwnedPaths(acc.actor)
            for (path, evflags) in ownedPaths:
                if path.match(f.getName()) and \
                        acc.allowedByFlagFilter(evflags, f):
                    self.incrementScore('ownedPathAccess', f, acc.actor)
                    f.recordAccessCost(acc, OWNED_PATH_ACCESS, appWide=True)
                    return OWNED_PATH_ACCESS

        # Files in the same folder as a designated file are allowed.
        if self.folderInCache(self.designatedFoldersCache, folder, acc.actor):
            if not composed:
                self.incrementScore('policyAccess', f, acc.actor)
                f.recordAccessCost(acc, POLICY_ACCESS, appWide=True)
            return POLICY_ACCESS

        if not composed:
            # We could not justify the access, increase the usabiltiy cost.
            self.incrementScore('illegalAccess', f, acc.actor)

            # If a prior interruption granted access, don't overcount.
            self.incrementScore('cumulGrantingCost', f, acc.actor)
            if (not self.folderInCache(self.illegalFoldersCache, folder,
                                       acc.actor) and not
                    f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS, appWide=True)):
                self.incrementScore('grantingCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, OWNED_PATH_ACCESS, appWide=True):
                self.incrementScore('grantingOwnedCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, DESIGNATION_ACCESS, appWide=True):
                self.incrementScore('grantingDesigCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, POLICY_ACCESS, appWide=True):
                self.incrementScore('grantingPolicyCost', f, acc.actor)
            f.recordAccessCost(acc, ILLEGAL_ACCESS, appWide=True)
        self.addToCache(self.illegalFoldersCache, folder, acc.actor)
        return ILLEGAL_ACCESS

    def appsHaveMemory(self):
        """Return True if Application have a memory across instances."""
        return False


class FutureAccessListPolicy(Policy):
    """Policy where files can be accessed by future instances indefinitely."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='FutureAccessListPolicy'):
        """Construct a FutureAccessListPolicy."""
        super(FutureAccessListPolicy, self).__init__(userConf, name)
        self.list = dict()

    def accessFunc(self,
                   engine: 'PolicyEngine',
                   f: File,
                   acc: FileAccess,
                   composed: bool=False):
        """Assess the usability score of a FileAccess."""
        # Designation accesses are considered cost-free.
        if not composed:
            if acc.evflags & EventFileFlags.designation:
                self.incrementScore('desigAccess', f, acc.actor)
                f.recordAccessCost(acc, DESIGNATION_ACCESS,
                                   appWide=self.appWideRecords())
                self.addToList(f, acc.actor)
                return DESIGNATION_ACCESS

            # Some files are allowed because they clearly belong to the app
            ownedPaths = self.generateOwnedPaths(acc.actor)
            for (path, evflags) in ownedPaths:
                if path.match(f.getName()) and \
                        acc.allowedByFlagFilter(evflags, f):
                    self.incrementScore('ownedPathAccess', f, acc.actor)
                    f.recordAccessCost(acc, OWNED_PATH_ACCESS,
                                       appWide=self.appWideRecords())
                    return OWNED_PATH_ACCESS

        # Check for legality coming from the acting app's policy.
        (allowed, __) = self.allowedByPolicy(f, acc.actor)
        if allowed:
            if not composed:
                self.incrementScore('policyAccess', f, acc.actor)
                f.recordAccessCost(acc, POLICY_ACCESS,
                                   appWide=self.appWideRecords())
            self.addToList(f, acc.actor)
            return POLICY_ACCESS

        if not composed:
            # We could not justify the access, increase the usabiltiy cost.
            self.incrementScore('illegalAccess', f, acc.actor)

            # If a prior interruption granted access, don't overcount.
            self.incrementScore('cumulGrantingCost', f, acc.actor)
            if not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                          appWide=self.appWideRecords()):
                self.incrementScore('grantingCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, OWNED_PATH_ACCESS,
                                      appWide=self.appWideRecords()):
                self.incrementScore('grantingOwnedCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, DESIGNATION_ACCESS,
                                      appWide=self.appWideRecords()):
                self.incrementScore('grantingDesigCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, POLICY_ACCESS,
                                      appWide=self.appWideRecords()):
                self.incrementScore('grantingPolicyCost', f, acc.actor)
            f.recordAccessCost(acc, ILLEGAL_ACCESS,
                               appWide=self.appWideRecords())
        return ILLEGAL_ACCESS

    def addToList(self, f: File, app: Application):
        """Add a File to this policy's future access list."""
        l = self.list.get(app.desktopid) or list()
        l.append(f)
        self.list[app.desktopid] = l

    def fileInlist(self, f: File, app: Application):
        """Tell if a File is in this policy's future access list."""
        return f in (self.list.get(app.desktopid) or list())

    def appWideRecords(self):
        """Return True if access records are across instances, False else."""
        return True

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        if self.fileInlist(f, app):
            return (True, 0)
        else:
            return (False, 0)


class UnsecurePolicy(Policy):
    """Policy where every access is allowed, apps are basically unsandboxed."""

    def __init__(self,
                 userConf: UserConfigLoader,
                 name: str='UnsecurePolicy'):
        """Construct a UnsecurePolicy."""
        super(UnsecurePolicy, self).__init__(userConf, name)

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return (True, 0)


class CompositionalPolicy(Policy):
    """A policy made up of compositions of other policies.

    A policy made up of compositions of other policies. Allows an access if any
    of the underlying policies would allow it. Pass it a list of policy class
    names in order to instantiate it.
    """

    def __init__(self,
                 userConf: UserConfigLoader,
                 policies: list,
                 name: str="CompositionalPolicy"):
        """Construct a CompositionalPolicy."""
        cname = name + " ["
        for polClass in policies:
            cname += polClass.__name__ + ", "
        cname += "]"

        self.policies = []
        for polClass in policies:
            pol = polClass(userConf)
            self.policies.append(pol)

        super(CompositionalPolicy, self).__init__(userConf, cname)

    def accessFunc(self,
                   engine: 'PolicyEngine',
                   f: File,
                   acc: FileAccess,
                   composed: bool=False):
        """Assess the usability score of a FileAccess."""
        if composed:
            raise AttributeError("Compositions of compositional policies are"
                                 "not supported, aborting.")

        # Designation accesses are considered cost-free.
        if acc.evflags & EventFileFlags.designation:
            self.incrementScore('desigAccess', f, acc.actor)
            f.recordAccessCost(acc, DESIGNATION_ACCESS,
                               appWide=self.appWideRecords())
            return DESIGNATION_ACCESS

        # Some files are allowed because they clearly belong to the app
        ownedPaths = self.generateOwnedPaths(acc.actor)
        for (path, evflags) in ownedPaths:
            if path.match(f.getName()) and acc.allowedByFlagFilter(evflags, f):
                self.incrementScore('ownedPathAccess', f, acc.actor)
                f.recordAccessCost(acc, OWNED_PATH_ACCESS,
                                   appWide=self.appWideRecords())
                return OWNED_PATH_ACCESS

        # Loop through policies until we find a decision we can return.
        for pol in self.policies:
            decision = pol.accessFunc(engine, f, acc, composed=True)
            finished = self._selectAccessFuncDecision(decision)
            if finished:
                break
        # If all policies return the weak decision (illegal for this policy,
        # legal for the strict policy), then we return that weak decision.
        else:
            decision = self._returnWeakAccessFuncDecision(f, acc)

        # Now, we update scores and return the decision.
        if decision == ILLEGAL_ACCESS:
            # We could not justify the access, increase the usabiltiy cost.
            self.incrementScore('illegalAccess', f, acc.actor)

            # If a prior interruption granted access, don't overcount.
            self.incrementScore('cumulGrantingCost', f, acc.actor)
            if not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                          appWide=self.appWideRecords()):
                self.incrementScore('grantingCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, OWNED_PATH_ACCESS,
                                      appWide=self.appWideRecords()):
                self.incrementScore('grantingOwnedCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, DESIGNATION_ACCESS,
                                      appWide=self.appWideRecords()):
                self.incrementScore('grantingDesigCost', f, acc.actor)
            if f.hadPastSimilarAccess(acc, POLICY_ACCESS,
                                      appWide=self.appWideRecords()):
                self.incrementScore('grantingPolicyCost', f, acc.actor)
            f.recordAccessCost(acc, ILLEGAL_ACCESS,
                               appWide=self.appWideRecords())
            return ILLEGAL_ACCESS
        else:  # decision == POLICY_ACCESS
            self.incrementScore('policyAccess', f, acc.actor)
            f.recordAccessCost(acc, POLICY_ACCESS,
                               appWide=self.appWideRecords())
            return POLICY_ACCESS

    def _returnWeakAccessFuncDecision(self, f: File, acc: FileAccess):
        """Return the default decision for this compositional policy."""
        return ILLEGAL_ACCESS

    def _selectAccessFuncDecision(self, decision: int):
        """Choose if a sub-policy's accessFunc output should be selected."""
        if decision in (DESIGNATION_ACCESS, OWNED_PATH_ACCESS, POLICY_ACCESS):
            return True
        else:
            return False

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        for policy in self.policies:
            if policy.allowedByPolicy(f, app):
                return (True, 0)

        return (False, 0)


class StrictCompositionalPolicy(CompositionalPolicy):
    """A policy made up of compositions of other policies.

    A policy made up of compositions of other policies. Allows an access only
    if ALL of the underlying policies would allow it, as opposed to
    CompositionalPolicy which is more permissive. Pass it a list of policy
    class names in order to instantiate it.
    """

    def __init__(self,
                 userConf: UserConfigLoader,
                 policies: list,
                 name: str="StrictCompositionalPolicy"):
        """Construct a StrictCompositionalPolicy."""
        super(StrictCompositionalPolicy, self).__init__(userConf,
                                                        policies,
                                                        name)

    def _returnWeakAccessFuncDecision(self, f: File, acc: FileAccess):
        """Return the default decision for this compositional policy."""
        return POLICY_ACCESS

    def _selectAccessFuncDecision(self, decision: int):
        """Choose if a sub-policy's accessFunc output should be selected."""
        if decision in (DESIGNATION_ACCESS, OWNED_PATH_ACCESS, ILLEGAL_ACCESS):
            return True
        else:
            return False

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        for policy in self.policies:
            if not policy.allowedByPolicy(f, app):
                return (False, 0)

        return (True, 0)
