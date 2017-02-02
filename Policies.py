"""Policy definitions."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from PolicyEngine import Policy
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, ILLEGAL_ACCESS, \
                      OWNED_PATH_ACCESS
import sys


class OneLibraryPolicy(Policy):
    """Libraries made up of a single location. One library set per app."""

    def __init__(self,
                 supportedLibraries=['documents', 'image', 'music', 'video'],
                 name: str='OneLibraryPolicy'):
        """Construct a OneLibraryPolicy."""
        super(OneLibraryPolicy, self).__init__(name)

        self.appPolicyCache = dict()
        self.supportedLibraries = supportedLibraries

        self.documentsLibrary = dict()
        self.imageLibrary = dict()
        self.musicLibrary = dict()
        self.videoLibrary = dict()

        self.loadUserLibraryPreferences()

    def loadUserLibraryPreferences(self):
        """Load user's library and folder names."""
        self.documentsLibrary[self.userConf.getSetting('XdgDocumentsDir')] = 0
        self.imageLibrary[self.userConf.getSetting('XdgImageDir')] = 0
        self.musicLibrary[self.userConf.getSetting('XdgMusicDir')] = 0
        self.videoLibrary[self.userConf.getSetting('XdgVideoDir')] = 0

    def getAppPolicy(self, actor: Application):
        """Return the library capabilities policy for one Application."""
        if actor.desktopid not in self.appPolicyCache:
            policies = actor.getSetting('LibraryCaps',
                                        type='string list') or []
            self.appPolicyCache[actor.desktopid] = policies

        return self.appPolicyCache[actor.desktopid]

    def allowedByPolicy(self, file: File, actor: Application):
        """Tell if a File is allowed to be accessed by a Policy."""
        policies = self.getAppPolicy(actor)
        for pol in policies:
            if pol not in self.supportedLibraries:
                continue

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
                 name: str='CompoundLibraryPolicy'):
        """Construct a CompoundLibraryPolicy."""
        super(CompoundLibraryPolicy, self).__init__(name)

    def loadUserLibraryPreferences(self):
        super(CompoundLibraryPolicy, self).loadUserLibraryPreferences()

        """Load user's extra libraries."""
        confCost = 0
        for d in self.userConf.getSetting('ExtraDocumentsDirs',
                                          defaultValue=[],
                                          type='string list'):
            self.documentsLibrary[d] = 1
            confCost += 1
        for d in self.userConf.getSetting('ExtraImageDirs',
                                          defaultValue=[],
                                          type='string list'):
            self.imageLibrary[d] = 1
            confCost += 1
        for d in self.userConf.getSetting('ExtraMusicDirs',
                                          defaultValue=[],
                                          type='string list'):
            self.musicLibrary[d] = 1
            confCost += 1
        for d in self.userConf.getSetting('ExtraVideoDirs',
                                          defaultValue=[],
                                          type='string list'):
            self.videoLibrary[d] = 1
            confCost += 1

        # Record the cost of configuring the policy
        self.incrementScore('configCost', None, None, increment=confCost)

    def globalConfigCost(self):
        """Return True if the Policy has a global config cost for all apps."""
        return True


class FileTypePolicy(Policy):
    """Policy where accesses are allowed by on files' file types."""

    def __init__(self,
                 name: str='FileTypePolicy'):
        """Construct a FileTypePolicy."""
        super(FileTypePolicy, self).__init__(name)
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

    def getAppAllowedTypes(self, app: Application):
        """Return the handled MIME types for one Application."""
        if app.desktopid not in self.appMimeTypesCache:
            allowedTypes = app.getSetting('MimeType', type='string list')
            self.appMimeTypesCache[app.desktopid] = allowedTypes

            mimeCost = app.getSetting('MimeTypeCost', type='numeric') or 0
            self.incrementScore('configCost', None, app, increment=mimeCost)

        return self.appMimeTypesCache[app.desktopid]

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
            if dot != -1 and dot > 0:
                ext = f.getFileName()[dot+1:]
                self.unsupportedExts.add(ext)

        return (fileType in allowedTypes or allowedTypes[0] == "*", 0)

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
                 name: str='DesignationPolicy'):
        """Construct a DesignationPolicy."""
        super(DesignationPolicy, self).__init__(name)

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return (False, 0)


class FolderPolicy(Policy):
    """Policy where whole folders can be accessed after a designation event."""

    def __init__(self,
                 name: str='FolderPolicy'):
        """Construct a FolderPolicy."""
        super(FolderPolicy, self).__init__(name)
        self.desigCache = dict()
        self.illegalCache = dict()

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return f.getParentName()

    def _accFunCondPolicy(self,
                          f: File,
                          acc: FileAccess,
                          composed: bool,
                          data):
        """Calculate condition for POLICY_ACCESS to be returned."""
        return self.dataInCache(self.desigCache, data, acc.actor)

    def _accFunSimilarAccessCond(self,
                                 f: File,
                                 acc: FileAccess,
                                 composed: bool,
                                 data):
        """Calculate condition for grantingCost to be incremented."""
        return not self.dataInCache(self.illegalCache, data, acc.actor) and \
            not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                       appWide=self.appWideRecords())

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        if not data:
            data = self._accFunPreCompute(f, acc)
        self.addToCache(self.desigCache, data, acc.actor)

    def updateAllowedState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on POLICY_ACCESS."""
        self.updateDesignationState(f, acc, data)

    def updateIllegalState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on ILLEGAL_ACCESS."""
        if not data:
            data = self._accFunPreCompute(f, acc)
        self.addToCache(self.illegalCache, data, acc.actor)

    def addToCache(self, cache: dict, data: str, app: Application):
        """Record that data has been previously accessed by an app."""
        if not data:
            return
        key = app.desktopid if self.appWideRecords() else app.uid()
        s = cache.get(key) or set()
        s.add(data)
        cache[key] = s

    def dataInCache(self, cache: dict, data: str, app: Application):
        """Tell if data has been previously accessed by an app."""
        if not data:
            return False
        s = cache.get(app.desktopid if self.appWideRecords() else app.uid())
        return data in s if s else False

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        folder = f.getParentName()
        if self.dataInCache(self.desigCache, folder, app):
            return (True, 0)
        else:
            return (False, 0)


class OneFolderPolicy(FolderPolicy):
    """Policy where apps can access a single folder only."""

    def __init__(self,
                 name: str='OneFolderPolicy'):
        """Construct a OneFolderPolicy."""
        super(OneFolderPolicy, self).__init__(name)
        self.desigCache = dict()
        self.illegalCache = dict()

    def appHasFolderCached(self, app: Application):
        """Tell if a folder has been previously accessed by an app."""
        s = self.desigCache.get(app.desktopid if self.appWideRecords() else
                                app.uid())
        return s is not None

    def _accFunCondDesignation(self,
                               f: File,
                               acc: FileAccess,
                               composed: bool,
                               data):
        """Calculate condition for DESIGNATION_ACCESS to be returned."""
        return not self.appHasFolderCached(acc.actor) and \
            (acc.evflags & EventFileFlags.designation)

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Add the file's folder to the correct folder cache."""
        if not self.appHasFolderCached(acc.actor):
            if not data:
                data = self._accFunPreCompute(f, acc)
            self.addToCache(self.desigCache, data, acc.actor)

    def appsHaveMemory(self):
        """Return True if Application have a memory across instances."""
        return False


class FutureAccessListPolicy(FolderPolicy):
    """Policy where files can be accessed by future instances indefinitely."""

    def __init__(self,
                 name: str='FutureAccessListPolicy'):
        """Construct a FutureAccessListPolicy."""
        super(FutureAccessListPolicy, self).__init__(name)

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return f.inode

    def appWideRecords(self):
        """Return True if access records are across instances, False else."""
        return True

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        if self.dataInCache(self.desigCache, f.inode, app):
            return (True, 0)
        else:
            return (False, 0)


class UnsecurePolicy(Policy):
    """Policy where every access is allowed, apps are basically unsandboxed."""

    def __init__(self,
                 name: str='UnsecurePolicy'):
        """Construct a UnsecurePolicy."""
        super(UnsecurePolicy, self).__init__(name)

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
                 policies: list,
                 polArgs: list,
                 name: str="CompositionalPolicy"):
        """Construct a CompositionalPolicy."""
        if name.endswith("CompositionalPolicy"):
            cname = name + " ["
            for polClass in policies:
                cname += polClass.__name__ + ", "
            cname += "]"
        else:
            cname = name

        self.policies = []
        for (polIdx, polClass) in enumerate(policies):
            if polArgs[polIdx]:
                pol = polClass(**polArgs[polIdx])
            else:
                pol = polClass()
            self.policies.append(pol)

        super(CompositionalPolicy, self).__init__(cname)

    def accessFunc(self,
                   engine: 'PolicyEngine',
                   f: File,
                   acc: FileAccess,
                   composed: bool=False):
        """Assess the usability score of a FileAccess."""

        if not composed:
            # Designation accesses are considered cost-free.
            if acc.evflags & EventFileFlags.designation:
                self.incrementScore('desigAccess', f, acc.actor)
                self.updateDesignationState(f, acc)
                return DESIGNATION_ACCESS

            # Some files are allowed because they clearly belong to the app
            ownedPaths = self.generateOwnedPaths(acc.actor)
            for (path, evflags) in ownedPaths:
                if path.match(f.getName()) and \
                        acc.allowedByFlagFilter(evflags, f):
                    self.incrementScore('ownedPathAccess', f, acc.actor)
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
            if not composed:
                # We could not justify the access, increase the usabiltiy cost.
                self.incrementScore('illegalAccess', f, acc.actor)

                # If a prior interruption granted access, don't overcount.
                self.incrementScore('cumulGrantingCost', f, acc.actor)
                if not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                              appWide=self.appWideRecords()):
                    self.incrementScore('grantingCost', f, acc.actor)
                f.recordAccessCost(acc, ILLEGAL_ACCESS,
                                   appWide=self.appWideRecords())
                self.updateIllegalState(f, acc)

            return ILLEGAL_ACCESS

        # decision == POLICY_ACCESS
        else:
            if not composed:
                self.incrementScore('policyAccess', f, acc.actor)
                self.updateAllowedState(f, acc)

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

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        for pol in self.policies:
            pol.updateDesignationState(f, acc)

    def updateAllowedState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on POLICY_ACCESS."""
        for pol in self.policies:
            pol.updateAllowedState(f, acc)

    def updateIllegalState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on ILLEGAL_ACCESS."""
        for pol in self.policies:
            pol.updateIllegalState(f, acc)


class StrictCompositionalPolicy(CompositionalPolicy):
    """A policy made up of compositions of other policies.

    A policy made up of compositions of other policies. Allows an access only
    if ALL of the underlying policies would allow it, as opposed to
    CompositionalPolicy which is more permissive. Pass it a list of policy
    class names in order to instantiate it.
    """

    def __init__(self,
                 policies: list,
                 polArgs: list,
                 name: str="StrictCompositionalPolicy"):
        """Construct a StrictCompositionalPolicy."""
        super(StrictCompositionalPolicy, self).__init__(policies,
                                                        polArgs,
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


class StickyBitPolicy(Policy):
    """Policy where only accesses to files that one created are allowed."""

    def __init__(self,
                 folders: list=["/tmp"],
                 name: str='StickyBitPolicy'):
        """Construct a StickyBitPolicy."""
        super(StickyBitPolicy, self).__init__(name)

        self.created = dict()
        self.folders = list()

        home = self.userConf.getHomeDir() or "/MISSING-HOME-DIR"
        desk = self.userConf.getSetting("XdgDesktopDir") or "~/Desktop"
        user = self.userConf.getSetting("Username") or "user"
        host = self.userConf.getSetting("Hostname") or "localhost"

        for f in folders:
            f = f.replace('@XDG_DESKTOP_DIR@', desk)
            f = f.replace('@USER@', user)
            f = f.replace('@HOSTNAME@', host)
            f = f.replace('~', home)
            self.folders.append(f)

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        # Verify if the file was in one of the authorised folders.
        # Then, check if it was created, now, or previously.
        fileJustCreated = acc.isFileCreation() and self.inRightFolder(f)
        fileAmongCreated = fileJustCreated or self.wasCreatedBy(f, acc.actor)

        return (fileJustCreated, fileAmongCreated)

    def _accFunCondPolicy(self,
                          f: File,
                          acc: FileAccess,
                          composed: bool,
                          data):
        """Calculate condition for POLICY_ACCESS to be returned."""
        return data[1]

    def inRightFolder(self, f: File):
        """Check if the file is contained in one of the authorised folders."""
        folder = f.getParentName()
        for allowedFolder in self.folders:
            if folder.startswith(allowedFolder):
                return True
        return False

    def addCreatedFile(self, f: File, app: Application):
        """Record that a file was created by an app."""
        s = self.created.get(app.uid()) or set()
        s.add(f)
        self.created[app.uid()] = s

    def wasCreatedBy(self, f: File, app: Application):
        """Return True of :app: is known to have created :f:, else False."""
        return f in (self.created.get(app.uid()) or set())

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        if (data or self._accFunPreCompute(f, acc))[0]:
            self.addCreatedFile(f, acc.actor)

    def updateAllowedState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on POLICY_ACCESS."""
        self.updateDesignationState(f, acc, data)

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return (self.wasCreatedBy(f, app), 0)


class ProtectedFolderPolicy(Policy):
    """Policy where accesses in some folders are forbidden."""

    def __init__(self,
                 folders: list=["~/Protected", "~/.ssh", "~/.pki"],
                 name: str='ProtectedFolderPolicy'):
        """Construct a ProtectedFolderPolicy."""
        super(ProtectedFolderPolicy, self).__init__(name)

        self.folders = list()

        home = self.userConf.getHomeDir() or "/MISSING-HOME-DIR"
        desk = self.userConf.getSetting("XdgDesktopDir") or "~/Desktop"
        user = self.userConf.getSetting("Username") or "user"
        host = self.userConf.getSetting("Hostname") or "localhost"

        for f in folders:
            f = f.replace('@XDG_DESKTOP_DIR@', desk)
            f = f.replace('@USER@', user)
            f = f.replace('@HOSTNAME@', host)
            f = f.replace('~', home)
            self.folders.append(f)

    def inForbiddenFolder(self, f: File):
        """Return True if :f: is in a folder forbidden for this policy."""
        # Verify if the file was in one of the forbidden folders.
        # Then, check if it was created, now, or previously.
        folder = f.getParentName()
        for forbiddenFolder in self.folders:
            if folder.startswith(forbiddenFolder):
                return True
        return False

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return (not self.inForbiddenFolder(f), 0)


class FilenamePolicy(FolderPolicy):
    """Policy where files with the same filename can be accessed."""

    def __init__(self,
                 name: str='FilenamePolicy'):
        """Construct a FilenamePolicy."""
        super(FilenamePolicy, self).__init__(name)

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return f.getNameWithoutExtension()

    def allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        if self.dataInCache(self.desigCache, f.getNameWithoutExtension(), app):
            return (True, 0)
        else:
            return (False, 0)
