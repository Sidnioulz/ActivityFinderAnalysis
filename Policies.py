"""Policy definitions."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from PolicyEngine import Policy
from FileStore import FileStore
from LibraryManager import LibraryManager
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, ILLEGAL_ACCESS, \
                      OWNED_PATH_ACCESS
import sys
import math
import re


class OneLibraryPolicy(Policy):
    """Libraries made up of a single location. One library set per app."""

    def __init__(self,
                 supportedLibraries=['documents', 'image', 'music', 'video'],
                 name: str='OneLibraryPolicy',
                 libMode: int=LibraryManager.Default):
        """Construct a OneLibraryPolicy."""
        super(OneLibraryPolicy, self).__init__(name)

        self.mgr = LibraryManager.get()
        self.libMode = libMode
        self.supportedLibraries = supportedLibraries
        self.incrementConfigCost()

    def incrementConfigCost(self):
        """Increment the configuration cost of this library policy."""
        cost = self.mgr.configCosts[self.libMode]
        if cost:
            self.incrementScore('configCost', None, None, increment=cost)

    def _allowedByPolicy(self, file: File, actor: Application):
        """Tell if a File is allowed to be accessed by a Policy."""
        policies = self.mgr.getAppPolicy(actor, libMod=self.libMode)
        lib = self.mgr.getLibraryForFile(file, libMod=self.libMode)

        if not lib:
            return False

        if lib not in self.supportedLibraries:
            return False

        if lib not in policies:
            return False

        return True

    def globalConfigCost(self):
        """Return True if the Policy has a global config cost for all apps."""
        return True


class CompoundLibraryPolicy(OneLibraryPolicy):
    """Libraries made up of compound locations. One library set per app."""

    def __init__(self,
                 supportedLibraries=LibraryManager.CompoundList,
                 name: str='CompoundLibraryPolicy'):
        """Construct a CompoundLibraryPolicy."""
        super(CompoundLibraryPolicy, self).__init__(supportedLibraries,
                                                    name,
                                                    LibraryManager.Compound)


class CustomLibraryPolicy(OneLibraryPolicy):
    """A policy with custom libraries."""

    def __init__(self,
                 supportedLibraries=LibraryManager.CustomList,
                 name: str='CustomLibraryPolicy'):
        """Construct a CustomLibraryPolicy."""
        super(CustomLibraryPolicy, self).__init__(supportedLibraries,
                                                  name,
                                                  LibraryManager.Custom)


# class RemovableMediaPolicy(OneLibraryPolicy):
#     """Grant access to removable media folders."""
# 
#     def __init__(self,
#                  name: str='OneLibraryPolicy'):
#         """Construct a OneLibraryPolicy."""
#         rm = ['removable']
#         super(OneLibraryPolicy, self).__init__(supportedLibraries=rm,
#                                                name=name)


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

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        allowedTypes = self.getAppAllowedTypes(app)

        if not allowedTypes:
            libCaps = self.getAppLibCaps(app)
            if libCaps:
                print("Warning: application '%s' with library capabilities "
                      " '%s' does not handle any MIME types. This is an "
                      "omissin from the writers of the app's .desktop file." %
                      (app.desktopid, libCaps))
            return False

        fileType = f.getType()
        if not fileType:
            dot = f.getFileName().rfind(".")
            if dot != -1 and dot > 0:
                ext = f.getFileName()[dot+1:]
                self.unsupportedExts.add(ext)

        return fileType and \
            (fileType in allowedTypes or allowedTypes[0] == "*")

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

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return False


class FolderPolicy(Policy):
    """Policy where whole folders can be accessed after a designation event."""

    def __init__(self,
                 secure: bool=False,
                 name: str='FolderPolicy'):
        """Construct a FolderPolicy."""
        super(FolderPolicy, self).__init__(name)
        self.desigCache = dict()
        self.illegalCache = dict()
        self.secure = secure

    def _computeFolder(self, f: File):
        """Return the folder used for a given file."""
        return f.getParentName()

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return self._computeFolder(f)

    def _uaccFunCondPolicy(self,
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

    def updateAllowedState(self, f: File, acc: FileAccess, data=None, strong=True):
        """Blob for policies to update their state on POLICY_ACCESS."""
        if strong or not self.secure:
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

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        folder = self._computeFolder(f)
        if self.dataInCache(self.desigCache, folder, app):
            return True
        else:
            return False


class OneFolderPolicy(FolderPolicy):
    """Policy where apps can access a single folder only."""

    def __init__(self,
                 secure: bool=False,
                 name: str='OneFolderPolicy'):
        """Construct a OneFolderPolicy."""
        super(OneFolderPolicy, self).__init__(secure, name)
        self.desigCache = dict()
        self.illegalCache = dict()

    def appHasFolderCached(self, app: Application):
        """Tell if a folder has been previously accessed by an app."""
        s = self.desigCache.get(app.desktopid if self.appWideRecords() else
                                app.uid())
        return s is not None

    def _uaccFunCondDesignation(self,
                                f: File,
                                acc: FileAccess,
                                composed: bool,
                                data):
        """Calculate condition for DESIGNATION_ACCESS to be returned."""
        return acc.isByDesignation() and not self.appHasFolderCached(acc.actor)

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Add the file's folder to the correct folder cache."""
        if not self.appHasFolderCached(acc.actor):
            if not data:
                data = self._accFunPreCompute(f, acc)
            self.addToCache(self.desigCache, data, acc.actor)

    def appsHaveMemory(self):
        """Return True if Application have a memory across instances."""
        return False


class OneDistantFolderPolicy(OneFolderPolicy):
    """Policy where apps access files in the same distant parent folders."""

    def __init__(self,
                 secure: bool=False,
                 name: str='OneDistantFolderPolicy'):
        """Construct a OneDistantFolderPolicy."""
        super(OneDistantFolderPolicy, self).__init__(secure, name)
        self.desigCache = dict()
        self.illegalCache = dict()
        self.rootCache = dict()
        self.roots = \
          LibraryManager.get().getAllLibraryRoots(libMod=LibraryManager.Custom)

    def _computeFolder(self, f: File):
        """Return the folder used for a given file."""
        parent = f.getParentName()
        if not parent:
            return f.path

        if parent not in self.rootCache:
            # Find a matching root, and calculate the largest folder we can use
            # to grant access to files based on that.
            for root in self.roots:
                if parent.startswith(root):
                    nextSlash = parent.find('/', len(root) + 1)

                    if nextSlash == -1:
                        self.rootCache[parent] = parent
                    else:
                        self.rootCache[parent] = parent[:nextSlash]

                    break

            # No root folder among ~, /media and various libraries.
            else:
                self.rootCache[parent] = parent

        return self.rootCache[parent]


class DistantFolderPolicy(FolderPolicy):
    """Policy where apps access files in the same distant parent folders."""

    def __init__(self,
                 secure: bool=False,
                 name: str='DistantFolderPolicy'):
        """Construct a DistantFolderPolicy."""
        super(DistantFolderPolicy, self).__init__(secure, name)
        self.desigCache = dict()
        self.illegalCache = dict()
        self.rootCache = dict()
        self.roots = \
          LibraryManager.get().getAllLibraryRoots(libMod=LibraryManager.Custom)

    def _computeFolder(self, f: File):
        """Return the folder used for a given file."""
        parent = f.getParentName()
        if not parent:
            return f.path

        if parent not in self.rootCache:
            # Find a matching root, and calculate the largest folder we can use
            # to grant access to files based on that.
            for root in self.roots:
                if parent.startswith(root):
                    nextSlash = parent.find('/', len(root) + 1)

                    if nextSlash == -1:
                        self.rootCache[parent] = parent
                    else:
                        self.rootCache[parent] = parent[:nextSlash]

                    break

            # No root folder among ~, /media and various libraries.
            else:
                self.rootCache[parent] = parent

        return self.rootCache[parent]


class LibraryFolderPolicy(DistantFolderPolicy):
    """Policy where apps access files in root folders of a library."""

    def __init__(self,
                 supportedLibraries=['downloads', 'desktop'],
                 secure: bool=False,
                 name: str='LibraryFolderPolicy'):
        """Construct a LibraryFolderPolicy."""
        super(LibraryFolderPolicy, self).__init__(secure, name)
        self.desigCache = dict()
        self.illegalCache = dict()
        self.rootCache = dict()
        self.roots = \
          LibraryManager.get().getLibraryRoots(supportedLibraries,
                                               libMod=LibraryManager.Custom)
        self.scope = tuple(self.roots)
        self.ftp = FileTypePolicy()

    def _computeFolder(self, f: File):
        """Return the folder used for a given file."""
        parent = f.getParentName()
        if not parent:
            return "FILETYPE"

        if parent not in self.rootCache:
            # Find a matching root, and calculate the largest folder we can use
            # to grant access to files based on that.
            for root in self.roots:
                if parent.startswith(root):
                    nextSlash = parent.find('/', len(root) + 1)

                    if nextSlash == -1:
                        self.rootCache[parent] = parent if len(parent) != \
                            len(root) else "FILETYPE"
                    else:
                        self.rootCache[parent] = parent[:nextSlash]

                    break

            # No root folder among ~, /media and various libraries.
            else:
                self.rootCache[parent] = parent

        return self.rootCache[parent]

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return self._computeFolder(f)

    def _uaccFunCondPolicy(self,
                           f: File,
                           acc: FileAccess,
                           composed: bool,
                           data):
        """Calculate condition for POLICY_ACCESS to be returned."""
        if data == "FILETYPE":
            return self.ftp._uaccFunCondPolicy(f, acc, True, data)
        else:
            return self.dataInCache(self.desigCache, data, acc.actor)

    def _accFunSimilarAccessCond(self,
                                 f: File,
                                 acc: FileAccess,
                                 composed: bool,
                                 data):
        """Calculate condition for grantingCost to be incremented."""
        if data == "FILETYPE":
            return self.ftp._accFunSimilarAccessCond(f, acc, True, data)
        else:
            return not self.dataInCache(self.illegalCache, data, acc.actor) \
                and not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                               appWide=self.appWideRecords())

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        if not data:
            data = self._accFunPreCompute(f, acc)
        if data == "FILETYPE":
            self.ftp.updateDesignationState(f, acc, data)
        else:
            self.addToCache(self.desigCache, data, acc.actor)

    def updateAllowedState(self, f: File, acc: FileAccess, data=None, strong=True):
        """Blob for policies to update their state on POLICY_ACCESS."""
        self.updateDesignationState(f, acc, data)

    def updateIllegalState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on ILLEGAL_ACCESS."""
        if not data:
            data = self._accFunPreCompute(f, acc)
        if data == "FILETYPE":
            self.ftp.updateIllegalState(f, acc, data)
        else:
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

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        folder = self._computeFolder(f)
        if folder == "FILETYPE":
            return self.ftp._allowedByPolicy(f, app)
        else:
            if self.dataInCache(self.desigCache, folder, app):
                return True
            else:
                return False


class ProjectsPolicy(FolderPolicy):
    """Policy where apps access files in the same project folders."""

    def __init__(self,
                 secure: bool=False,
                 name: str='ProjectsPolicy'):
        """Construct a ProjectsPolicy."""
        super(ProjectsPolicy, self).__init__(secure, name)
        self.desigCache = dict()
        self.illegalCache = dict()
        self.projectsCache = dict()
        self.projects = self.userConf.getProjects()

        self.projectNames = dict()
        for proj in self.projects:
            projName = '|'.join(proj)
            for path in proj:
                self.projectNames[path] = projName

    def _computeFolder(self, f: File):
        """Return the folder used for a given file."""
        parent = f.getParentName()
        if not parent:
            return None

        if parent not in self.projectsCache:
            found = False
            # Find a matching project.
            for proj in self.projects:
                for path in proj:
                    if parent.startswith(path):
                        self.projectsCache[parent] = self.projectNames[path]
                        found = True
                        break
                if found:
                    break

            # No matching project.
            else:
                self.projectsCache[parent] = None

        return self.projectsCache[parent]


class FutureAccessListPolicy(FolderPolicy):
    """Policy where files can be accessed by future instances indefinitely."""

    def __init__(self,
                 name: str='FutureAccessListPolicy'):
        """Construct a FutureAccessListPolicy."""
        super(FutureAccessListPolicy, self).__init__(secure=False, name=name)

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return f.inode

    def getLastAccessDecisionStrength(self):
        """Tell if last access decision is valid enough for Folder policies."""
        return False

    def appWideRecords(self):
        """Return True if access records are across instances, False else."""
        return True

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        if self.dataInCache(self.desigCache, f.inode, app):
            return True
        else:
            return False


class UnsecurePolicy(Policy):
    """Policy where every access is allowed, apps are basically unsandboxed."""

    def __init__(self,
                 name: str='UnsecurePolicy'):
        """Construct an UnsecurePolicy."""
        super(UnsecurePolicy, self).__init__(name)

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return True


class RestrictedAppsPolicy(Policy):
    """Policy where some apps cannot access files other than by designation."""

    def __init__(self,
                 name: str='RestrictedAppsPolicy',
                 apps: list=[]):
        """Construct a RestrictedAppsPolicy."""
        super(RestrictedAppsPolicy, self).__init__(name)
        self.apps = apps

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return app.desktopid not in self.apps


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

        self.lastAccessDecisionStrong = False
        super(CompositionalPolicy, self).__init__(cname)

    def getLastAccessDecisionStrength(self):
        """Tell if last access decision is valid enough for Folder policies."""
        return self.lastAccessDecisionStrong

    def accessFunc(self,
                   engine: 'PolicyEngine',
                   f: File,
                   acc: FileAccess,
                   composed: bool=False,
                   dbgPrint: bool=False):
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
        self.lastAccessDecisionStrong = False
        decision = None
        for pol in self.policies:
            polStrong = pol.getLastAccessDecisionStrength()

            # We are still looking for a final decision.
            if not decision:
                # Check for a final decision.
                polDecision = pol.accessFunc(engine, f, acc, composed=True)
                decision = self._selectAccessFuncDecision(polDecision)

                # We have found a strong decision, we can leave the loop.
                if decision and polStrong:
                    self.lastAccessDecisionStrong = True
                    break

                # A conclusive decision was taken, but it's not strong (i.e. it
                # comes from policies which, combined with some contextual
                # policies like FolderPolicy, introduce structural insecurity).
                # We continue looking for a decision that is strong, though we
                # already have a final decision for the policy.
                elif decision and not polStrong:
                    pass

            # We have a final decision, but we need a strong policy to confirm
            # it in order to say the policy decision we made is strong. If the
            # current policy is also weak, it is not worth wasting CPU time
            # computing a decision for it, so we jump to the next one.
            elif decision and polStrong:
                polDecision = pol.accessFunc(engine, f, acc, composed=True)
                if polDecision == decision:
                    self.lastAccessDecisionStrong = True
                    break

        # If all policies return the inconclusive decision (illegal for this
        # policy, legal for the strict policy), then we return that decision.
        else:
            # If there was a decision made and we reach this point, it means
            # the decision was not strong. In that case, we do nothing, we just
            # have a weak decision. Else, we use the default decision and we
            # state the decision is strong since all policies agree on it.
            if not decision:
                decision = self._returnDefaultAccessFuncDecision(f, acc)
                self.lastAccessDecisionStrong = True

        # Now, we update scores and return the decision.
        if decision == ILLEGAL_ACCESS:
            if not composed:
                # We could not justify the access, increase the usabiltiy cost.
                self.incrementScore('illegalAccess', f, acc.actor)

                # If a prior interruption granted access, don't overcount.
                self.incrementScore('cumulGrantingCost', f, acc.actor)
                if self._accFunSimilarAccessCond(f, acc, composed, None):
                    self.incrementScore('grantingCost', f, acc.actor)
                f.recordAccessCost(acc, ILLEGAL_ACCESS,
                                   appWide=self.appWideRecords())
                self.updateIllegalState(f, acc)

            return ILLEGAL_ACCESS

        # decision == POLICY_ACCESS
        else:
            if not composed:
                self.incrementScore('policyAccess', f, acc.actor)
                self.updateAllowedState(f,
                                        acc,
                                        data=None,
                                        strong=self.getLastAccessDecisionStrength())

            return POLICY_ACCESS

    def _accFunSimilarAccessCond(self,
                                 f: File,
                                 acc: FileAccess,
                                 composed: bool,
                                 data):
        """Calculate condition for grantingCost to be incremented."""
        for pol in self.policies:
            data = pol._accFunPreCompute(f, acc)
            if not pol._accFunSimilarAccessCond(f, acc, composed, data):
                return False

        return True

    def _returnDefaultAccessFuncDecision(self, f: File, acc: FileAccess):
        """Return the default decision for this compositional policy."""
        return ILLEGAL_ACCESS

    def _selectAccessFuncDecision(self, decision: int):
        """Choose if a sub-policy's accessFunc output should be selected."""
        if decision in (DESIGNATION_ACCESS, OWNED_PATH_ACCESS, POLICY_ACCESS):
            return decision
        else:
            return None

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        for policy in self.policies:
            if policy.allowedByPolicy(f, app):
                return True

        return False

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        for pol in self.policies:
            pol.updateDesignationState(f, acc)

    def updateAllowedState(self, f: File, acc: FileAccess, data=None, strong=True):
        """Blob for policies to update their state on POLICY_ACCESS."""
        for pol in self.policies:
            pol.updateAllowedState(f, acc, data=None, strong=strong)

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

    def _returnDefaultAccessFuncDecision(self, f: File, acc: FileAccess):
        """Return the default decision for this compositional policy."""
        return POLICY_ACCESS

    def _selectAccessFuncDecision(self, decision: int):
        """Choose if a sub-policy's accessFunc output should be selected."""
        if decision in (DESIGNATION_ACCESS, OWNED_PATH_ACCESS, ILLEGAL_ACCESS):
            return decision
        else:
            return None

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        for policy in self.policies:
            if not policy.allowedByPolicy(f, app):
                return False

        return True


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
        down = self.userConf.getSetting("XdgDownloadsDir") or "~/Downloads"
        user = self.userConf.getSetting("Username") or "user"
        host = self.userConf.getSetting("Hostname") or "localhost"

        for f in folders:
            f = f.replace('@XDG_DESKTOP_DIR@', desk)
            f = f.replace('@XDG_DOWNLOADS_DIR@', down)
            f = f.replace('@USER@', user)
            f = f.replace('@HOSTNAME@', host)
            f = f.replace('~', home)
            self.folders.append(f)

    def getLastAccessDecisionStrength(self):
        """Tell if last access decision is valid enough for Folder policies."""
        return False

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        # Verify if the file was in one of the authorised folders.
        # Then, check if it was created, now, or previously.
        fileJustCreated = acc.isFileCreation() and self.inRightFolder(f)
        fileAmongCreated = fileJustCreated or self.wasCreatedBy(f, acc.actor)

        return (fileJustCreated, fileAmongCreated)

    def _uaccFunCondPolicy(self,
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

    def updateAllowedState(self, f: File, acc: FileAccess, data=None, strong=True):
        """Blob for policies to update their state on POLICY_ACCESS."""
        self.updateDesignationState(f, acc, data)

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return self.wasCreatedBy(f, app)


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
        down = self.userConf.getSetting("XdgDownloadsDir") or "~/Downloads"
        user = self.userConf.getSetting("Username") or "user"
        host = self.userConf.getSetting("Hostname") or "localhost"

        for f in folders:
            f = f.replace('@XDG_DESKTOP_DIR@', desk)
            f = f.replace('@XDG_DOWNLOADS_DIR@', down)
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

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        return not self.inForbiddenFolder(f)


class FilenamePolicy(FolderPolicy):
    """Policy where files with the same filename can be accessed."""

    def __init__(self,
                 secure: bool=False,
                 name: str='FilenamePolicy'):
        """Construct a FilenamePolicy."""
        super(FilenamePolicy, self).__init__(secure, name)

    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return f.getNameWithoutExtension()

    def _allowedByPolicy(self, f: File, app: Application):
        """Tell if a File can be accessed by an Application."""
        if self.dataInCache(self.desigCache, f.getNameWithoutExtension(), app):
            return True
        else:
            return False


class DocumentsFileTypePolicy(StrictCompositionalPolicy):
    """Windows 8 Policy bit - DocumentsLibrary + FileType."""

    def __init__(self,
                 supportedLibraries: list=["documents"],
                 name: str='DocumentsFileTypePolicy'):
        """Construct a DocumentsFileTypePolicy."""
        policies = [OneLibraryPolicy, FileTypePolicy]
        polArgs = [dict(supportedLibraries=supportedLibraries), None]
        super(DocumentsFileTypePolicy, self).__init__(policies, polArgs, name)


class Win8Policy(CompositionalPolicy):
    """Windows 8 Policy."""

    def __init__(self,
                 name: str='Win8Policy'):
        """Construct a Win8Policy."""
        policies = [OneLibraryPolicy,
                    DocumentsFileTypePolicy,
                    FutureAccessListPolicy]
        polArgs = [dict(supportedLibraries=["music", "image", "video"]),
                   None,
                   None]
        super(Win8Policy, self).__init__(policies, polArgs, name)


class Win10Policy(CompositionalPolicy):
    """Windows 10 Policy."""

    def __init__(self,
                 name: str='Win10Policy'):
        """Construct a Win10Policy."""
        policies = [CompoundLibraryPolicy,
                    DocumentsFileTypePolicy,
                    StickyBitPolicy,
                    FutureAccessListPolicy]
        polArgs = [dict(supportedLibraries=["music", "image", "video"]),
                   dict(supportedLibraries=["documents", "removable"]),
                   dict(folders=["@XDG_DOWNLOADS_DIR@", "/tmp"]),
                   None]
        super(Win10Policy, self).__init__(policies, polArgs, name)


class FolderFilenamePolicy(CompositionalPolicy):
    """Folder v Filename."""

    def __init__(self,
                 secure: bool=False,
                 name: str='FolderFilenamePolicy'):
        """Construct a FolderFilenamePolicy."""
        policies = [FolderPolicy, FilenamePolicy]
        polArgs = [dict(secure=secure), None]
        super(FolderFilenamePolicy, self).__init__(policies, polArgs, name)


class FolderRestrictedAppsPolicy(StrictCompositionalPolicy):
    """Folder v RestrictedAppsPolicy."""

    def __init__(self,
                 secure: bool=False,
                 name: str='FolderRestrictedAppsPolicy'):
        """Construct a FolderRestrictedAppsPolicy."""
        policies = [FolderPolicy, RestrictedAppsPolicy]
        polArgs = [dict(secure=secure),
                   dict(apps=["telegram", "android", "ruby", "eclipse",
                              "python", "cargo", "dropbox", "wine", "skype"]),]
        super(FolderRestrictedAppsPolicy, self).__init__(policies, polArgs, name)


class ExclusionPolicy(Policy):
    """Policy that prevents reading files from multiple locations."""

    def __init__(self,
                 exclusionList: list,
                 excludeOutsideLists: bool=False,
                 countConfigCosts: bool=True,
                 name: str='ExclusionPolicy'):
        """Construct a ExclusionPolicy."""
        super(ExclusionPolicy, self).__init__(name)
        self.excludeOutsideLists = excludeOutsideLists
        self.currentPath = dict()
        self.matchCache = dict()
        self.illegalCache = dict()

        self.exclusionList = []
        self.exclusionREs = dict()
        self.cost = 0
        self.exclusionList = exclusionList
        for path in exclusionList:
            if countConfigCosts:
                self.cost += 1
            self.exclusionREs[path] = re.compile(path)

    def _match(self, f: File):
        """Precompute a data structure about the file."""
        matched = None

        if f not in self.matchCache:
            for path in self.exclusionList:
                pattern = self.exclusionREs[path]
                res = pattern.match(f.path)
                matched = res.group(0) if res else None
                if matched:
                    self.matchCache[f] = path
                    break
            else:
                self.matchCache[f] = []  # Differentiate from None.

        return self.matchCache[f]


    def _accFunPreCompute(self,
                          f: File,
                          acc: FileAccess):
        """Precompute a data structure about the file or access."""
        return self._match(f)

    def _uaccFunCondDesignation(self,
                                f: File,
                                acc: FileAccess,
                                composed: bool,
                                data):
        """Calculate condition for DESIGNATION_ACCESS to be returned."""
        if not acc.evflags & EventFileFlags.designation:
            return False

        key = acc.actor.desktopid if self.appWideRecords() else acc.actor.uid()
        data = data or self._match(f)

        if key in self.currentPath:
            if not self.excludeOutsideLists and data == []:
                return True
            else:
                return data == self.currentPath[key]
        else:
            return data != [] or not self.excludeOutsideLists

    def _allowedByPolicy(self, file: File, actor: Application):
        """Tell if a File is allowed to be accessed by a Policy."""
        data = self._match(file)
        key = actor.desktopid if self.appWideRecords() else actor.uid()

        # The list is not set yet.
        if key not in self.currentPath:
            return data != [] or not self.excludeOutsideLists
        # If there is a list, our file must belong to no other list.
        else:
            return data == self.currentPath[key] or \
                (data == [] and not self.excludeOutsideLists)

    def updateDesignationState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on DESIGNATION_ACCESS."""
        if data is None:
            data = self._match(f)

        key = acc.actor.desktopid if self.appWideRecords() else acc.actor.uid()
        if key not in self.currentPath and data:
            self.currentPath[key] = data

    def updateAllowedState(self, f: File, acc: FileAccess, data=None, strong=True):
        """Blob for policies to update their state on POLICY_ACCESS."""
        self.updateDesignationState(f, acc, data)

    def updateIllegalState(self, f: File, acc: FileAccess, data=None):
        """Blob for policies to update their state on ILLEGAL_ACCESS."""
        if not data:
            data = self._accFunPreCompute(f, acc)
        self.addToCache(data, acc.actor)

    def dataInCache(self, data: str, app: Application):
        """Tell if data has been previously accessed by an app."""
        if data is None:
            return False
        key = app.desktopid if self.appWideRecords() else app.uid()
        s = self.illegalCache.get(key)
        return data in s if s else False

    def _accFunSimilarAccessCond(self,
                                 f: File,
                                 acc: FileAccess,
                                 composed: bool,
                                 data):
        """Calculate condition for grantingCost to be incremented."""
        return not self.dataInCache(data, acc.actor) and \
            not f.hadPastSimilarAccess(acc, ILLEGAL_ACCESS,
                                       appWide=self.appWideRecords())

    def addToCache(self, data: str, app: Application):
        """Record that data has been previously accessed by an app."""
        if not data:
            return
        key = app.desktopid if self.appWideRecords() else app.uid()
        s = self.illegalCache.get(key) or set()
        s.add(data)
        self.illegalCache[key] = s


class RemovableMediaPolicy(ExclusionPolicy):
    """Policy that prevents reading files from multiple locations."""

    def __init__(self,
                 name: str='RemovableMediaPolicy'):
        """Construct a RemovableMediaPolicy."""
        fs = FileStore.get()
        mgr = LibraryManager.get()

        exclusionList = []

        mediaLib = mgr.getRemovableMediaDir(LibraryManager.Default)
        mediaPath = list(mediaLib.keys())[0] + '/'
        children = fs.getChildrenFromPath(mediaPath, -1)
        for child in children:
            exclusionList.append('^%s' % re.escape(child.path))
        exclusionList.append("^/.*")

        super(RemovableMediaPolicy, self).__init__(name=name,
                                                   exclusionList=exclusionList,
                                                   excludeOutsideLists=True,
                                                   countConfigCosts=False)


class BlackListPolicy(CustomLibraryPolicy):
    """Policy that blacklists some libraries."""

    def __init__(self,
                 supportedLibraries=LibraryManager.CustomList,
                 name: str='BlackListPolicy'):
        """Construct a BlackListPolicy."""
        super(BlackListPolicy, self).__init__(supportedLibraries, name)

    def _allowedByPolicy(self, file: File, actor: Application):
        """Tell if a File is allowed to be accessed by a Policy."""
        lib = self.mgr.getLibraryForFile(file, libMod=self.libMode)

        if not lib:
            return True

        if lib not in self.supportedLibraries:
            return True

        return False


class BlackListOneDistantFolderPolicy(StrictCompositionalPolicy):
    """OneDistantFolder applied to a subset of files (excludes libraries)."""

    def __init__(self,
                 supportedLibraries: list=["desktop"],
                 secure: bool=False,
                 name: str='BlackListOneDistantFolderPolicy'):
        """Construct a BlackListOneDistantFolderPolicy."""
        policies = [BlackListPolicy,
                    OneDistantFolderPolicy]
        polArgs = [dict(supportedLibraries=supportedLibraries),
                   dict(secure=secure)]
        super(BlackListOneDistantFolderPolicy, self).__init__(policies,
                                                              polArgs,
                                                              name)

class HSecurePolicy(CompositionalPolicy):
    """Secure hypothesis based on per-lib analysis of base policies."""

    def __init__(self,
                 name: str='HSecurePolicy'):
        """Construct a HSecurePolicy."""
        policies = [CustomLibraryPolicy,
                    DesignationPolicy]
        polArgs = [dict(supportedLibraries=["documents", "music",
                                            "image", "programming"]),
                   None]
        super(HSecurePolicy, self).__init__(policies, polArgs, name)


class HBalancedPolicy(CompositionalPolicy):
    """Balanced hypothesis based on per-lib analysis of base policies."""

    def __init__(self,
                 secure: bool=False,
                 name: str='HBalancedPolicy'):
        """Construct a HBalancedPolicy."""
        policies = [CustomLibraryPolicy,
                    FileTypePolicy,
                    BlackListOneDistantFolderPolicy]
        polArgs = [dict(supportedLibraries=["video", "music", "image"]),
                   None,
                   dict(secure=secure),]
        super(HBalancedPolicy, self).__init__(policies, polArgs, name)
        self.policies[1].scope = tuple(LibraryManager.get().getLibraryRoots(
            ["removable"], libMod=LibraryManager.Custom))
        self.policies[1].unscopedDefAllowed = False


class HBalancedSecuredPolicy(HBalancedPolicy):

    def __init__(self,
                 name: str='HBalancedSecuredPolicy'):
        """Construct a HBalancedSecuredPolicy."""
        super(HBalancedSecuredPolicy, self).__init__(secure=True, name=name)


class HUsableSecuredPolicy(OneDistantFolderPolicy):

    def __init__(self,
                 name: str='HUsableSecuredPolicy'):
        """Construct a HUsableSecuredPolicy."""
        super(HUsableSecuredPolicy, self).__init__(secure=True, name=name)


class FolderSecuredPolicy(FolderPolicy):

    def __init__(self,
                 name: str='FolderSecuredPolicy'):
        """Construct a FolderSecuredPolicy."""
        super(FolderSecuredPolicy, self).__init__(secure=True, name=name)


class OneFolderSecuredPolicy(OneFolderPolicy):

    def __init__(self,
                 name: str='OneFolderSecuredPolicy'):
        """Construct a OneFolderSecuredPolicy."""
        super(OneFolderSecuredPolicy, self).__init__(secure=True, name=name)


class DistantFolderSecuredPolicy(DistantFolderPolicy):

    def __init__(self,
                 name: str='DistantFolderSecuredPolicy'):
        """Construct a DistantFolderSecuredPolicy."""
        super(DistantFolderSecuredPolicy, self).__init__(secure=True, name=name)


class OneDistantFolderSecuredPolicy(OneDistantFolderPolicy):

    def __init__(self,
                 name: str='OneDistantFolderSecuredPolicy'):
        """Construct a OneDistantFolderSecuredPolicy."""
        super(OneDistantFolderSecuredPolicy, self).__init__(secure=True, name=name)
