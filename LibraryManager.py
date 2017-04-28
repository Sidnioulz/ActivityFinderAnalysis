"""Load libraries and verify if Files are part of libraries."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from UserConfigLoader import UserConfigLoader
import sys
import math


class LibraryManager(object):
    """Load libraries and verify if Files are part of libraries."""

    """A service to store File instances."""
    __lib_mgr = None

    # Lists of libraries supported in each library mode.
    DefaultList = ['documents', 'image', 'music', 'video', 'removable']
    CompoundList = DefaultList
    CustomList = ['documents', 'image', 'music', 'video', 'removable',
                  'downloads', 'desktop', 'programming', 'ebooks', 'scores']

    # Supported library modes.
    Default = 0
    Compound = 1
    Custom = 2

    @staticmethod
    def get():
        """Return the LibraryManager for the entire application."""
        if LibraryManager.__lib_mgr is None:
            LibraryManager.__lib_mgr = LibraryManager()
        return LibraryManager.__lib_mgr

    @staticmethod
    def reset():
        LibraryManager.__lib_mgr = None

    def __init__(self):
        """Construct a LibraryManager."""
        super(LibraryManager, self).__init__()
        self.initDefaults()

    def initDefaults(self):
        """Initialise folder lists for all 3 library configurations."""
        # Caches for library locations.
        self.defaults = dict()
        self.compounds = dict()
        self.customs = dict()

        # Roots of all libraries, reverse-sorted by length.
        self.defaultRoots = list()
        self.compoundRoots = list()
        self.customRoots = list()

        # Map of paths to library names, to use with sorted root lists.
        self.defaultMap = dict()
        self.compoundMap = dict()
        self.customMap = dict()

        self.configCosts = dict()

        # Cache for application policies.
        self.appPolicyCache = dict()
        appPolicyCacheCustom = dict()

        # Cache for files.
        self.fileCacheDefault = dict()
        self.fileCacheCompound = dict()
        self.fileCacheCustom = dict()

        # Loading default libraries.
        userConf = UserConfigLoader.get()
        self.userHome = userConf.getHomeDir()
        for lib in LibraryManager.DefaultList:
            fD = dict()
            fD[userConf.getSetting('Xdg%sDir' % lib.capitalize())] = 0
            self.defaults[lib] = fD
        self.configCosts[LibraryManager.Default] = 0
            
        # Loading compound libraries.
        confCost = 0
        for lib in LibraryManager.CompoundList:
            fD = dict()
            fD[userConf.getSetting('Xdg%sDir' % lib.capitalize())] = 0
            for d in userConf.getSetting('Extra%sDirs' % lib.capitalize(),
                                          defaultValue=[],
                                          type='string list'):
                fD[d] = 1
                confCost += 1
            self.compounds[lib] = fD
        self.configCosts[LibraryManager.Compound] = confCost

        # Loading custom libraries.
        confCost = 0
        for lib in LibraryManager.CustomList:
            fD = dict()

            defaultKey = userConf.getSetting('Xdg%sDir' % lib.capitalize())
            if defaultKey:
              fD[defaultKey] = 0

            for d in userConf.getSetting('Extra%sDirs' % lib.capitalize(),
                                          defaultValue=[],
                                          type='string list'):
                fD[d] = 1
                confCost += 1

            if fD:
                self.customs[lib] = fD
        self.configCosts[LibraryManager.Custom] = confCost

        self.defaultRoots = self.getAllLibraryRoots(LibraryManager.Default,
                                                    addXdgRoots=False,
                                                    mapToFill=self.defaultMap)
        self.compoundRoots = self.getAllLibraryRoots(LibraryManager.Compound,
                                                    addXdgRoots=False,
                                                    mapToFill=self.compoundMap)
        self.customRoots = self.getAllLibraryRoots(LibraryManager.Custom,
                                                    addXdgRoots=False,
                                                    mapToFill=self.customMap)

    def getAppPolicy(self, actor: Application, libMod: int):
        """Return the library capabilities policy for one Application."""
        if libMod == LibraryManager.Custom:
            if actor.desktopid not in self.appPolicyCacheCustom:
                policies = actor.getSetting('LibraryCapsCustom',
                                            type='string list') or \
                    self.getAppPolicy(actor, LibraryManager.Default)

                self.appPolicyCacheCustom[actor.desktopid] = policies

            return self.appPolicyCacheCustom[actor.desktopid]

        else:
            if actor.desktopid not in self.appPolicyCache:
                policies = actor.getSetting('LibraryCaps',
                                            type='string list') or []

                self.appPolicyCache[actor.desktopid] = policies

            return self.appPolicyCache[actor.desktopid]

    def getLibraryForFile(self, f: File, libMod: int):
        """Return the name of the library a File belongs to."""
        if libMod == LibraryManager.Default:
            fileCache = self.fileCacheDefault
            roots = self.defaultRoots
            libMap = self.defaultMap
        elif libMod == LibraryManager.Compound:
            fileCache = self.fileCacheCompound
            roots = self.compoundRoots
            libMap = self.compoundMap
        elif libMod == LibraryManager.Custom:
            fileCache = self.fileCacheCustom
            roots = self.customRoots
            libMap = self.customMap
        else:
            raise AttributeError("Invalid library mode '%d'." % libMod)

        if f not in fileCache:
            val = None
            
            for path in roots:
                if(f.path.startswith(path)):
                    val = libMap[path]
                    break

            # Non-library file, distinguish user documents.
            if not val:
              if f.isUserDocument(userHome=self.userHome,
                                  allowHiddenFiles=True):
                val = "UnclassifiedUserDocument"
              else:
                val = "Unclassified"
            fileCache[f] = val

        return fileCache[f]

    def getRemovableMediaDir(self, libMod: int):
        """Return the root directory for the user's removable media."""
        if libMod == LibraryManager.Default:
            libraries = self.defaults
        elif libMod == LibraryManager.Compound:
            libraries = self.compounds
        elif libMod == LibraryManager.Custom:
            libraries = self.customs
        else:
            raise AttributeError("Invalid library mode '%d'." % libMod)

        return libraries['removable']

    def getAllLibraryRoots(self, libMod: int,
                           addXdgRoots: bool=True,
                           mapToFill: dict=None):
        """Return all the root folders for libraries, and for XDG folders."""
        if libMod == LibraryManager.Default:
            libraries = self.defaults
        elif libMod == LibraryManager.Compound:
            libraries = self.compounds
        elif libMod == LibraryManager.Custom:
            libraries = self.customs
        else:
            raise AttributeError("Invalid library mode '%d'." % libMod)

        userConf = UserConfigLoader.get()
        rootSet = set()

        for (libName, lib) in libraries.items():
            for (path, cost) in lib.items():
                rootSet.add(path)
                if mapToFill is not None:
                    mapToFill[path] = libName

        if addXdgRoots:
            desk = userConf.getSetting('XdgDesktopDir') or \
                '%s/Desktop' % self.userHome
            down = userConf.getSetting('XdgDownloadsDir') or \
                '%s/Downloads' % self.userHome
            cfg = '%s/.config' % self.userHome
            cache = '%s/.cache' % self.userHome
            data = '%s/.local/share' % self.userHome

            rootSet = rootSet.union([desk, down, self.userHome,
                                      cfg, cache, data])

        rootList = list(rootSet)
        rootList.sort(key=len, reverse=True)
        return rootList
