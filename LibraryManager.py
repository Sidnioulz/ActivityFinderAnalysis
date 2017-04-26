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
    DefaultList = ['documents', 'image', 'music', 'video']
    CompoundList = DefaultList
    CustomList = ['documents', 'image', 'music', 'video', 'downloads',
                  'scores', '3d', 'programming', 'health', 'ebooks']

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

        self.configCosts = dict()

        # Cache for application policies.
        self.appPolicyCache = dict()

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
            fD[userConf.getSetting('Xdg%sDir' % lib.capitalize())] = 0
            for d in userConf.getSetting('Extra%sDirs' % lib.capitalize(),
                                          defaultValue=[],
                                          type='string list'):
                fD[d] = 1
                confCost += 1
            self.customs[lib] = fD
        self.configCosts[LibraryManager.Custom] = confCost

        # for d in self.userConf.getSetting('RemovableMediaDirs',
        #                                   defaultValue=[],
        #                                   type='string list'):
        #     self.removableMediaLibrary[d] = 1

    def getAppPolicy(self, actor: Application):
        """Return the library capabilities policy for one Application."""
        if actor.desktopid not in self.appPolicyCache:
            policies = actor.getSetting('LibraryCaps',
                                        type='string list') or []
            self.appPolicyCache[actor.desktopid] = policies

        return self.appPolicyCache[actor.desktopid]

    def getLibraryForFile(self, f: File, libMod: int):
        """Return the name of the library a File belongs to."""
        if libMod == LibraryManager.Default:
            fileCache = self.fileCacheDefault
            libraries = self.defaults
        elif libMod == LibraryManager.Compound:
            fileCache = self.fileCacheCompound
            libraries = self.compounds
        elif libMod == LibraryManager.Custom:
            fileCache = self.fileCacheCustom
            libraries = self.customs
        else:
            raise AttributeError("Invalid library mode '%d'." % libMod)

        if f not in fileCache:
            val = None
            
            for (libName, lib) in libraries.items():
                if val:
                    break
                for (path, cost) in lib.items():
                    if(f.path.startswith(path)):
                        val = libName
                        break

            fileCache[f] = val

        return fileCache[f]

    def getAllLibraryRoots(self, libMod: int, addXdgRoots: bool=True):
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

        if addXdgRoots:
            desk = userConf.getSetting('XdgDesktopDir') or \
                '%s/Desktop' % self.userHome
            down = userConf.getSetting('XdgDownloadsDir') or \
                '%s/Downloads' % self.userHome
            medias = userConf.getSetting('RemovableMediaDirs',
                                         type='string list') or []

            rootSet = rootSet.union(*[medias, [desk, down]])

        return rootSet
