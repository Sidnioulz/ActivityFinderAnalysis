"""A cache for lists of files that can be accessed by apps for a policy."""
from File import File, FileAccess, EventFileFlags
from FileStore import FileStore
from FileFactory import FileFactory
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from utils import debugEnabled, hasIntersection


class AccessListCache(object):
    """A cache for lists of files that can be accessed by apps for a policy."""
    __list_cache = None

    @staticmethod
    def get():
        """Return the AccessListCache for the entire application."""
        if AccessListCache.__list_cache is None:
            AccessListCache.__list_cache = AccessListCache()
        return AccessListCache.__list_cache

    @staticmethod
    def reset():
        AccessListCache.__list_cache = None

    def __init__(self):
        """Construct a AccessListCache."""
        super(AccessListCache, self).__init__()
        self.cache = dict()
        self.userHome = UserConfigLoader.get().getHomeDir()

    def getLinkList(self):
        """Get a list of links between files."""
        if not "fileLinks" in self.cache:
            links = FileFactory.get().getFileLinks()
            fileStore = FileStore.get()
            accessListsLinks = list()

            for (pred, follow) in links.items():
                predFile = fileStore.getFile(pred.inode)
                followFile = fileStore.getFile(follow)
                pair = set()
                pair.add(predFile)
                pair.add(followFile)
                accessListsLinks.append(pair)

            self.cache["fileLinks"] = accessListsLinks
        
        return self.cache["fileLinks"]

    def getAccessList(self,
                      name: str=None,
                      allowedFn=lambda *x, **xx: True,
                      accessAllowedFn=lambda *x, **xx: False):
        """Build access list for a given allowed function and name."""
        if not name in self.cache:
            fileStore = FileStore.get()
            accessListsInst = dict()

            for f in fileStore:
                # Ignore folders without accesses (auto-created by factory).
                if f.isFolder() and not f.hasAccesses():
                    continue

                # Only take user documents.
                # if not f.isUserDocument(userHome=self.userHome,
                #                         allowHiddenFiles=True):
                #     continue

                for acc in f.getAccesses():
                    if not acc.actor.isUserlandApp():
                        continue

                    if allowedFn(f, acc.actor) or accessAllowedFn(f, acc):
                        l = accessListsInst.get(acc.actor.uid()) or set()
                        l.add((f, acc))
                        accessListsInst[acc.actor.uid()] = l

            self.cache[name] = accessListsInst

        return self.cache[name]

    def getAccessListFromPolicy(self, pol):
        """Build access list for a given Policy."""
        return self.getAccessList(pol.name,
                                  pol.allowedByPolicy, 
                                  pol.accessAllowedByPolicy)
