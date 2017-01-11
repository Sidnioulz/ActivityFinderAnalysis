"""Service to retrieve existing files or to create them."""

from Application import Application
from ApplicationStore import ApplicationStore
from File import File, EventFileFlags
from FileStore import FileStore
import sys


class FileFactory(object):
    """A service to retrieve existing files or to create them."""
    __file_factory = None

    @staticmethod
    def get():
        """Return the FileFactory for the entire application."""
        if not FileFactory.__file_factory:
            FileFactory.__file_factory = FileFactory(FileStore.get(),
                                                     ApplicationStore.get())
        return FileFactory.__file_factory

    @staticmethod
    def reset():
        FileFactory.__file_factory = None

    def __init__(self, fileStore: FileStore, appStore: ApplicationStore):
        """Construct a FileFactory."""
        super(FileFactory, self).__init__()
        if not fileStore:
            raise ValueError("A FileFactory must have a valid FileStore.")
        self.fileStore = fileStore
        self.appStore = appStore

    def __getFile(self, name: str, time: int, ftype: str=''):
        """Internal implementation of getFile()."""
        # Ensure the parent folder is initialised
        parentPath = File.getParentNameFromName(name)
        if parentPath:
            self.getFile(parentPath, time, ftype='inode/directory')

        files = self.fileStore.getFilesForName(name)
        prevTend = 0
        for file in files:
            tstart = file.getTimeOfStart()
            tend = file.getTimeOfEnd()

            # Current file is invalid, as it's been created after our time.
            # We must make our own file, which pre-existed. Note that since
            # events are sorted, this should never happen.
            if time < tstart:
                print("Warning: the File Factory was asked to provide File "
                      "'%s' at time '%d', but no such file existed until time "
                      "'%d'. This should not happen because Events are "
                      "supposedly sorted prior to being simulated." % (
                       name, time, tstart),
                      file=sys.stderr)
                f = File(path=name, tstart=prevTend, tend=tstart, ftype=ftype)
                f.setGuessFlags(True, True)
                self.fileStore.addFile(f)
                return file
            # Current file is valid as it has not ended yet
            elif not tend:
                return file
            # If current file has an end, ensure it is after the time we target
            # or it is equal (useful for when referring to the deletion event
            # itself).
            elif tend >= time:
                return file

            prevTend = tend
        else:
            # Make a new file starting where the last one ended, and not ending
            f = File(path=name, tstart=prevTend, tend=0, ftype=ftype)
            f.setGuessFlags(True, False)
            self.fileStore.addFile(f)
            return f

    def resolveFDRef(self, name: str, time: int):
        if not self.appStore:
            return None

        try:
            (__, fdref, appref, path) = name.split("@")
            fdref = int(fdref[6:])
            appref = appref[7:]
        except(ValueError) as e:
            print("Error: FD reference '%s' is syntactically invalid." % name,
                  file=sys.stderr)
            return None
        else:
            # print("Resolving %d ~ %s ~ %s" % (fdref, appref, path))  # FIXME

            app = self.appStore.lookupUid(appref)
            if not app:
                return None

            resolved = app.resolveFD(fdref, time)
            # print("RESOLVED: %s .. / .. %s" % (resolved, path))
            return resolved

    def getFile(self, name: str, time: int, ftype: str=''):
        """Get a File for a given name and time, or creates one.

        Looks up the FileStore for Files that match the given name and exist at
        the given time. If no File is found, one is created and added to the
        FileStore.
        """
        if name.endswith('/') and len(name) > 1:
            name = name[:-1]
            ftype = ftype if ftype else "inode/directory"

        # Check if the file's path is a reference to an unresolved FD
        resolved = self.resolveFDRef(name, time) if name.startswith("@fdref") \
            else None

        # We managed to translate the fd reference into an actual file name.
        if resolved:
            oldFile = self.getFileIfExists(name, time)

            # If the File had been stored under its ref, we must update it
            if oldFile:
                oldPath = oldFile.path
                oldFile.path = resolved
                self.fileStore.updateFile(oldFile, oldName=oldPath)
                return oldFile
            # Else we create a new File, as usual
            else:
                return self.__getFile(resolved, time, ftype)
        # The File is not a FD reference, or the reference can't be solved yet.
        else:
            return self.__getFile(name, time, ftype)

    def getFileIfExists(self, name: str, time: int):
        """Get a File for a given name and time, if it exists.

        Looks up the FileStore for Files that match the given name and exist at
        the given time. If no File is found, returns None. This function does
        not create new Files if they do not exist. Use @getFile for that.
        """
        if name.endswith('/') and len(name) > 1:
            name = name[:-1]

        files = self.fileStore.getFilesForName(name)
        for file in files:
            tstart = file.getTimeOfStart()
            tend = file.getTimeOfEnd()

            if time < tstart:
                return None
            elif not tend or tend >= time:
                return file
        else:
            return None

    def deleteFile(self,
                   file: File,
                   deleter: Application,
                   time: int,
                   evflags: EventFileFlags):
        """Delete a File for a given name and time, as well as its children.

        Deletes a File, by marking its time of end. If the File is a folder,
        the children are deleted too. This function will update the File in the
        underlying FileStore.
        """
        # Delete children if folder
        if file.isFolder():
            for child in self.fileStore.getChildren(file, time):
                self.deleteFile(child, deleter, time, evflags)

        # Record access on file
        file.addAccess(actor=deleter, flags=evflags, time=time)

        # Delete file
        file.setTimeOfEnd(time)
        self.fileStore.updateFile(file)
