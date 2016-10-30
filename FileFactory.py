"""Service to retrieve existing files or to create them."""
from Application import Application
from File import File, EventFileFlags
from FileStore import FileStore
import sys


class FileFactory(object):
    """A service to retrieve existing files or to create them."""

    store = None  # type: FileStore

    def __init__(self, fileStore: FileStore):
        """Construct a FileFactory."""
        super(FileFactory, self).__init__()
        if not fileStore:
            raise ValueError("A FileFactory must have a valid FileStore.")
        self.store = fileStore

    def getFile(self, name: str, time: int, ftype: str=''):
        """Get a File for a given name and time, or creates one.

        Looks up the FileStore for Files that match the given name and exist at
        the given time. If no File is found, one is created and added to the
        FileStore.
        """

        # Ensure the parent folder is initialised
        parentPath = File.getParentName(name)
        if parentPath:
            self.getFile(parentPath, time, ftype='inode/directory')

        files = self.store.getFilesForName(name)
        prevTend = 0
        for file in files:
            tstart = file.getTimeOfStart()
            tend = file.getTimeOfEnd()

            # Current file is invalid, as it's been created after our time.
            # We must make our own file, which pre-existed. Note that since
            # events are sorted, this should never happen.
            if time < tstart:
                print("Warning: an Event referenced a file that existed before"
                      " the first file on the heap for name '%s'. This should "
                      "not happen because Events are supposedly sorted prior "
                      "to being simulated." % name, file=sys.stderr)
                f = File(path=name, tstart=prevTend, tend=tstart, ftype=ftype)
                f.setGuessFlags(True, True)
                self.store.addFile(f)
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
            self.store.addFile(f)
            return f

    def getFileIfExists(self, name: str, time: int):
        """Get a File for a given name and time, if it exists.

        Looks up the FileStore for Files that match the given name and exist at
        the given time. If no File is found, returns None. This function does
        not create new Files if they do not exist. Use @getFile for that.
        """

        files = self.store.getFilesForName(name)
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
            for child in self.store.getChildren(file, time):
                self.deleteFile(child, deleter, time, evflags)

        # Record access on file
        file.addAccess(actor=deleter, flags=evflags, time=time)

        # Delete file
        file.setTimeOfEnd(time)
        self.store.updateFile(file)
