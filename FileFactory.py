"""Service to retrieve existing files or to create them."""
from File import File
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

    def getFile(self, name, time):
        """Get a File for a given name and time, or creates one.

        Looks up the FileStore for Files that match the given name and exist at
        the given time. If no File is found, one is created and added to the
        FileStore.
        """

        # TODO: transparently generate parents when making a new File
        # This will help with dealing with folders that are created in the
        # toolkit.

        files = self.store.getFilesForName(name)
        prevTend = 0
        for file in files:
            tstart = file.getTimeOfStart()
            tend = file.getTimeOfEnd()

            # Current file is invalid, as it's been created after our time
            if time < tstart:
                print("Warning: an Event referenced a file that existed before"
                      " the first file on the heap for name '%s'. This should "
                      "not happen because Events are supposedly sorted prior "
                      "to being simulated." % name, file=sys.stderr)
                f = File(path=name, tstart=prevTend, tend=tstart)
                f.setGuessFlags(True, True)
                self.store.addFile(f)
                return file
            # Current file is valid as it has not ended yet
            elif not tend:
                return file
            # If current file has an end, ensure it is after the time we target
            elif tend > time:
                return file

            prevTend = tend
        else:
            f = File(path=name, tstart=prevTend, tend=0)
            f.setGuessFlags(True, False)
            self.store.addFile(f)
            return f
