"""Service to store File instances."""
from File import File


class FileStore(object):
    """A service to store File instances."""

    def __init__(self):
        """Construct a FileStore."""
        super(FileStore, self).__init__()
        self.clear()

    def clear(self):
        """Empty the FileStore."""
        self.nameStore = dict()   # type: dict

    def getFilesForName(self, name):
        """Return all Files that have the given name as a path."""
        try:
            return self.nameStore['name']
        except(KeyError) as e:
            return []

    def updateFile(self, file: File):
        """Add a File to the FileStore."""
        filesWithName = self.getFilesForName(file.getName())

        # Empty case
        for (index, old) in enumerate(filesWithName):
            if old.inode == file.inode:
                filesWithName[index] = file
                break
        else:
            # TODO error
            raise ArithmeticError("Updated a file that isn't present yet.")

    def addFile(self, file: File):
        """Add a File to the FileStore."""
        name = file.getName()
        tstart = file.getTimeOfStart()
        tend = file.getTimeOfEnd()

        filesWithName = self.getFilesForName(name)

        # Empty case
        if len(filesWithName) == 0:
            self.nameStore[name] = [file]
            return

        # We must be the last for this name as the data must be sorted
        lastFile = filesWithName[-1]
        if lastFile.getTimeOfEnd() > tstart:
            # TODO error
            raise ArithmeticError("Newly inserted file not last")
            return
        else:
            filesWithName.append(file)
            self.nameStore[name] = filesWithName
            return

        # DEBUGGING: Get past all apps that ended before this one
        for named in filesWithName:
            if named.getTimeOfEnd() == 0:
                raise ArithmeticError("Found undeleted file for this name")
                # TODO error
                return
            elif named.getTimeOfEnd() > tstart:
                raise ArithmeticError("Time overlap between two files on name")
                # TODO error
                return

            if tend and tend < named.getTimeOfStart():
                raise ArithmeticError("TODO: not implemented, mid-insert")
                # TODO insert before named
                break

        else:
            raise ArithmeticError("I lost myself on the way...")
            # TODO error why are we here!?
            pass
