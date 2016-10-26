"""Service to store File instances."""
from File import File
from utils import timestampZgPrint


class FileStore(object):
    """A service to store File instances."""

    def __init__(self):
        """Construct a FileStore."""
        super(FileStore, self).__init__()
        self.clear()

    def clear(self):
        """Empty the FileStore."""
        self.nameStore = dict()   # type: dict

    def guessFileTypes(self):
        """Guess file types for files without a type, using their extension."""
        # TODO
        pass

    def printFiles(self,
                   showDeleted: bool=False,
                   showCreationTime: bool=False,
                   onlyDesignated: bool=False):
        """Print all the files currently being stored."""
        for key in sorted(self.nameStore, key=lambda s: s.lower()):
            files = self.nameStore[key]
            last = files[-1]

            printpath = last.getName()
            lastDir = printpath.rfind('/')
            if lastDir:
                printpath = (lastDir+1)*' ' + printpath[lastDir+1:]
                if last.isFolder():
                    printpath += "/"

            # Non-deleted files
            if not last.getTimeOfEnd():
                if showCreationTime and last.getTimeOfStart():
                    print("%s\tCREATED on %s" % (
                           printpath,
                           timestampZgPrint(last.getTimeOfStart())))
                else:
                    print("%s" % printpath)
            else:
                if showDeleted:
                    print("%s\tDELETED on %s)" % (
                           printpath,
                           timestampZgPrint(last.getTimeOfEnd())))

        # TODO onlyDesignated

    def getFilesForName(self, name):
        """Return all Files that have the given name as a path."""
        try:
            return self.nameStore[name]
        except(KeyError) as e:
            return []

    def updateFile(self, file: File):
        """Add a File to the FileStore."""
        filesWithName = self.getFilesForName(file.getName())

        for (index, old) in enumerate(filesWithName):
            if old.inode == file.inode:
                filesWithName[index] = file
                break
        else:
            raise ArithmeticError("Attempted to update file '%s' (made on %s)"
                                  ", but it has not yet been added to the "
                                  "store." % (file, file.getTimeOfStart()))

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
            raise ArithmeticError("Newly inserted file '%s' (made on %s) not "
                                  "last. Followed by a file made on %s." % (
                                   name, tstart, lastFile.getTimeOfEnd()))
            return
        else:
            filesWithName.append(file)
            self.nameStore[name] = filesWithName
            return

        assert False, "FileStore.addFile(): temporal inconsistency on '%s' " \
                      "(made on %s). This is due to some Events not being " \
                      "captured or some event types not being processed. " % (
                       name, tstart)

        # DEBUGGING: Get past all apps that ended before this one
        for named in filesWithName:
            if named.getTimeOfEnd() == 0:
                raise ArithmeticError("Found undeleted file for this name")
                return
            elif named.getTimeOfEnd() > tstart:
                raise ArithmeticError("Time overlap between two files on name")
                return

            if tend and tend < named.getTimeOfStart():
                raise ArithmeticError("TODO: not implemented, mid-insert")
                break

        else:
            raise ArithmeticError("I lost myself on the way...")
            pass
