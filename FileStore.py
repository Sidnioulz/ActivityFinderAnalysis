"""Service to store File instances."""
from File import File, EventFileFlags
from utils import time2Str


class FileStore(object):
    """A service to store File instances."""
    __file_store = None

    @staticmethod
    def get():
        """Return the FileStore for the entire application."""
        if not FileStore.__file_store:
            FileStore.__file_store = FileStore()
        return FileStore.__file_store

    @staticmethod
    def reset():
        FileStore.__file_store = None

    def __init__(self):
        """Construct a FileStore."""
        super(FileStore, self).__init__()
        self.clear()

    def __iter__(self):
        for name in sorted(self.nameStore):
            for f in self.nameStore[name]:
                yield f

    def clear(self):
        """Empty the FileStore."""
        self.nameStore = dict()   # type: dict

    def guessFileTypes(self):
        """Guess file types for files without a type, using their extension."""
        # TODO
        pass

    def getChildren(self, f: File, time: int):
        parent = f.getName() + '/'
        children = []
        for item in [k for k in self.nameStore.items()
                     if k[0].startswith(parent)]:
            # Only direct children
            if item[0][len(parent)+1:].find('/') == -1:
                    for file in item[1]:
                        tstart = file.getTimeOfStart()
                        tend = file.getTimeOfEnd()

                        if time < tstart:
                            break
                        elif not tend or tend >= time:
                            children.append(file)
                            break

        return children

    def printFiles(self,
                   showDeleted: bool=False,
                   showCreationTime: bool=False,
                   showDocumentsOnly: bool=False,
                   userHome: str=None,
                   showDesignatedOnly: bool=False):
        """Print all the files currently being stored."""

        for key in sorted(self.nameStore, key=lambda s: s.lower()):
            files = self.nameStore[key]
            last = files[-1]  # TODO handle multiple versions
            printpath = last.getName()

            # Print only files accessed by designation, if asked to
            if showDesignatedOnly:
                flags = EventFileFlags.designation
                if not last.getAccesses(flags):
                    continue

            # Print only user documents, if we have a home to compare to
            if showDocumentsOnly and userHome:
                if last.isHidden():
                    continue
                if not printpath.startswith("/media") and \
                   not printpath.startswith(userHome):
                    continue

            # Ensure we print folders with a /, and files with leading space
            lastDir = printpath.rfind('/')
            # FIXME /home is still not printed properly, check it
            if lastDir > 0:
                printpath = (lastDir+1)*' ' + printpath[lastDir+1:]
                if last.isFolder():
                    printpath += "/"
            elif lastDir == 0 and last.isFolder():
                    printpath += "/"

            # Non-deleted files
            if not last.getTimeOfEnd():
                if showCreationTime and last.getTimeOfStart():
                    print("%s\tCREATED on %s" % (
                           printpath,
                           time2Str(last.getTimeOfStart())))
                else:
                    print("%s" % printpath)
            # Deleted files, if the callee wants them too
            elif showDeleted:
                if showCreationTime and last.getTimeOfStart():
                    print("%s\tCREATED on %s, DELETED on %s" % (
                           printpath,
                           time2Str(last.getTimeOfStart()),
                           time2Str(last.getTimeOfEnd())))
                else:
                    print("%s\tDELETED on %s" % (
                           printpath,
                           time2Str(last.getTimeOfEnd())))

    def getFilesForName(self, name):
        """Return all Files that have the given name as a path."""
        try:
            return self.nameStore[name]
        except(KeyError) as e:
            return []

    def updateFile(self, file: File, oldName: str=None):
        """Add a File to the FileStore."""
        filesWithName = self.getFilesForName(oldName or file.getName())

        for (index, old) in enumerate(filesWithName):
            if old.inode == file.inode:
                if not oldName:
                    filesWithName[index] = file
                    break
                else:
                    del filesWithName[index]
                    self.addFile(file)
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
