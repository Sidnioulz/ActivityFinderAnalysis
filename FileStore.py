"""Service to store File instances."""
from File import File, EventFileFlags
from utils import time2Str, debugEnabled
import os
import shutil
import sys


class FileStore(object):
    """A service to store File instances."""
    __file_store = None

    @staticmethod
    def get():
        """Return the FileStore for the entire application."""
        if FileStore.__file_store is None:
            FileStore.__file_store = FileStore()
        return FileStore.__file_store

    @staticmethod
    def reset():
        FileStore.__file_store = None

    def __init__(self):
        """Construct a FileStore."""
        super(FileStore, self).__init__()
        self.clear()

    def __len__(self):
        """Return the number of Files in the FileStore."""
        return len(self.inodeStore)

    def __iter__(self):
        """Iterate over all Files."""
        for name in sorted(self.nameStore):
            for f in self.nameStore[name]:
                yield f

    def clear(self):
        """Empty the FileStore."""
        self.nameStore = dict()   # type: dict
        self.inodeStore = dict()  # type: dict

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
                if not last.isUserDocument(userHome):
                    continue

            # Ensure we print folders with a /, and files with leading space
            lastDir = printpath.rfind('/')
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

    def makeFiles(self,
                  outputDir: str,
                  showDeleted: bool=False,
                  showDocumentsOnly: bool=False,
                  userHome: str=None,
                  showDesignatedOnly: bool=False):
        """Make all the files currently being stored into a folder."""

        if not outputDir:
            raise ValueError("You must provide an output location to make "
                             "Files.")
        else:
            if os.path.exists(outputDir):
                backup = outputDir.rstrip("/") + ".backup"
                if os.path.exists(backup):
                    shutil.rmtree(backup)
                os.replace(outputDir, backup)
            os.makedirs(outputDir, exist_ok=False)

        for key in sorted(self.nameStore, key=lambda s: s.lower()):
            files = self.nameStore[key]
            lastCnt = 0
            for last in reversed(files):
                if outputDir.endswith("/") or last.getName().startswith("/"):
                    outpath = outputDir + last.getName()
                else:
                    outpath = outputDir + "/" + last.getName()

                # Deal with previous versions
                if lastCnt:
                    outpath += ".prev.%d" % lastCnt
                lastCnt += 1

                # Print only files accessed by designation, if asked to
                if showDesignatedOnly:
                    flags = EventFileFlags.designation
                    if not last.getAccesses(flags):
                        continue

                # Print only user documents, if we have a home to compare to
                if showDocumentsOnly and userHome:
                    if not last.isUserDocument(userHome):
                        continue

                # Ensure all parent folders exist
                parentFileName = last.getParentName()
                if parentFileName:
                    parentPath = outputDir + '/' + parentFileName
                    try:
                        os.makedirs(parentPath, exist_ok=True)
                    except(FileExistsError) as e:
                        print("Warning: file '%s' aready exists, but is a "
                              "parent folder for file '%s'. Attempting to "
                              "delete the file and create a folder "
                              "instead..." % (parentFileName,
                                              last.getName()),
                              file=sys.stderr)
                        parentFiles = self.getFilesForName(parentFileName)
                        for parentFile in parentFiles:
                            if parentFile.getType() and not \
                                    parentFile.isFolder():
                                print("Warning: file '%s' already exists and"
                                      " is not a directory. Mime type: %s" %
                                       (parentFile.path, parentFile.getType()))
                            parentFile.setType('inode/directory')
                            self.updateFile(parentFile)
                        os.remove(parentPath)
                        os.makedirs(parentPath, exist_ok=False)
                        print("Info: updated %d files with name '%s'." % (
                               len(parentFiles), parentFile.getName()),
                              file=sys.stderr)

                if not last.getTimeOfEnd() or showDeleted:
                    if last.isFolder():
                        # Make the folder. If there's a file with the same
                        # name, that file was a folder and must be corrected.
                        os.makedirs(outpath, exist_ok=True)
                        with open(outpath+"/.ucl-metadata", 'a') as f:
                            os.utime(outpath+"/.ucl-metadata", None)
                            last.writeStatistics(f)
                    else:
                        try:
                            with open(outpath, 'a') as f:
                                os.utime(outpath, None)
                                last.writeStatistics(f)
                        # Seems to happen sometimes when a file was updated
                        # above.
                        except(IsADirectoryError) as e:
                            os.makedirs(outpath, exist_ok=True)
                            with open(outpath+"/.ucl-metadata", 'a') as f:
                                os.utime(outpath+"/.ucl-metadata", None)
                                last.writeStatistics(f)

    def getFilesForName(self, name: str):
        """Return all Files that have the given name as a path."""
        try:
            return self.nameStore[name]
        except(KeyError) as e:
            return []

    def getFile(self, inode: int):
        """Return the File identified by an inode."""
        try:
            return self.inodeStore[inode]
        except(KeyError) as e:
            return None

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
            self.inodeStore[file.inode] = file
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
            self.inodeStore[file.inode] = file
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

    def purgeFDReferences(self):
        """Remove FD references that weren't solved yet from the FileStore."""
        count = 0
        dels = set()
        delInodes = set()
        for name in self.nameStore:
            if name.startswith("@fdref"):
                dels.add(name)
                for f in self.nameStore.get(name):
                    delInodes.add(f.inode)

        for name in dels:
            del self.nameStore[name]

        for inode in delInodes:
            count += 1
            del self.inodeStore[inode]

        if debugEnabled():
            print("Info: purged %d unresolved file descriptor references." %
                  count)
