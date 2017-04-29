"""A store for Event objects."""
from DesignationCache import DesignationCache
from Event import Event, EventFileFlags, EventSource
from FileStore import FileStore
from FileFactory import FileFactory
from math import floor
from constants import FD_OPEN, FD_CLOSE
from utils import time2Str, debugEnabled
import sys


class EventStore(object):
    """A store for Event objects.

    EventStore is a store for Events. It sorts all Events by timestamp to
    allow their simulation and the building of a filesystem and information
    flow models.
    """
    __event_store = None

    @staticmethod
    def get():
        """Return the EventStore for the entire application."""
        if not EventStore.__event_store:
            EventStore.__event_store = EventStore()
        return EventStore.__event_store

    @staticmethod
    def reset():
        EventStore.__event_store = None

    def __init__(self):
        """Construct an EventStore."""
        super(EventStore, self).__init__()
        self.clear()

    def clear(self):
        """Empty the EventStore."""
        self.store = list()                   # type: list
        self._sorted = True                   # type: bool
        self.desigcache = DesignationCache()  # type: DesignationCache

    def append(self, event: Event):
        """Append an Event to the store. The store will no longer be sorted."""
        if event.time == 0:
            raise ValueError("Events must have a timestamp.")
        self.store.append(event)
        self._sorted = False

    def insert(self, event: Event):
        """Insert an Event. Maintains the store sorted, if it was sorted."""
        if event.time == 0:
            raise ValueError("Events must have a timestamp.")

        # Binary search, first part: find a good index where to insert
        targetval = event.time
        targetb = 0
        minb = 0
        maxb = len(self.store)
        while maxb > minb + 1:
            currentb = minb + floor((maxb-minb)/2)
            currentval = self.store[currentb].time

            # Equal timestamps: put event after events with the same timestamp
            if currentval == targetval:
                targetb = currentb
                break
                pass
            # Event must go before the current value
            elif currentval > targetval:
                maxb = currentb
            # Event must go after the current value
            else:  # store[nextb] < target:
                minb = currentb
        else:
            # Reached if minb == maxb, aka event goes between minb and maxb
            targetb = minb

        # This serves two purposes: firstly, it inserts the new event after
        # those with a strictly equal timestamp. secondly, it 'finishes' the
        # previous loop by ensuring that we place our targetb cursor on the
        # nearest larger value. This is necessary because insert will insert
        # before the index it's given, rather than after, so we must target
        # the nearest larger value. We could have used ceiling instead of
        # floor in the previous loop to avoid that but we still needed to
        # iterate when timestamps are equal.
        maxb = len(self.store)
        while targetb < maxb and self.store[targetb].time <= targetval:
            targetb += 1
        self.store.insert(targetb, event)

    def sort(self):
        """Sort all the inserted Events by timestamp."""
        self.store = sorted(self.store, key=lambda x: x.time)
        self._sorted = True

    def getAllEvents(self):
        """Return all the events in the store. Very memory-intensive."""
        return self.store

    def getEventCount(self):
        """Return the number of events currently in the store."""
        return len(self.store)

    def simulateAccess(self,
                       event: Event,
                       fileFactory: FileFactory,
                       fileStore: FileStore):
        """Simulate a file access Event."""
        files = []

        # Get each File
        for subj in event.getData():
            file = fileFactory.getFile(name=subj.path,
                                       time=event.time,
                                       ftype=subj.ftype)
            files.append(file)

        # Check acts of designation
        res = self.desigcache.checkForDesignation(event, files)
        del files

        # Then, for each File, log the access
        for (file, flags) in res:
            file.addAccess(actor=event.actor,
                           flags=flags,
                           time=event.time)
            fileStore.updateFile(file)

    def simulateDestroy(self,
                        event: Event,
                        fileFactory: FileFactory,
                        fileStore: FileStore):
        """Simulate a file deletion Event."""
        filesDeleted = []
        files = []

        # Get each File
        for subj in event.getData():
            file = fileFactory.getFile(name=subj.path,
                                       time=event.time,
                                       ftype=subj.ftype)
            files.append(file)

        # Check acts of designation
        res = self.desigcache.checkForDesignation(event, files)
        del files

        # Then, for each File, set its end time, and update the store
        for (file, flags) in res:
            fileFactory.deleteFile(file,
                                   event.actor,
                                   event.time,
                                   flags)
            filesDeleted.append(file)

        return filesDeleted

    def __doCreateFile(self,
                       name: str,
                       ftype: str,
                       event: Event,
                       fileFactory: FileFactory,
                       fileStore: FileStore):
        """Create a File, and return it."""

        file = fileFactory.getFile(name=name,
                                   time=event.time,
                                   ftype=ftype)
        file.setTimeOfStart(event.time)

        res = self.desigcache.checkForDesignation(event, [file])
        file.addAccess(actor=event.actor,
                       time=event.time,
                       flags=res[0][1])
        fileStore.updateFile(file)

        return file

    def simulateCreate(self,
                       event: Event,
                       fileFactory: FileFactory,
                       fileStore: FileStore):
        """Simulate a file creation Event."""
        filesCreated = []

        # Get each File
        for subj in event.getData():

            # Remove old File if it exists and we overwrite.
            if event.evflags & EventFileFlags.overwrite:
                oldFile = fileFactory.getFileIfExists(subj.path, event.time)
                if oldFile:
                    deleting = True

                    # Check if the File was created by us, recently.
                    # TODO

                    # Check if we accessed the File, recently (some overwrites
                    # can be false positives). This means this Event is
                    # actually a simulated write to File, so we must correct
                    # that.
                    # TODO

                    deleting = False  # FIXME temporary till above code written
                    # If we decide to delete the File, this is executed.
                    if deleting:
                        baseFlags = event.evflags
                        event.evflags = (event.evflags |
                                         EventFileFlags.write |
                                         EventFileFlags.destroy &
                                         ~EventFileFlags.create &
                                         ~EventFileFlags.overwrite &
                                         ~EventFileFlags.read &
                                         ~EventFileFlags.copy &
                                         ~EventFileFlags.move)
                        res = self.desigcache.checkForDesignation(event, [f])
                        fileFactory.deleteFile(oldFile,
                                               event.actor,
                                               event.time,
                                               res[0][1])
                        event.evflags = baseFlags

            f = self.__doCreateFile(subj.path,
                                    subj.ftype,
                                    event,
                                    fileFactory,
                                    fileStore)
            filesCreated.append(f)

        return filesCreated

    def simulateCopy(self,
                     event: Event,
                     fileFactory: FileFactory,
                     fileStore: FileStore,
                     keepOld: bool=True):
        """Simulate a file copy or move Event, based on :keepOld:."""
        newFiles = []
        ctype = 'copy' if keepOld else 'move'
        baseFlags = event.evflags

        def _delFile(event: Event, f, read: bool=False):
            event.evflags = (baseFlags |
                             EventFileFlags.write |
                             EventFileFlags.destroy)
            if read:
                event.evflags |= EventFileFlags.read
            res = self.desigcache.checkForDesignation(event, [f])
            fileFactory.deleteFile(f, event.actor, event.time, res[0][1])
            event.evflags = baseFlags

        def _addRead(event: Event, f):
            event.evflags = (baseFlags | EventFileFlags.read)
            res = self.desigcache.checkForDesignation(event, [f])
            f.addAccess(actor=event.actor,
                        flags=res[0][1],
                        time=event.time)
            event.evflags = baseFlags

        def _createCopy(event: Event, oldFile, newPath):
            # Create a file on the new path which is identical to the old File.
            event.evflags = (baseFlags |
                             EventFileFlags.write |
                             EventFileFlags.create |
                             EventFileFlags.overwrite)
            newFile = self.__doCreateFile(newPath,
                                          oldFile.ftype,
                                          event,
                                          fileFactory,
                                          fileStore)
            event.evflags = baseFlags

            # Update the files' links
            oldFile.addFollower(newFile.inode, event.time, ctype)
            newFile.setPredecessor(oldFile.inode, event.time, ctype)
            fileStore.updateFile(oldFile)
            fileStore.updateFile(newFile)

            return newFile

        # Get each file, set its starting time and type, and update the store
        subjects = list((old.path, new.path) for (old, new) in event.getData())
        for (old, new) in subjects:

            # Not legal. 'a' and 'a' are the same file.
            if old == new:
                # TODO DBG?
                continue

            # Get the old file. It must exist, or the simulation is invalid.
            oldFile = fileFactory.getFile(old, event.time)
            if not oldFile:
                raise ValueError("Attempting to move/copy from a file that "
                                 "does not exist: %s at time %d" % (
                                  old,
                                  event.time))

            if debugEnabled():
                print("Info: %s '%s' to '%s' at time %s, by actor %s." % (
                      ctype,
                      old,
                      new,
                      time2Str(event.time),
                      event.actor.uid()))

            # Check if the target is a directory, or a regular file. If it does
            # not exist, it's a regular file.
            newFile = fileFactory.getFileIfExists(new, event.time)
            newIsFolder = newFile and newFile.isFolder()

            # If the target is a directory, we will copy/move inside it.
            sourceIsFolder = oldFile.isFolder()
            targetPath = new if not newIsFolder else \
                new + "/" + oldFile.getFileName()
            # If mv/cp'ing a folder to an existing path, restrictions apply.
            if sourceIsFolder:
                # oldFile is a/, newFile is b/, targetFile is b/a/
                targetFile = fileFactory.getFileIfExists(targetPath,
                                                         event.time)
                targetIsFolder = targetFile and targetFile.isFolder()

                # cannot overwrite non-directory 'b' with directory 'a'
                # cannot overwrite non-directory 'b/a' with directory 'a'
                if targetFile and not targetIsFolder:
                    # TODO DBG?
                    continue

                # mv: cannot move 'a' to 'b/a': Directory not empty
                elif targetIsFolder and ctype == "move":
                    children = fileStore.getChildren(targetFile, event.time)
                    if len(children) == 0:
                        _delFile(event, targetFile)
                    else:
                        # TODO DBG?
                        continue

                # mv or cp would make the target directory here. Our code later
                # on in this function will create a copy of the old file, which
                # means the new folder will be made, with a creation access
                # from the actor that performs the copy event we are analysing.
                elif not targetFile and ctype == "copy":
                    pass

            # When the source is a file, just delete the new target path.
            else:
                targetFile = fileFactory.getFileIfExists(targetPath,
                                                         event.time)
                if targetFile:
                    _delFile(event, targetFile)

            # Collect the children of the source folder.
            children = fileStore.getChildren(oldFile, event.time) if \
                sourceIsFolder else []

            # Make the target file, and link the old and target files.
            _createCopy(event, oldFile, targetPath)
            if ctype == "move":
                _delFile(event, oldFile, read=True)
            else:
                _addRead(event, oldFile)

            # Move or copy the children.
            for child in children:
                childRelPath = child.path[len(oldFile.path)+1:]
                childTargetPath = targetPath + "/" + childRelPath
                childNewFile = None

                # Let the Python purists hang me for that. Iterators will catch
                # appended elements on a mutable list and this is easier to
                # read than other solutions that don't modify the list while it
                # is iterated over.
                subjects.append((child.path, childTargetPath))

            newFiles.append(targetFile)

        return newFiles

    def simulateAllEvents(self):
        """Simulate all events to instantiate Files in the FileStore."""
        if not self._sorted:
            self.sort()

        fileStore = FileStore.get()
        fileFactory = FileFactory.get()

        # First, parse for Zeitgeist designation events in order to instantiate
        # the designation cache.
        if debugEnabled():
            print("Instantiating Zeitgeist acts of designation...")
        for event in self.store:
            if event.isInvalid():
                continue

            if event.getSource() == EventSource.zeitgeist:
                # The event grants 5 minutes of designation both ways.
                self.desigcache.addItem(event,
                                        start=event.time - 5*60*1000,
                                        duration=10*60*1000)
            # The current Event is an act of designation for future Events
            # related to the same Application and Files. Save it.
            elif event.getFileFlags() & EventFileFlags.designationcache:
                self.desigcache.addItem(event)

        if debugEnabled():
            print("Done. Starting simulation...")
        # Then, dispatch each event to the appropriate handler
        for event in self.store:
            if event.isInvalid():
                continue

            # Designation events are already processed.
            if event.getFileFlags() & EventFileFlags.designationcache:
                continue

            if debugEnabled():
                print("Simulating Event %s from %s at time %s." % (
                    event.evflags, event.actor.uid(), time2Str(event.time)))

            for data in event.data_app:
                if data[2] == FD_OPEN:
                    event.actor.openFD(data[0], data[1], event.time)
                elif data[2] == FD_CLOSE:
                    event.actor.closeFD(data[0], event.time)

            if event.getFileFlags() & EventFileFlags.destroy:
                res = self.simulateDestroy(event, fileFactory, fileStore)

            elif event.getFileFlags() & EventFileFlags.create:
                res = self.simulateCreate(event, fileFactory, fileStore)

            elif event.getFileFlags() & EventFileFlags.overwrite:
                res = self.simulateCreate(event, fileFactory, fileStore)

                # We received a list of files that were created
                if isinstance(res, list):
                    pass
                # We received instructions to hot-patch the event list
                else:
                    raise NotImplementedError  # TODO

            elif event.getFileFlags() & (EventFileFlags.read |
                                         EventFileFlags.write):
                self.simulateAccess(event, fileFactory, fileStore)

            # Keep me last, or use elif guards: I WILL change your event flags!
            elif event.getFileFlags() & EventFileFlags.move or \
                    event.getFileFlags() & EventFileFlags.copy:
                res = self.simulateCopy(event,
                                        fileFactory,
                                        fileStore,
                                        keepOld=event.getFileFlags() &
                                        EventFileFlags.copy)

        # Filter out invalid file descriptor references before computing stats.
        fileStore.purgeFDReferences()
