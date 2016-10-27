"""A store for Event objects."""
from Event import Event, EventFileFlags
from FileStore import FileStore
from FileFactory import FileFactory
from math import floor


class EventStore(object):
    """A store for Event objects.

    EventStore is a store for Events. It sorts all Events by timestamp to
    allow their simulation and the building of a filesystem and information
    flow models.
    """

    def __init__(self):
        """Construct an EventStore."""
        super(EventStore, self).__init__()
        self.clear()

    def clear(self):
        """Empty the EventStore."""
        self.store = list()   # type: list
        self._sorted = True   # type: bool

    def append(self, event: Event):
        """Append an Event to the store. The store will no longer be sorted."""
        if event.getTime() == 0:
            raise ValueError("Events must have a timestamp.")
        self.store.append(event)
        self._sorted = False

    def insert(self, event: Event):
        """Insert an Event. Maintains the store sorted, if it was sorted."""
        if event.getTime() == 0:
            raise ValueError("Events must have a timestamp.")

        # Binary search, first part: find a good index where to insert
        targetval = event.getTime()
        targetb = 0
        minb = 0
        maxb = len(self.store)
        while maxb > minb + 1:
            currentb = minb + floor((maxb-minb)/2)
            currentval = self.store[currentb].getTime()

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
        while targetb < maxb and self.store[targetb].getTime() <= targetval:
            targetb += 1
        self.store.insert(targetb, event)

    def sort(self):
        """Sort all the inserted Events by timestamp."""
        self.store = sorted(self.store, key=lambda x: x.getTime())
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
        for subj in event.getData():
            file = fileFactory.getFile(name=subj.getName(),
                                       time=event.time,
                                       ftype=subj.getType())
            file.addAccess(event.getActor(),
                           event.getFileFlags(),
                           event.time)
            fileStore.updateFile(file)

    def simulateDestroy(self,
                        event: Event,
                        fileFactory: FileFactory,
                        fileStore: FileStore):
        """Simulate a file deletion Event."""
        filesDeleted = []

        # Get each file, set its end time, and update the store
        for subj in event.getData():
            file = fileFactory.getFile(name=subj.getName(),
                                       time=event.time,
                                       ftype=subj.getType())
            file.addAccess(event.getActor(),
                           event.getFileFlags(),
                           event.time)
            fileFactory.deleteFile(file, event.time)
            filesDeleted.append(file)

        return filesDeleted

    def __doCreateFile(self,
                       name: str,
                       ftype: str,
                       event: Event,
                       fileFactory: FileFactory,
                       fileStore: FileStore):
        """Create a File, and return it."""

        file = fileFactory.getFile(name=name, time=event.time, ftype=ftype)
        file.setTimeOfStart(event.time)
        file.setType(ftype)
        file.addAccess(event.getActor(),
                       event.getFileFlags(),
                       event.time)
        fileStore.updateFile(file)

        return file

    def simulateCreate(self,
                       event: Event,
                       fileFactory: FileFactory,
                       fileStore: FileStore):
        """Simulate a file creation Event."""
        filesCreated = []

        # TODO: if a file has an overwrite flag, DESTROY PREVIOUS VERSION first
        # TODO: else, apply the rules below for ZG, and treat as an open/access
        #       for syscalls

        # TODO
        """
        get file.
        if file did not exist:
            proceed to set up file and updateFile
        elif file existed:
            if created less than 1 sec ago AND from SAME ACTOR (how?)
                    AND from actor in a whitelist (soffice.bin, etc):
                pass  # it's a dup
            elif same but actor not whitelisted:
                print warning to manually check the data
                exit

            if file was accessed by same application instance:
                ignore event
                inject a FileModified equivalent event right after
            else:
                ignore event
                inject a FileDestroyed for the same file right after
                inject the original event after the FileDestroyed
        """

        # Get each file, set its starting time and type, and update the store
        for subj in event.getData():
            f = self.__doCreateFile(subj.getName(),
                                    subj.getType(),
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

        # FIXME: attn, for syscalls, a cp to a folder doesn't cause deletion of
        # the folder, but only of the overridden children!

        # Get each file, set its starting time and type, and update the store
        for subj in event.getData():
            old = subj[0]
            new = subj[1]

            print("ACHTUNG: copying '%s' to '%s' at time %d" % (
                old.getName(), new.getName(), event.time
            ))

            # Delete any File on the new path as it would get overwritten.
            newFile = fileFactory.getFileIfExists(new.getName(), event.time)
            if newFile:
                fileFactory.deleteFile(newFile, event.time)

            # Create a file on the new path which is identical to the old File.
            newFile = self.__doCreateFile(new.getName(),
                                          old.getType(),
                                          event,
                                          fileFactory,
                                          fileStore)

            # Delete the old file for move events only.
            if not keepOld:
                oldFile = fileFactory.getFile(old.getName(), event.time)
                fileFactory.deleteFile(oldFile, event.time)

            # Update the files' links
            ctype = 'copy' if keepOld else 'move'
            oldFile = fileFactory.getFile(old.getName(), event.time)
            oldFile.addFollower(newFile.getName(), event.time, ctype)
            newFile.setPredecessor(oldFile.getName(), event.time, ctype)
            fileStore.updateFile(oldFile)
            fileStore.updateFile(newFile)

            newFiles.append(newFile)

        return newFiles

    def simulateAllEvents(self,
                          fileFactory: FileFactory,
                          fileStore: FileStore):
        """Simulate all events to instantiate Files in the FileStore."""
        if not self._sorted:
            self.sort()

        # Dispatch event to the appropriate handler
        for event in self.store:
            if event.getFileFlags() & EventFileFlags.destroy:
                res = self.simulateDestroy(event, fileFactory, fileStore)

            if event.getFileFlags() & EventFileFlags.create:
                res = self.simulateCreate(event, fileFactory, fileStore)

                # We received a list of files that were created
                if isinstance(res, list):
                    pass
                # We received instructions to hot-patch the event list
                else:
                    print("NOT IMPLEMENTED YET.")
                    pass

            # TODO resolve @fd@ for create/write/read/etc.
            # add to Application's fds list to track writes/reads to files

            if event.getFileFlags() & EventFileFlags.move:
                res = self.simulateCopy(event,
                                        fileFactory,
                                        fileStore,
                                        keepOld=False)

            if event.getFileFlags() & EventFileFlags.copy:
                res = self.simulateCopy(event,
                                        fileFactory,
                                        fileStore)

            if event.getFileFlags() & (EventFileFlags.read |
                                       EventFileFlags.write):
                self.simulateAccess(event, fileFactory, fileStore)
