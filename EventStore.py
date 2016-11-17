"""A store for Event objects."""
from DesignationCache import DesignationCache
from Event import Event, EventFileFlags
from FileStore import FileStore
from FileFactory import FileFactory
from math import floor
from constants import FD_OPEN, FD_CLOSE
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
        files = []

        # Get each File
        for subj in event.getData():
            file = fileFactory.getFile(name=subj.getName(),
                                       time=event.getTime(),
                                       ftype=subj.getType())
            files.append(file)

        # Check acts of designation
        res = self.desigcache.checkForDesignation(event, files)
        del files

        # Then, for each File, log the access
        for (file, flags) in res:
            file.addAccess(actor=event.getActor(),
                           flags=flags,
                           time=event.getTime())
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
            file = fileFactory.getFile(name=subj.getName(),
                                       time=event.getTime(),
                                       ftype=subj.getType())
            files.append(file)

        # Check acts of designation
        res = self.desigcache.checkForDesignation(event, files)
        del files

        # Then, for each File, set its end time, and update the store
        for (file, flags) in res:
            fileFactory.deleteFile(file,
                                   event.getActor(),
                                   event.getTime(),
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
                                   time=event.getTime(),
                                   ftype=ftype)
        file.setTimeOfStart(event.getTime())
        file.setType(ftype)

        res = self.desigcache.checkForDesignation(event, [file])
        file.addAccess(actor=event.getActor(),
                       time=event.getTime(),
                       flags=res[0][1])
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

        # Get each File
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

        # Get each file, set its starting time and type, and update the store
        baseFlags = event.evflags
        for subj in event.getData():
            old = subj[0]
            new = subj[1]

            # print("Info: copying '%s' to '%s' at time %s" % (
            #     old.getName(), new.getName(), time2Str(event.getTime())))

            # Delete any File on the new path as it would get overwritten.
            newFile = fileFactory.getFileIfExists(new.getName(),
                                                  event.getTime())
            if newFile:
                # FIXME: attn, for syscalls, a cp to a folder doesn't cause
                # deletion of the folder, but only of the overridden children!

                if newFile.isFolder():
                    print("Warning: user copied to a folder. Must support "
                          "in-depth copy! Folder is: %s" % newFile.getName(),
                          file=sys.stderr)
                    sys.exit(0)
                baseFlags = event.evflags
                event.evflags = (baseFlags |
                                 EventFileFlags.write |
                                 EventFileFlags.destroy)
                res = self.desigcache.checkForDesignation(event, [newFile])
                fileFactory.deleteFile(newFile,
                                       event.getActor(),
                                       event.getTime(),
                                       res[0][1])

            # Create a file on the new path which is identical to the old File.
            event.evflags = (baseFlags |
                             EventFileFlags.write |
                             EventFileFlags.create |
                             EventFileFlags.overwrite)
            newFile = self.__doCreateFile(new.getName(),
                                          old.getType(),
                                          event,
                                          fileFactory,
                                          fileStore)

            # Delete the old file for move events only.
            oldFile = fileFactory.getFile(old.getName(), event.getTime())
            if not keepOld:
                event.evflags = (baseFlags |
                                 EventFileFlags.read |
                                 EventFileFlags.write |
                                 EventFileFlags.destroy)
                res = self.desigcache.checkForDesignation(event, [oldFile])
                fileFactory.deleteFile(oldFile,
                                       event.getActor(),
                                       event.getTime(),
                                       res[0][1])
            else:
                event.evflags = (baseFlags | EventFileFlags.read)
                res = self.desigcache.checkForDesignation(event, [oldFile])
                oldFile.addAccess(actor=event.getActor(),
                                  flags=res[0][1],
                                  time=event.getTime())

            # Update the files' links
            ctype = 'copy' if keepOld else 'move'
            oldFile = fileFactory.getFile(old.getName(), event.getTime())
            oldFile.addFollower(newFile.getName(), event.getTime(), ctype)
            newFile.setPredecessor(oldFile.getName(), event.getTime(), ctype)
            fileStore.updateFile(oldFile)
            fileStore.updateFile(newFile)

            newFiles.append(newFile)

        return newFiles

    def simulateAllEvents(self):
        """Simulate all events to instantiate Files in the FileStore."""
        if not self._sorted:
            self.sort()

        fileStore = FileStore.get()
        fileFactory = FileFactory.get()

        # Dispatch event to the appropriate handler
        for event in self.store:
            # The current Event is an act of designation for future Events
            # related to the same Application and Files. Save it.
            if event.getFileFlags() & EventFileFlags.designationcache:
                self.desigcache.addItem(event)
                continue

            for data in event.data_app:
                if data[2] == FD_OPEN:
                    event.actor.openFD(data[0], data[1], event.time)
                elif data[2] == FD_CLOSE:
                    event.actor.closeFD(data[0], event.time)

            if event.getFileFlags() & EventFileFlags.destroy:
                res = self.simulateDestroy(event, fileFactory, fileStore)

            elif event.getFileFlags() & EventFileFlags.create:
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

        # TODO: filter out invalid @fdref events
