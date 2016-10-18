"""A store for Event objects."""
from Event import Event
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

    def insertList(self, events: list):
        for event in events:
            self.append(event)
        self.sort()

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

    def clear(self):
        self.store = list()   # type: list
        self._sorted = True   # type: bool

    def getAllEvents(self):
        return self.store

    def getEventCount(self):
        return len(self.store)
