import unittest
from Application import Application
from Event import Event
from EventStore import EventStore


class TestEventStore(unittest.TestCase):
    def setUp(self):
        self.store = EventStore.get()

    def test_insert_sorted(self):
        self.store.clear()
        app = Application("firefox.desktop", pid=21, tstart=0, tend=10)

        first = Event(app, 1, syscallStr="test")
        second = Event(app, 2, syscallStr="test")
        third = Event(app, 3, syscallStr="test")
        forth = Event(app, 4, syscallStr="test")
        fifth = Event(app, 5, syscallStr="test")
        sixth = Event(app, 6, syscallStr="test")
        seventh = Event(app, 7, syscallStr="test")
        eight = Event(app, 8, syscallStr="test")

        self.store.insert(eight)
        self.store.insert(first)
        self.store.insert(sixth)
        self.store.insert(fifth)
        self.store.insert(third)
        self.store.insert(forth)
        self.store.insert(seventh)
        self.store.insert(second)

        alle = self.store.getAllEvents()
        sorte = [first, second, third, forth, fifth, sixth, seventh, eight]
        self.assertEqual(sorte, alle)

    def test_insert_identical_timestamps(self):
        self.store.clear()
        app = Application("firefox.desktop", pid=21, tstart=0, tend=3)
        lastapp = Application("ristretto.desktop", pid=22, tstart=3, tend=4)

        first = Event(app, 1, syscallStr="test")
        second = Event(app, 2, syscallStr="test")
        third = Event(app, 3, syscallStr="test")
        last = Event(lastapp, 3, syscallStr="test")

        self.store.insert(first)
        self.store.insert(third)
        self.store.insert(last)
        self.store.insert(second)

        alle = self.store.getAllEvents()
        sorte = [first, second, third, last]
        self.assertEqual(sorte, alle)

    def tearDown(self):
        EventStore.reset()
