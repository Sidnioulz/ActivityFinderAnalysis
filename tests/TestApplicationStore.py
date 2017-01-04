import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from EventStore import EventStore


class TestApplicationStore(unittest.TestCase):
    def setUp(self):
        self.store = ApplicationStore.get()

    def test_merge_equal(self):
        self.store.clear()
        a = Application("firefox.desktop", pid=21, tstart=0, tend=2)
        b = Application("firefox.desktop", pid=21, tstart=21, tend=32)
        d = Application("ristretto.desktop", pid=21, tstart=5, tend=8)
        f = Application("firefox.desktop", pid=21, tstart=2, tend=4)
        self.store.insert(a)
        self.store.insert(b)
        self.store.insert(d)
        self.store.insert(f)
        self.assertEqual(len(self.store.lookupPid(21)), 3)

    def test_merge_equal_b(self):
        self.store.clear()
        a = Application("firefox.desktop", pid=18495, tstart=0, tend=2)
        b = Application("firefox.desktop", pid=245, tstart=21, tend=32)
        f = Application("firefox.desktop", pid=6023, tstart=2, tend=4)
        self.store.insert(a)
        self.store.insert(b)
        self.store.insert(f)
        self.assertEqual(len(self.store.lookupDesktopId(a.desktopid)), 3)
        self.assertEqual(len(self.store.lookupDesktopId(a.getDesktopId())), 3)

    def tearDown(self):
        EventStore.reset()
        ApplicationStore.reset()
