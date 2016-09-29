import unittest
from Application import Application
from AppInstanceStore import AppInstanceStore


class TestStoreInsertion(unittest.TestCase):
    store = None  # type: AppInstanceStore

    def setUp(self):
        self.store = AppInstanceStore()

    def test_merge_equal(self):
        a = Application("firefox.desktop", pid=21, tstart=0, tend=2)
        b = Application("firefox.desktop", pid=21, tstart=21, tend=32)
        d = Application("ristretto.desktop", pid=21, tstart=5, tend=8)
        f = Application("firefox.desktop", pid=21, tstart=2, tend=4)
        self.store.insert(a)
        self.store.insert(b)
        self.store.insert(d)
        self.store.insert(f)
        self.assertEqual(len(self.store.lookupPid(21)), 3)

    def tearDown(self):
        self.store = None
