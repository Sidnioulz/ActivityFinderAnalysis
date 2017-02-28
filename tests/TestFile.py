import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from File import EventFileFlags
from FileFactory import FileFactory


class TestEventFlags(unittest.TestCase):
    def setUp(self):
        self.eventStore = EventStore.get()
        self.appStore = ApplicationStore.get()
        self.fileFactory = FileFactory.get()

    def test_merge_equal(self):
        app = Application("firefox.desktop", pid=21, tstart=1, tend=200000)
        self.appStore.insert(app)

        ss = "open64|/home/user/.kde/share/config/kdeglobals|fd " \
             "10: with flag 524288, e0|"
        e1 = Event(actor=app, time=10, syscallStr=ss)
        self.eventStore.append(e1)

        cmd = "@firefox|2294|firefox -p /home/user/.kde/file"
        e2 = Event(actor=app, time=1, cmdlineStr=cmd)
        self.eventStore.append(e2)

        st = "open64|/home/user/.kde/file|fd " \
             "10: with flag 524288, e0|"
        e3 = Event(actor=app, time=13, syscallStr=st)
        self.eventStore.append(e3)

        self.eventStore.simulateAllEvents()

        ef1 = EventFileFlags.no_flags
        ef1 |= EventFileFlags.programmatic
        ef1 |= EventFileFlags.read
        self.assertEqual(ef1, e1.getFileFlags())

        ef3 = EventFileFlags.no_flags
        ef3 |= EventFileFlags.designation
        ef3 |= EventFileFlags.read

        file = self.fileFactory.getFile("/home/user/.kde/file", 20)
        accs = file.getAccesses()
        self.assertEqual(file.getAccessCount(), 1)
        self.assertEqual(next(accs).evflags, ef3)

    def tearDown(self):
        EventStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
        FileStore.reset()


class TestFile(unittest.TestCase):
    def setUp(self):
        self.factory = FileFactory.get()

    def test_file_hidden(self):
        first = "/path/to/first"
        second = "/path/to/.second"
        third = "/path/.to/third"

        file1 = self.factory.getFile(first, 0)
        file2 = self.factory.getFile(second, 0)
        file3 = self.factory.getFile(third, 0)

        self.assertFalse(file1.isHidden())
        self.assertTrue(file2.isHidden())
        self.assertTrue(file3.isHidden())

    def tearDown(self):
        FileFactory.reset()
