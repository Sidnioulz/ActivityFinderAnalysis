import unittest
import re
from Application import Application
from ApplicationStore import ApplicationStore
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from File import File
from FileFactory import FileFactory
from PreloadLoggerLoader import PreloadLoggerLoader
from constants import PYTHONRE, PYTHONNAMER


class TestStoreInsertion(unittest.TestCase):
    store = None  # type: ApplicationStore

    def setUp(self):
        self.store = ApplicationStore()

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

    def tearDown(self):
        self.store = None


class TestInterpreterRes(unittest.TestCase):
    def test_python(self):
        pyre = re.compile(PYTHONRE)

        self.assertIsNotNone(pyre.match("python"))
        self.assertIsNone(pyre.match("pythen"))
        self.assertIsNone(pyre.match("python-bar"))
        self.assertIsNone(pyre.match("/python"))

        self.assertIsNotNone(pyre.match("python2"))
        self.assertIsNotNone(pyre.match("python3"))
        self.assertIsNone(pyre.match("python3-foo"))

        self.assertIsNotNone(pyre.match("python2.7"))
        self.assertIsNotNone(pyre.match("python3.4"))
        self.assertIsNone(pyre.match("python4.1"))

        self.assertIsNotNone(pyre.match("/usr/bin/python"))
        self.assertIsNotNone(pyre.match("/usr/bin/python2"))
        self.assertIsNotNone(pyre.match("/usr/bin/python3"))
        self.assertIsNone(pyre.match("/usr/bin/python-foo"))

    def test_python_naming(self):
        pyre = re.compile(PYTHONNAMER)

        res = pyre.match("/usr/share/catfish/bin/catfish.py")
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.groups())
        self.assertEqual(len(res.groups()), 1)
        self.assertEqual(res.groups()[0], "catfish")

        res = pyre.match("/home/user/pylote.pyw")
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.groups())
        self.assertEqual(len(res.groups()), 1)
        self.assertEqual(res.groups()[0], "pylote")

        res = pyre.match("calibre")
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.groups())
        self.assertEqual(len(res.groups()), 1)
        self.assertEqual(res.groups()[0], "calibre")

        res = pyre.match("test.pyc")
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.groups())
        self.assertEqual(len(res.groups()), 1)
        self.assertEqual(res.groups()[0], "test")

        res = pyre.match("test.py")
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.groups())
        self.assertEqual(len(res.groups()), 1)
        self.assertEqual(res.groups()[0], "test")

        res = pyre.match("/usr/share/software-center/piston_generic_helper.py")
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.groups())
        self.assertEqual(len(res.groups()), 1)
        self.assertEqual(res.groups()[0], "piston_generic_helper")


class TestPreloadLoggerLoader(unittest.TestCase):
    loader = None  # type: PreloadLoggerLoader

    def setUp(self):
        self.loader = PreloadLoggerLoader('/not/needed')

    def test_python(self):
        g = ('python', 1234, 'python /home/lucie/pylote/pylote.pyw')
        h = self.loader.parsePython(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'pylote')
        self.assertEqual(h[2], '/home/lucie/pylote/pylote.pyw')

        g = ('/usr/bin/python2.7', 1234, '/usr/bin/python2.7 '
             '/usr/bin/update-manager --no-update')
        h = self.loader.parsePython(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'update-manager')
        self.assertEqual(h[2], '/usr/bin/update-manager --no-update')

        g = ('/usr/bin/python', 1234, '/usr/bin/python '
             '/usr/share/software-center/piston_generic_helper.py --datadir '
             '/usr/share/software-center/ SoftwareCenterAgentAPI exhibits '
             '{"lang": "fr", "series": "trusty"}')
        h = self.loader.parsePython(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'piston_generic_helper')
        self.assertEqual(h[2], '/usr/share/software-center/piston_generic_'
                               'helper.py --datadir /usr/share/software-center'
                               '/ SoftwareCenterAgentAPI exhibits {"lang": "fr'
                               '", "series": "trusty"}')

        g = ('python', 1234, 'python')
        h = self.loader.parsePython(g)
        self.assertIsNotNone(h)
        self.assertEqual(g, h)

    def test_java(self):
        g = ('java', 1234, 'java -jar /usr/share/java/pcalendar.jar')
        h = self.loader.parseJava(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'pcalendar')
        self.assertEqual(h[2], '/usr/share/java/pcalendar.jar')

        g = ('/usr/bin/java', 1234, '/usr/bin/java /usr/bin/jtestapp '
             '/path/to/file --param="some value"')
        h = self.loader.parseJava(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'jtestapp')
        self.assertEqual(h[2], '/usr/bin/jtestapp /path/to/file '
                               '--param="some value"')

        g = ('java', 1234, 'java')
        h = self.loader.parseJava(g)
        self.assertIsNotNone(h)
        self.assertEqual(g, h)

    def test_perl(self):
        g = ('perl', 1234, 'perl /usr/bin/debconf-communicate')
        h = self.loader.parsePerl(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'debconf-communicate')
        self.assertEqual(h[2], '/usr/bin/debconf-communicate')

        g = ('perl', 1234, 'perl -w /usr/bin/debconf-communicate')
        h = self.loader.parsePerl(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'debconf-communicate')
        self.assertEqual(h[2], '/usr/bin/debconf-communicate')

        g = ('perl', 1234, 'perl')
        h = self.loader.parsePerl(g)
        self.assertIsNotNone(h)
        self.assertEqual(g, h)

        g = ('perl', 1234, 'perl -w')
        h = self.loader.parsePerl(g)
        self.assertIsNotNone(h)
        self.assertEqual(g, h)

    def test_mono(self):
        g = ('mono-sgen', 1234, 'banshee /usr/lib/banshee/Banshee.exe '
             '--redirect-log --play-enqueued')
        h = self.loader.parseMono(g)
        self.assertIsNotNone(h)
        self.assertNotEqual(g, h)
        self.assertEqual(h[0], 'banshee')
        self.assertEqual(h[2], g[2])

        g = ('mono-sgen', 1234, 'mono-sgen')
        h = self.loader.parseMono(g)
        self.assertIsNotNone(h)
        self.assertEqual(g, h)

    def tearDown(self):
        self.loader = None


class TestEventStoreInsertion(unittest.TestCase):
    store = None  # type: EventStore

    def setUp(self):
        self.store = EventStore()

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
        self.store = None


class TestFileStore(unittest.TestCase):
    store = None    # type: FileStore
    factory = None  # type: FileFactory

    def setUp(self):
        self.store = FileStore()
        self.factory = FileFactory(self.store)

    def test_add(self):
        first = "/path/to/first/file"
        file1 = File(first, 0, 0, "image/jpg")
        self.store.addFile(file1)
        self.assertEqual(len(self.store.getFilesForName(first)), 1)


class TestFileFactory(unittest.TestCase):
    store = None    # type: FileStore
    factory = None  # type: FileFactory

    def setUp(self):
        self.store = FileStore()
        self.factory = FileFactory(self.store)

    def test_get_same_twice(self):
        first = "/path/to/first"
        time = 1

        file1 = self.factory.getFile(first, time)
        file2 = self.factory.getFile(first, time)

        self.assertEqual(file1.inode, file2.inode)

    def test_get_existing_file(self):
        first = "/path/to/first/file"
        second = "/path/to/second/file"

        exist1 = File(first, 0, 0, "image/jpg")
        self.store.addFile(exist1)

        file1 = self.factory.getFile(first, 0)
        self.assertEqual(exist1.inode, file1.inode)
        file2 = self.factory.getFile(first, 10)
        self.assertEqual(exist1.inode, file2.inode)

        exist2 = File(second, 0, 3, "text/html")
        exist3 = File(second, 4, 0, "text/html")
        self.store.addFile(exist2)
        self.store.addFile(exist3)

        file3 = self.factory.getFile(second, 0)
        self.assertNotEqual(exist3.inode, file3.inode)
        self.assertEqual(exist2.inode, file3.inode)
        file4 = self.factory.getFile(second, 10)
        self.assertNotEqual(exist2.inode, file4.inode)
        self.assertEqual(exist3.inode, file4.inode)

    def test_update_time_end(self):
        path = "/path/to/first/file"

        f1 = File(path, 0, 0, "image/jpg")
        self.store.addFile(f1)

        f2 = self.factory.getFile(path, 0)
        self.factory.deleteFile(f2, 100)
        self.store.updateFile(f2)

        f3 = self.factory.getFile(path, 0)
        self.assertEqual(f3.getTimeOfEnd(), 100)

    def tearDown(self):
        self.factory = None
        self.store = None
