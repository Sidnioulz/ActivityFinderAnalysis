import unittest
import re
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from File import File, EventFileFlags
from FileFactory import FileFactory
from PreloadLoggerLoader import PreloadLoggerLoader
from PolicyEngine import PolicyEngine
from LibraryPolicies import OneLibraryPolicy
from constants import PYTHONRE, PYTHONNAMER


class TestSecurityScores(unittest.TestCase):
    def setUp(self):
        self.eventStore = EventStore.get()
        self.appStore = ApplicationStore.get()
        self.fileFactory = FileFactory.get()
        self.userConf = UserConfigLoader("user.ini")
        self.engine = PolicyEngine()

        self.ar1 = Application("ristretto.desktop", pid=21, tstart=1, tend=2000)
        self.ar2 = Application("ristretto.desktop", pid=22, tstart=2600, tend=2900)
        self.ag1 = Application("gimp.desktop", pid=23, tstart=1, tend=4000)
        self.ag2 = Application("gimp.desktop", pid=24, tstart=4500, tend=4590)

    def test_clusters_illegal(self):
        self.eventStore.reset()

        # Insert an illegal file, we'll check it's in no clusters.
        s1 = "open64|/home/user/ForbiddenFile.xml|fd 10: with flag 524288, e0|"
        e1 = Event(actor=self.ag1, time=10, syscallStr=s1)
        self.eventStore.append(e1)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        # Ensure there is no cluster.
        self.assertIsNotNone(pol.clusters)
        self.assertEqual(len(pol.clusters), 0)

    def test_clusters_owned_path(self):
        self.eventStore.reset()

        # Insert an illegal file, we'll check it's in no clusters.
        s1 = "open64|/home/user/.config/gimp/config.ini|fd 10: with " \
             "flag 524288, e0|"
        e1 = Event(actor=self.ag1, time=10, syscallStr=s1)
        self.eventStore.append(e1)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        # Ensure there is no cluster.
        self.assertIsNotNone(pol.clusters)
        self.assertEqual(len(pol.clusters), 0)

    def test_clusters_linked(self):
        self.eventStore.reset()

        # Insert a file that will bridge r1 and g1.
        s2 = "open64|/home/user/Images/Picture.jpg|fd 10: with flag 524288, e0|"
        e2 = Event(actor=self.ag1, time=10, syscallStr=s2)
        self.eventStore.append(e2)
        e2b = Event(actor=self.ar1, time=12, syscallStr=s2)
        self.eventStore.append(e2b)

        # Insert a file that will bridge r1 and r2.
        s3 = "open64|/home/user/Images/Photo.jpg|fd 10: with flag 524288, e0|"
        e3 = Event(actor=self.ar1, time=10, syscallStr=s3)
        self.eventStore.append(e3)
        e3b = Event(actor=self.ar2, time=2710, syscallStr=s3)
        self.eventStore.append(e3b)

        # Insert a file that will bridge g1 and g2.
        s4 = "open64|/home/user/Images/Art.xcf|fd 10: with flag 524288, e0|"
        e4 = Event(actor=self.ag1, time=10, syscallStr=s4)
        self.eventStore.append(e4)
        e4b = Event(actor=self.ag2, time=4540, syscallStr=s4)
        self.eventStore.append(e4b)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        # Ensure there is only one cluster.
        self.assertIsNotNone(pol.clusters)
        self.assertEqual(len(pol.clusters), 1)

        # Ensure f2, f3 and f4 are together.
        f2 = self.fileFactory.getFile("/home/user/Images/Picture.jpg", 20)
        f3 = self.fileFactory.getFile("/home/user/Images/Photo.jpg", 20)
        f4 = self.fileFactory.getFile("/home/user/Images/Art.xcf", 20)
        self.assertIn(f2, pol.clusters[0])
        self.assertIn(f3, pol.clusters[0])
        self.assertIn(f4, pol.clusters[0])

    def test_clusters_disjoint(self):
        # Insert a file only for g1.
        s2 = "open64|/home/user/Images/Picture.jpg|fd 10: with flag 524288, e0|"
        e2 = Event(actor=self.ag1, time=10, syscallStr=s2)
        self.eventStore.append(e2)

        # Insert a file that will bridge r1 and r2.
        s3 = "open64|/home/user/Images/Photo.jpg|fd 10: with flag 524288, e0|"
        e3 = Event(actor=self.ar1, time=10, syscallStr=s3)
        self.eventStore.append(e3)
        e3b = Event(actor=self.ar2, time=2710, syscallStr=s3)
        self.eventStore.append(e3b)

        # Insert a file only for g2.
        s4 = "open64|/home/user/Images/Art.xcf|fd 10: with flag 524288, e0|"
        e4b = Event(actor=self.ag2, time=4540, syscallStr=s4)
        self.eventStore.append(e4b)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        # Ensure there are three clusters.
        self.assertIsNotNone(pol.clusters)
        self.assertIsNotNone(pol.clustersPerInstance)
        self.assertEqual(len(pol.clusters), 2)
        self.assertEqual(len(pol.clustersPerInstance), 3)

        # Ensure f1 is not included, and f2, f3 and f4 are together.
        f2 = self.fileFactory.getFile("/home/user/Images/Picture.jpg", 20)
        f3 = self.fileFactory.getFile("/home/user/Images/Photo.jpg", 20)
        f4 = self.fileFactory.getFile("/home/user/Images/Art.xcf", 20)
        for cluster in pol.clustersPerInstance:
            if f2 in cluster:
                self.assertNotIn(f3, cluster)
                self.assertNotIn(f4, cluster)
            if f3 in cluster:
                self.assertNotIn(f2, cluster)
                self.assertNotIn(f4, cluster)
            if f4 in cluster:
                self.assertNotIn(f2, cluster)
                self.assertNotIn(f3, cluster)
        for cluster in pol.clusters:
            if f2 in cluster:
                self.assertNotIn(f3, cluster)
                self.assertIn(f4, cluster)
            if f3 in cluster:
                self.assertNotIn(f2, cluster)
                self.assertNotIn(f4, cluster)
            if f4 in cluster:
                self.assertIn(f2, cluster)
                self.assertNotIn(f3, cluster)

    def tearDown(self):
        self.userConf = None
        self.engine = None
        EventStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
        FileStore.reset()


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
        acc = file.getAccesses()
        self.assertEqual(len(acc), 1)
        self.assertEqual(acc[0].evflags, ef3)

    def tearDown(self):
        EventStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
        FileStore.reset()


class TestApplicationStoreInsertion(unittest.TestCase):
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

    def tearDown(self):
        EventStore.reset()
        ApplicationStore.reset()


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


class TestFileStore(unittest.TestCase):
    def setUp(self):
        self.fileStore = FileStore.get()
        self.appStore = ApplicationStore.get()
        self.factory = FileFactory.get()

    def test_add(self):
        first = "/path/to/first/file"
        file1 = File(first, 0, 0, "image/jpg")
        self.fileStore.addFile(file1)
        self.assertEqual(len(self.fileStore.getFilesForName(first)), 1)

    def test_get_children(self):
        file1 = File("/path/to/file", 0, 0, "image/jpg")
        file2 = File("/path/to/document", 0, 0, "image/jpg")
        self.fileStore.addFile(file1)
        self.fileStore.addFile(file2)

        fparent = File("/path/to", 0, 0, "inode/directory")
        children = self.fileStore.getChildren(fparent, 0)
        self.assertEqual(len(children), 2)
        self.assertTrue(file1 in children)
        self.assertTrue(file2 in children)

    def test_iteration(self):
        file1 = File("/path/to/file", 0, 0, "image/jpg")
        file2 = File("/path/to/document", 0, 5, "image/jpg")
        file3 = File("/path/to/document", 6, 0, "image/jpg")
        self.fileStore.addFile(file1)
        self.fileStore.addFile(file2)
        self.fileStore.addFile(file3)

        rebuilt = []
        for f in self.fileStore:
            rebuilt.append(f)
        self.assertEqual(len(rebuilt), 3)
        self.assertEqual(rebuilt[0], file2)
        self.assertEqual(rebuilt[1], file3)
        self.assertEqual(rebuilt[2], file1)

    def getChildren(self, f: File):
        parent = f.getName() + '/'
        children = []
        for item in [k for k, v in self.nameStore.items()
                     if k.startswith(parent)]:
            if item[0][len(parent)+1:].find('/') == -1:
                children.append(item[1])

        return children

    def tearDown(self):
        FileStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()


class TestFileFactory(unittest.TestCase):
    def setUp(self):
        self.fileStore = FileStore.get()
        self.appStore = ApplicationStore.get()
        self.factory = FileFactory.get()

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
        self.fileStore.addFile(exist1)

        file1 = self.factory.getFile(first, 0)
        self.assertEqual(exist1.inode, file1.inode)
        file2 = self.factory.getFile(first, 10)
        self.assertEqual(exist1.inode, file2.inode)

        exist2 = File(second, 0, 3, "text/html")
        exist3 = File(second, 4, 0, "text/html")
        self.fileStore.addFile(exist2)
        self.fileStore.addFile(exist3)

        file3 = self.factory.getFile(second, 0)
        self.assertNotEqual(exist3.inode, file3.inode)
        self.assertEqual(exist2.inode, file3.inode)
        file4 = self.factory.getFile(second, 10)
        self.assertNotEqual(exist2.inode, file4.inode)
        self.assertEqual(exist3.inode, file4.inode)

    def test_update_time_end(self):
        app = Application("firefox.desktop", pid=21, tstart=0, tend=300)
        self.appStore.insert(app)

        path = "/path/to/file"
        f1 = File(path, 0, 0, "image/jpg")
        self.fileStore.addFile(f1)

        f2 = self.factory.getFile(path, 0)
        self.factory.deleteFile(f2, app, 100, EventFileFlags.no_flags)
        self.fileStore.updateFile(f2)

        f3 = self.factory.getFile(path, 0)
        self.assertEqual(f3.getTimeOfEnd(), 100)

    def tearDown(self):
        FileStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()


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


class TestOneLibraryPolicy(unittest.TestCase):
    def setUp(self):
        self.appStore = ApplicationStore.get()
        self.eventStore = EventStore.get()
        self.fileStore = FileStore.get()
        self.fileFactory = FileFactory.get()
        self.userConf = UserConfigLoader("user.ini")

    def test_pol_load_app_conf(self):
        app = Application("ristretto.desktop", pid=21, tstart=0, tend=300)
        file = File("/home/user/Images/sample.jpg", 140, 0, "image/jpeg")
        file.addAccess(app, 140, EventFileFlags.create | EventFileFlags.read)

        self.appStore.insert(app)
        res = OneLibraryPolicy(userConf=self.userConf).getAppPolicy(app)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0], "image")

    def test_access_recording(self):
        app = Application("firefox.desktop", pid=21, tstart=1, tend=200000)
        self.appStore.insert(app)

        path = "/home/user/.kde/file"
        st = "open64|%s|fd 10: with flag 524288, e0|" % path
        e1 = Event(actor=app, time=10, syscallStr=st)
        self.eventStore.append(e1)
        e2 = Event(actor=app, time=13, syscallStr=st)
        self.eventStore.append(e2)

        self.eventStore.simulateAllEvents()

        file = self.fileFactory.getFile(name=path, time=20)
        accs = file.getAccesses()
        self.assertEqual(len(accs), 2)

        lp = OneLibraryPolicy(userConf=self.userConf)

        lp.accessFunc(None, file, accs[0])
        self.assertEqual(lp.s.illegalAccess, 1)
        self.assertEqual(lp.s.grantingCost, 1)
        self.assertEqual(lp.s.cumulGrantingCost, 1)

        lp.accessFunc(None, file, accs[1])
        self.assertEqual(lp.s.illegalAccess, 2)
        self.assertEqual(lp.s.grantingCost, 1)
        self.assertEqual(lp.s.cumulGrantingCost, 2)
        FileFactory.reset()

    def test_app_owned_files(self):
        app = Application("ristretto.desktop", pid=123, tstart=1, tend=200000)
        self.appStore.insert(app)

        path = "/home/user/.cache/ristretto/file"
        st = "open64|%s|fd 10: with flag 524288, e0|" % path
        e1 = Event(actor=app, time=10, syscallStr=st)
        self.eventStore.append(e1)

        self.eventStore.simulateAllEvents()

        file = self.fileFactory.getFile(name=path, time=20)
        accs = file.getAccesses()
        self.assertEqual(len(accs), 1)

        lp = OneLibraryPolicy(userConf=self.userConf)

        lp.accessFunc(None, file, accs[0])
        self.assertEqual(lp.s.ownedPathAccess, 1)
        FileFactory.reset()

    def tearDown(self):
        self.userConf = None
        ApplicationStore.reset()
        EventStore.reset()
        FileStore.reset()
        FileFactory.reset()
