import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from File import File, EventFileFlags
from FileFactory import FileFactory
from Policies import OneLibraryPolicy, UnsecurePolicy, DesignationPolicy, \
                     FileTypePolicy


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


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.appStore = ApplicationStore.get()
        self.eventStore = EventStore.get()
        self.fileStore = FileStore.get()
        self.fileFactory = FileFactory.get()
        self.userConf = UserConfigLoader("user.ini")
        self.a1 = Application("ristretto.desktop", pid=1, tstart=1, tend=2000)
        self.a2 = Application("firefox.desktop", pid=2, tstart=1, tend=2000)
        self.appStore.insert(self.a1)
        self.appStore.insert(self.a2)

        self.p001 = "/home/user/.cache/firefox/file"
        s001 = "open64|%s|fd 10: with flag 524288, e0|" % self.p001
        e001 = Event(actor=self.a1, time=10, syscallStr=s001)
        e001.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e001)
        e001b = Event(actor=self.a2, time=10, syscallStr=s001)
        e001b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e001b)

        self.p002 = "/home/user/Images/picture.jpg"
        s002 = "open64|%s|fd 10: with flag 524288, e0|" % self.p002
        e002 = Event(actor=self.a1, time=10, syscallStr=s002)
        e002.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e002)

        self.p003 = "/home/user/Downloads/logo.jpg"
        s003 = "open64|%s|fd 10: with flag 524288, e0|" % self.p003
        e003 = Event(actor=self.a1, time=10, syscallStr=s003)
        e003.evflags |= EventFileFlags.designation  # this event by designation
        self.eventStore.append(e003)

        self.p004 = "/home/user/Downloads/logo2.png"
        s004 = "open64|%s|fd 10: with flag 524288, e0|" % self.p004
        e004 = Event(actor=self.a1, time=10, syscallStr=s004)
        e004.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e004)

        self.p005 = "/home/user/Dropbox/Photos/holidays.jpg"
        s005 = "open64|%s|fd 10: with flag 524288, e0|" % self.p005
        e005 = Event(actor=self.a1, time=10, syscallStr=s005)
        e005.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e005)

        self.p006 = "/home/user/Images/random.txt"
        s006 = "open64|%s|fd 10: with flag 524288, e0|" % self.p006
        e006 = Event(actor=self.a1, time=10, syscallStr=s006)
        e006.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e006)

        self.eventStore.simulateAllEvents()

    def test_unsecure(self):
        pol = UnsecurePolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.assertEqual(pol.s.desigAccess, 0)
        self.assertEqual(pol.s.policyAccess, 1)
        self.assertEqual(pol.s.illegalAccess, 0)

        f002 = self.fileFactory.getFile(name=self.p002, time=21)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.assertEqual(pol.s.desigAccess, 0)
        self.assertEqual(pol.s.policyAccess, 2)
        self.assertEqual(pol.s.illegalAccess, 0)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 2)
        self.assertEqual(pol.s.illegalAccess, 0)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 3)
        self.assertEqual(pol.s.illegalAccess, 0)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 4)
        self.assertEqual(pol.s.illegalAccess, 0)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 5)
        self.assertEqual(pol.s.illegalAccess, 0)

    def test_designation(self):
        pol = DesignationPolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.assertEqual(pol.s.desigAccess, 0)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 1)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.assertEqual(pol.s.desigAccess, 0)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 2)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 2)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 3)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 4)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 5)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[1])
        self.assertEqual(pol.s.ownedPathAccess, 1)
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 5)

    def test_filetype(self):
        pol = FileTypePolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.assertEqual(pol.s.desigAccess, 0)
        self.assertEqual(pol.s.policyAccess, 0)
        self.assertEqual(pol.s.illegalAccess, 1)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.assertEqual(pol.s.desigAccess, 0)
        self.assertEqual(pol.s.policyAccess, 1)
        self.assertEqual(pol.s.illegalAccess, 1)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 1)
        self.assertEqual(pol.s.illegalAccess, 1)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 2)
        self.assertEqual(pol.s.illegalAccess, 1)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 3)
        self.assertEqual(pol.s.illegalAccess, 1)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 3)
        self.assertEqual(pol.s.illegalAccess, 2)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[1])
        self.assertEqual(pol.s.ownedPathAccess, 1)
        self.assertEqual(pol.s.desigAccess, 1)
        self.assertEqual(pol.s.policyAccess, 3)
        self.assertEqual(pol.s.illegalAccess, 2)


    def tearDown(self):
        self.userConf = None
        ApplicationStore.reset()
        EventStore.reset()
        FileStore.reset()
        FileFactory.reset()
