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
                     FileTypePolicy, FolderPolicy, OneFolderPolicy, \
                     FutureAccessListPolicy


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
        self.a3 = Application("ristretto.desktop", pid=3, tstart=3000,
                              tend=6000)
        self.appStore.insert(self.a1)
        self.appStore.insert(self.a2)
        self.appStore.insert(self.a3)

        self.p001 = "/home/user/.cache/firefox/file"
        s001 = "open64|%s|fd 10: with flag 524288, e0|" % self.p001
        e001 = Event(actor=self.a1, time=10, syscallStr=s001)
        e001.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e001)
        e001b = Event(actor=self.a2, time=11, syscallStr=s001)
        e001b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e001b)

        self.p002 = "/home/user/Images/picture.jpg"
        s002 = "open64|%s|fd 10: with flag 524288, e0|" % self.p002
        e002 = Event(actor=self.a1, time=12, syscallStr=s002)
        e002.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e002)

        self.p003 = "/home/user/Downloads/logo.jpg"
        s003 = "open64|%s|fd 10: with flag 524288, e0|" % self.p003
        e003 = Event(actor=self.a1, time=13, syscallStr=s003)
        e003.evflags |= EventFileFlags.designation  # this event by designation
        self.eventStore.append(e003)
        e003b = Event(actor=self.a3, time=3003, syscallStr=s003)
        e003b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e003b)

        self.p004 = "/home/user/Downloads/logo2.png"
        s004 = "open64|%s|fd 10: with flag 524288, e0|" % self.p004
        e004 = Event(actor=self.a1, time=14, syscallStr=s004)
        e004.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e004)

        self.p005 = "/home/user/Dropbox/Photos/holidays.jpg"
        s005 = "open64|%s|fd 10: with flag 524288, e0|" % self.p005
        e005 = Event(actor=self.a1, time=15, syscallStr=s005)
        e005.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e005)

        self.p006 = "/home/user/Images/random.txt"
        s006 = "open64|%s|fd 10: with flag 524288, e0|" % self.p006
        e006 = Event(actor=self.a1, time=16, syscallStr=s006)
        e006.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e006)

        self.p007 = "/home/user/Images/file.jpg"
        s007 = "open64|%s|fd 10: with flag 524288, e0|" % self.p007
        e007 = Event(actor=self.a1, time=17, syscallStr=s007)
        e007.evflags |= EventFileFlags.designation  # this event by designation
        self.eventStore.append(e007)

        self.p008 = "/home/user/Images/other.foo"
        s008 = "open64|%s|fd 10: with flag 524288, e0|" % self.p008
        e008 = Event(actor=self.a1, time=18, syscallStr=s008)
        e008.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e008)

        self.eventStore.simulateAllEvents()
        self._reset()

    def _reset(self):
        self.owned = 0
        self.desig = 0
        self.policy = 0
        self.illegal = 0

    def _assert(self, pol):
        self.assertEqual(pol.s.ownedPathAccess, self.owned)
        self.assertEqual(pol.s.desigAccess, self.desig)
        self.assertEqual(pol.s.policyAccess, self.policy)
        self.assertEqual(pol.s.illegalAccess, self.illegal)

    def test_unsecure(self):
        pol = UnsecurePolicy(userConf=self.userConf)
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.policy += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=21)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        pol.accessFunc(None, f003b, accs[1])
        self.policy += 1
        self._assert(pol)

    def test_designation(self):
        pol = DesignationPolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.illegal += 1
        self._assert(pol)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[1])
        self.owned += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        pol.accessFunc(None, f003b, accs[1])
        self.illegal += 1
        self._assert(pol)

    def test_filetype(self):
        pol = FileTypePolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, accs[0])
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        pol.accessFunc(None, f003b, accs[1])
        self.policy += 1
        self._assert(pol)

    def test_folder(self):
        pol = FolderPolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, accs[0])
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, accs[0])
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        pol.accessFunc(None, f003b, accs[1])
        self.illegal += 1
        self._assert(pol)

    def test_one_folder(self):
        pol = OneFolderPolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, accs[0])
        self.illegal += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        pol.accessFunc(None, f003b, accs[1])
        self.illegal += 1
        self._assert(pol)

    def test_future_access(self):
        pol = FutureAccessListPolicy(userConf=self.userConf)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, accs[0])
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, accs[0])
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, accs[0])
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, accs[0])
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, accs[0])
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, accs[0])
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, accs[0])
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        pol.accessFunc(None, f003b, accs[1])
        self.policy += 1
        self._assert(pol)

    def tearDown(self):
        self.userConf = None
        ApplicationStore.reset()
        EventStore.reset()
        FileStore.reset()
        FileFactory.reset()
