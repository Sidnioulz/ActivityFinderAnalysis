import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from File import File, EventFileFlags
from FileFactory import FileFactory
from LibraryManager import LibraryManager
from Policies import OneLibraryPolicy, UnsecurePolicy, DesignationPolicy, \
                     FileTypePolicy, FolderPolicy, OneFolderPolicy, \
                     FutureAccessListPolicy, CompositionalPolicy, \
                     StrictCompositionalPolicy, StickyBitPolicy, \
                     FilenamePolicy, ProtectedFolderPolicy, \
                     DistantFolderPolicy, ProjectsPolicy, ExclusionPolicy, \
                     RemovableMediaPolicy, LibraryFolderPolicy, \
                     HBalancedSecuredPolicy, HBalancedPolicy

class TestOneLibraryPolicy(unittest.TestCase):
    def setUp(self):
        self.appStore = ApplicationStore.get()
        self.eventStore = EventStore.get()
        self.fileStore = FileStore.get()
        self.fileFactory = FileFactory.get()
        self.userConf = UserConfigLoader.get("user.ini")

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
        self.assertEqual(file.getAccessCount(), 2)

        lp = OneLibraryPolicy()

        lp.accessFunc(None, file, next(accs))
        self.assertEqual(lp.s.illegalAccess, 1)
        self.assertEqual(lp.s.grantingCost, 1)
        self.assertEqual(lp.s.cumulGrantingCost, 1)

        lp.accessFunc(None, file, next(accs))
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
        accs = iter(file.getAccesses())
        self.assertEqual(file.getAccessCount(), 1)

        lp = OneLibraryPolicy()

        lp.accessFunc(None, file, next(accs))
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
        self.ac = Application("catfish.desktop", pid=100, tstart=1, tend=2900)
        self.appStore.insert(self.a1)
        self.appStore.insert(self.a2)
        self.appStore.insert(self.a3)
        self.appStore.insert(self.ac)

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
        e002b = Event(actor=self.ac, time=30, syscallStr=s002)
        e002b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e002b)
        e002b = Event(actor=self.a2, time=31, syscallStr=s002)
        e002b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e002b)

        self.p003 = "/home/user/Downloads/logo.jpg"
        s003 = "open64|%s|fd 10: with flag 524288, e0|" % self.p003
        e003 = Event(actor=self.a1, time=13, syscallStr=s003)
        e003.evflags |= EventFileFlags.designation  # this event by designation
        self.eventStore.append(e003)
        e003b = Event(actor=self.a3, time=3003, syscallStr=s003)
        e003b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e003b)

        self.p004 = "/home/user/Downloads/logo.png"
        s004 = "open64|%s|fd 10: with flag 64, e0|" % self.p004
        e004 = Event(actor=self.a1, time=14, syscallStr=s004)
        e004.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e004)

        self.p005 = "/home/user/Dropbox/Photos/holidays.jpg"
        s005 = "open64|%s|fd 10: with flag 524288, e0|" % self.p005
        e005 = Event(actor=self.a1, time=15, syscallStr=s005)
        e005.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e005)
        e005b = Event(actor=self.a1, time=3005, syscallStr=s005)
        e005b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e005b)

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
        s008 = "open64|%s|fd 10: with flag 64, e0|" % self.p008
        e008 = Event(actor=self.a1, time=18, syscallStr=s008)
        e008.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e008)

        self.p009 = "/home/user/Downloads/unknown.data"
        s009 = "open64|%s|fd 10: with flag 64, e0|" % self.p009
        # e009 = Event(actor=self.a1, time=18, syscallStr=s009)
        # e009.evflags |= EventFileFlags.designation  # this event by designation
        # self.eventStore.append(e009)
        e009b = Event(actor=self.a3, time=3009, syscallStr=s009)
        e009b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e009b)

        self.p010 = "/home/user/Dropbox/Photos/holidays.metadata"
        s010 = "open64|%s|fd 10: with flag 524288, e0|" % self.p010
        e010 = Event(actor=self.a1, time=20, syscallStr=s010)
        e010.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e010)
        e010b = Event(actor=self.a3, time=20, syscallStr=s010)
        e010b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e010b)

        self.p011 = "/home/user/Dropbox/Photos/holidays.evenmoremetadata"
        s011 = "open64|%s|fd 11: with flag 524288, e0|" % self.p011
        e011 = Event(actor=self.a3, time=3020, syscallStr=s011)
        e011.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e011)

        self.p012 = "/home/user/Images/Scotland/index.txt"
        s012 = "open64|%s|fd 10: with flag 524288, e0|" % self.p012
        e012 = Event(actor=self.a1, time=10, syscallStr=s012)
        e012.evflags |= EventFileFlags.designation  # this event by designation
        self.eventStore.append(e012)
        e012b = Event(actor=self.a3, time=22, syscallStr=s012)
        e012b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e012b)

        self.p013 = "/home/user/Images/Scotland/DSC13.jpg"
        s013 = "open64|%s|fd 10: with flag 524288, e0|" % self.p013
        e013 = Event(actor=self.a1, time=11, syscallStr=s013)
        e013.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e013)

        self.p014 = "/home/user/Images/Scotland/Edinburgh/DSC14.jpg"
        s014 = "open64|%s|fd 10: with flag 524288, e0|" % self.p014
        e014 = Event(actor=self.a1, time=12, syscallStr=s014)
        e014.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e014)

        self.p015 = "/home/user/Images/Ireland/DSC15.jpg"
        s015 = "open64|%s|fd 10: with flag 524288, e0|" % self.p015
        e015 = Event(actor=self.a1, time=13, syscallStr=s015)
        e015.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e015)
        e015b = Event(actor=self.a3, time=14, syscallStr=s015)
        e015b.evflags |= EventFileFlags.designation  # this by designation
        self.eventStore.append(e015b)

        self.p016 = "/media/user/USB_A/document.png"
        s016 = "open64|%s|fd 10: with flag 524288, e0|" % self.p016
        e016 = Event(actor=self.a1, time=16, syscallStr=s016)
        e016.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e016)

        self.p017 = "/media/user/USB_B/report.doc"
        s017 = "open64|%s|fd 10: with flag 524288, e0|" % self.p017
        e017 = Event(actor=self.a1, time=17, syscallStr=s017)
        e017.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e017)

        self.p018 = "/home/user/Desktop/Folder_A/any.file"
        s018 = "open64|%s|fd 10: with flag 524288, e0|" % self.p018
        e018 = Event(actor=self.a1, time=18, syscallStr=s018)
        e018.evflags |= EventFileFlags.designation  # this by designation
        self.eventStore.append(e018)
        e018b = Event(actor=self.a3, time=22, syscallStr=s018)
        e018b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e018b)

        self.p019 = "/home/user/Desktop/Folder_A/other.file"
        s019 = "open64|%s|fd 10: with flag 524288, e0|" % self.p019
        e019 = Event(actor=self.a1, time=19, syscallStr=s019)
        e019.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e019)
        e019b = Event(actor=self.a3, time=24, syscallStr=s019)
        e019b.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e019b)

        self.p020 = "/home/user/Desktop/Folder_B/other.file"
        s020 = "open64|%s|fd 10: with flag 524288, e0|" % self.p020
        e020 = Event(actor=self.a1, time=20, syscallStr=s020)
        e020.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e020)

        self.eventStore.simulateAllEvents()
        self._reset()

    def _reset(self):
        self.owned = 0
        self.desig = 0
        self.policy = 0
        self.illegal = 0
        self.grantingCost = 0
        self.cumulGrantingCost = 0

    def _assert(self, pol):
        self.assertEqual(pol.s.ownedPathAccess, self.owned)
        self.assertEqual(pol.s.desigAccess, self.desig)
        self.assertEqual(pol.s.policyAccess, self.policy)
        self.assertEqual(pol.s.illegalAccess, self.illegal)

    def _assertCosts(self, pol):
        self.assertEqual(pol.s.grantingCost, self.grantingCost)
        self.assertEqual(pol.s.cumulGrantingCost, self.cumulGrantingCost)

    def test_unsecure(self):
        pol = UnsecurePolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.policy += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=21)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_designation(self):
        pol = DesignationPolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f001, next(accs))
        self.owned += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_filetype(self):
        pol = FileTypePolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)
        self.assertEqual(pol.s.configCost, 1)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_folder(self):
        pol = FolderPolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_distant_folder(self):
        pol = DistantFolderPolicy()
        self._reset()

        f012 = self.fileFactory.getFile(name=self.p012, time=20)
        accs = f012.getAccesses()
        pol.accessFunc(None, f012, next(accs))
        self.desig += 1
        self._assert(pol)

        f013 = self.fileFactory.getFile(name=self.p013, time=20)
        accs = f013.getAccesses()
        pol.accessFunc(None, f013, next(accs))
        self.policy += 1
        self._assert(pol)

        f014 = self.fileFactory.getFile(name=self.p014, time=20)
        accs = f014.getAccesses()
        pol.accessFunc(None, f014, next(accs))
        self.policy += 1
        self._assert(pol)

        f015 = self.fileFactory.getFile(name=self.p015, time=20)
        accs = f015.getAccesses()
        pol.accessFunc(None, f015, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_projects(self):
        pol = ProjectsPolicy()
        self._reset()

        f012 = self.fileFactory.getFile(name=self.p012, time=20)
        accs = f012.getAccesses()
        pol.accessFunc(None, f012, next(accs))
        self.desig += 1
        self._assert(pol)

        f013 = self.fileFactory.getFile(name=self.p013, time=20)
        accs = f013.getAccesses()
        pol.accessFunc(None, f013, next(accs))
        self.policy += 1
        self._assert(pol)

        f014 = self.fileFactory.getFile(name=self.p014, time=20)
        accs = f014.getAccesses()
        pol.accessFunc(None, f014, next(accs))
        self.policy += 1
        self._assert(pol)

        f015 = self.fileFactory.getFile(name=self.p015, time=20)
        accs = f015.getAccesses()
        pol.accessFunc(None, f015, next(accs))
        self.illegal += 1
        self._assert(pol)

        # Now test a3 designation access to ireland, and that the other project
        # files are subsequently allowed.
        pol.accessFunc(None, f015, next(accs))
        self.desig += 1
        self._assert(pol)

        f010 = self.fileFactory.getFile(name=self.p010, time=20)
        accs = f010.getAccesses()
        next(accs)
        pol.accessFunc(None, f010, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_one_folder(self):
        pol = OneFolderPolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)
        pol.accessFunc(None, f001, next(accs))
        self.owned += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.illegal += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_future_access(self):
        pol = FutureAccessListPolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

        f012 = self.fileFactory.getFile(name=self.p012, time=20)
        accs = f012.getAccesses()
        pol.accessFunc(None, f012, next(accs))
        self.desig += 1
        pol.accessFunc(None, f012, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_compositional(self):
        pol = CompositionalPolicy(policies=[FileTypePolicy, OneLibraryPolicy],
                                  polArgs=[None, None])
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.policy += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_strict_compositional(self):
        pol = StrictCompositionalPolicy(policies=[FileTypePolicy,
                                                  OneLibraryPolicy],
                                        polArgs=[None, None])
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_compositional_stateful(self):
        pol = CompositionalPolicy(policies=[OneLibraryPolicy,
                                            FutureAccessListPolicy],
                                  polArgs=[dict(supportedLibraries=["image"]),
                                           None])
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.policy += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_sticky_bit(self):
        pol = StickyBitPolicy(folders=["/tmp",
                                       "~/Desktop",
                                       "~/Downloads"])
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_filename(self):
        pol = FilenamePolicy()
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_filename_scoped(self):
        pol = FilenamePolicy()
        pol.scope = ('/home/user/Images',)
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.policy += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

        pol = FilenamePolicy()
        pol.scope = ('/home/user/Dropbox',)
        pol.unscopedDefDesignated = False
        pol.unscopedDefAllowed = False
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.illegal += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.illegal += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_sticky_bit(self):
        pol = StickyBitPolicy(folders=["/tmp",
                                       "~/Desktop",
                                       "~/Downloads"])
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_sticky_bit_scoped(self):
        pol = StickyBitPolicy(folders=["/tmp",
                                       "~/Desktop",
                                       "~/Downloads"])
        pol.scope = ('/home/user/Images',)
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.policy += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.policy += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.illegal += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.policy += 1
        self._assert(pol)

    def test_protected_folder(self):
        pol = ProtectedFolderPolicy(folders=["~/Downloads", "~/Dropbox"])
        self._reset()

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.policy += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.illegal += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.policy += 1
        self._assert(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self.desig += 1
        self._assert(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self.policy += 1
        self._assert(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_library_folder(self):
        pol = LibraryFolderPolicy()
        self._reset()

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f009 = self.fileFactory.getFile(name=self.p009, time=3010)
        accs = f009.getAccesses()
        pol.accessFunc(None, f009, next(accs))
        self.illegal += 1
        self._assert(pol)

        f018 = self.fileFactory.getFile(name=self.p018, time=3010)
        accs = f018.getAccesses()
        pol.accessFunc(None, f018, next(accs))
        self.desig += 1
        self._assert(pol)

        f019 = self.fileFactory.getFile(name=self.p019, time=3010)
        accs = f019.getAccesses()
        pol.accessFunc(None, f019, next(accs))
        self.policy += 1
        self._assert(pol)

        f020 = self.fileFactory.getFile(name=self.p020, time=3010)
        accs = f020.getAccesses()
        pol.accessFunc(None, f020, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_balanced(self):
        pols = [HBalancedPolicy, FutureAccessListPolicy]
        args = [None, None]
        pol = CompositionalPolicy(pols, args, "HBalancedFaPolicy")
        self._reset()

        f018 = self.fileFactory.getFile(name=self.p018, time=40)
        accs = f018.getAccesses()
        pol.accessFunc(None, f018, next(accs))
        self.desig += 1
        self._assert(pol)
        pol.accessFunc(None, f018, next(accs))
        self.policy += 1
        self._assert(pol)

        f019 = self.fileFactory.getFile(name=self.p019, time=40)
        accs = f019.getAccesses()
        next(accs)  # skip first access, from another app.
        pol.accessFunc(None, f019, next(accs))
        self.policy += 1
        self._assert(pol)

        # Check that individual bits return illegal when expected to.
        pol = CompositionalPolicy(pols, args, "HBalancedFaPolicy")
        self._reset()
        f018 = self.fileFactory.getFile(name=self.p018, time=40)
        accs = f018.getAccesses()
        next(accs)
        pol.accessFunc(None, f018, next(accs))
        self.illegal += 1
        self._assert(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=40)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        # Check that the secured balanced policy works.
        pols = [HBalancedSecuredPolicy, FutureAccessListPolicy]
        args = [None, None]
        pol = CompositionalPolicy(pols, args, "HBalancedSecuredFaPolicy")
        self._reset()

        f018 = self.fileFactory.getFile(name=self.p018, time=40)
        accs = f018.getAccesses()
        pol.accessFunc(None, f018, next(accs))
        self.desig += 1
        self._assert(pol)
        pol.accessFunc(None, f018, next(accs))
        self.policy += 1
        self._assert(pol)

        f019 = self.fileFactory.getFile(name=self.p019, time=40)
        accs = f019.getAccesses()
        next(accs)  # skip first access, from another app.
        pol.accessFunc(None, f019, next(accs))
        self.illegal += 1
        self._assert(pol)

    def _test_folder_costs(self, pol):
        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        accs = f001.getAccesses()
        pol.accessFunc(None, f001, next(accs))
        self.grantingCost += 1
        self.cumulGrantingCost += 1
        self._assertCosts(pol)

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.grantingCost += 1
        self.cumulGrantingCost += 1
        self._assertCosts(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self._assertCosts(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self._assertCosts(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.grantingCost += 1
        self.cumulGrantingCost += 1
        self._assertCosts(pol)
        pol.accessFunc(None, f005, next(accs))
        self.cumulGrantingCost += 1
        self._assertCosts(pol)

        f006 = self.fileFactory.getFile(name=self.p006, time=20)
        accs = f006.getAccesses()
        pol.accessFunc(None, f006, next(accs))
        self.cumulGrantingCost += 1
        self._assertCosts(pol)

        f007 = self.fileFactory.getFile(name=self.p007, time=20)
        accs = f007.getAccesses()
        pol.accessFunc(None, f007, next(accs))
        self._assertCosts(pol)

        f008 = self.fileFactory.getFile(name=self.p008, time=20)
        accs = f008.getAccesses()
        pol.accessFunc(None, f008, next(accs))
        self._assertCosts(pol)

        f003b = self.fileFactory.getFile(name=self.p003, time=3000)
        accs = f003b.getAccesses()
        next(accs)  # pass accs[0]
        pol.accessFunc(None, f003b, next(accs))
        self.grantingCost += 1
        self.cumulGrantingCost += 1
        self._assertCosts(pol)

        f009 = self.fileFactory.getFile(name=self.p009, time=3010)
        accs = f009.getAccesses()
        self.cumulGrantingCost += 1
        pol.accessFunc(None, f009, next(accs))
        self._assertCosts(pol)

        f010 = self.fileFactory.getFile(name=self.p010, time=20)
        accs = f010.getAccesses()
        pol.accessFunc(None, f010, next(accs))
        self.cumulGrantingCost += 1  # f003b authorised folder
        self._assertCosts(pol)

        f011 = self.fileFactory.getFile(name=self.p011, time=20)
        accs = f011.getAccesses()
        pol.accessFunc(None, f011, next(accs))
        self.grantingCost += 1
        self.cumulGrantingCost += 1  # f003b authorised folder
        self._assertCosts(pol)

    def test_folder_granting_costs(self):
        pol = FolderPolicy()
        self._reset()
        self._test_folder_costs(pol)

    def test_compositional_granting_costs(self):
        pol = CompositionalPolicy(policies=[FolderPolicy, DesignationPolicy],
                                  polArgs=[None, None])
        self._reset()
        self._test_folder_costs(pol)

    def test_exclusion(self):
        excl = ['^/home/user/Downloads/.*', '^/home/user/Dropbox/.*']
        pol = ExclusionPolicy(exclusionList=excl,
                              excludeOutsideLists=False,
                              countConfigCosts=False)
        self._reset()

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f009 = self.fileFactory.getFile(name=self.p009, time=3010)
        accs = f009.getAccesses()
        pol.accessFunc(None, f009, next(accs))
        self.policy += 1
        self._assert(pol)

        f010 = self.fileFactory.getFile(name=self.p010, time=20)
        accs = f010.getAccesses()
        pol.accessFunc(None, f010, next(accs))
        self.illegal += 1
        self._assert(pol)

        f011 = self.fileFactory.getFile(name=self.p011, time=20)
        accs = f011.getAccesses()
        pol.accessFunc(None, f011, next(accs))
        self.illegal += 1
        self._assert(pol)

        pol = ExclusionPolicy(exclusionList=excl,
                              excludeOutsideLists=True,
                              countConfigCosts=False)
        self._reset()

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.illegal += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        f004 = self.fileFactory.getFile(name=self.p004, time=20)
        accs = f004.getAccesses()
        pol.accessFunc(None, f004, next(accs))
        self.policy += 1
        self._assert(pol)

        f005 = self.fileFactory.getFile(name=self.p005, time=20)
        accs = f005.getAccesses()
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)
        pol.accessFunc(None, f005, next(accs))
        self.illegal += 1
        self._assert(pol)

        f009 = self.fileFactory.getFile(name=self.p009, time=3010)
        accs = f009.getAccesses()
        pol.accessFunc(None, f009, next(accs))
        self.policy += 1
        self._assert(pol)

        f010 = self.fileFactory.getFile(name=self.p010, time=20)
        accs = f010.getAccesses()
        pol.accessFunc(None, f010, next(accs))
        self.illegal += 1
        self._assert(pol)

        f011 = self.fileFactory.getFile(name=self.p011, time=20)
        accs = f011.getAccesses()
        pol.accessFunc(None, f011, next(accs))
        self.illegal += 1
        self._assert(pol)

    def test_removable(self):
        pol = RemovableMediaPolicy()
        self._reset()

        f002 = self.fileFactory.getFile(name=self.p002, time=20)
        accs = f002.getAccesses()
        pol.accessFunc(None, f002, next(accs))
        self.policy += 1
        self._assert(pol)

        f003 = self.fileFactory.getFile(name=self.p003, time=20)
        accs = f003.getAccesses()
        pol.accessFunc(None, f003, next(accs))
        self.desig += 1
        self._assert(pol)

        # Get the files before, so the policy gets properly initialised.
        f016 = self.fileFactory.getFile(name=self.p016, time=20)
        f017 = self.fileFactory.getFile(name=self.p017, time=20)

        pol = RemovableMediaPolicy()
        self._reset()

        accs = f016.getAccesses()
        pol.accessFunc(None, f016, next(accs))
        self.policy += 1
        self._assert(pol)

        accs = f017.getAccesses()
        pol.accessFunc(None, f017, next(accs))
        self.illegal += 1
        self._assert(pol)

        f010 = self.fileFactory.getFile(name=self.p010, time=21)
        accs = f010.getAccesses()
        pol.accessFunc(None, f010, next(accs))
        self.illegal += 1
        self._assert(pol)

    def tearDown(self):
        self.userConf = None
        ApplicationStore.reset()
        EventStore.reset()
        FileStore.reset()
        FileFactory.reset()
