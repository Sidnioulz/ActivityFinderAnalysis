import unittest
from AccessListCache import AccessListCache
from AttackSimulator import AttackSimulator, Attack
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from File import File, EventFileFlags
from FileFactory import FileFactory
from Policies import UnsecurePolicy, OneFolderPolicy


class TestAttackSimulator(unittest.TestCase):
    def setUp(self):
        self.userConf = UserConfigLoader.get("user.ini")
        self.appStore = ApplicationStore.get()
        self.eventStore = EventStore.get()
        self.fileStore = FileStore.get()
        self.fileFactory = FileFactory.get()
        self.sim = AttackSimulator()
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
        e005b = Event(actor=self.a1, time=1005, syscallStr=s005)
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

        self.p011 = "/home/user/Dropbox/Photos/holidays.evenmoremetadata"
        s011 = "open64|%s|fd 11: with flag 524288, e0|" % self.p011
        e011 = Event(actor=self.a3, time=3020, syscallStr=s011)
        e011.evflags &= ~EventFileFlags.designation  # not by designation
        self.eventStore.append(e011)

        self.eventStore.simulateAllEvents()

        self.acCache = AccessListCache.get()
        self.lookUps = dict()
        self.allowedCache = dict()

    def test_attack_memory(self):
        pol = UnsecurePolicy()
        acListInst = self.acCache.getAccessListFromPolicy(pol)

        attack = Attack(time=1999, source=self.a1)
        counts = self.sim._runAttackRound(attack=attack,
                                          policy=pol,
                                          acListInst=acListInst,
                                          lookUps=self.lookUps,
                                          allowedCache=self.allowedCache)
        self.assertEqual(len(counts[0]), 1)
        self.assertEqual(counts[2], 3)

        attack.appMemory = False
        counts = self.sim._runAttackRound(attack=attack,
                                          policy=pol,
                                          acListInst=acListInst,
                                          lookUps=self.lookUps,
                                          allowedCache=self.allowedCache)
        self.assertEqual(len(counts[0]), 1)
        self.assertEqual(counts[2], 0)
        
        FileFactory.reset()

    def test_pol_unsecure(self):
        pol = UnsecurePolicy()
        acListInst = self.acCache.getAccessListFromPolicy(pol)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        attack = Attack(time=11, source=f001)
        counts = self.sim._runAttackRound(attack=attack,
                                          policy=pol,
                                          acListInst=acListInst,
                                          lookUps=self.lookUps,
                                          allowedCache=self.allowedCache)
        self.assertEqual(len(counts[0]), 0)
        self.assertEqual(counts[2], 1)

        
        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        attack = Attack(time=10, source=f001)
        counts = self.sim._runAttackRound(attack=attack,
                                          policy=pol,
                                          acListInst=acListInst,
                                          lookUps=self.lookUps,
                                          allowedCache=self.allowedCache)
        self.assertEqual(len(counts[0]), 1)
        self.assertEqual(counts[2], 1)
        FileFactory.reset()

    def test_pol_onefolder(self):
        pol = OneFolderPolicy()
        acListInst = self.acCache.getAccessListFromPolicy(pol)

        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        attack = Attack(time=11, source=f001)
        counts = self.sim._runAttackRound(attack=attack,
                                          policy=pol,
                                          acListInst=acListInst,
                                          lookUps=self.lookUps,
                                          allowedCache=self.allowedCache)
        self.assertEqual(len(counts[0]), 0)
        self.assertEqual(counts[2], 1)
        
        f001 = self.fileFactory.getFile(name=self.p001, time=20)
        attack = Attack(time=10, source=f001)
        counts = self.sim._runAttackRound(attack=attack,
                                          policy=pol,
                                          acListInst=acListInst,
                                          lookUps=self.lookUps,
                                          allowedCache=self.allowedCache)
        self.assertEqual(len(counts[0]), 1)
        self.assertEqual(counts[2], 1)

        FileFactory.reset()

    def test_run_attacks(self):
        pol = OneFolderPolicy()
        self.sim.runAttacks(policy=pol, outputDir="/tmp")
        FileFactory.reset()

    def tearDown(self):
        self.userConf = None
        ApplicationStore.reset()
        EventStore.reset()
        FileStore.reset()
        FileFactory.reset()


