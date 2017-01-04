import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from FileFactory import FileFactory
from Policies import OneLibraryPolicy
from PolicyEngine import PolicyEngine, SecurityScores


class TestSecurityScores(unittest.TestCase):
    def setUp(self):
        self.eventStore = EventStore.get()
        self.appStore = ApplicationStore.get()
        self.fileFactory = FileFactory.get()
        self.userConf = UserConfigLoader("user.ini")
        self.engine = PolicyEngine()

        self.ar1 = Application("ristretto.desktop", pid=21, tstart=1,
                               tend=2000)
        self.ar2 = Application("ristretto.desktop", pid=22, tstart=2600,
                               tend=2900)
        self.ag1 = Application("gimp.desktop", pid=23, tstart=1, tend=4000)
        self.ag2 = Application("gimp.desktop", pid=24, tstart=4500, tend=4590)
        self.appStore.insert(self.ar1)
        self.appStore.insert(self.ar2)
        self.appStore.insert(self.ag1)
        self.appStore.insert(self.ag2)

    def test_clusters_illegal(self):
        self.eventStore.reset()
        self.fileFactory.reset()

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
        self.fileFactory.reset()

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
        self.fileFactory.reset()

        # Insert a file that will bridge r1 and g1.
        s2 = "open64|/home/user/Images/Picture.jpg|fd 4: with flag 524288, e0|"
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
        self.eventStore.reset()
        self.fileFactory.reset()

        # Insert a file only for g1.
        s2 = "open64|/home/user/Images/Picture.jpg|fd 4: with flag 524288, e0|"
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

    def test_exclusion_list(self):
        self.eventStore.reset()
        self.fileFactory.reset()

        # Test the foo/bar exclusion for the clusters per app / per instance.
        s4 = "open64|/home/user/Images/Foo/Art.xcf|fd 2: with flag 524288, e0|"
        e4 = Event(actor=self.ag2, time=4540, syscallStr=s4)
        self.eventStore.append(e4)
        s5 = "open64|/home/user/Images/Bar/Bar.xcf|fd 2: with flag 524288, e0|"
        e5 = Event(actor=self.ag2, time=4540, syscallStr=s5)
        self.eventStore.append(e5)

        # Test the clients rule with a wildcard.
        s6 = "open64|/home/user/Images/Clients/C1/id.jpg|fd 2: with flag " \
             "524288, e0|"
        e6 = Event(actor=self.ag2, time=110, syscallStr=s6)
        self.eventStore.append(e6)
        s7a = "open64|/home/user/Images/Clients/C2/id.jpg|fd 2: with flag " \
              "524288, e0|"
        e7a = Event(actor=self.ag1, time=120, syscallStr=s7a)
        self.eventStore.append(e7a)
        s7b = "open64|/home/user/Images/Clients/C2/pp.jpg|fd 2: with flag " \
              "524288, e0|"
        e7b = Event(actor=self.ag1, time=122, syscallStr=s7b)
        self.eventStore.append(e7b)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        def _ctfn(clusters, scores, assertFn):
            for (index, cluster) in enumerate(clusters):
                for (scIndex, excl) in enumerate(scores[index]):
                    matchSum = 0
                    seenFoo = False
                    seenBar = False
                    seenC1 = False
                    seenC2 = False
                    for (path, match) in excl.items():
                        if path == "/home/user/Images/Foo/":
                            seenFoo = True
                        elif path == "/home/user/Images/Bar/":
                            seenBar = True
                        elif path == "/home/user/Images/C1/":
                            seenC1 = True
                        elif path == "/home/user/Images/C2/":
                            seenC2 = True
                        matchSum += 1

                    assertFn(seenFoo, seenBar, seenC1, seenC2, matchSum)

        def _assertPerApp(seenFoo, seenBar, seenC1, seenC2, matchSum):
            self.assertEqual(seenFoo, seenBar)
            self.assertEqual(seenC1, seenC2)
            self.assertIn(matchSum, (0, 2))

        def _assertPerInstance(seenFoo, seenBar, seenC1, seenC2, matchSum):
            self.assertEqual(seenFoo, seenBar)
            if seenC1 or seenC2:
                self.assertNotEqual(seenC1, seenC2)  # Only 1
                self.assertEqual(matchSum, 1)
            pass

        _ctfn(pol.clusters, pol.exclScores, _assertPerApp)
        _ctfn(pol.clustersPerInstance,
              pol.exclScoresPerInstance,
              _assertPerInstance)

    def test_exclusion_list_aorb(self):
        self.eventStore.reset()
        self.fileFactory.reset()

        sa = "open64|/home/user/Images/A/foo.jpg|fd 2: with flag 524288, e0|"
        ea = Event(actor=self.ag1, time=110, syscallStr=sa)
        self.eventStore.append(ea)
        sb = "open64|/home/user/Images/B/foo.jpg|fd 2: with flag 524288, e0|"
        eb = Event(actor=self.ag1, time=120, syscallStr=sb)
        self.eventStore.append(eb)
        sc = "open64|/home/user/Images/C/foo.jpg|fd 2: with flag 524288, e0|"
        ec = Event(actor=self.ag1, time=122, syscallStr=sc)
        self.eventStore.append(ec)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        def _ctfn(clusters, scores):
            for (index, cluster) in enumerate(clusters):
                for (scIndex, excl) in enumerate(scores[index]):
                    matchSum = set()
                    seenA = None
                    seenB = None
                    seenC = None
                    for (path, match) in excl.items():
                        if path == "/home/user/Images/A/":
                            seenA = match[0]
                        elif path == "/home/user/Images/B/":
                            seenB = match[0]
                        elif path == "/home/user/Images/C/":
                            seenC = match[0]
                        matchSum.add(match[0])

                    self.assertEqual(seenA, seenB)
                    if seenA or seenC:
                        self.assertNotEqual(seenA, seenC)
                    self.assertIn(len(matchSum), (0, 2))

        _ctfn(pol.clusters, pol.exclScores)
        _ctfn(pol.clustersPerInstance, pol.exclScoresPerInstance)

    def test_overentitlement(self):
        self.eventStore.reset()
        self.fileFactory.reset()

        # Insert a file accessed, but not allowed, by GIMP.
        s2 = "open64|/home/other/Photo.jpg|fd 10: with flag 524288, e0|"
        e2 = Event(actor=self.ag1, time=10, syscallStr=s2)
        self.eventStore.append(e2)

        # Insert a file reachable, but not accessed, by GIMP.
        s3 = "open64|/home/user/Images/Photo.jpg|fd 10: with flag 524288, e0|"
        e3 = Event(actor=self.ar1, time=10, syscallStr=s3)
        self.eventStore.append(e3)
        e3b = Event(actor=self.ar2, time=2710, syscallStr=s3)
        self.eventStore.append(e3b)

        # Insert a file opened by g1.
        s4 = "open64|/home/user/Images/Art.xcf|fd 10: with flag 524288, e0|"
        e4 = Event(actor=self.ag1, time=10, syscallStr=s4)
        self.eventStore.append(e4)

        # Simulate.
        self.eventStore.simulateAllEvents()
        pol = OneLibraryPolicy(userConf=self.userConf)
        self.engine.runPolicy(pol, quiet=True)

        f2 = self.fileFactory.getFile("/home/other/Photo.jpg", 20)
        f3 = self.fileFactory.getFile("/home/user/Images/Photo.jpg", 20)
        f4 = self.fileFactory.getFile("/home/user/Images/Art.xcf", 20)

        self.assertEqual(2, len(pol.ss.overEntitlements[0]))
        self.assertEqual(2, len(pol.ss.overEntitlements[1]))

        self.assertNotIn(f2, pol.ss.overEntitlements[0])
        self.assertNotIn(f2, pol.ss.overEntitlements[1])

        self.assertIn(f3, pol.ss.overEntitlements[0])
        self.assertIn(f3, pol.ss.overEntitlements[1])
        self.assertIn(f4, pol.ss.overEntitlements[0])
        self.assertIn(f4, pol.ss.overEntitlements[1])

        gimp = SecurityScores()

        for oe in pol.perInstanceSecurityScores:
            oes = pol.perInstanceSecurityScores[oe].overEntitlements
            if oe == self.ag2.uid():
                gimp += pol.perInstanceSecurityScores[oe]
                self.assertEqual(0, len(oes[0]))
                self.assertEqual(2, len(oes[1]))
            elif oe == self.ag1.uid():
                gimp += pol.perInstanceSecurityScores[oe]
                self.assertEqual(1, len(oes[0]))
                self.assertEqual(2, len(oes[1]))

        calcGimp = pol.perAppSecurityScores.get("gimp") or \
            SecurityScores()
        self.assertEqual(gimp, calcGimp)

    def tearDown(self):
        self.userConf = None
        self.engine = None
        EventStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
        FileStore.reset()
