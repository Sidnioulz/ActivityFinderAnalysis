import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from UserConfigLoader import UserConfigLoader
from Event import Event
from EventStore import EventStore
from FileStore import FileStore
from FileFactory import FileFactory
from GraphEngine import AccessGraph
import os.path


class TestGraph(unittest.TestCase):
    def setUp(self):
        self.eventStore = EventStore.get()
        self.appStore = ApplicationStore.get()
        self.fileFactory = FileFactory.get()
        self.fileStore = FileStore.get()
        self.userConf = UserConfigLoader.get("user.ini")

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

    def test_graph_print(self):
        g = AccessGraph()
        g.populate()
        g.plot(output="graph-accesses")
        self.assertTrue(os.path.isfile("/tmp/graph-accesses.graph.svg"))
        self.assertTrue(os.path.isfile("/tmp/graph-accesses.clusters.svg"))

    def tearDown(self):
        EventStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
        FileStore.reset()
        self.userConf = None
