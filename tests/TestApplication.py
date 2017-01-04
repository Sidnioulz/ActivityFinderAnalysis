import unittest
from Application import Application


class TestApplication(unittest.TestCase):
    def test_app_types(self):
        ff = Application("firefox.desktop", pid=1, tstart=0, tend=2)
        cf = Application("catfish.desktop", pid=2, tstart=21, tend=32)
        th = Application("thunar.desktop", pid=3, tstart=5, tend=8)
        gd = Application("gnome-disks.desktop", pid=4, tstart=2, tend=4)

        self.assertTrue(ff.isUserlandApp())
        self.assertTrue(cf.isDesktopApp())
        self.assertTrue(th.isDesktopApp())
        self.assertTrue(gd.isDesktopApp())
