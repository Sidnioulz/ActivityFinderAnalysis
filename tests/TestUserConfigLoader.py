import unittest
from UserConfigLoader import UserConfigLoader


class TestUserConfigLoader(unittest.TestCase):
    def setUp(self):
        self.userConf = UserConfigLoader("user.ini")

    def test_load_exclusion_list(self):
        expectedList = [
            ['/home/user/Images/Foo/', '/home/user/Images/Bar/'],
            ['/home/user/Images/Clients/.*?/'],
            ['/home/user/Images/(A|B)', '/home/user/Images/C']]
        lists = self.userConf.getSecurityExclusionLists()
        self.assertEqual(lists, expectedList)

    def test_get_home(self):
        home = self.userConf.getSetting("HomeDir")
        self.assertEqual(home, "/home/user")

    def tearDown(self):
        self.userConf = None
