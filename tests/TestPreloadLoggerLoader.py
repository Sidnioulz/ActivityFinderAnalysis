import unittest
from PreloadLoggerLoader import PreloadLoggerLoader


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
