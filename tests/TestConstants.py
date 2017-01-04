import unittest
import re
from constants import PYTHONRE, PYTHONNAMER


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
