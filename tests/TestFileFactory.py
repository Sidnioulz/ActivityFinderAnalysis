import unittest
from Application import Application
from ApplicationStore import ApplicationStore
from FileStore import FileStore
from File import File, EventFileFlags
from FileFactory import FileFactory


class TestFileFactory(unittest.TestCase):
    def setUp(self):
        self.fileStore = FileStore.get()
        self.appStore = ApplicationStore.get()
        self.factory = FileFactory.get()

    def test_get_same_twice(self):
        first = "/path/to/first"
        time = 1

        file1 = self.factory.getFile(first, time)
        file2 = self.factory.getFile(first, time)

        self.assertEqual(file1.inode, file2.inode)

    def test_get_existing_file(self):
        first = "/path/to/first/file"
        second = "/path/to/second/file"

        exist1 = File(first, 0, 0, "image/jpg")
        self.fileStore.addFile(exist1)

        file1 = self.factory.getFile(first, 0)
        self.assertEqual(exist1.inode, file1.inode)
        file2 = self.factory.getFile(first, 10)
        self.assertEqual(exist1.inode, file2.inode)

        exist2 = File(second, 0, 3, "text/html")
        exist3 = File(second, 4, 0, "text/html")
        self.fileStore.addFile(exist2)
        self.fileStore.addFile(exist3)

        file3 = self.factory.getFile(second, 0)
        self.assertNotEqual(exist3.inode, file3.inode)
        self.assertEqual(exist2.inode, file3.inode)
        file4 = self.factory.getFile(second, 10)
        self.assertNotEqual(exist2.inode, file4.inode)
        self.assertEqual(exist3.inode, file4.inode)

    def test_update_time_end(self):
        app = Application("firefox.desktop", pid=21, tstart=0, tend=300)
        self.appStore.insert(app)

        path = "/path/to/file"
        f1 = File(path, 0, 0, "image/jpg")
        self.fileStore.addFile(f1)

        f2 = self.factory.getFile(path, 0)
        self.factory.deleteFile(f2, app, 100, EventFileFlags.no_flags)
        self.fileStore.updateFile(f2)

        f3 = self.factory.getFile(path, 0)
        self.assertEqual(f3.getTimeOfEnd(), 100)

    def tearDown(self):
        FileStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
