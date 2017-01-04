import unittest
from ApplicationStore import ApplicationStore
from File import File
from FileStore import FileStore
from FileFactory import FileFactory


class TestFileStore(unittest.TestCase):
    def setUp(self):
        self.fileStore = FileStore.get()
        self.appStore = ApplicationStore.get()
        self.factory = FileFactory.get()

    def test_add(self):
        first = "/path/to/first/file"
        file1 = File(first, 0, 0, "image/jpg")
        self.fileStore.addFile(file1)
        self.assertEqual(len(self.fileStore.getFilesForName(first)), 1)

    def test_get_children(self):
        file1 = File("/path/to/file", 0, 0, "image/jpg")
        file2 = File("/path/to/document", 0, 0, "image/jpg")
        self.fileStore.addFile(file1)
        self.fileStore.addFile(file2)

        fparent = File("/path/to", 0, 0, "inode/directory")
        children = self.fileStore.getChildren(fparent, 0)
        self.assertEqual(len(children), 2)
        self.assertTrue(file1 in children)
        self.assertTrue(file2 in children)

    def test_iteration(self):
        file1 = File("/path/to/file", 0, 0, "image/jpg")
        file2 = File("/path/to/document", 0, 5, "image/jpg")
        file3 = File("/path/to/document", 6, 0, "image/jpg")
        self.fileStore.addFile(file1)
        self.fileStore.addFile(file2)
        self.fileStore.addFile(file3)

        rebuilt = []
        for f in self.fileStore:
            rebuilt.append(f)
        self.assertEqual(len(rebuilt), 3)
        self.assertEqual(rebuilt[0], file2)
        self.assertEqual(rebuilt[1], file3)
        self.assertEqual(rebuilt[2], file1)

    def getChildren(self, f: File):
        parent = f.getName() + '/'
        children = []
        for item in [k for k, v in self.nameStore.items()
                     if k.startswith(parent)]:
            if item[0][len(parent)+1:].find('/') == -1:
                children.append(item[1])

        return children

    def tearDown(self):
        FileStore.reset()
        ApplicationStore.reset()
        FileFactory.reset()
