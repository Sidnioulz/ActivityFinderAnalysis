"""Modelling the lifecycle of UNIX files."""
from os.path import dirname
from Application import Application
from flags import Flags


class EventFileFlags(Flags):
    """Flags for accesses to files in Events."""

    create = 1 << 0
    overwrite = 1 << 1
    destroy = 1 << 2
    move = 1 << 3
    copy = 1 << 4
    read = 1 << 5
    write = 1 << 6
    designation = 1 << 7
    programmatic = 1 << 8


class FileAccess(object):
    """Something to hold info on who accessed a File."""
    actor = None       # type: Application
    time = 0           # type: int
    accessType = None  # type: event

    def __init__(self,
                 actor: Application,
                 time: int,
                 accessType: EventFileFlags):
        """Construct a FileAccess."""
        super(FileAccess, self).__init__()
        self.actor = actor
        self.time = time
        self.accessType = accessType


class FileCopy(object):
    """Something to hold info on a File's previous or next version."""
    path = ''
    time = 0
    copytype = None

    def __init__(self,
                 path: str,
                 time: int,
                 copytype: str):
        """Construct a FileCopy, with a type ('move', 'copy', or 'link')."""
        super(FileCopy, self).__init__()
        self.path = path
        self.time = time
        self.copytype = copytype


class File(object):
    """A UNIX File, with its time of existence and its history of names.

    A File is a representation of a filesystem file, which holds data on its
    lifecycle and type. Files are uniquely identified by their inode, or by
    their name + tstart + tend. When a file is renamed, a new File is created.
    """

    inode = 0      # type: int; a unique identifier to deal with renames
    path = ''      # type: str; the name of this file
    pred = None    # type: FileCopy; previous name of this file before renaming
    follow = None  # type: list; next name of this file after renaming
    # TODO links
    tstart = 0     # type: int; when the file was created
    tend = 0       # type: int; when the file was deleted
    tsg = False    # type: bool; whether the file creation date is guessed
    teg = False    # type: bool; whether the file deletion date is guessed
    ftype = ''     # type: str; the MIME type of the file
    accesses = []  # type: list; access events to this File

    @staticmethod
    def __allocInode(file):
        """Get an inode number allocated to a new File object."""
        File.inode += 1
        file.inode = File.inode

    def __init__(self,
                 path: str,
                 tstart: int=0,
                 tend: int=0,
                 ftype: str=''):
        """Construct a File, with a path and optional start and end times."""
        super(File, self).__init__()

        if not path:
            raise ValueError("Files must have a valid path.")

        File.__allocInode(self)
        self.path = path
        self.pred = None
        self.follow = []
        self.tstart = tstart
        self.tend = tend
        self.tsg = False
        self.teg = False
        self.ftype = ftype
        self.accesses = []

    def setGuessFlags(self, sf: bool, ef: bool):
        """Set whether the start and end times are guessed instead of known."""
        self.tsg = sf
        self.teg = ef

    @staticmethod
    def getParentName(path: str):
        if not path:
            return None

        parentPath = dirname(path)
        return parentPath if path != parentPath else None

    def getName(self):
        """Return the path of the file."""
        return self.path

    def getTimeOfStart(self):
        """Return the time at which the file was known to start existing."""
        return self.tstart

    def setTimeOfStart(self, tstart):
        """Set the time at which the file was known to start existing."""
        self.tstart = tstart

    def getTimeOfEnd(self):
        """Return the time at which the file was known to cease existing."""
        return self.tend

    def setTimeOfEnd(self, tend):
        """Set the time at which the file was known to cease existing."""
        self.tend = tend

    def getPredecessor(self):
        """Return the previous name of the file, if any."""
        return self.pred

    def getFollowers(self):
        """Return the next names of the file, if any."""
        return self.follow

    def setPredecessor(self, name: str, time: int, copytype: str):
        self.pred = FileCopy(name, time, copytype)

    def addFollower(self, name: str, time: int, copytype: str):
        copy = FileCopy(name, time, copytype)
        self.follow.append(copy)

    def clearFollowers(self):
        self.follow.clear()

    def setType(self, ftype: str):
        """Set the MIME type of the file to the given value."""
        self.ftype = ftype

    def getType(self):
        """Return the MIME type of the file."""
        return self.ftype

    def isFolder(self):
        """Return True if the file is a folder."""
        return self.ftype in ("inode/directory",)

    def isBinary(self):
        """Return true if the file is binary, or not a known format."""
        return self.ftype in ("application/octet-stream",)

    def addAccess(self, actor: Application, time: int, flags: EventFileFlags):
        """Record an access event for this File."""
        acc = FileAccess(actor, time, flags)
        self.accesses.append(acc)
