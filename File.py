"""Modelling the lifecycle of UNIX files."""
from enum import Enum


class File(object):
    """A UNIX File, with its time of existence and its history of names.

    A File is a representation of a filesystem file, which holds data on its
    lifecycle and type. Files are uniquely identified by their inode, or by
    their name + tstart + tend. When a file is renamed, a new File is created.
    """

    inode = 0     # type: int; a unique identifier to deal with renames
    path = ''     # type: str; the name of this file
    # TODO FIXME: decide if you'll index inodes and use that, or use name+time
    prevName = 0  # type: int; previous name of this file before it was renamed
    nextName = 0  # type: int; next name of this file after it will be renamed
    prevTime = 0  # type: int; time this file was renamed from previous to self
    nextTime = 0  # type: int; time this file was renamed from self to next
    tstart = 0    # type: int; when the file was created
    tend = 0      # type: int; when the file was deleted
    tsg = False   # type: bool; whether the file creation date is guessed
    teg = False   # type: bool; whether the file deletion date is guessed
    ftype = ''    # type: str; the MIME type of the file

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
        self.tstart = tstart
        self.tend = tend
        self.ftype = ftype

    def setGuessFlags(self, sf: bool, ef: bool):
        """Set whether the start and end times are guessed instead of known."""
        self.tsg = sf
        self.teg = ef

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

    def getPreviousName(self):
        """Return the previous name of the file, if any."""
        return self.prevName

    def getPreviousTime(self):
        """Return the time at which the file was renamed to self, if any."""
        return self.prevTime

    def getNextName(self):
        """Return the next name of the file, if any."""
        return self.nextName

    def getNextTime(self):
        """Return the time at which this file was renamed to next, if any."""
        return self.nextTime

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
