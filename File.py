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
    designationcache = 1 << 9

    def __str__(self):
        """Human-readable version of the flags."""
        ret = "1" if self & EventFileFlags.designationcache else "0"
        ret += "1" if self & EventFileFlags.programmatic else "0"
        ret += "1" if self & EventFileFlags.designation else "0"
        ret += " "
        ret += "1" if self & EventFileFlags.write else "0"
        ret += "1" if self & EventFileFlags.read else "0"
        ret += " "
        ret += "1" if self & EventFileFlags.copy else "0"
        ret += "1" if self & EventFileFlags.move else "0"
        ret += " "
        ret += "1" if self & EventFileFlags.destroy else "0"
        ret += "1" if self & EventFileFlags.overwrite else "0"
        ret += "1" if self & EventFileFlags.create else "0"
        return ret

    def __eq__(self, other):
        return int(self) == int(other)


class FileAccess(object):
    """Something to hold info on who accessed a File."""
    actor = None    # type: Application
    time = 0        # type: int
    evflags = None  # type: EventFileFlags

    def __init__(self,
                 actor: Application,
                 time: int,
                 evflags: EventFileFlags):
        """Construct a FileAccess."""
        super(FileAccess, self).__init__()
        self.actor = actor
        self.time = time
        self.evflags = EventFileFlags(evflags)

    def getActor(self):
        """Return the actor that accessed the File."""
        return self.actor

    def getTime(self):
        """Return the time at which the access occurred."""
        return self.time

    def getFileFlags(self):
        """Return the EventFileFlags that describe this access event."""
        return self.evflags

class FileCopy(object):
    """Something to hold info on a File's previous or next version."""
    path = ''
    time = 0
    copytype = None

    def __init__(self,
                 path: str,
                 time: int,
                 copytype: str):
        """Construct a FileCopy, with a type ('move', 'copy', 'link').

        Valid types are 'move', 'copy', 'link' and 'symlink'.
        """
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
    links = None   # type: list list of hard links to this File
    symlinksrc = None  # type: FileCopy; target of this file if it is a symlink
    symlinks = None    # type: list list of symbolic links to this File
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

    def __eq__(self, other: 'File'):
        """Override the default Equals behavior"""
        if isinstance(other, self.__class__):
            return self.inode == other.inode
        return False

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
        self.links = []
        self.symlinksrc = None
        self.symlinks = []
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

    def addLink(self, linkedFile: 'File'):
        """Add a hard link to this File."""
        self.links.append(linkedFile)
        linkedFile.links.append(self)

    def removeLink(self, linkedFile: 'File'):
        """Remove a hard link from this File."""
        self.links.remove(linkedFile)
        linkedFile.links.remove(self)

    def symlink(self, linkedFile: 'File'):
        """Add a symbolic link to this File."""
        linkedFile.symlinks.append(self)
        self.symlinksrc = linkedFile

    def removeSymlink(self, linkedFile: 'File'):
        """Add a symbolic link to this File."""
        linkedFile.symlinks.remove(self)
        self.symlinksrc = None

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

    def getAccesses(self, flags: EventFileFlags=None):
        """Get the acts of access on this File."""
        if not flags:
            return self.accesses
        else:
            ret = []
            for access in self.accesses:
                if access.evflags & flags:
                    ret.append(access)

            return ret
