"""Modelling the lifecycle of UNIX files."""
from os.path import dirname
from Application import Application
from flags import Flags
from utils import time2Str
import mimetypes


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

    def containsAllAccessFlags(self, other):
        """Tell if other contains access not contained in self.

        For instance, this function returns True if :other: only reads Files,
        and :self: reads or writes Files. It returns False if :other: copies
        Files, but :self: only reads them.
        """
        if not isinstance(other, self.__class__):
            return False

        # Ignore the access mode flags and focus on access types.
        self = (self | EventFileFlags.designationcache |
                EventFileFlags.designation | EventFileFlags.programmatic)
        other = (other | EventFileFlags.designationcache |
                 EventFileFlags.designation | EventFileFlags.programmatic)

        return self & other == other


class FileAccess(object):
    """Something to hold info on who accessed a File."""

    def __init__(self,
                 actor: Application,
                 time: int,
                 evflags: EventFileFlags):
        """Construct a FileAccess."""
        super(FileAccess, self).__init__()
        self.actor = actor
        self.time = time
        self.evflags = EventFileFlags(evflags)

    def __str__(self):
        """Human-readable version of the FileAccess."""
        ret = "<FileAccess from %s at time %s: %s" % (
               self.actor.uid(),
               self.time,
               self.evflags)
        return ret

    def getActor(self):
        """Return the actor that accessed the File."""
        return self.actor

    def getTime(self):
        """Return the time at which the access occurred."""
        return self.time

    def getFileFlags(self):
        """Return the EventFileFlags that describe this access event."""
        return self.evflags

    def isReadOnly(self):
        """Return True if the FileAccess did not modify the File."""
        return self.evflags & EventFileFlags.read

    def isByDesignation(self):
        """Return True if this FileAccess is performed by designation."""
        return (self.evflags & EventFileFlags.designation) and \
            not (self.evflags & EventFileFlags.designationcache)

    def isFileCreation(self):
        """Return True if this FileAccess created a File."""
        return (self.evflags & EventFileFlags.create) or \
            (self.evflags & EventFileFlags.overwrite)

    def allowedByFlagFilter(self, filter: EventFileFlags, f: 'File'):
        if filter.containsAllAccessFlags(self.evflags):
            return True

        # Filters with only the create flag represent the UNIX sticky bit
        elif filter == EventFileFlags.create:
            try:
                accs = f.getAccesses(filter)
                firstAccess = next(accs)
                if firstAccess.actor == self.actor:
                    return True
            except(StopIteration):
                pass

            # The file was created by the same actor, the sticky bit is valid
            from FileFactory import FileFactory
            fileFactory = FileFactory.get()
            parentPath = f.getParentName()
            if parentPath:
                parent = fileFactory.getFileIfExists(parentPath, self.time)
                if parent:
                    return self.allowedByFlagFilter(filter, parent)
        return False


class FileCopy(object):
    """Something to hold info on a File's previous or next version."""

    def __init__(self,
                 inode: int,
                 time: int,
                 copytype: str):
        """Construct a FileCopy, with a type ('move', 'copy', 'link').

        Valid types are 'move', 'copy', 'link' and 'symlink'.
        """
        super(FileCopy, self).__init__()
        self.inode = inode
        self.time = time
        self.copytype = copytype


class File(object):
    """A UNIX File, with its time of existence and its history of names.

    A File is a representation of a filesystem file, which holds data on its
    lifecycle and type. Files are uniquely identified by their inode, or by
    their name + tstart + tend. When a file is renamed, a new File is created.
    """

    inode = 0  # type: int; global inode counter used for inode allocation.
    _namecache = dict()

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

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        """Human-readable version of the File."""
        ret = "<File %d - '%s' created on '%s'%s" % (
               self.inode,
               self.path,
               time2Str(self.tstart),
               ", deleted on '%s'" % time2Str(self.tend) if self.tend else '')
        return ret

    def __hash__(self):
        """Return a hash for this File."""
        return hash(self.inode)

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
        if ftype:
            self.ftype = ftype
        else:
            self.ftype = None
            self.guessType()
        self.accesses = []
        self.accessCosts = dict()
        self._isFolder = None
        self._isHidden = None
        self._inHiddenFolder = None

    def guessType(self):
        """Guess the type of the File, and set it automatically."""
        fileType = mimetypes.guess_type(self.path, strict=False)
        if fileType and fileType[0]:
            self.ftype = fileType[0]

    def setGuessFlags(self, sf: bool, ef: bool):
        """Set whether the start and end times are guessed instead of known."""
        self.tsg = sf
        self.teg = ef

    @staticmethod
    def getParentNameFromName(path: str):
        """Return the path of an arbitrary path string's parent folder."""
        if not path:
            return None

        if path not in File._namecache:
            parentPath = dirname(path)
            File._namecache[path] = parentPath if path != parentPath else None

        return File._namecache[path]

    def getParentName(self):
        """Return the path of the file's parent folder."""
        return File.getParentNameFromName(self.path)

    def getName(self):
        """Return the path of the file."""
        return self.path

    def getNameWithoutExtension(self):
        """Return the path of the file without its ending extension."""
        dot = self.path.rfind(".")
        slash = self.path.rfind("/")

        if dot <= slash+1:
            return self.path
        else:
            return self.path[:dot]

    def getFileName(self, folderEnd: bool=False):
        """Return the file name (last end of the path) of the file."""
        lastDir = self.path.rfind('/')

        if lastDir == 0 and not folderEnd:
            name = self.path
        elif lastDir >= 0:
            name = self.path[lastDir+1:]
        else:
            name = self.path

        return name + ('/' if folderEnd and self.isFolder() else '')

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

    def setPredecessor(self, inode: int, time: int, copytype: str):
        self.pred = FileCopy(inode, time, copytype)

    def addFollower(self, inode: int, time: int, copytype: str):
        copy = FileCopy(inode, time, copytype)
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

    def isUserDocument(self, userHome: str, allowHiddenFiles: bool=False):
        """Return True if the file is not hidden, and in ~ or /media."""
        if allowHiddenFiles:
            # We also don't allow hidden files at the Home root as they are
            # usually configuration files or X11 data.
            if self.isInHiddenFolder() or self.path.startswith(userHome+"/."):
                return False
        elif self.isHidden():
            return False

        if not self.path.startswith("/media") and \
                not self.path.startswith("/mnt") and \
                not self.path.startswith(userHome):
            return False

        return True

    def isInHiddenFolder(self):
        """Return True if the file is in a hidden parent folder."""
        if self._inHiddenFolder is None:
            hasParent = True
            hidden = False
            path = self.path

            while hasParent and not hidden:
                path = File.getParentNameFromName(path)
                hasParent = True if path else False

                if hasParent:
                    lastDir = path.rfind('/')

                    if lastDir >= 0:
                        hidden = len(path) > lastDir+1 and \
                            path[lastDir+1] == '.'
                    else:
                        hidden = path[0] == '.'

            self._inHiddenFolder = hidden

        return self._inHiddenFolder

    def isHidden(self):
        """Return True if the file is hidden (name starts with a dot)."""
        if self._isHidden is None:
            hasParent = True
            hidden = False
            path = self.path

            while hasParent and not hidden:
                lastDir = path.rfind('/')

                if lastDir >= 0:
                    hidden = len(path) > lastDir+1 and path[lastDir+1] == '.'
                else:
                    hidden = path[0] == '.'

                path = File.getParentNameFromName(path)
                hasParent = True if path else False
            self._isHidden = hidden

        return self._isHidden

    def isFolder(self):
        """Return True if the file is a folder."""
        if self._isFolder is None:
            self._isFolder = self.ftype in ("inode/directory",)

        return self._isFolder

    def isBinary(self):
        """Return true if the file is binary, or not a known format."""
        return self.ftype in ("application/octet-stream",)

    def addAccess(self, actor: Application, time: int, flags: EventFileFlags):
        """Record an access event for this File."""
        acc = FileAccess(actor, time, flags)
        self.accesses.append(acc)

    def hasAccesses(self):
        """Tell whether a File has had any accesses at all."""
        return False if not self.accesses else True

    def getAccesses(self, flags: EventFileFlags=None):
        """Get the acts of access on this File."""
        for access in self.accesses:
            if (not flags) or (access.evflags & flags):
                yield access

    def getAccessCount(self, flags: EventFileFlags=None):
        """Get the number of acts of access on this File."""
        if not flags:
            return len(self.accesses)

        cnt = 0
        for access in self.accesses:
            if access.evflags & flags:
                cnt += 1
        return cnt

    def clearAccessCosts(self):
        """Remove any past access costs that were recorded."""
        self.accessCosts.clear()

    def _getAccessCost(self,
                       acc: FileAccess,
                       accessType: int,
                       appWide: bool=False):
        """Get the recorded access cost for a FileAccess and type."""
        costsForType = self.accessCosts.get(accessType) or dict()
        key = acc.actor.uid() if not appWide else acc.actor.desktopid
        return costsForType.get(key) or EventFileFlags.no_flags

    def _setAccessCost(self,
                       acc: FileAccess,
                       accCost: EventFileFlags,
                       accessType: int,
                       appWide: bool=False):
        """Set the record access cost for a FileAccess and type."""
        costsForType = self.accessCosts.get(accessType) or dict()
        key = acc.actor.uid() if not appWide else acc.actor.desktopid
        costsForType[key] = accCost
        self.accessCosts[accessType] = costsForType

    def recordAccessCost(self,
                         acc: FileAccess,
                         accessType: int,
                         appWide: bool=False):
        """Record that a cost was paid to allow a past illegal access.

        This function allows us to remember past accesses to a file which led
        to a cost for end users. Here are how each type of access are treated:
         * create: recorded, grants additional rights
         * overwrite: recorded
         * destroy: NOT recorded; deleting the same name would be another file.
         * move: NOT recorded; moving the same name would be another file.
         * copy: recorded source; not recorded target
         * read: recorded
         * write: recorded

         # ALLOW moving and copying to the same destination again
        """
        recordedFlags = acc.evflags & (EventFileFlags.create |
                                       EventFileFlags.overwrite |
                                       EventFileFlags.read |
                                       EventFileFlags.write)
        if acc.evflags & EventFileFlags.copy and \
                acc.evflags & EventFileFlags.read:
            recordedFlags |= EventFileFlags.copy
        elif acc.evflags & EventFileFlags.create:
            recordedFlags |= (EventFileFlags.read | EventFileFlags.write |
                              EventFileFlags.destroy | EventFileFlags.move |
                              EventFileFlags.copy | EventFileFlags.overwrite)
        # TODO: move destionations and copy destionations should be allowed

        accCost = self._getAccessCost(acc, accessType, appWide)
        self._setAccessCost(acc, accCost | recordedFlags, accessType, appWide)

    def hadPastSimilarAccess(self,
                             acc: FileAccess,
                             accessType: int,
                             appWide: bool=False):
        """Check if a similar access was recorded for the same app."""
        accCost = self._getAccessCost(acc, accessType, appWide)

        recordedFlags = acc.evflags & (EventFileFlags.create |
                                       EventFileFlags.overwrite |
                                       EventFileFlags.read |
                                       EventFileFlags.write)
        if acc.evflags & EventFileFlags.copy and \
                acc.evflags & EventFileFlags.read:
            recordedFlags |= EventFileFlags.copy

        return (recordedFlags & accCost == recordedFlags)

    def writeStatistics(self, out):
        """Write information on creation, deletion and accesses to the File."""
        print("FILE %d@%s" % (self.inode, self.path), file=out)
        print("CREATED %d" % self.tstart, file=out)
        print("DELETED %d" % self.tend, file=out)
        for a in self.accesses:
            print("*%s|%d|%s" % (a.actor.uid(), a.time, a.evflags), file=out)
