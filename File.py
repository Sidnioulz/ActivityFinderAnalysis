"""Modelling the lifecycle of UNIX files."""

from enum import Enum


class FileType(Enum):
    """Supported file types for our analysis tool."""

    unknown = 0
    regular = 1
    folder = 2
    socket = 3


class File(object):
    """A UNIX File, with its time of existence and its history of names.

    A File is a representation of a filesystem file, which holds data on its
    lifecycle and type. Files are uniquely identified by their inode, or by
    their name + tstart + tend. When a file is renamed, a new File is created.
    """

    inode = 0     # type: int; a unique identifier to deal with renames
    path = ''     # type: str; the name of this file
    prevName = 0  # type: int; previous name of this file before it was renamed
    nextName = 0  # type: int; next name of this file after it will be renamed
    tstart = 0    # type: int; when the file was created
    tend = 0      # type: int; when the file was deleted
    fileType = FileType.unknown  # type: FileType

    @staticmethod
    def __allocInode(file):
        """Get an inode number allocated to a new File object."""
        File.inode += 1
        file.inode = File.inode

    def __init__(self, path: str, tstart: int=0, tend: int=0):
        """Construct a File, with a path and optional start and end times."""
        super(File, self).__init__()

        if not path:
            raise ValueError("Files must have a valid path.")

        self.path = path
        self.tstart = tstart
        self.tend = tend
