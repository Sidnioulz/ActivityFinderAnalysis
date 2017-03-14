from datetime import datetime
import os
from urllib.parse import urlparse, unquote
import re
import mimetypes
import random
import string
from constants import SPACE_REGEXP, PYTHONRE, PYTHONNAMER, PYTHONPROCNAME, \
                      JAVARE, JAVANAMER, JAVAPROCNAME, PERLRE, PERLNAMER, \
                      MONORE, MONONAMER, MONOPROCNAME, DEFAULTDATAPATH, \
                      NAMEDDATAPATHBASE, PHPRE, PHPNAMER, PHPPROCNAME

__opt_check = False
__opt_check_exclfiles = False
__opt_debug = False
__opt_output_fs = None
__opt_related_files = False
__opt_score = False
__opt_graph = False
__opt_plotting_disabled = False
__opt_clusters = False
__opt_user = None


def __setCheckMissing(opt):
    """Set the return value of :checkMissingEnabled():."""
    global __opt_check
    __opt_check = opt


def __setCheckExcludedFiles(opt):
    """Set the return value of :checkExcludedFilesEnabled():."""
    global __opt_check_exclfiles
    __opt_check_exclfiles = opt


def __setDebug(opt):
    """Set the return value of :debugEnabled():."""
    global __opt_debug
    __opt_debug = opt


def __setOutputFs(opt):
    """Set the return value of :outputFsEnabled():."""
    global __opt_output_fs
    __opt_output_fs = opt


def __setRelatedFiles(opt):
    """Set the return value of :relatedFilesEnabled():."""
    global __opt_related_files
    __opt_related_files = opt


def __setScore(opt):
    """Set the return value of :scoreEnabled():."""
    global __opt_score
    __opt_score = opt


def __setGraph(opt):
    """Set the return value of :graphEnabled():."""
    global __opt_graph
    __opt_graph = opt



def __setPlottingDisabled(opt):
    """Set the return value of :plottingDisabledEnabled():."""
    global __opt_plotting_disabled
    __opt_plotting_disabled = opt


def __setPrintClusters(opt):
    """Set the return value of :printClustersEnabled():."""
    global __opt_clusters
    __opt_clusters = opt


def __setUser(opt):
    """Set the return value of :userEnabled():."""
    global __opt_user
    __opt_user = opt


def checkMissingEnabled():
    """Return True if the --check-missing flag was passed, False otherwise."""
    global __opt_check
    return __opt_check


def checkExcludedFilesEnabled():
    """Return True if the --check-excluded-files flag was passed."""
    global __opt_check_exclfiles
    return __opt_check_exclfiles


def debugEnabled():
    """Return True if the --debug flag was passed, False otherwise."""
    global __opt_debug
    return __opt_debug


def outputFsEnabled():
    """Return the value passed to the --output-fs flag, if any."""
    global __opt_output_fs
    return __opt_output_fs


def relatedFilesEnabled():
    """Return True if --related-files was passed, False otherwise."""
    global __opt_related_files
    return __opt_related_files


def scoreEnabled():
    """Return True if --score was passed, False otherwise."""
    global __opt_score
    return __opt_score


def graphEnabled():
    """Return True if --graph was passed, False otherwise."""
    global __opt_graph
    return __opt_graph


def plottingDisabled():
    """Return True if --disable-plotting was passed, False otherwise."""
    global __opt_plotting_disabled
    return __opt_plotting_disabled


def printClustersEnabled():
    """Return True if --print-clusters was passed, False otherwise."""
    global __opt_clusters
    return __opt_clusters


def userEnabled():
    """Return the value of the --user flag, if any."""
    global __opt_user
    return __opt_user


def getDataPath():
    """Return the folder from which data is to be read."""
    if not userEnabled():
        return DEFAULTDATAPATH
    else:
        return NAMEDDATAPATHBASE + __opt_user + "/"


def genRandStr(count: int=10, chars=string.ascii_uppercase + string.digits):
    """Generate a random string."""
    return ''.join(random.choice(chars) for _ in range(count))


def time2Str(timestamp):
    """Transform a Zeitgeist timestamp into a human-readable string."""
    (timestamp, remainder) = divmod(timestamp, 1000)
    string = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    string += (".%d" % remainder)
    return string


def urlToUnixPath(url):
    """Convert a file:// URL to a Unix path string."""
    p = urlparse(url)
    return unquote(os.path.abspath(os.path.join(p.netloc, p.path)))


def uq(s):
    """Unquote a string."""
    return unquote(s)


def int16(i):
    """Convert strings to hexadecimal integers (unary version)."""
    if i == "(nil)":
        return -1
    else:
        return int(i, 16)


def hasIntersection(s1, s2):
    """Return True if two sets share at least one item, False otherwise."""
    for i in s1:
        for j in s2:
            if i == j:
                return True

    return False


def intersection(l1, l2):
    """Return the intersection of two lists. Naive implementation."""
    ret = []
    for i in l1:
        if i in l2:
            ret.append(i)

    return ret


def initMimeTypes():
    "Initialise the MIME type library and add Linux specific types."
    mimetypes.init()

    # We would use mimetypes.add_type but there's something rotten in the
    # mimetypes API and it ignores our added types...
    # TODO
    mimetypes.add_type("application/x-dia-diagram", ".dia", strict=False)

    mimetypes.add_type("application/octet-stream", ".rdb", strict=False)
    mimetypes.add_type("application/octet-stream", ".session", strict=False)
    mimetypes.add_type("application/octet-stream", ".idx", strict=False)
    mimetypes.add_type("application/octet-stream", ".dirs", strict=False)
    mimetypes.add_type("application/octet-stream", ".err", strict=False)
    mimetypes.add_type("application/octet-stream", ".error", strict=False)
    mimetypes.add_type("application/octet-stream", ".ICE-authority",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".ICE-authority-c",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".ICE-authority-n",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".ICE-authority-l",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".Xauthority", strict=False)
    mimetypes.add_type("application/octet-stream", ".Xdefaults", strict=False)
    mimetypes.add_type("application/octet-stream", ".u1conflict", strict=False)
    mimetypes.add_type("application/octet-stream", ".dropbox", strict=False)
    mimetypes.add_type("application/octet-stream", ".data", strict=False)
    mimetypes.add_type("application/octet-stream", ".xpt", strict=False)
    mimetypes.add_type("application/octet-stream", ".upload", strict=False)
    mimetypes.add_type("application/octet-stream", ".writeability",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".tdb", strict=False)
    mimetypes.add_type("application/octet-stream", ".sys", strict=False)
    mimetypes.add_type("application/octet-stream", ".lock", strict=False)
    mimetypes.add_type("application/octet-stream", ".pid", strict=False)
    mimetypes.add_type("application/octet-stream", ".addins", strict=False)
    mimetypes.add_type("application/octet-stream", ".maddin", strict=False)
    mimetypes.add_type("application/octet-stream", ".parentlock", strict=False)
    mimetypes.add_type("application/octet-stream", ".sqlite-journal",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".db-journal",
                       strict=False)
    mimetypes.add_type("application/octet-stream", ".pa", strict=False)
    mimetypes.add_type("application/octet-stream", ".crash", strict=False)
    mimetypes.add_type("application/octet-stream", ".tmp", strict=False)

    mimetypes.add_type("application/x-dosexec", ".sys", strict=False)

    mimetypes.add_type("application/vnd.oasis.opendocument.text", ".odt_0odt",
                       strict=False)
    mimetypes.add_type("application/vnd.oasis.opendocument.text", ".odt_1odt",
                       strict=False)
    mimetypes.add_type("application/vnd.oasis.opendocument.text",
                       ".untitled_0odt",
                       strict=False)
    mimetypes.add_type("application/vnd.oasis.opendocument.text",
                       ".untitled_1odt#",
                       strict=False)
    mimetypes.add_type("application/vnd.oasis.opendocument.text", ".odt_0odt",
                       strict=False)
    mimetypes.add_type("application/vnd.oasis.opendocument.text", ".odt_1odt#",
                       strict=False)

    mimetypes.add_type("inode/x-empty", ".new", strict=False)
    mimetypes.add_type("inode/x-empty", ".tbcache", strict=False)
    mimetypes.add_type("inode/x-empty", ".socket", strict=False)
    mimetypes.add_type("inode/x-empty", ".slave-socket", strict=False)
    mimetypes.add_type("inode/x-empty", ".shm", strict=False)
    mimetypes.add_type("inode/x-empty", ".sqlite-journal", strict=False)
    mimetypes.add_type("inode/x-empty", ".db-journal", strict=False)

    mimetypes.add_type("text/x-apport", ".crash", strict=False)

    mimetypes.add_type("text/cache-manifest", ".manifest", strict=False)

    mimetypes.add_type("application/graphml+xml", ".graphml", strict=False)

    mimetypes.add_type("text/plain", ".ini", strict=False)
    mimetypes.add_type("text/plain", ".cfg", strict=False)
    mimetypes.add_type("text/plain", ".desktop", strict=False)
    mimetypes.add_type("text/plain", ".manifest", strict=False)
    mimetypes.add_type("text/plain", ".mab", strict=False)
    mimetypes.add_type("text/plain", ".pmap", strict=False)
    mimetypes.add_type("text/plain", ".rc", strict=False)
    mimetypes.add_type("text/plain", ".kcache", strict=False)
    mimetypes.add_type("text/plain", ".access", strict=False)
    mimetypes.add_type("text/plain", ".session", strict=False)
    mimetypes.add_type("text/plain", ".aff", strict=False)
    mimetypes.add_type("text/plain", ".ovpn", strict=False)

    # mimetypes.add_type("text/x-c", ".rc", strict=False)
    # mimetypes.add_type("text/x-shellscript", ".rc", strict=False)

    mimetypes.add_type("text/markdown", ".md", strict=False)

    mimetypes.add_type("text/xml", ".xba", strict=False)
    mimetypes.add_type("text/xml", ".xbel", strict=False)
    mimetypes.add_type("text/xml", ".xcu", strict=False)
    # mimetypes.add_type("text/xml", ".session", strict=False)

    mimetypes.add_type("application/x-sqlite3", ".sqlite-shm", strict=False)
    mimetypes.add_type("application/x-sqlite3", ".sqlite-wal", strict=False)
    mimetypes.add_type("application/x-sqlite3", ".sqlite", strict=False)
    mimetypes.add_type("application/x-sqlite3", ".db", strict=False)

    mimetypes.add_type("text/x-tex", ".tex", strict=False)

    # for (key, ext) in sorted(mimetypes.types_map.items()):
    #     print("%s\t->\t%s" % (key, ext))
    # print("Done initialising MIME types.")


# Regular Expression parsers.
space = re.compile(SPACE_REGEXP)
pyre = re.compile(PYTHONRE)
pynamer = re.compile(PYTHONNAMER)
pyprocname = re.compile(PYTHONPROCNAME)
javare = re.compile(JAVARE)
javanamer = re.compile(JAVANAMER)
javaprocname = re.compile(JAVAPROCNAME)
perlre = re.compile(PERLRE)
perlnamer = re.compile(PERLNAMER)
monore = re.compile(MONORE)
mononamer = re.compile(MONONAMER)
monoprocname = re.compile(MONOPROCNAME)
phpre = re.compile(PHPRE)
phpnamer = re.compile(PHPNAMER)
phpprocname = re.compile(PHPPROCNAME)


# Get the last line of a file
BLOCKSIZE = 4096
def tail(f):
    # Save old position.
    oldPos = f.tell()

    # Seek to end of file to get file length.
    f.seek(0, 2)
    bytesInFile = f.tell()

    # Parse file to get tail.
    linesFound = 0
    totalBytesScanned = 0

    # Find any position (efficiently-ish) such that it's before 2+ lines.
    while (linesFound < 2 and bytesInFile > totalBytesScanned):
        byteBlock = min(BLOCKSIZE, bytesInFile - totalBytesScanned)
        f.seek( -(byteBlock + totalBytesScanned), 2)
        totalBytesScanned += byteBlock

        buff = f.read(BLOCKSIZE)
        try:
            countableBuff = buff.decode('utf-8')
        except(UnicodeDecodeError) as e:
            return None
        else:
            linesFound += countableBuff.count('\n')

    # Seek to that position where there are 2+ lines, and then read lines.
    f.seek(-totalBytesScanned, 2)
    lineList = list(f.readlines())

    # Reset position;
    f.seek(oldPos, 0)

    # Return the last line.
    try:
        readableLine = lineList[-1].decode('utf-8')
    except(UnicodeDecodeError) as e:
        return None
    else:
        return readableLine


# Copied from StackExchange, timed prints.
import atexit
from time import time
from datetime import timedelta

__timed_print_start = time()

def __secondsToStr(t):
    global __timed_print_start
    return str(timedelta(seconds=t - __timed_print_start))

def tprnt(msg: str):
    stripped = msg.lstrip("\n")
    leadingCount = len(msg) - len(stripped)
    print("%s%s: %s" % ("\n" * leadingCount, __secondsToStr(time()), stripped))

def __finalTimedPrint():
    tprnt("Exiting.")

def registerTimePrint():
    atexit.register(__finalTimedPrint)
