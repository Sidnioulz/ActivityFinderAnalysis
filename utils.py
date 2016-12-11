from datetime import datetime
import os
from urllib.parse import urlparse, unquote
import re
from constants import SPACE_REGEXP, PYTHONRE, PYTHONNAMER, PYTHONPROCNAME, \
                      JAVARE, JAVANAMER, JAVAPROCNAME, PERLRE, PERLNAMER, \
                      MONORE, MONONAMER, MONOPROCNAME

__opt_check = False
__opt_debug = False
__opt_output_fs = None
__opt_related_files = None
__opt_score = None


def __setCheckMissing(opt):
    """Set the return value of :checkMissingEnabled():."""
    global __opt_check
    __opt_check = opt


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


def checkMissingEnabled():
    """Return True if the --check-missing flag was passed, False otherwise."""
    global __opt_check
    return __opt_check


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


# Regular Expression parsers
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
