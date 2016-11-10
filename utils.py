from datetime import datetime
import os
from urllib.parse import urlparse, unquote
import re
from constants import SPACE_REGEXP, PYTHONRE, PYTHONNAMER, PYTHONPROCNAME, \
                      JAVARE, JAVANAMER, JAVAPROCNAME, PERLRE, PERLNAMER, \
                      MONORE, MONONAMER, MONOPROCNAME

__opt_check = False
__opt_debug = False

def __setCheckMissing(opt):
    global __opt_check
    __opt_check = opt


def __setDebug(opt):
    global __opt_debug
    __opt_debug = opt


def checkMissingEnabled():
    global __opt_check
    return __opt_check


def debugEnabled():
    global __opt_debug
    return __opt_debug


def time2Str(timestamp):
    """Transforms a Zeitgeist timestamp into a human-readable string."""
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
    """A unary function to convert strings to hexadecimal integers."""
    if i == "(nil)":
        return 0
    else:
        return int(i, 16)

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
