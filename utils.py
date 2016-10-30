from datetime import datetime
import os
from urllib.parse import urlparse, unquote


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
