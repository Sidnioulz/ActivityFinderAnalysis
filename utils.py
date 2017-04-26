from datetime import datetime
import os
from urllib.parse import urlparse, unquote
import re
import mimetypes
import random
import string
from constants import SPACE_REGEXP, PYTHONRE, PYTHONNAMER, PYTHONPROCNAME, \
                      BASHRE, BASHNAMER, BASHPROCNAME, \
                      JAVARE, JAVANAMER, JAVAPROCNAME, PERLRE, PERLNAMER, \
                      MONORE, MONONAMER, MONOPROCNAME, DEFAULTDATAPATH, \
                      NAMEDDATAPATHBASE, PHPRE, PHPNAMER, PHPPROCNAME

__opt_check = False
__opt_check_exclfiles = False
__opt_debug = False
__opt_ext = False
__opt_freq = 40
__opt_output_fs = None
__opt_related_files = False
__opt_score = False
__opt_skip = None
__opt_graph = False
__opt_plotting_disabled = False
__opt_clusters = False
__opt_user = None
__opt_attack = False


def __setAttacks(opt):
    """Set the return value of :AttacksEnabled():."""
    global __opt_attack
    __opt_attack = opt


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


def __setPrintExtensions(opt):
    """Set the return value of :printExtensions():."""
    global __opt_ext
    __opt_ext = opt


def __setFrequency(opt):
    """Set the return value of :frequency():."""
    global __opt_freq
    __opt_freq = int(opt)


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


def __setSkip(opt):
    """Set the return value of :skipEnabled():."""
    global __opt_skip
    __opt_skip = opt


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


def attacksEnabled():
    """Return True if the --attacks flag was passed, False otherwise."""
    global __opt_attack
    return __opt_attack


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


def printExtensions():
    """Return True if the --extensions flag was passed, False otherwise."""
    global __opt_ext
    return __opt_ext


def frequency():
    """Return the value passed to the --frequency flag (default 40)."""
    global __opt_freq
    return __opt_freq


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


def skipEnabled():
    """Return the value of --skip if it was passed, None otherwise."""
    global __opt_skip
    return __opt_skip


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
    mimetypes.add_type("text/markdown", ".markdown", strict=False)

    mimetypes.add_type("text/xml", ".xba", strict=False)
    mimetypes.add_type("text/xml", ".xbel", strict=False)
    mimetypes.add_type("text/xml", ".xcu", strict=False)
    # mimetypes.add_type("text/xml", ".session", strict=False)

    mimetypes.add_type("application/x-sqlite3", ".sqlite-shm", strict=False)
    mimetypes.add_type("application/x-sqlite3", ".sqlite-wal", strict=False)
    mimetypes.add_type("application/x-sqlite3", ".sqlite", strict=False)
    mimetypes.add_type("application/x-sqlite3", ".db", strict=False)

    mimetypes.add_type("text/x-tex-aux", ".aux", strict=False)
    mimetypes.add_type("text/x-bibtex", ".bib", strict=False)
    mimetypes.add_type("text/x-tex", ".tex", strict=False)

    mimetypes.add_type("application/java-archive", ".aar", strict=False)
    mimetypes.add_type("application/octet-stream", ".acm", strict=False)
    mimetypes.add_type("application/octet-stream", ".adb", strict=False)
    mimetypes.add_type("application/octet-stream", ".addon", strict=False)
    mimetypes.add_type("text/plain", ".ads", strict=False)
    mimetypes.add_type("image/x-pix", ".alias", strict=False)
    mimetypes.add_type("text/plain", ".am", strict=False)
    mimetypes.add_type("application/octet-stream", ".app", strict=False)
    mimetypes.add_type("text/plain", ".ashx", strict=False)
    mimetypes.add_type("application/octet-stream", ".asi", strict=False)
    mimetypes.add_type("application/octet-stream", ".as", strict=False)
    mimetypes.add_type("text/plain", ".aspx", strict=False)
    mimetypes.add_type("application/x-photoshop", ".asv", strict=False)
    mimetypes.add_type("application/octet-stream", ".avd", strict=False)
    mimetypes.add_type("text/plain", ".awk", strict=False)
    mimetypes.add_type("text/plain", ".axd", strict=False)
    mimetypes.add_type("application/octet-stream", ".bau", strict=False)
    mimetypes.add_type("application/octet-stream", ".blob", strict=False)
    mimetypes.add_type("text/plain", ".bb", strict=False)
    mimetypes.add_type("application/octet-stream", ".bc", strict=False)
    mimetypes.add_type("application/blender", ".blend", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend1", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend2", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend3", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend4", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend5", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend6", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend7", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend8", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend9", strict=False)
    mimetypes.add_type("application/blender-backup", ".blend10", strict=False)
    mimetypes.add_type("application/octet-stream", ".bnk", strict=False)
    mimetypes.add_type("application/octet-stream", ".bor", strict=False)
    mimetypes.add_type("image/x-sgi", ".bw", strict=False)
    mimetypes.add_type("application/x-bzip2", ".bz2", strict=False)
    mimetypes.add_type("text/plain", ".cmake", strict=False)
    mimetypes.add_type("application/octet-stream", ".circ", strict=False)
    mimetypes.add_type("application/octet-stream", ".cgi", strict=False)
    mimetypes.add_type("application/octet-stream", ".cn", strict=False)
    mimetypes.add_type("application/octet-stream", ".cnf", strict=False)
    mimetypes.add_type("application/x-com", ".com", strict=False)
    mimetypes.add_type("application/octet-stream", ".cpl", strict=False)
    mimetypes.add_type("application/octet-stream", ".crypt", strict=False)
    mimetypes.add_type("application/octet-stream", ".csl", strict=False)
    mimetypes.add_type("application/octet-stream", ".cs", strict=False)
    mimetypes.add_type("application/octet-stream", ".csr", strict=False)
    mimetypes.add_type("text/css", ".css_t", strict=False)
    mimetypes.add_type("image/x-win-bitmap", ".cur", strict=False)
    mimetypes.add_type("application/octet-stream", ".CVS", strict=False)
    mimetypes.add_type("application/octet-stream", ".dat_i", strict=False)
    mimetypes.add_type("application/octet-stream", ".dbf", strict=False)
    mimetypes.add_type("application/octet-stream", ".dbt", strict=False)
    mimetypes.add_type("application/octet-stream", ".dbx", strict=False)
    mimetypes.add_type("image/x-dcx", ".dcx", strict=False)
    mimetypes.add_type("application/octet-stream", ".del", strict=False)
    mimetypes.add_type("application/octet-stream", ".desc", strict=False)
    mimetypes.add_type("application/octet-stream", ".dex", strict=False)
    mimetypes.add_type("application/octet-stream", ".dj2", strict=False)
    mimetypes.add_type("application/x-msdownload", ".dll16", strict=False)
    mimetypes.add_type("application/octet-stream", ".drv16", strict=False)
    mimetypes.add_type("application/octet-stream", ".drv", strict=False)
    mimetypes.add_type("application/octet-stream", ".ds", strict=False)
    mimetypes.add_type("application/octet-stream", ".egg", strict=False)
    mimetypes.add_type("application/octet-stream", ".elf", strict=False)
    mimetypes.add_type("application/octet-stream", ".emx", strict=False)
    mimetypes.add_type("application/octet-stream", ".enc", strict=False)
    mimetypes.add_type("application/octet-stream", ".er1", strict=False)
    mimetypes.add_type("application/octet-stream", ".er2", strict=False)
    mimetypes.add_type("application/octet-stream", ".eth", strict=False)
    mimetypes.add_type("application/octet-stream", ".eu", strict=False)
    mimetypes.add_type("text/plain", ".exc", strict=False)
    mimetypes.add_type("application/x-ms-dos-executable", ".exe16", strict=False)
    mimetypes.add_type("application/octet-stream", ".exp", strict=False)
    mimetypes.add_type("application/octet-stream", ".fdt", strict=False)
    mimetypes.add_type("application/octet-stream", ".fdx", strict=False)
    mimetypes.add_type("text/x-fortran", ".fi", strict=False)
    mimetypes.add_type("application/octet-stream", ".flt", strict=False)
    mimetypes.add_type("application/octet-stream", ".fmt", strict=False)
    mimetypes.add_type("application/octet-stream", ".fnm", strict=False)
    mimetypes.add_type("application/octet-stream", ".fon", strict=False)
    mimetypes.add_type("application/octet-stream", ".font", strict=False)
    mimetypes.add_type("application/octet-stream", ".frag", strict=False)
    mimetypes.add_type("application/octet-stream", ".frq", strict=False)
    mimetypes.add_type("application/octet-stream", ".gbk", strict=False)
    mimetypes.add_type("application/octet-stream", ".ggr", strict=False)
    mimetypes.add_type("text/xml", ".glade", strict=False)
    mimetypes.add_type("application/octet-stream", ".G", strict=False)
    mimetypes.add_type("application/octet-stream", ".gnu", strict=False)
    mimetypes.add_type("application/gpg-keys", ".gpg", strict=False)
    mimetypes.add_type("text/plain", ".gpl", strict=False)
    mimetypes.add_type("text/plain", ".gtkrc", strict=False)
    mimetypes.add_type("application/octet-stream", ".gypi", strict=False)
    mimetypes.add_type("application/octet-stream", ".gyp", strict=False)
    mimetypes.add_type("application/x-gzip", ".gz", strict=False)
    mimetypes.add_type("application/octet-stream", ".h0", strict=False)
    mimetypes.add_type("application/octet-stream", ".hbs", strict=False)
    mimetypes.add_type("application/octet-stream", ".hd", strict=False)
    mimetypes.add_type("application/octet-stream", ".his", strict=False)
    mimetypes.add_type("application/octet-stream", ".icns", strict=False)
    mimetypes.add_type("image/x-icon", ".icon", strict=False)
    mimetypes.add_type("application/octet-stream", ".id", strict=False)
    mimetypes.add_type("application/octet-stream", ".img", strict=False)
    mimetypes.add_type("application/octet-stream", ".iml", strict=False)
    mimetypes.add_type("application/octet-stream", ".im", strict=False)
    mimetypes.add_type("application/octet-stream", ".inc", strict=False)
    mimetypes.add_type("application/x-inf", ".inf", strict=False)
    mimetypes.add_type("text/plain", ".i", strict=False)
    mimetypes.add_type("application/octet-stream", ".inv", strict=False)
    mimetypes.add_type("application/octet-stream", ".io", strict=False)
    mimetypes.add_type("application/octet-stream", ".ipc", strict=False)
    mimetypes.add_type("application/octet-stream", ".ipynb", strict=False)
    mimetypes.add_type("application/octet-stream", ".itdb", strict=False)
    mimetypes.add_type("image/jpc", ".j2k", strict=False)
    mimetypes.add_type("application/octet-stream", ".ja", strict=False)
    mimetypes.add_type("application/octet-stream", ".jdt", strict=False)
    mimetypes.add_type("image/jp2", ".jp2", strict=False)
    mimetypes.add_type("text/javascript", ".jsm", strict=False)
    mimetypes.add_type("application/octet-stream", ".jws", strict=False)
    mimetypes.add_type("application/octet-stream", ".kdbx", strict=False)
    mimetypes.add_type("audio/x-la", ".la", strict=False)
    mimetypes.add_type("application/octet-stream", ".LCK", strict=False)
    mimetypes.add_type("application/octet-stream", ".lck", strict=False)
    mimetypes.add_type("application/octet-stream", ".ld", strict=False)
    mimetypes.add_type("application/octet-stream", ".len", strict=False)
    mimetypes.add_type("application/octet-stream", ".le", strict=False)
    mimetypes.add_type("application/octet-stream", ".lo", strict=False)
    mimetypes.add_type("application/octet-stream", ".love", strict=False)
    mimetypes.add_type("application/octet-stream", ".lst", strict=False)
    mimetypes.add_type("application/octet-stream", ".lt", strict=False)
    mimetypes.add_type("text/plain", ".lua", strict=False)
    mimetypes.add_type("application/octet-stream", ".lut", strict=False)
    mimetypes.add_type("text/plain", ".m4", strict=False)
    mimetypes.add_type("text/plain", ".make", strict=False)
    mimetypes.add_type("text/plain", ".mak", strict=False)
    mimetypes.add_type("application/octet-stream", ".map", strict=False)
    mimetypes.add_type("application/octet-stream", ".mdc", strict=False)
    mimetypes.add_type("text/plain", ".menu", strict=False)
    mimetypes.add_type("application/x-tex-mf", ".MF", strict=False)
    mimetypes.add_type("application/x-tex-mf", ".mf", strict=False)
    mimetypes.add_type("image/vnd.mix", ".mix", strict=False)
    mimetypes.add_type("text/plain", ".mk", strict=False)
    mimetypes.add_type("text/plain", ".ml", strict=False)
    mimetypes.add_type("application/vnd.wap.mms-message", ".mms", strict=False)
    mimetypes.add_type("application/matlab-m", ".m", strict=False)
    mimetypes.add_type("audio/x-mod", ".mod16", strict=False)
    mimetypes.add_type("audio/x-mod", ".mod", strict=False)
    mimetypes.add_type("application/octet-stream", ".mo", strict=False)
    mimetypes.add_type("image/mpo", ".mpo", strict=False)
    mimetypes.add_type("application/octet-stream", ".msc", strict=False)
    mimetypes.add_type("image/msp", ".msp", strict=False)
    mimetypes.add_type("application/octet-stream", ".mtl", strict=False)
    mimetypes.add_type("application/octet-stream", ".mwb", strict=False)
    mimetypes.add_type("application/octet-stream", ".MYD", strict=False)
    mimetypes.add_type("application/octet-stream", ".MYI", strict=False)
    mimetypes.add_type("application/octet-stream", ".NET", strict=False)
    mimetypes.add_type("application/octet-stream", ".net", strict=False)
    mimetypes.add_type("application/octet-stream", ".nix", strict=False)
    mimetypes.add_type("application/octet-stream", ".nl", strict=False)
    mimetypes.add_type("application/octet-stream", ".nls", strict=False)
    mimetypes.add_type("application/octet-stream", ".nm", strict=False)
    mimetypes.add_type("application/octet-stream", ".nrm", strict=False)
    mimetypes.add_type("application/octet-stream", ".nz", strict=False)
    mimetypes.add_type("application/octet-stream", ".OCM", strict=False)
    mimetypes.add_type("application/octet-stream", ".ocx", strict=False)
    mimetypes.add_type("application/octet-stream", ".opt", strict=False)
    mimetypes.add_type("application/octet-stream", ".p2", strict=False)
    mimetypes.add_type("application/octet-stream", ".pack", strict=False)
    mimetypes.add_type("application/octet-stream", ".pak", strict=False)
    mimetypes.add_type("application/octet-stream", ".pc", strict=False)
    mimetypes.add_type("application/x-x509-user-cert", ".pem", strict=False)
    mimetypes.add_type("text/php", ".php", strict=False)
    mimetypes.add_type("application/octet-stream", ".pil", strict=False)
    mimetypes.add_type("application/octet-stream", ".pipe", strict=False)
    mimetypes.add_type("application/octet-stream", ".pip", strict=False)
    mimetypes.add_type("application/octet-stream", ".pkv", strict=False)
    mimetypes.add_type("application/octet-stream", ".Plo", strict=False)
    mimetypes.add_type("application/octet-stream", ".plt", strict=False)
    mimetypes.add_type("application/octet-stream", ".pol", strict=False)
    mimetypes.add_type("application/octet-stream", ".pom", strict=False)
    mimetypes.add_type("text/plain", ".Po", strict=False)
    mimetypes.add_type("text/plain", ".po", strict=False)
    mimetypes.add_type("application/octet-stream", ".prefs", strict=False)
    mimetypes.add_type("application/octet-stream", ".pro", strict=False)
    mimetypes.add_type("application/octet-stream", ".prop", strict=False)
    mimetypes.add_type("application/octet-stream", ".prx", strict=False)
    mimetypes.add_type("text/x-python", ".pth", strict=False)
    mimetypes.add_type("application/octet-stream", ".pup", strict=False)
    mimetypes.add_type("application/octet-stream", ".pvr", strict=False)
    mimetypes.add_type("application/octet-stream", ".pws", strict=False)
    mimetypes.add_type("application/octet-stream", ".pxd", strict=False)
    mimetypes.add_type("application/octet-stream", ".pxi", strict=False)
    mimetypes.add_type("text/x-python", ".pyamf", strict=False)
    mimetypes.add_type("text/x-python", ".pytz", strict=False)
    mimetypes.add_type("text/x-python", ".pyw", strict=False)
    mimetypes.add_type("text/x-python", ".pyx", strict=False)
    mimetypes.add_type("application/octet-stream", ".qm", strict=False)
    mimetypes.add_type("application/octet-stream", ".qpg", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r1", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r2", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r3", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r4", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r5", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r6", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r7", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r8", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r9", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r10", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r11", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r12", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r13", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r14", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r15", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r16", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r17", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r18", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r19", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r20", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r21", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r22", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r23", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r24", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r25", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r26", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r27", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r28", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r29", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r30", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r31", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r32", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r33", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r34", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r35", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r36", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r37", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r38", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r39", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r40", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r41", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r42", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r43", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r44", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r45", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r46", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r47", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r48", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r49", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r50", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r51", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r52", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r53", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r54", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r55", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r56", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r57", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r58", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r59", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r60", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r61", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r62", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r63", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r64", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r65", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r66", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r67", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r68", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r69", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r70", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r71", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r72", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r73", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r74", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r75", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r76", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r77", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r78", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r79", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r80", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r81", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r82", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r83", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r84", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r85", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r86", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r87", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r88", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r89", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r90", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r91", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r92", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r93", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r94", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r95", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r96", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r97", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r98", strict=False)
    mimetypes.add_type("application/x-rar-compressed", ".r99", strict=False)
    mimetypes.add_type("image/raw", ".raw", strict=False)
    mimetypes.add_type("application/octet-stream", ".rcc", strict=False)
    mimetypes.add_type("application/octet-stream", ".rda", strict=False)
    mimetypes.add_type("text/plain", ".reg", strict=False)
    mimetypes.add_type("application/octet-stream", ".roi", strict=False)
    mimetypes.add_type("application/octet-stream", ".rpa", strict=False)
    mimetypes.add_type("application/octet-stream", ".rpyb", strict=False)
    mimetypes.add_type("application/octet-stream", ".rpyc", strict=False)
    mimetypes.add_type("application/octet-stream", ".rpymc", strict=False)
    mimetypes.add_type("application/octet-stream", ".rpym", strict=False)
    mimetypes.add_type("application/octet-stream", ".rpy", strict=False)
    mimetypes.add_type("application/x-pkcs7", ".RSA", strict=False)
    mimetypes.add_type("application/x-pkcs7", ".rsa", strict=False)
    mimetypes.add_type("application/octet-stream", ".rst", strict=False)
    mimetypes.add_type("text/rust", ".rust", strict=False)
    mimetypes.add_type("application/octet-stream", ".sas", strict=False)
    mimetypes.add_type("application/octet-stream", ".sbd", strict=False)
    mimetypes.add_type("text/css", ".scss", strict=False)
    mimetypes.add_type("application/octet-stream", ".sdv", strict=False)
    mimetypes.add_type("application/octet-stream", ".sfd", strict=False)
    mimetypes.add_type("application/octet-stream", ".SF", strict=False)
    mimetypes.add_type("application/octet-stream", ".sf", strict=False)
    mimetypes.add_type("application/octet-stream", ".sh3d", strict=False)
    mimetypes.add_type("application/octet-stream", ".six", strict=False)
    mimetypes.add_type("application/octet-stream", ".SJIS", strict=False)
    mimetypes.add_type("application/octet-stream", ".sjis", strict=False)
    mimetypes.add_type("application/octet-stream", ".sln", strict=False)
    mimetypes.add_type("application/octet-stream", ".snap", strict=False)
    mimetypes.add_type("application/octet-stream", ".sob", strict=False)
    mimetypes.add_type("application/octet-stream", ".soc", strict=False)
    mimetypes.add_type("application/octet-stream", ".sod", strict=False)
    mimetypes.add_type("application/octet-stream", ".soe", strict=False)
    mimetypes.add_type("application/octet-stream", ".sog", strict=False)
    mimetypes.add_type("application/octet-stream", ".soh", strict=False)
    mimetypes.add_type("application/octet-stream", ".sol", strict=False)
    mimetypes.add_type("application/octet-stream", ".srl", strict=False)
    mimetypes.add_type("application/octet-stream", ".suo", strict=False)
    mimetypes.add_type("application/octet-stream", ".swn", strict=False)
    mimetypes.add_type("application/octet-stream", ".swo", strict=False)
    mimetypes.add_type("application/octet-stream", ".swp", strict=False)
    mimetypes.add_type("application/vnd.oasis.opendocument.text", ".swx", strict=False)
    mimetypes.add_type("application/octet-stream", ".sxx", strict=False)
    mimetypes.add_type("text/plain", ".tab_i", strict=False)
    mimetypes.add_type("text/plain", ".tab", strict=False)
    mimetypes.add_type("application/octet-stream", ".tc", strict=False)
    mimetypes.add_type("application/octet-stream", ".tcvn", strict=False)
    mimetypes.add_type("text/plain", ".theme", strict=False)
    mimetypes.add_type("image/x-thm", ".thm", strict=False)
    mimetypes.add_type("image/x-thm", ".THM", strict=False)
    mimetypes.add_type("application/octet-stream", ".tii", strict=False)
    mimetypes.add_type("application/octet-stream", ".tis", strict=False)
    mimetypes.add_type("application/octet-stream", ".tlb", strict=False)
    mimetypes.add_type("application/octet-stream", ".tmpl", strict=False)
    mimetypes.add_type("text/plain", ".toc", strict=False)
    mimetypes.add_type("application/octet-stream", ".toml", strict=False)
    mimetypes.add_type("application/octet-stream", ".TPo", strict=False)
    mimetypes.add_type("application/octet-stream", ".Tpo", strict=False)
    mimetypes.add_type("application/octet-stream", ".tree", strict=False)
    mimetypes.add_type("application/octet-stream", ".trs", strict=False)
    mimetypes.add_type("application/octet-stream", ".tv", strict=False)
    mimetypes.add_type("text/xml", ".ui", strict=False)
    mimetypes.add_type("application/x-url", ".url", strict=False)
    mimetypes.add_type("application/octet-stream", ".user", strict=False)
    mimetypes.add_type("application/octet-stream", ".vdf", strict=False)
    mimetypes.add_type("application/octet-stream", ".ver", strict=False)
    mimetypes.add_type("application/octet-stream", ".vert", strict=False)
    mimetypes.add_type("application/octet-stream", ".video", strict=False)
    mimetypes.add_type("application/octet-stream", ".vimeo", strict=False)
    mimetypes.add_type("text/plain", ".vim", strict=False)
    mimetypes.add_type("application/octet-stream", ".vxd", strict=False)
    mimetypes.add_type("application/java-archive", ".war", strict=False)
    mimetypes.add_type("application/x-zip-compressed", ".whl", strict=False)
    mimetypes.add_type("application/font-woff", ".woff2", strict=False)
    mimetypes.add_type("application/octet-stream", ".x86", strict=False)
    mimetypes.add_type("application/octet-stream", ".xmi", strict=False)
    mimetypes.add_type("application/octet-stream", ".xxx", strict=False)
    mimetypes.add_type("application/x-xz", ".xz", strict=False)
    mimetypes.add_type("text/plain", ".yaml", strict=False)
    mimetypes.add_type("text/plain", ".yml", strict=False)

    mimetypes.add_type("text/plain", ".cmakein", strict=False)
    mimetypes.add_type("text/plain", ".gpi", strict=False)
    mimetypes.add_type("text/plain", ".plt", strict=False)
    mimetypes.add_type("text/plain", ".gp", strict=False)
    mimetypes.add_type("text/plain", ".gnu", strict=False)
    mimetypes.add_type("text/plain", ".gnuplot", strict=False)
    mimetypes.add_type("application/octet-stream", ".csproj", strict=False)
    mimetypes.add_type("application/octet-stream", ".egg-info", strict=False)
    mimetypes.add_type("application/octet-stream", ".gpr", strict=False)
    mimetypes.add_type("application/octet-stream", ".gr", strict=False)

    mimetypes.add_type("application/octet-stream", ".aes", strict=False)
    mimetypes.add_type("application/octet-stream", ".aex", strict=False)
    mimetypes.add_type("application/octet-stream", ".cwl", strict=False)
    mimetypes.add_type("application/octet-stream", ".el", strict=False)
    mimetypes.add_type("application/octet-stream", ".ign", strict=False)
    mimetypes.add_type("application/octet-stream", ".kdb", strict=False)
    mimetypes.add_type("application/octet-stream", ".lic", strict=False)
    mimetypes.add_type("application/octet-stream", ".luc", strict=False)
    mimetypes.add_type("application/octet-stream", ".nbm", strict=False)
    mimetypes.add_type("application/octet-stream", ".vcxproj", strict=False)
    mimetypes.add_type("application/octet-stream", ".vf", strict=False)
    mimetypes.add_type("application/octet-stream", ".zsh", strict=False)
    mimetypes.add_type("text/plain", ".ass", strict=False)
    mimetypes.add_type("text/plain", ".zshrc", strict=False)
    mimetypes.add_type("application/x-chrome-extension", ".crx", strict=False)
    mimetypes.add_type("application/x-gzip", ".gzip", strict=False)
    mimetypes.add_type("application/jsp", ".jsp", strict=False)
    mimetypes.add_type("audio/sdx", ".sdx", strict=False)
    mimetypes.add_type("application/vnd.lotus-freelance ", ".sym", strict=False)

    # for (key, ext) in sorted(mimetypes.types_map.items()):
    #     print("%s\t->\t%s" % (key, ext))
    # print("Done initialising MIME types.")


# Regular Expression parsers.
space = re.compile(SPACE_REGEXP)
pyre = re.compile(PYTHONRE)
pynamer = re.compile(PYTHONNAMER)
pyprocname = re.compile(PYTHONPROCNAME)
bashre = re.compile(BASHRE)
bashnamer = re.compile(BASHNAMER)
bashprocname = re.compile(BASHPROCNAME)
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
