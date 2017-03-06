# Data location constants
DEFAULTDATAPATH = "../data/current/"
NAMEDDATAPATHBASE = "../data/data/"
USERCONFIGNAME = "user.ini"
DATABASENAME = "activity.sqlite"

# Path splitting regexp
SPACE_REGEXP = r'(?<!\\) '

# Application constants
APPMERGEWINDOW = 60 * 60 * 1000
DESKTOPPATHS = ['./applications/',
                '/usr/share/applications/',
                '~/.local/share/applications/']

DESKTOPIDRE = "^(?:[^/]*/)*(.*?)(?:\.desktop)?$"

PYTHONRE = "^(/usr/bin/)?python([23](.\d)?)?$"
PYTHONNAMER = "^(?:[^/]*/)*(.*?)(?:\.py.?)?$"
PYTHONPROCNAME = "^(.*?)(?:\.py.?)?$"
JAVARE = "^(?:[^/]*/)*java$"
JAVANAMER = "^(?:[^/]*/)*(.*?)(?:\.jar)?$"
JAVAPROCNAME = "^(.*?)(?:\.jar)?$"
PERLRE = "^(?:[^/]*/)*perl$"
PERLNAMER = "^(?:[^/]*/)*(.*?)$"
MONORE = "^(?:[^/]*/)*mono-sgen$"
MONONAMER = "^(?:[^/]*/)*(.*?)(?:\.exe)?$"
MONOPROCNAME = "^(.*?)(?:\.exe)?$"
PHPRE = "^(?:[^/]*/)*php(5)?$"
PHPNAMER = "^(?:[^/]*/)*(.*?)(?:\.php)?$"
PHPPROCNAME = "^(.*?)(?:\.php)?$"

# Zeitgeist Event index constants
EV_ID = 0
EV_TIMESTAMP = 1
EV_INTERPRETATION = 2
EV_MANIFESTATION = 3
EV_ACTOR = 4
EV_PAYLOAD = 5
EV_SUBJ_URI = 6
EV_SUBJ_ID = 7
EV_SUBJ_INTERPRETATION = 8
EV_SUBJ_MANIFESTATION = 9
EV_SUBJ_ORIGIN = 10
EV_SUBJ_ORIGIN_URI = 11
EV_SUBJ_MIMETYPE = 12
EV_SUBJ_TEXT = 13
EV_SUBJ_STORAGE = 14
EV_SUBJ_STORAGE_STATE = 15
EV_ORIGIN = 16
EV_EVENT_ORIGIN_URI = 17
EV_SUBJ_CURRENT_URI = 18
EV_SUBJ_ID_CURRENT = 19
EV_SUBJ_TEXT_ID = 20
EV_SUBJ_STORAGE_ID = 21
EV_ACTOR_URI = 22
EV_SUBJ_ORIGIN_CURRENT = 23
EV_SUBJ_ORIGIN_CURRENT_URI = 24

# POSIX event and system call constants
FD_OPEN = True
FD_CLOSE = False

POSIX_OPEN_RE = '^(.*?)\|fd (\-?\d+): with flag (\-?\d+), e(\-?\d+)\|(.*?)$'
POSIX_FOPEN_RE = '^(.*?)\|FILE (0x[a-f0-9]+|\(nil\)): with flag (\-?\d+),' \
                 ' e(\-?\d+)\|(.*?)$'
POSIX_FDOPEN_RE = '^fd: (-?\d+)\|\|.*?\n FILE (0x[a-f0-9]+)\|with flag' \
                  ' (\-?\d+), e(\-?\d+)\|'
POSIX_FDOPENDIR_RE = '^fd: (-?\d+)\|\|.*?\n DIR (0x[a-f0-9]+)\|e(\-?\d+)\|'
POSIX_OPENDIR_RE = '^(.*?)\|DIR (0x[a-f0-9]+|\(nil\)): e(\-?\d+)\|(.*?)$'
POSIX_UNLINK_RE = '^(.*?)\|e(\-?\d+)\|(.*?)$'
POSIX_CLOSE_RE = '^fd: (-?\d+)\|e(\-?\d+)\|.*$'
POSIX_FCLOSE_RE = '^(?:FILE|DIR): (0x[a-f0-9]+)\|e(\-?\d+)\|.*$'
POSIX_RENAME_RE = '^ (.*?)\|Old file\|(.*?)\n (.*?)\|New file: with flags' \
                  ' (\-?\d+), e(\-?\d+)\|(.*)$'
POSIX_DUP_RE = '^ fd: (\-?\d+)\|Old fd\|(.*?)\n fd: (\-?\d+)\|New fd: ' \
               '(\(null\)|e\-?\d+)\|(.*?)$'

O_ACCMODE = 0o3
O_RDONLY = 0o0
O_WRONLY = 0o1
O_RDWR = 0o2

O_CREAT = 0o100
O_EXCL = 0o200
O_NOCTTY = 0o400

O_TRUNC = 0o1000
O_APPEND = 0o2000
O_NONBLOCK = 0o4000

O_DSYNC = 0o10000
O_FASYNC = 0o20000
O_DIRECT = 0o40000

O_LARGEFILE = 0o100000
O_DIRECTORY = 0o200000
O_NOFOLLOW = 0o400000

O_NOATIME = 0o1000000
O_CLOEXEC = 0o2000000

# CONFIG CONSTANTS
USERCFG_VERSION = 1.0

# POLICY CONSTANTS
DESIGNATION_ACCESS = 1
OWNED_PATH_ACCESS = 2
POLICY_ACCESS = 3
ILLEGAL_ACCESS = 4
