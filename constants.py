# General constants
USAGE_STRING = '__main__.py [--check-missing]'

# Data location constants
DATAPATH = "../data/current/"
DATABASENAME = "activity.sqlite"

# Application constants
DESKTOPPATHS = ['../applications/usr/share/applications/',
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
POSIX_OPEN_RE = '^(.*?)\|fd (\-?\d+): with flag (\-?\d+), e(\-?\d+)\|(.*?)$'
POSIX_FOPEN_RE = '^(.*?)\|FILE (0x[a-f0-9]+|\(nil\)): with flag (\-?\d+),' \
                 ' e(\-?\d+)\|(.*?)$'
POSIX_FDOPEN_RE = '^fd: (-?\d+)\|\|.*?\n\n FILE (0x[a-f0-9]+)\|with flag' \
                  ' (\-?\d+), e(\-?\d+)\|'
POSIX_OPENDIR_RE = '^(.*?)\|DIR (0x[a-f0-9]+|\(nil\)): e(\-?\d+)\|(.*?)$'
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
