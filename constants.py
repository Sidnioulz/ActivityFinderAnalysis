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

# Event constants
# TODO

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
EV_INTERPRETATION_URI = 25
EV_MANIFESTATION_URI = 26
