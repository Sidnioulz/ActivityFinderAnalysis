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
