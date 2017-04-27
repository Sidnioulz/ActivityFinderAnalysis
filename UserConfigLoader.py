"""UserConfigLoader loads settings related to the user being analysed."""
from xdg import IniFile
from constants import USERCFG_VERSION


class UserConfigLoader(object):
    """UserConfigLoader loads settings related to the user being analysed."""

    __loader = None

    @staticmethod
    def get(path: str=None):
        """Return the UserConfigLoader for the entire application."""
        if not UserConfigLoader.__loader:
            if path:
                UserConfigLoader.__loader = UserConfigLoader(path)
            else:
                raise ValueError("UserConfigLoader is not initialised yet and "
                                 "needs a config file path.")
        return UserConfigLoader.__loader

    @staticmethod
    def reset():
        UserConfigLoader.__loader = None

    def __init__(self, path: str):
        """Construct a UserConfigLoader."""
        super(UserConfigLoader, self).__init__()

        self.ini = IniFile.IniFile()
        try:
            self.ini.parse(path)
        except(IniFile.ParsingError) as e:
            raise ValueError("Current user's config file could not be parsed.")
        else:
            vs = self.ini.get(key='Version',
                              group='User Config',
                              type='numeric')
            assert(vs == USERCFG_VERSION), ("Error: User config file version "
                                            "mismatch: expected %f, was %f" % (
                                             USERCFG_VERSION,
                                             vs or -1.0))

    def getHomeDir(self):
        """Get the user's home directory."""
        return self.getSetting("HomeDir")

    def getSetting(self, key: str, defaultValue=None, type: str="string"):
        """Get a stored setting relative to the current participant."""
        if not self.ini:
            return defaultValue

        isList = False
        if type.endswith(" list"):
            isList = True
            type = type[:-5]

        return self.ini.get(key,
                            group='User Config',
                            type=type,
                            list=isList) or defaultValue

    def getExcludedHomeDirs(self):
        def _get(self):
            """Get the list of directories excluded from analysis."""
            if not self.ini:
                return []

            return self.ini.get('HomeExclDirs',
                                group='User Config',
                                type='string', list=True) or []

        l = _get(self)
        l.append("/srv/")
        l.append("/run/")
        l.append("/proc/")
        l.append("/dev/")
        l.append("/usr/")
        l.append("/tmp/")
        return l

    def getSecurityExclusionLists(self):
        """Get the security exclusion lists setting."""
        if not self.ini:
            return dict()

        def _parseVals(key):
            vals = self.ini.get(key,
                                group='User Config',
                                type='string', list=True) or []

            result = []
            for value in vals:
                excls = value.strip('|').split('||')
                if not excls:
                    raise ValueError("Syntax error in user configuration's "
                                     "SecurityExclusionLists on bit '%s'" %
                                     value)
                else:
                    result.append(excls)

            return result

        exclLists = dict()
        for key in ['ExplicitExclusion',
                    'WorkPersonalSeparation',
                    'ProjectSeparation']:
            exclLists[key] = _parseVals(key)

        return exclLists

    def getProjects(self):
        """Get the projects of a participant."""
        if not self.ini:
            return list()

        projs = self.ini.get('Projects',
                             group='User Config',
                             type='string', list=True) or ''

        result = []
        for project in projs:
            projectLocations = project.split('|')
            result.append(projectLocations)

        return result

