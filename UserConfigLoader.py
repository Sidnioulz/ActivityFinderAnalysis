"""UserConfigLoader loads settings related to the user being analysed."""
from xdg import IniFile
from constants import USERCFG_VERSION


class UserConfigLoader(object):
    """UserConfigLoader loads settings related to the user being analysed."""

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
