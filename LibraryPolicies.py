"""An engine for running algorithms that implement an access control policy."""

from File import File, FileAccess, EventFileFlags
from Application import Application
from PolicyEngine import Policy, PolicyEngine
from UserConfigLoader import UserConfigLoader
from constants import DESIGNATION_ACCESS, POLICY_ACCESS, OWNED_PATH_ACCESS, \
                      ILLEGAL_ACCESS

import re


class OneLibraryPolicy(Policy):
    """Libraries made up of a single location. One library set per app."""

    def __init__(self, userConf: UserConfigLoader):
        """Construct a OneLibraryPolicy."""
        super(OneLibraryPolicy, self).__init__(name='OneLibraryPolicy')

        self.appPathCache = dict()
        self.appPolicyCache = dict()
        self.userConf = userConf

        self.documentsLibrary = dict()
        self.imageLibrary = dict()
        self.musicLibrary = dict()
        self.videoLibrary = dict()

        self.loadUserLibraryPreferences(userConf)
        # TODO map app desktop entries to library names

    def loadUserLibraryPreferences(self, userConf: UserConfigLoader):
        """Load user's library and folder names."""
        self.documentsLibrary[userConf.getSetting('XdgDocumentsDir')] = 0
        self.imageLibrary[userConf.getSetting('XdgImageDir')] = 0
        self.musicLibrary[userConf.getSetting('XdgMusicDir')] = 0
        self.videoLibrary[userConf.getSetting('XdgVideoDir')] = 0

        # TODO: subclass this, call super for defaults and then add the below:
        # self.pictureLibrary[additionalPictureDir] = 1
        # self.confCost ++ (the vals of the libraries)

    def getAppPolicy(self, actor: Application):
        """Return the library capabilities policy for one Application."""
        if actor not in self.appPolicyCache:
            policies = actor.getSetting('LibraryCaps',
                                        type='string list') or []
            self.appPolicyCache[actor] = policies

        return self.appPolicyCache[actor]

    def generateOwnedPaths(self, actor: Application):
        """Return the paths where an Application can fully write Files."""
        if actor not in self.appPathCache:
            paths = []
            home = self.userConf.getSetting("HomeDir") or "/MISSING-HOME-DIR"
            desk = self.userConf.getSetting("XdgDesktopDir") or "~/Desktop"
            did = re.escape(actor.desktopid)

# FIXME *: '^/usr/lib/python2\.7/.*\.pyc'
# python3.4 python 3.5 python


            # Full privileges in one's home!
            rwf = (EventFileFlags.read | EventFileFlags.write |
                   EventFileFlags.overwrite | EventFileFlags.destroy |
                   EventFileFlags.create | EventFileFlags.move |
                   EventFileFlags.copy)
            paths.append((re.compile('^%s/\.%s' % (home, did)), rwf))
            paths.append((re.compile('^%s/\.cache/%s' % (home, did)), rwf))
            paths.append((re.compile('^%s/\.config/%s' % (home, did)), rwf))
            paths.append((re.compile('^%s/\.local/share/%s' % (home, did)),
                         rwf))
            paths.append((re.compile('^/dev/null$'), rwf))

            # Append the app-specific home paths
            appSpecificRWPaths = actor.getSetting('RWPaths',
                                                  type='string list') or []
            for path in appSpecificRWPaths:
                path = path.replace('@XDG_DESKTOP_DIR@', desk)
                path = path.replace('~', home)
                paths.append((re.compile(path), rwf))

            # Sticky bit in /tmp: one can touch what they created
            paths.append((re.compile('^/tmp/'), EventFileFlags.create))

            # Read-only / copy-only installed files
            rof = (EventFileFlags.read | EventFileFlags.copy)
            paths.append((re.compile('^/etc/%s' % did), rof))
            paths.append((re.compile('^/usr/include/%s' % did), rof))
            paths.append((re.compile('^/usr/lib/%s' % did), rof))
            paths.append((re.compile('^/usr/share/%s' % did), rof))
            paths.append((re.compile('^/usr/lib/pkgconfig/%s\.pc' % did), rof))
            paths.append((re.compile('^/usr/share/GConf/gsettings/%s\..*' %
                          did), rof))
            paths.append((re.compile('^/usr/share/appdata/%s\.appdata\.xml' %
                          did), rof))
            paths.append((re.compile('^/usr/share/appdata/%s(\-.*)?\.'
                          'metainfo\.xml' % did), rof))
            paths.append((re.compile('^/usr/share/applications/(.*\.)?%s\.'
                          'desktop' % did), rof))
            paths.append((re.compile('^/usr/share/icons/.*%s\.(png|svg)' %
                          did), rof))
            paths.append((re.compile('^/usr/share/dbus-1/services/.*\.%s\.'
                          'service' % did), rof))
            paths.append((re.compile('^/usr/share/gtk-doc/html/%s' % did),
                          rof))
            paths.append((re.compile('^/usr/share/help/.*/%s' % did), rof))
            paths.append((re.compile('^/usr/share/locale/.*/LC_MESSAGES/%s\.mo'
                          % did), rof))
            paths.append((re.compile('^/usr/share/man/man1/%s\.1\.gz' % did),
                         rof))
            paths.append((re.compile('^/usr/local/%s' % did), rof))
            paths.append((re.compile('^/opt/%s' % did), rof))
            paths.append((re.compile('^%s/\.X(defaults|authority)' % (home)),
                         rof))
            paths.append((re.compile('^%s/\.ICEauthority' % (home)), rof))
            paths.append((re.compile('^%s/\.config/(pango/pangorc|dconf/user|'
                                     'user-dirs.dirs)' % (home)), rof))
            paths.append((re.compile('^%s/\.local/share/+(mime/|recently\-'
                                     'used\.xbel)' % (home)), rof))
            paths.append((re.compile('^%s/\.local/share/applications(/|/mime'
                                     'info\.cache|/mimeapps\.list)?$' %
                                     (home)), rof))
            paths.append((re.compile('^/run/user/\d+/dconf/user'), rof))
            paths.append((re.compile('%s/\.icons/.*?/(index\.theme|cursors/)' %
                         (home)), rof))
            paths.append((re.compile('%s/\.(config/)?enchant/' % (home)), rof))
            paths.append((re.compile('^/usr/share/myspell'), rof))

            # Append the app-specific system paths
            appSpecificROPaths = actor.getSetting('ROPaths',
                                                  type='string list') or []
            for path in appSpecificROPaths:
                path = path.replace('@XDG_DESKTOP_DIR@', desk)
                path = path.replace('~', home)
                paths.append((re.compile(path), rof))

            # /usr/include/%s-3.14
            # /usr/share/(vala|vala-0.32)/vapi/%s*
            #
            # /home/steve/.cache/mozilla/firefox
            # /home/steve/.mozilla/firefox
            self.appPathCache[actor] = paths

        return self.appPathCache[actor]

    def accessFunc(self, engine: PolicyEngine, f: File, acc: FileAccess):
        """Assess the security and usability score of a FileAccess."""
        # Designation accesses are considered cost-free.
        if acc.evflags & EventFileFlags.designation:
            self.desigAccess += 1
            f.recordAccessCost(acc)
            return DESIGNATION_ACCESS

        # Some files are allowed because they clearly belong to the app
        ownedPaths = self.generateOwnedPaths(acc.actor)
        for (path, evflags) in ownedPaths:
            if path.match(f.getName()) and acc.allowedByFlagFilter(evflags, f):
                self.ownedPathAccess += 1
                f.recordAccessCost(acc)
                return OWNED_PATH_ACCESS

        # Check for legality coming from the acting app's policy.
        policies = self.getAppPolicy(acc.actor)
        for pol in policies:
            try:
                attr = self.__getattribute__(pol+"Library")
            except (AttributeError):
                pass
            else:
                for (path, cost) in attr.items():
                    if(f.getName().startswith(path)):
                        self.policyAccess += 1
                        f.recordAccessCost(acc)
                        return POLICY_ACCESS

        # We could not justify the access, increase the usabiltiy cost.
        self.illegalAccess += 1
        self.cumulGrantCost += 1
        # If a prior interruption granted access, don't overcount.
        if not f.hadPastSimilarAccess(acc):
            self.interruptionCost += 1
            self.grantingCost += 1
        f.recordAccessCost(acc)
        return ILLEGAL_ACCESS
