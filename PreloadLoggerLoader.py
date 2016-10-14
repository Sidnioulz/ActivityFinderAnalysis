import sys
import os
import re
from Application import Application
from AppInstanceStore import AppInstanceStore
from constants import PYTHONRE, PYTHONNAMER, PYTHONPROCNAME, \
                      JAVARE, JAVANAMER, JAVAPROCNAME, \
                      PERLRE, PERLNAMER, \
                      MONORE, MONONAMER, MONOPROCNAME


class PreloadLoggerLoader(object):
    path = ""
    pattern = None
    delpattern = None

    """ PreloadLoggerLoader loads all PreloadLogger log files from a user
        directory, and parses them into appropriate events. """
    def __init__(self, path):
        self.path = path
        self.pattern = re.compile("^\d{4}-\d{2}-\d{2}_\d+_\d+.log$")
        self.header = re.compile("^@(.*?)[|](\d+)[|](.*)$")
        self.syscall = re.compile("^(\d+)[|](.*)$")
        self.space = re.compile(r'(?<!\\) ')
        self.pyre = re.compile(PYTHONRE)
        self.pynamer = re.compile(PYTHONNAMER)
        self.pyprocname = re.compile(PYTHONPROCNAME)
        self.javare = re.compile(JAVARE)
        self.javanamer = re.compile(JAVANAMER)
        self.javaprocname = re.compile(JAVAPROCNAME)
        self.perlre = re.compile(PERLRE)
        self.perlnamer = re.compile(PERLNAMER)
        self.monore = re.compile(MONORE)
        self.mononamer = re.compile(MONONAMER)
        self.monoprocname = re.compile(MONOPROCNAME)
        self.delpattern = None  # TODO
        super(PreloadLoggerLoader, self).__init__()

    """ Get the proper app identity out of a Python execution, by parsing the
    Python command line. """
    def parsePython(self, g: tuple, items: list=None):
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = self.space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) == 1:
            return g

        res = self.pynamer.match(items[1])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = self.pyprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            newcmd = ' '.join(items[1:])
            return (newproc, g[1], newcmd)
        else:
            return g

    """ Get the proper app identity out of a Java execution, by parsing the
    Java command line. """
    def parseJava(self, g: tuple, items: list=None):
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = self.space.split(g[2])

        # Remove -jar if present
        if len(items) > 1 and items[1] == "-jar":
            del items[1]

        # Return if there are no parameters, the interpreter is the app
        if len(items) == 1:
            return g

        res = self.javanamer.match(items[1])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = self.javaprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            newcmd = ' '.join(items[1:])
            return (newproc, g[1], newcmd)
        else:
            return g

    """ Get the proper app identity out of a Perl execution, by parsing the
    Perl command line. """
    def parsePerl(self, g: tuple, items: list=None):
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = self.space.split(g[2])

        # Remove -w if present
        if len(items) > 1 and items[1] == "-w":
            del items[1]

        # Return if there are no parameters, the interpreter is the app
        if len(items) == 1:
            return g

        res = self.perlnamer.match(items[1])
        name = res.groups()[0] if res.groups() else None

        if name:
            newcmd = ' '.join(items[1:])
            return (name, g[1], newcmd)
        else:
            return g

    """ Get the proper app identity out of a Mono execution, by parsing the
    Mono command line. """
    def parseMono(self, g: tuple, items: list=None):
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = self.space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) == 1:
            return g

        # Mono apps in our logs seem to log the command-line properly, e.g. our
        # mono-sgen actor has a command-line starting with "banshee" when the
        # Banshee app is launched. Thus, we only update the process name
        res = self.mononamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = self.monoprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            return (newproc, g[1], g[2])
        else:
            return g

    """ Go through the logs and print the list of .desktop files that are
        missing on the system used for analysis. Exits if some apps are
        missing. """
    def listMissingActors(self):
        self.loadDb(store=None, checkInitialised=True)

    """ Go through the directory and create all the relevant app instances
    and events. Can be made to insert all found apps into an AppInstanceStore,
    or to exit if some Application instances are not properly initialised. """
    def loadDb(self,
               store: AppInstanceStore = None,
               checkInitialised: bool = False):

        count = 0              # Counter of fetched files, for stats
        actors = set()         # Apps that logged anything at all
        empties = 0            # Matching files without content (logger crash)
        invalids = 0           # Files with corrupted content (logger crash)
        nosyscalls = []        # Logs with zero syscalls logged (not a bug)
        nosyscallactors = set()  # Apps that logged zero syscalls
        instanceCount = 0      # Count of distinct app instances in the dataset
        hasErrors = False      # Whether some uninitialised apps were found

        # List all log files that match the PreloadLogger syntax
        for file in os.listdir(self.path):
            # Ignore files that don't match
            if not self.pattern.match(file):
                continue

            count += 1

            # Process log files that match the PreloadLogger name pattern
            try:
                f = open(self.path + "/" + file, 'rb')
            except(IOError) as e:
                print("Error: could not open file %s: %s" % (
                       file,
                       str(e)),
                      file=sys.stderr)
            else:
                with f:
                    content = f.readlines()  # type: list

                    # Parse the first line to get the identity of the app,
                    # but sometimes the header ends up on the second line
                    # in some logs... So, parse until we find a match, and
                    # remember the line index of the header
                    headerLocation = 0
                    result = None
                    for (idx, binary) in enumerate(content):
                        try:
                            line = binary.decode('utf-8')
                        except(UnicodeDecodeError) as e:
                            print("Error: %s has a non utf-8 line: %s " % (
                                   file,
                                   str(e)),
                                  file=sys.stderr)
                            continue
                        result = self.header.match(line)
                        if result:
                            headerLocation = idx
                            break

                    # Remove the header to help the syscall parser
                    del content[headerLocation]

                    # Files with a missing or corrupted header are invalid
                    if result is None:
                        print("%s is missing a header" % file,
                              file=sys.stderr)
                        invalids += 1
                        continue
                    g = result.groups()
                    if (len(g) != 3):
                        print("%s has wrong group count: " % file,
                              content[0],
                              file=sys.stderr)
                        invalids += 1
                        continue

                    # Filter interpreters, and rewrite them to get the identity
                    # of the app they launched instead. #TODO
                    items = self.space.split(g[2])
                    interpreterid = None

                    # Python
                    if (self.pyre.match(g[0])):
                        interpreterid = g[0]
                        g = self.parsePython(g, items)
                        # print("PYTHON APP: %s" % g[2])

                    # Java
                    if (self.javare.match(g[0])):
                        interpreterid = g[0]
                        g = self.parseJava(g, items)
                        # print("JAVA APP: %s" % g[2])

                    # Perl
                    if (self.perlre.match(g[0])):
                        interpreterid = g[0]
                        g = self.parsePerl(g, items)
                        # print("PERL APP: %s" % g[2])

                    # Mono
                    if (self.monore.match(g[0])):
                        interpreterid = g[0]
                        g = self.parseMono(g, items)
                        # print("MONO APP: %s" % g[2])

                    # Parse file content to calculate the timestamps
                    tstart = float("inf")
                    tend = 0
                    syscalls = []
                    for binary in content:
                        try:
                            line = binary.decode('utf-8')
                        except(UnicodeDecodeError) as e:
                            print("Error: %s has a non utf-8 line: %s " % (
                                   file,
                                   str(e)),
                                  file=sys.stderr)
                            continue

                        # Line is a parameter to the last system call logged
                        if line.startswith(' '):
                            syscalls[-1] = syscalls[-1] + '\n' + line
                            continue

                        # Check that line is a syntactically vlaid system call
                        result = self.syscall.match(line)
                        if result is None:
                            print("%s has a corrupted line: %s" % (
                                   file,
                                   line),
                                  file=sys.stderr)
                            continue

                        # Update the timestamp
                        h = result.groups()
                        timestamp = int(h[0])
                        tstart = min(tstart, timestamp)
                        tend = max(tend, timestamp)

                        # Append the system call to our syscall list
                        syscalls.append(h[1])

                    # Check if the timestamps have been set
                    if tend == 0:
                        nosyscalls.append(g)
                        nosyscallactors.add(g[0])
                        continue

                    # Normalise timestamps with the ZG format...
                    tstart *= 1000
                    tend *= 1000

                    # TODO: process deletions and remove corresponding files

                    # Make the application
                    app = Application(desktopid=g[0],
                                      pid=int(g[1]),
                                      tstart=tstart,
                                      tend=tend,
                                      interpreterid=interpreterid)

                    # Add the found process id to our list of actors, using the
                    # app identity that was resolved by the Application ctor
                    # actors.add(app.getDesktopId())  # FIXME
                    actors.add(g[0])

                    if checkInitialised and not app.isInitialised():
                        print("MISSING: %s" % g[0],
                              file=sys.stderr)
                        hasErrors = True

                    # Insert into the AppInstanceStore if one is available
                    if store:
                        store.insert(app)
                        instanceCount += 1

        if checkInitialised and hasErrors:
            sys.exit(-1)

        print("Apps that logged valid files:")
        for act in sorted(actors):
            print(act)

        print("\nApps that logged files without a single system call:")
        for act in sorted(nosyscallactors):
            print(act)

        print("\nFinished loading DB.\n%d files seen, %d valid from %d apps, "
              "%d empty files, "
              "%d logs with 0 syscalls from %d apps, "
              "%d invalid.\nIn "
              "total, %.02f%% files processed." % (
               count,
               count-empties-invalids-len(nosyscalls),
               len(actors),
               empties,
               len(nosyscalls), len(nosyscallactors),
               invalids,
               100-100*(invalids+empties+len(nosyscalls)) / (count)))
        print("Instance count: %d" % instanceCount)
