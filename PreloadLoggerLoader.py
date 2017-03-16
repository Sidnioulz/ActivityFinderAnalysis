import sys
import os
import re
from Application import Application
from ApplicationStore import ApplicationStore
from Event import Event
from utils import space, pyre, bashre, pynamer, pyprocname, javare, javanamer, \
                  javaprocname, perlre, perlnamer, monore, mononamer, \
                  monoprocname, phpre, phpnamer, phpprocname, debugEnabled, \
                  tail


class PreloadLoggerLoader(object):
    path = ""
    pattern = re.compile("^\d{4}-\d{2}-\d{2}_\d+_\d+.log$")
    header = re.compile("^@(.*?)[|](\d+)[|](.*)$")
    syscall = re.compile("^(\d+)[|](.*)$")
    delpattern = None  # TODO

    """ PreloadLoggerLoader loads all PreloadLogger log files from a user
        directory, and parses them into appropriate events. """
    def __init__(self, path):
        self.path = path
        super(PreloadLoggerLoader, self).__init__()

    """ Get the proper app identity out of a Python execution, by parsing the
    Python command line. """
    def parsePython(self, g: tuple, items: list=None):
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) <= 1:
            return g

        while len(items):
            del items[0]

            # Everything got deleted! It's an interactive interpreter session.
            if not items:
                return g

            # Remove -Es if present.
            if items[0] == "-Es":
                continue

            # Remove -m if present, and use module name.
            if items[0] == "-m":
                continue

            # Return if a command was passed, as it's actually Python running.
            if items[0] == "-c":
                return g

            # Ignore "python -O /tmp/..."
            if items[0] == "-O":
                if len(items) > 1 and items[1].startswith("/tmp/"):
                    return g

            # # Return if an unknown parameter was passed.
            # if items[0].startswith('-'):
            #     continue
            break
        # We had to delete every item without breaking, this means the
        # interpreter had no actual application parameter. It was interactive.
        else:
            return g

        res = pynamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = pyprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            newcmd = ' '.join(items[0:])
            return (newproc, g[1], newcmd)
        else:
            return g

    def parseBash(self, g: tuple, items: list=None):
        """Parse cmdline to find the proper app behind a Bash command."""
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) <= 1:
            return g

        while len(items):
            del items[0]

            # Everything got deleted! It's an interactive interpreter session.
            if not items:
                return g

            # # Return if an unknown parameter was passed.
            # if items[0].startswith('-'):
            #     continue
            break
        # We had to delete every item without breaking, this means the
        # interpreter had no actual application parameter. It was interactive.
        else:
            return g

        res = bashnamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = bashprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            newcmd = ' '.join(items[0:])
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
            items = space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) <= 1:
            return g

        while len(items):
            del items[0]

            # Everything got deleted! It's an interactive interpreter session.
            if not items:
                return g

            # Remove -jar if present.
            if items[0] == "-jar":
                continue

            # Return if -version was passed, as it's actually Java running.
            if items[0] == "-version":
                return g

            # Skip the classpath if passed, and delete the next argument (the
            # value of the classpath parameter).
            if items[0] in ["-classpath", "-cp"]:
                if len(items) > 1:
                    del items[0]
                    continue
                # Not enough parameters, incorrect call, return java.
                else:
                    return g

            # Remove -D/-X definitions.
            if items[0].startswith("-D") or items[0].startswith("-X"):
                continue

            # Remove -dsa and -esa, and -da and -ea.
            if items[0] in ["dsa", "esa", "-da", "-ea"]:
                continue

            # # Return if an unknown parameter was passed.
            # if items[0].startswith('-'):
            #     continue
            break
        # We had to delete every item without breaking, this means the
        # interpreter had no actual application parameter. It was interactive.
        else:
            return g

        res = javanamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = javaprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            newcmd = ' '.join(items[0:])
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
            items = space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) <= 1:
            return g

        while len(items):
            del items[0]

            # Everything got deleted! It's an interactive interpreter session.
            if not items:
                return g

            # Remove -w if present.
            if items[0] == "-w":
                continue

            break
        # We had to delete every item without breaking, this means the
        # interpreter had no actual application parameter. It was interactive.
        else:
            return g

        res = perlnamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            newcmd = ' '.join(items[0:])
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
            items = space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) <= 1:
            return g

        # Mono apps in our logs seem to log the command-line properly, e.g. our
        # mono-sgen actor has a command-line starting with "banshee" when the
        # Banshee app is launched. Thus, we only update the process name
        res = mononamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = monoprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name
            return (newproc, g[1], g[2])
        else:
            return g

    """ Get the proper app identity out of a PHP execution, by parsing the
    PHP command line. """
    def parsePHP(self, g: tuple, items: list=None):
        if not hasattr(g, '__len__'):
            return g
        if len(g) is not 3:
            return g

        if not items:
            items = space.split(g[2])

        # Return if there are no parameters, the interpreter is the app
        if len(items) <= 1:
            return g

        res = phpnamer.match(items[0])
        name = res.groups()[0] if res.groups() else None

        if name:
            procres = phpprocname.match(name)
            newproc = procres.groups()[0] if procres.groups() else name

            return (newproc, g[1], g[2])
        else:
            return g

    def listMissingActors(self):
        """List missing applications' desktop files.

        Go through the logs and print the list of .desktop files that are
        missing on the system used for analysis. Exits if some apps are
        missing.
        """
        self.loadDb(store=None, checkInitialised=True)

    def loadDb(self,
               store: ApplicationStore = None,
               checkInitialised: bool = False):
        """Load the PreloadLogger database.

        Go through the directory and create all the relevant app instances and
        events. Can be made to insert all found apps into an ApplicationStore,
        or to exit if some Application instances are not properly initialised.
        """

        count = 0              # Counter of fetched files, for stats
        actors = set()         # Apps that logged anything at all
        empties = 0            # Matching files without content (logger crash)
        invalids = 0           # Files with corrupted content (logger crash)
        nosyscalls = []        # Logs with zero syscalls logged (not a bug)
        nosyscallactors = set()  # Apps that logged zero syscalls
        instanceCount = 0      # Count of distinct app instances in the dataset
        hasErrors = False      # Whether some uninitialised apps were found
        invalidApps = set()    # List of desktop IDs that could not be init'd

        # List all log files that match the PreloadLogger syntax
        for file in os.listdir(self.path):
            # Ignore files that don't match
            if not PreloadLoggerLoader.pattern.match(file):
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
                    if os.fstat(f.fileno()).st_size == 0:
                        print("Info: file '%s' is empty. Skipping." % file)
                        continue

                    # Parse the first line to get the identity of the app,
                    # but sometimes the header ends up on the second line
                    # in some logs... So, parse until we find a match, and
                    # remember the line index of the header
                    idx = 0
                    headerLocation = 0
                    result = None
                    for binary in f:
                        try:
                            line = binary.decode('utf-8')
                        except(UnicodeDecodeError) as e:
                            print("Error: %s has a non utf-8 line: %s " % (
                                   file,
                                   str(e)),
                                  file=sys.stderr)
                            idx += 1
                            continue
                        result = PreloadLoggerLoader.header.match(line)
                        if result:
                            headerLocation = idx
                            break
                        idx += 1

                    # Files with a missing or corrupted header are invalid
                    if result is None:
                        print("%s is missing a header" % file,
                              file=sys.stderr)
                        invalids += 1
                        continue

                    # Parse the header line, make sure it has the right length.
                    g = result.groups()
                    if (len(g) != 3):
                        print("%s has wrong group count: " % file,
                              result.group(),
                              file=sys.stderr)
                        invalids += 1
                        continue

                    # Filter interpreters, and rewrite them to get the identity
                    # of the app they launched instead.
                    items = space.split(g[2])
                    interpreterid = None

                    # Python
                    if (pyre.match(g[0])):
                        interpreterid = g[0]
                        g = self.parsePython(g, items)
                        # print("PYTHON APP: %s" % g[2])

                    # Bash
                    if (bashre.match(g[0])):
                        interpreterid = g[0]
                        g = self.parseBash(g, items)
                        # print("BASH APP: %s" % g[2])

                    # Java
                    if (javare.match(g[0])):
                        interpreterid = g[0]
                        g = self.parseJava(g, items)
                        # print("JAVA APP: %s" % g[2])
                    # Perl
                    if (perlre.match(g[0])):
                        interpreterid = g[0]
                        g = self.parsePerl(g, items)
                        # print("PERL APP: %s" % g[2])

                    # Mono
                    if (monore.match(g[0])):
                        interpreterid = g[0]
                        g = self.parseMono(g, items)
                        # print("MONO APP: %s" % g[2])

                    # PHP
                    if (phpre.match(g[0])):
                        interpreterid = g[0]
                        g = self.parsePHP(g, items)
                        # print("PHP APP: %s" % g[2])

                    # Get first and last event to calculate the timestamps.
                    tstart = float("inf")
                    tend = 0

                    skipCache = None
                    lineIdx = 0
                    f.seek(0, 0)
                    for binary in f:
                        # Ignore the header.
                        if lineIdx == headerLocation:
                            lineIdx += 1
                            skipCache = None
                            continue

                        # Decode line.
                        try:
                            line = binary.decode('utf-8')
                        except(UnicodeDecodeError) as e:
                            print("Error: %s has a non utf-8 line: %s " % (
                                   file,
                                   str(e)),
                                  file=sys.stderr)
                            lineIdx += 1
                            skipCache = None
                            continue

                        # Previous line did not end and was skipped, merge it.
                        if skipCache:
                            line = skipCache + line
                            skipCache = None

                        # Line continues...
                        if line.endswith('\\\n'):
                            skipCache = line
                            lineIdx += 1
                            continue

                        line = line.rstrip("\n").lstrip(" ")

                        # Line is a parameter to the last system call logged
                        if line.startswith(' '):
                            lineIdx += 1
                            continue

                        # Check that line is a syntactically valid system call
                        result = PreloadLoggerLoader.syscall.match(line)
                        if result is None:
                            if debugEnabled():
                                print("%s has a corrupted line (match): %s" % (
                                       file,
                                       line),
                                      file=sys.stderr)
                            lineIdx += 1
                            continue

                        # Update the timestamp (convert to ZG millisec format)
                        h = result.groups()
                        tstart = int(h[0]) * 1000
                        break

                    # TODO, first non-header line + tail code.
                    lastLine = tail(f)
                    result = None
                    if lastLine:
                        result = PreloadLoggerLoader.syscall.match(lastLine)

                    if result is None:
                        if debugEnabled():
                            print("%s's last line is corrupted: %s" % (
                                   file,
                                   lastLine),
                                  file=sys.stderr)
                    else:
                        # Update the timestamp (convert to ZG millisec format)
                        h = result.groups()
                        tend = int(h[0]) * 1000

                    # Check if the timestamps have been set
                    if tend == 0:
                        nosyscalls.append(g)
                        nosyscallactors.add(g[0])
                        continue

                    # Sometimes, short logs have event ordering problems... We
                    # can try to ignore these problems as all events are indi-
                    # vidually timestamped anyway.
                    if tstart > tend:
                        tend, start = tstart, tend

                    # TODO: process deletions and remove corresponding files

                    # Make the application
                    try:
                        app = Application(desktopid=g[0],
                                          pid=int(g[1]),
                                          tstart=tstart,
                                          tend=tend,
                                          interpreterid=interpreterid)
                        app.setCommandLine(g[2])
                    except(ValueError) as e:
                        print("MISSING: %s" % g[0],
                              file=sys.stderr)
                        hasErrors = True
                        invalidApps.add(g[0])
                        continue

                    # Ignore study artefacts!
                    if app.isStudyApp():
                        continue

                    # Add command-line event
                    event = Event(actor=app, time=tstart, cmdlineStr=g[2])
                    app.addEvent(event)

                    # Add system call events
                    skipCache = None
                    lineIdx = 0
                    currentCall = None
                    prevTimestamp = 0
                    timeDelta = 0
                    f.seek(0, 0)
                    for binary in f:
                        # Ignore the header.
                        if lineIdx == headerLocation:
                            lineIdx += 1
                            skipCache = None
                            continue

                        # Decode line.
                        try:
                            line = binary.decode('utf-8')
                        except(UnicodeDecodeError) as e:
                            print("Error: %s has a non utf-8 line: %s " % (
                                   file,
                                   str(e)),
                                  file=sys.stderr)
                            lineIdx += 1
                            skipCache = None
                            continue

                        # Previous line did not end and was skipped, merge it.
                        if skipCache:
                            line = skipCache + line
                            skipCache = None

                        # Line continues...
                        if line.endswith('\\\n'):
                            skipCache = line
                            lineIdx += 1
                            continue

                        line = line[:-1]  # Remove ending "\n"

                        # Line is a parameter to the last system call logged
                        if line.startswith(' '):
                            if currentCall:
                                currentCall = (currentCall[0],
                                               currentCall[1] + '\n' + line)
                            elif debugEnabled():
                                print("%s has a corrupted line (no call): %s" %
                                      (file, line),
                                      file=sys.stderr)
                            lineIdx += 1
                            continue

                        # Check that line is a syntactically valid system call
                        result = PreloadLoggerLoader.syscall.match(line)
                        if result is None:
                            if debugEnabled():
                                print("%s has a corrupted line (match): %s" % (
                                       file,
                                       line),
                                      file=sys.stderr)
                            lineIdx += 1
                            continue

                        # Update the timestamp (convert to ZG millisec format)
                        h = result.groups()
                        timestamp = int(h[0]) * 1000

                        # Append the system call to our syscall list. Note that
                        # we do something odd with the timestamp: because PL
                        # only logs at second precision, a lot of system calls
                        # have the same timestamp, which causes the EventStore
                        # to sort them in the wrong order. So, every time we
                        # have a timestamp identical to the previous one, we
                        # increase a counter that sorts them. This works under
                        # the assumption that there are at most 1000 events per
                        # second.
                        if timestamp == prevTimestamp:
                            timeDelta += 1
                        else:
                            timeDelta = 0

                        # Process the last system call into an Event, and clear
                        # up the syscalls list to keep RAM free!
                        if currentCall:
                            event = Event(actor=app,
                                          time=currentCall[0],
                                          syscallStr=currentCall[1])
                            app.addEvent(event)

                        # Create the new syscalls list.
                        currentCall = (timestamp + timeDelta, h[1])
                        prevTimestamp = timestamp

                        lineIdx += 1

                    # Add the found process id to our list of actors, using the
                    # app identity that was resolved by the Application ctor
                    actors.add(app.desktopid)

                    if checkInitialised and not app.isInitialised():
                        print("MISSING: %s" % g[0],
                              file=sys.stderr)
                        hasErrors = True

                    # Insert into the ApplicationStore if one is available
                    if store is not None:
                        store.insert(app)
                        instanceCount += 1

        if checkInitialised and hasErrors:
            if invalidApps:
                print("Invalid apps:", file=sys.stderr)
                for a in sorted(invalidApps):
                    print("\t%s" % a, file=sys.stderr)
            sys.exit(-1)

        # print("Apps that logged valid files:")
        # for act in sorted(actors):
        #     print(act)

        # print("\nApps that logged files without a single system call:")
        # for act in sorted(nosyscallactors):
        #     print(act)

        print("Finished loading DB.\n%d files seen, %d valid from %d apps, "
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
