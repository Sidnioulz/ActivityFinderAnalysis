#!/usr/bin/env python3

from ApplicationStore import ApplicationStore
from Event import dbgPrintExcludedEvents
from EventStore import EventStore
from FileStore import FileStore
from PreloadLoggerLoader import PreloadLoggerLoader
from SqlLoader import SqlLoader
from UserConfigLoader import UserConfigLoader
from GraphEngine import GraphEngine
from PolicyEngine import PolicyEngine
from FrequentFileEngine import FrequentFileEngine
from Policies import OneLibraryPolicy, CompoundLibraryPolicy, UnsecurePolicy, \
                     FileTypePolicy, DesignationPolicy, FolderPolicy, \
                     OneFolderPolicy, FutureAccessListPolicy, \
                     StickyBitPolicy, FilenamePolicy, ProtectedFolderPolicy, \
                     Win8Policy, Win10Policy, FFFPolicy, OneFFFPolicy, \
                     FFFSbPolicy, OneFFFSbPolicy
from constants import DATABASENAME, USERCONFIGNAME
from utils import __setCheckMissing, __setDebug, __setOutputFs, \
                  __setRelatedFiles, __setScore, __setGraph, \
                  __setPrintClusters, __setUser, __setCheckExcludedFiles, \
                  checkMissingEnabled, debugEnabled, outputFsEnabled, \
                  relatedFilesEnabled, scoreEnabled, graphEnabled, \
                  printClustersEnabled, checkExcludedFilesEnabled, \
                  initMimeTypes, getDataPath
import getopt
import sys

USAGE_STRING = 'Usage: __main__.py [--user=<NAME> --check-missing ' \
               '--output-fs=<DIR> --debug --help --score\n --clusters' \
               ' --graph-clusters --check-excluded-files]\n\tor\n' \
               '__main__.py --inode=<INODE> [--user=<NAME>]\n\tor\n' \
               '__main__.py --post-analysis=<DIR,DIR,DIR>'


# Main function
# @profile
def main(argv):
    __opt_inode_query = None
    __opt_post_analysis = None

    # Parse command-line parameters
    try:
        (opts, args) = getopt.getopt(argv, "ha:cedf:srpgi:u:",
                                     ["help",
                                      "post-analysis",
                                      "check-missing",
                                      "check-excluded-files",
                                      "debug",
                                      "inode",
                                      "related-files",
                                      "output-fs=",
                                      "score",
                                      "user",
                                      "clusters",
                                      "graph-clusters"])
    except(getopt.GetoptError):
        print(USAGE_STRING)
        sys.exit(2)
    else:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                print(USAGE_STRING + "\n")

                print("--check-missing:\n\tChecks whether some Desktop IDs "
                      "for apps in the user's directory are\n\tmissing. If so,"
                      " aborts execution of the program.\n")
                print("--check-excluded-files:\n\tPrints the lists of files "
                      "accessed by apps that also wrote to\n\texcluded files,"
                      " then aborts execution of the program.\n")
                print("--help:\n\tPrints this help information and exits.\n")
                print("--post-analysis=<DIR,DIR,DIR>:\n\t"
                      "Uses the analysis output pointed to"
                      " by --output-fs in order to produce graphs and "
                      "statistics.\n")
                print("--debug:\n\tPrints additional debug information in "
                      "various code paths to help debug\n\tthe program.\n")
                print("--output-fs=<DIR>:\n\tSaves a copy of the simulated "
                      "files, and some information on events\n\trelated to "
                      "them, in a folder created at the <DIR> path.\n")
                print("--related-files:\n\tMines for files that are frequently"
                      " accessed together by apps. WORK IN\n\tPROGRESS!\n")
                print("--score:\n\tCalculates the usability and security "
                      "scores of a number of file access\n\tcontrol policies"
                      ", replayed over the simulated accesses. Prints results"
                      "\n\tand saves them to the output directory.\n")
                print("--clusters:\n\tPrints clusters of files with "
                      "information flows to one another.\n\tRequires the "
                      "--score option.\n")
                print("--graph-clusters:\n\tFind communities in file/app "
                      "accesses using graph theory methods.\n\tRequires the "
                      "--score and --cluster options for per-policy graphs.\n")
                sys.exit()
            elif opt in ('-c', '--check-missing'):
                __setCheckMissing(True)
            elif opt in ('-e', '--check-excluded-files'):
                __setCheckExcludedFiles(True)
            elif opt in ('-d', '--debug'):
                __setDebug(True)
            elif opt in ('-r', '--related-files'):
                __setRelatedFiles(True)
            elif opt in ('-s', '--score'):
                __setScore(True)
            elif opt in ('-p', '--print-clusters'):
                __setPrintClusters(True)
            elif opt in ('-g', '--graph-clusters'):
                __setGraph(True)
            elif opt in ('-f', '--output-fs'):
                if not arg:
                    print(USAGE_STRING)
                    sys.exit(2)
                __setOutputFs(arg[1:] if arg[0] == '=' else arg)
            elif opt in ('-u', '--user'):
                if not arg:
                    print(USAGE_STRING)
                    sys.exit(2)
                __setUser(arg[1:] if arg[0] == '=' else arg)
            elif opt in ('-i', '--inode'):
                if not arg:
                    print(USAGE_STRING)
                    sys.exit(2)
                try:
                    __opt_inode_query = (arg[1:] if arg[0] == '=' else arg)
                except(ValueError) as e:
                    print(USAGE_STRING)
                    sys.exit(2)
            elif opt in ('-a', '--post-analysis'):
                if not arg:
                    print(USAGE_STRING)
                    sys.exit(2)
                __opt_post_analysis = (arg[1:] if arg[0] == '=' else arg)

    if __opt_post_analysis:
        from AnalysisEngine import AnalysisEngine
        if outputFsEnabled():
            engine = AnalysisEngine(inputDir=__opt_post_analysis,
                                    outputDir=outputFsEnabled())
        else:
            engine = AnalysisEngine(inputDir=__opt_post_analysis)
        engine.analyse()
        sys.exit(0)

    # Make the application, event and file stores
    store = ApplicationStore.get()
    evStore = EventStore.get()
    fileStore = FileStore.get()
    initMimeTypes()
    datapath = getDataPath()

    # Load up user-related variables
    userConf = UserConfigLoader.get(path=datapath+USERCONFIGNAME)

    # Load up and check the SQLite database
    sql = None
    print("\nLoading the SQLite database: %s..." % (datapath+DATABASENAME))
    try:
        sql = SqlLoader(datapath+DATABASENAME)
    except ValueError as e:
        print("Failed to parse SQL: %s" % e.args[0], file=sys.stderr)
        sys.exit(-1)
    if checkMissingEnabled():
        print("Checking for missing application identities...")
        sql.listMissingActors()
    sql.loadDb(store)
    print("Loaded the SQLite database.")

    # Load up the PreloadLogger file parser
    print("\nLoading the PreloadLogger logs in folder: %s..." % datapath)
    pll = PreloadLoggerLoader(datapath)
    if checkMissingEnabled():
        print("Checking for missing application identities...")
        pll.listMissingActors()
    pll.loadDb(store)
    print("Loaded the PreloadLogger logs.")

    # Resolve actor ids in all apps' events
    print("\nUsing PreloadLogger Applications to resolve interpreters in "
          "Zeitgeist Applications...")
    (interpretersAdded, instancesEliminated) = store.resolveInterpreters()
    print("Resolved interpreter ids in %d Applications, and removed %d "
          "instances by merging them with another as a result." % (
           interpretersAdded, instancesEliminated))

    # Update events' actor ids in the ApplicationStore, then take them and send
    # them to the EvnetStore. Finally, sort the EventStore by timestamp.
    print("\nInserting and sorting all events...")
    store.sendEventsToStore()
    evStore.sort()
    print("Sorted all %d events in the event store." % evStore.getEventCount())

    # Simulate the events to build a file model
    print("\nSimulating all events to build a file model...")
    evStore.simulateAllEvents()
    del sql
    del pll
    evStore.sort()
    print("Simulated all events. %d files initialised." % len(fileStore))

    if checkExcludedFilesEnabled():
        print("\nPrinting files written and read by instances which wrote"
              "to excluded directories...")
        dbgPrintExcludedEvents()

    # Manage --inode queries
    if __opt_inode_query:
        inodes = __opt_inode_query.split(",")
        for inode in sorted(int(i) for i in inodes):
            f = fileStore.getFile(inode)
            print("\nInode queried: %d" % inode)
            print("Corresponding file: %s\n\t(%s)" % (f.getName(), f))
        sys.exit(0)

    # Print the model as proof of concept
    if debugEnabled():
        print("\nPrinting the file model...\n")
        fileStore.printFiles(showDeleted=True,
                             showCreationTime=True,
                             showDocumentsOnly=True,
                             userHome=userConf.getSetting("HomeDir"),
                             showDesignatedOnly=False)

    # Make the filesystem corresponding to the model
    if outputFsEnabled():
        print("\nMaking a copy of the file model at '%s'...\n" %
              outputFsEnabled())
        fileStore.makeFiles(outputDir=outputFsEnabled(),
                            showDeleted=True,
                            showDocumentsOnly=False,
                            userHome=userConf.getSetting("HomeDir"),
                            showDesignatedOnly=False)

    # Build a general access graph.
    if graphEnabled():
        engine = GraphEngine()
        engine.runGraph(policy=None)

    # Policy engine. Create a policy and run a simulation to score it.
    if scoreEnabled():
        engine = PolicyEngine()

        policies = [OneLibraryPolicy, CompoundLibraryPolicy, UnsecurePolicy,
                    DesignationPolicy, FileTypePolicy, FolderPolicy,
                    OneFolderPolicy, FutureAccessListPolicy, FilenamePolicy]

        policies = [FFFPolicy, FFFSbPolicy, OneFFFPolicy, OneFFFSbPolicy]

        polArgs = [None, None, None,
                   None, None, None,
                   None, None, None]
                   # dict(folders=["~/Downloads", "/tmp"])

        for (polIdx, polName) in enumerate(policies):
            if polArgs[polIdx]:
                pol = polName(**polArgs[polIdx])
            else:
                pol = polName()

            print("\nRunning %s..." % pol.name)
            engine.runPolicy(pol,
                             outputDir=outputFsEnabled(),
                             printClusters=printClustersEnabled())

            if pol.name == "FileTypePolicy" and checkMissingEnabled():
                pol.abortIfUnsupportedExtensions()

    # Calculate frequently co-accessed files:
    if relatedFilesEnabled():
        engine = FrequentFileEngine()

        print("\nMining for frequently co-accessed files...")
        engine.mineFiles()

        print("\nMining for frequently co-accessed file types...")
        engine.mineFileTypes()


if __name__ == "__main__":
    main(sys.argv[1:])
