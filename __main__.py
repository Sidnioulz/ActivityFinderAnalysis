#!/usr/bin/env python3

from ApplicationStore import ApplicationStore
from EventStore import EventStore
from FileStore import FileStore
from PreloadLoggerLoader import PreloadLoggerLoader
from SqlLoader import SqlLoader
from UserConfigLoader import UserConfigLoader
from GraphEngine import AccessGraph, ActivityGraph, InstanceGraph
from PolicyEngine import PolicyEngine
from FrequentFileEngine import FrequentFileEngine
from Policies import OneLibraryPolicy, CompoundLibraryPolicy, UnsecurePolicy, \
                     FileTypePolicy, DesignationPolicy, FolderPolicy
from constants import DATAPATH, DATABASENAME, USERCONFIGPATH
from utils import __setCheckMissing, __setDebug, __setOutputFs, \
                  __setRelatedFiles, __setScore, __setGraph, \
                  __setPrintClusters, \
                  checkMissingEnabled, debugEnabled, outputFsEnabled, \
                  relatedFilesEnabled, scoreEnabled, graphEnabled, \
                  printClustersEnabled, initMimeTypes
import getopt
import sys

USAGE_STRING = 'Usage: __main__.py [--check-missing --debug --help ' \
               '--output-fs=<DIR> --score\n --print-clusters ' \
               '--graph-clusters]'


# Main function
# @profile
def main(argv):
    # Parse command-line parameters
    try:
        (opts, args) = getopt.getopt(argv, "hcdf:srpg", ["help",
                                                         "check-missing",
                                                         "debug",
                                                         "related-files",
                                                         "output-fs=",
                                                         "score",
                                                         "print-clusters",
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
                print("--help:\n\tPrints this help information and exits.\n")
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
                print("--print-clusters:\n\tPrints clusters of files with "
                      "information flows to one another.\n\tRequires the "
                      "--score option.\n")
                print("--graph-clusters:\n\tFind communities in file/app "
                      "accesses using graph theory methods.\n\tRequires the "
                      "--score option for per-policy graphs.\n")
                sys.exit()
            elif opt in ('c', '--check-missing'):
                __setCheckMissing(True)
            elif opt in ('-d', '--debug'):
                __setDebug(True)
            elif opt in ('-r', '--related-files'):
                __setRelatedFiles(True)
            elif opt in ('-s', '--score'):
                __setScore(True)
            elif opt in ('-p', '--print-clusters'):
                __setPrintClusters(True)
            elif opt in ('-p', '--graph-clusters'):
                __setGraph(True)
            elif opt in ('-f', '--output-fs'):
                if not arg:
                    print(USAGE_STRING)
                    sys.exit(2)
                __setOutputFs(arg[1:] if arg[0] == '=' else arg)

    # Make the application, event and file stores
    store = ApplicationStore.get()
    evStore = EventStore.get()
    fileStore = FileStore.get()
    initMimeTypes()

    # Load up user-related variables
    userConf = UserConfigLoader(USERCONFIGPATH)

    # Load up and check the SQLite database
    sql = None
    print("\nLoading the SQLite database: %s..." % (DATAPATH+DATABASENAME))
    try:
        sql = SqlLoader(DATAPATH+DATABASENAME)
    except ValueError as e:
        print("Failed to parse SQL: %s" % e.args[0], file=sys.stderr)
        sys.exit(-1)
    if checkMissingEnabled():
        print("Checking for missing application identities...")
        sql.listMissingActors()
    sql.loadDb(store)
    print("Loaded the SQLite database.")

    # Load up the PreloadLogger file parser
    print("\nLoading the PreloadLogger logs in folder: %s..." % DATAPATH)
    pll = PreloadLoggerLoader(DATAPATH)
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
    print("Simulated all events.")

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
                            showDocumentsOnly=True,
                            userHome=userConf.getSetting("HomeDir"),
                            showDesignatedOnly=False)

    if graphEnabled():
        # TODO do a version with files of an instance all connected, to focus
        # on separating app instances instead of denying accesses.
        print("\nCompiling the general Access Graph...")
        g = AccessGraph()
        g.populate(userConf=userConf, policy=None)
        g.plot(output="graph-accesses")
        print("Done.")

        print("\nCompiling the general Activity Graph...")
        g = ActivityGraph()
        g.populate(userConf=userConf, policy=None)
        g.plot(output="graph-activities")
        print("Done.")

        print("\nCompiling the general Instance Graph...")
        g = InstanceGraph()
        g.populate(userConf=userConf, policy=None)
        g.plot(output="graph-instances")
        print("Done.")

    # Policy engine. Create a policy and run a simulation to score it.
    if scoreEnabled():
        engine = PolicyEngine()

        # print("\nRunning the Unsecure policy...")
        # engine.runPolicy(UnsecurePolicy(userConf=userConf),
        #                  outputDir=outputFsEnabled(),
        #                  printClusters=printClustersEnabled())

        print("\nRunning the Designation policy...")
        engine.runPolicy(DesignationPolicy(userConf=userConf),
                         outputDir=outputFsEnabled(),
                         printClusters=printClustersEnabled())

        print("\nRunning the Folder policy...")
        engine.runPolicy(FolderPolicy(userConf=userConf),
                         outputDir=outputFsEnabled(),
                         printClusters=printClustersEnabled())

        # print("\nRunning the One Library policy...")
        # engine.runPolicy(OneLibraryPolicy(userConf=userConf),
        #                  outputDir=outputFsEnabled(),
        #                  printClusters=printClustersEnabled())

        # print("\nRunning the Compound Library policy...")
        # engine.runPolicy(CompoundLibraryPolicy(userConf=userConf),
        #                  outputDir=outputFsEnabled(),
        #                  printClusters=printClustersEnabled())

        # print("\nRunning the File Type policy...")
        # pol = FileTypePolicy(userConf=userConf)
        # engine.runPolicy(pol,
        #                  outputDir=outputFsEnabled(),
        #                  printClusters=printClustersEnabled())
        # if checkMissingEnabled:
        #     pol.abortIfUnsupportedExtensions()

    # Calculate frequently co-accessed files:
    if relatedFilesEnabled():
        engine = FrequentFileEngine(userConf=userConf)

        print("\nMining for frequently co-accessed files...")
        engine.mineFiles()

        print("\nMining for frequently co-accessed file types...")
        engine.mineFileTypes()


if __name__ == "__main__":
    main(sys.argv[1:])
