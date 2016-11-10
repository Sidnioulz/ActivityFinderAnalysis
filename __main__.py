#!/usr/bin/env python3

from ApplicationStore import ApplicationStore
from EventStore import EventStore
from FileStore import FileStore
from PreloadLoggerLoader import PreloadLoggerLoader
from SqlLoader import SqlLoader
from UserConfigLoader import UserConfigLoader
from PolicyEngine import PolicyEngine
from LibraryPolicies import OneLibraryPolicy
from constants import USAGE_STRING, DATAPATH, DATABASENAME, USERCONFIGPATH
import getopt
import sys
from utils import __setCheckMissing, __setDebug, \
                  checkMissingEnabled, debugEnabled


# Main function
# @profile
def main(argv):
    # Parse command-line parameters
    try:
        (opts, args) = getopt.getopt(argv, "hcd", ["help", "check-missing",
                                                   "debug"])
    except(getopt.GetoptError):
        print(USAGE_STRING)
        sys.exit(2)
    else:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                print(USAGE_STRING)
                sys.exit()
            elif opt in ('c', '--check-missing'):
                __setCheckMissing(True)
            elif opt in ('-d', '--debug'):
                __setDebug(True)

    # Make the application, event and file stores
    store = ApplicationStore.get()
    evStore = EventStore.get()
    fileStore = FileStore.get()

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
    sql.loadDb(store, evStore)
    print("Loaded the SQLite database.")

    # Load up the PreloadLogger file parser
    print("\nLoading the PreloadLogger logs in folder: %s..." % DATAPATH)
    pll = PreloadLoggerLoader(DATAPATH)
    if checkMissingEnabled():
        print("Checking for missing application identities...")
        pll.listMissingActors()
    pll.loadDb(store, evStore)
    print("Loaded the PreloadLogger logs.")

    # Sort all the events in found Applications
    print("\nSorting all events...")
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
                             onlyDesignated=False)

    # Policy engine. Create a policy and run a simulation to score it.
    engine = PolicyEngine()  # FIXME
    print("\nRunning the One Library policy...")
    olp = OneLibraryPolicy(userConf=userConf)
    engine.runPolicy(olp)


if __name__ == "__main__":
    main(sys.argv[1:])
