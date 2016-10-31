#!/usr/bin/env python3

from ApplicationStore import ApplicationStore
from EventStore import EventStore
from FileStore import FileStore
from FileFactory import FileFactory
from PreloadLoggerLoader import PreloadLoggerLoader
from SqlLoader import SqlLoader
from constants import USAGE_STRING, DATAPATH, DATABASENAME
import getopt
import sys


# Main function
# @profile
def main(argv):
    # Application parameters
    __opt_check = False

    # Parse command-line parameters
    try:
        (opts, args) = getopt.getopt(argv, "h", ["help", "check-missing"])
    except(getopt.GetoptError):
        print(USAGE_STRING)
        sys.exit(2)
    else:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                print(USAGE_STRING)
                sys.exit()
            elif opt in ("--check-missing"):
                __opt_check = True

    # Make the application, event and file stores
    store = ApplicationStore()
    evStore = EventStore()
    fileStore = FileStore()

    # Load up and check the SQLite database
    sql = None
    print("\nLoading the SQLite database: %s..." % (DATAPATH+DATABASENAME))
    try:
        sql = SqlLoader(DATAPATH+DATABASENAME)
    except ValueError as e:
        print("Failed to parse SQL: %s" % e.args[0], file=sys.stderr)
        sys.exit(-1)
    if __opt_check:
        print("Checking for missing application identities...")
        sql.listMissingActors()
    sql.loadDb(store, evStore)
    print("Loaded the SQLite database.")

    # Load up the PreloadLogger file parser
    print("\nLoading the PreloadLogger logs in folder: %s..." % DATAPATH)
    pll = PreloadLoggerLoader(DATAPATH)
    if __opt_check:
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
    fileFactory = FileFactory(fileStore, store)
    evStore.simulateAllEvents(fileFactory, fileStore)
    print("Simulated all events.")

    # Print the model as proof of concept
    print("\nPrinting the file model...\n")
    fileStore.printFiles(showDeleted=True,
                         showCreationTime=True,
                         onlyDesignated=False)


if __name__ == "__main__":
    main(sys.argv[1:])
