#!/usr/bin/env python3

from ApplicationStore import ApplicationStore
from EventStore import EventStore
# from FileStore import FileStore
from PreloadLoggerLoader import PreloadLoggerLoader
from SqlLoader import SqlLoader
from constants import USAGE_STRING, DATAPATH, DATABASENAME
import getopt
import sys

# Debugging imports
import objgraph
from pympler import asizeof


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

    # Make the application store
    store = ApplicationStore()

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
    sql.loadDb(store)
    print("Loaded the SQLite database.")

    # Load up the PreloadLogger file parser
    print("\nLoading the PreloadLogger logs in folder: %s..." % DATAPATH)
    pll = PreloadLoggerLoader(DATAPATH)
    if __opt_check:
        print("Checking for missing application identities...")
        pll.listMissingActors()
    pll.loadDb(store)
    print("Loaded the PreloadLogger logs.")

    # Debugging
    roots = objgraph.get_leaking_objects()
    print("%d leaking objects" % len(roots))
    objgraph.show_most_common_types(objects=roots)
    asizeof.asizeof(objgraph.by_type('set'))

    # Retrieve all the events in found Applications
    print("\nSorting all events...")
    evStore = EventStore()
    evStore.sort()
    print("Sorted all %d events in the event store." % evStore.getEventCount())

    # Simulate the events to build a file model
    # fileStore = FileStore()
    # evStore.simulateAllEvents(fileStore)
    print("\nSimulating all events to build a file model...")


if __name__ == "__main__":
    main(sys.argv[1:])
