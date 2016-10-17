#!/usr/bin/env python3

from SqlLoader import SqlLoader
from PreloadLoggerLoader import PreloadLoggerLoader
from AppInstanceStore import AppInstanceStore
from EventStore import EventStore
from constants import USAGE_STRING, DATAPATH, DATABASENAME
import sys
import getopt


# Main function
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
    store = AppInstanceStore()

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

    # Parse all the events in found Applications
    print("\nCollecting and sorting all events...")
    evStore = EventStore()
    store.parseAllEvents(evStore)
    print("\nCollected all events.")

    # Simulate the events to build a file model
    print("\nSimulating all events to build a file model...")
    print("\e[31m\e[1mNOT IMPLEMENTED YET\e[0m")
    sys.exit(1)
    # fileStore = fileStore()
    # evStore.simulateAllEvents(fileStore)


if __name__ == "__main__":
    main(sys.argv[1:])
