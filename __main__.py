#!/usr/bin/env python3

from SqlLoader import SqlLoader
from PreloadLoggerLoader import PreloadLoggerLoader
from AppInstanceStore import AppInstanceStore
from constants import DATAPATH, DATABASENAME
import sys

# Make the application store
store = AppInstanceStore()

# # Load up and check the SQLite database
sql = None
print("Loading the SQLite database: %s" % (DATAPATH+DATABASENAME))
try:
    sql = SqlLoader(DATAPATH+DATABASENAME)
except ValueError as e:
    print("Failed to parse SQL: %s" % e.args[0], file=sys.stderr)
    sys.exit(-1)
# sql.listMissingActors()
sql.loadDb(store)
print("Loaded the SQLite database.")


# Load up the PreloadLogger file parser
pll = PreloadLoggerLoader(DATAPATH)
# pll.listMissingActors()

print("Loading the PreloadLogger logs in: %s" % DATAPATH)
pll.loadDb(store)
print("Loaded the PreloadLogger logs.")


# Read the database now that we know we can work with it
try:
    pids = store.lookupPid(5283)
except KeyError as e:
    pass
else:
    print(5283, pids)
