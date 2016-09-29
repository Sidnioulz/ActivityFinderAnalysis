#!/usr/bin/env python3

from SqlLoader import SqlLoader
from Application import Application
from AppInstanceStore import AppInstanceStore
from constants import DATAPATH, DATABASENAME
from utils import timestampZgPrint
import sys

# Make the application store
store = AppInstanceStore()

# Load up and check the SQLite database
sql = None
try:
    sql = SqlLoader(DATAPATH+DATABASENAME)
    print(sql)
except ValueError as e:
    print("Failed to parse SQL: %s" % e.args[0], file=sys.stderr)
    sys.exit(-1)
sql.listMissingActors()
print("Loaded the SQLite database: %s" % DATABASENAME)

# Read the database now that we know we can work with it
sql.loadDb()
