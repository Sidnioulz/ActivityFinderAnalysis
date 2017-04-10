import sqlite3 as lite
import sys
import re
from Application import Application
from ApplicationStore import ApplicationStore
from Event import Event
from SqlEvent import SqlEvent, SqlEventSubject
from constants import EV_ID, EV_TIMESTAMP, EV_INTERPRETATION, \
                      EV_MANIFESTATION, EV_ACTOR_URI, EV_EVENT_ORIGIN_URI, \
                      EV_SUBJ_URI, EV_SUBJ_INTERPRETATION, \
                      EV_SUBJ_MANIFESTATION, EV_SUBJ_ORIGIN_URI, \
                      EV_SUBJ_MIMETYPE, EV_SUBJ_TEXT, EV_SUBJ_STORAGE, \
                      EV_SUBJ_CURRENT_URI
from utils import uq, debugEnabled


class SqlLoader(object):
    path = ""
    con = None
    cur = None
    interpretations = dict()
    manifestations = dict()
    mimetypes = dict()

    """ SqlLoader loads a SQLite database from Zeitgeist and produces apps and
        app instances. Pass it the path to the activities.sqlite file. """
    def __init__(self, path):
        super(SqlLoader, self).__init__()
        self.path = path
        try:
            self.con = lite.connect(self.path)
        except lite.Error as e:
            print("Failed to initialise SqlLoader: %s" % e.args[0],
                  file=sys.stderr)
            raise ValueError(e.args)

        self.cur = self.con.cursor()

        # Cache interpretations
        self.cur.execute('SELECT * FROM interpretation;')
        data = self.cur.fetchone()
        while data:
            self.interpretations[data[0]] = data[1]
            data = self.cur.fetchone()

        # Cache manifestations
        self.cur.execute('SELECT * FROM manifestation;')
        data = self.cur.fetchone()
        while data:
            self.manifestations[data[0]] = data[1]
            data = self.cur.fetchone()

        # Cache mimetypes
        self.cur.execute('SELECT * FROM mimetype;')
        data = self.cur.fetchone()
        while data:
            self.mimetypes[data[0]] = uq(data[1])  # image%2Fjpeg in dataset
            data = self.cur.fetchone()

    def __exit__(self):
        if self.con:
            self.con.close()

    def getInterpretation(self, id: int):
        """Return the interpretation for a given interpretation id."""
        return self.interpretations.get(id)

    def getManifestation(self, id: int):
        """Return the manifestation for a given manifestation id."""
        return self.manifestations.get(id)

    def getMimeType(self, id: int):
        """Return the MIME type for a given mimetype id."""
        return self.mimetypes.get(id)

    def listMissingActors(self):
        """Check for missing apps.

        Go through the SQLite database and print the list of .desktop files
        that are missing on the system used for analysis. Exits if some apps
        are missing.
        """
        self.cur = self.con.cursor()
        self.cur.execute('SELECT * from actor')
        hasErrors = False

        data = self.cur.fetchall()
        invalidApps = set()
        for listing in data:
            try:
                app = Application(desktopid=listing[1])
            except(ValueError) as e:
                print("MISSING: %s" % listing[1],
                      file=sys.stderr)
                invalidApps.add(listing[1])
                hasErrors = True

        if invalidApps and hasErrors:
            print("Invalid apps:", file=sys.stderr)
            for a in sorted(invalidApps):
                print("\t%s" % a, file=sys.stderr)
            sys.exit(-1)

    def loadDb(self, store: ApplicationStore = None):
        """Browse the SQLite db and create all the relevant app instances."""

        # Load up our events from the Zeitgeist database
        self.cur = self.con.cursor()
        self.cur.execute('SELECT * \
                          FROM event_view \
                          WHERE id IN (SELECT DISTINCT id \
                                       FROM event_view \
                                       WHERE subj_uri LIKE "activity://%")')

        # Merge all event subjects based on their event id, and find their pids
        eventsMerged = dict()
        data = self.cur.fetchone()
        while data:
            pid = 0
            if "pid://" in data[EV_SUBJ_URI]:
                m = re.search('(?<=pid://)\d+', data[EV_SUBJ_URI])
                pid = int(m.group(0)) if m else 0

            ev = eventsMerged.get(data[EV_ID])
            if not ev:
                ev = SqlEvent(id=data[EV_ID],
                              pid=pid,
                              timestamp=data[EV_TIMESTAMP],
                              interpretation=self.getInterpretation(
                                             data[EV_INTERPRETATION]),
                              manifestation=self.getManifestation(
                                             data[EV_MANIFESTATION]),
                              origin_uri=data[EV_EVENT_ORIGIN_URI],
                              actor_uri=data[EV_ACTOR_URI])
            elif pid and ev.pid:
                assert ev.pid == pid, ("Error: multiple events record a pid "
                                       " event %d, and they disagree on the "
                                       "pid to record (%d != %d)." % (
                                        data[EV_ID], ev.pid, pid))
            elif pid and not ev.pid:
                ev.pid = pid

            subj = SqlEventSubject(uri=data[EV_SUBJ_URI],
                                   interpretation=self.getInterpretation(
                                                 data[EV_SUBJ_INTERPRETATION]),
                                   manifestation=self.getManifestation(
                                                 data[EV_SUBJ_MANIFESTATION]),
                                   origin_uri=data[EV_SUBJ_ORIGIN_URI],
                                   mimetype=self.getMimeType(
                                            data[EV_SUBJ_MIMETYPE]),
                                   text=data[EV_SUBJ_TEXT],
                                   storage_uri=data[EV_SUBJ_STORAGE],
                                   current_uri=data[EV_SUBJ_CURRENT_URI])
            ev.addSubject(subj)
            eventsMerged[data[EV_ID]] = ev

            data = self.cur.fetchone()

        # Now, sort the events per app PID so we can build apps
        nopids = []            # Matching events without a PID
        eventsPerPid = dict()  # Storage for our events
        count = len(eventsMerged)  # Counter of fetched events, for stats
        instanceCount = 0      # Count of distinct app instances in the dataset
        actors = set()

        for event in eventsMerged.items():
            pid = event[1].pid
            if not pid:
                nopids.append(event[1])
            else:
                try:
                    eventsPerPid[pid].append(event[1])
                except KeyError as e:
                    eventsPerPid[pid] = [event[1]]
        del eventsMerged  # no longer needed

        # For each PID, we'll now identify the successive Application instances
        for (pkey, pevent) in eventsPerPid.items():
            pevent = sorted(pevent, key=lambda x: x.timestamp)
            currentId = ''     # currently matched Desktop Id
            currentApp = None  # currently matched Application
            apps = []          # temp storage for found Applications

            for ev in pevent:
                (evId, __) = Application.getDesktopIdFromDesktopUri(
                    ev.actor_uri)

                if evId != currentId:
                    if debugEnabled():
                        print ("New application:", evId, currentId, ev)
                    currentId = evId
                    currentApp = Application(desktopid=evId,
                                             pid=int(pkey),
                                             tstart=ev.timestamp,
                                             tend=ev.timestamp)
                    actors.add(currentApp.desktopid)
                    apps.append(currentApp)
                else:
                    currentApp.setTimeOfStart(min(ev.timestamp,
                                                  currentApp.getTimeOfStart()))

                    currentApp.setTimeOfEnd(max(ev.timestamp,
                                                currentApp.getTimeOfEnd()))
                # Ignore study artefacts!
                if not currentApp.isStudyApp():
                    event = Event(actor=currentApp,
                                  time=ev.timestamp,
                                  zgEvent=ev)
                    currentApp.addEvent(event)

            # Insert into the ApplicationStore if one was given to us
            instanceCount += len(apps)
            if store is not None:
                for app in apps:
                    # Ignore study artefacts!
                    if not app.isStudyApp():
                        store.insert(app)
                    else:
                        instanceCount -= 1  # We discount this app instance


        self.appCount = len(actors)
        self.instCount = instanceCount
        self.eventCount = count
        self.validEventRatio = 100-100*len(nopids) / count

        print("Finished loading DB.\n%d events seen, %d normal, %d without a "
              "PID.\nIn total, %.02f%% events accepted." % (
               count,
               count-len(nopids),
               len(nopids),
               self.validEventRatio))
        print("Instance count: %d" % self.instCount)
