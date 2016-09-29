import sqlite3 as lite
import sys
import re
from Application import Application
from utils import timestampZgPrint


EV_ID = 0
EV_TIMESTAMP = 1
EV_INTERPRETATION = 2
EV_MANIFESTATION = 3
EV_ACTOR = 4
EV_PAYLOAD = 5
EV_SUBJ_URI = 6
EV_SUBJ_ID = 7
EV_SUBJ_INTERPRETATION = 8
EV_SUBJ_MANIFESTATION = 9
EV_SUBJ_ORIGIN = 10
EV_SUBJ_ORIGIN_URI = 11
EV_SUBJ_MIMETYPE = 12
EV_SUBJ_TEXT = 13
EV_SUBJ_STORAGE = 14
EV_SUBJ_STORAGE_STATE = 15
EV_ORIGIN = 16
EV_EVENT_ORIGIN_URI = 17
EV_SUBJ_CURRENT_URI = 18
EV_SUBJ_ID_CURRENT = 19
EV_SUBJ_TEXT_ID = 20
EV_SUBJ_STORAGE_ID = 21
EV_ACTOR_URI = 22
EV_SUBJ_ORIGIN_CURRENT = 23
EV_SUBJ_ORIGIN_CURRENT_URI = 24
EV_INTERPRETATION_URI = 25
EV_MANIFESTATION_URI = 26


class SqlLoader(object):
    path = ""
    con = None
    cur = None

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

    def __exit__(self):
        if self.con:
            self.con.close()

    """ Go through the SQLite database and print the list of .desktop files that
        are missing on the system used for analysis. Exits if some apps are
        missing. """
    def listMissingActors(self):
        self.cur = self.con.cursor()
        self.cur.execute('SELECT * from actor')
        hasErrors = False

        data = self.cur.fetchall()
        for listing in data:
            app = Application(desktopid=listing[1])
            if not app.isInitialised():
                print("MISSING: %s" % listing[1],
                      file=sys.stderr)
                hasErrors = True

        if hasErrors is True:
            sys.exit(-1)

    """ Go through the SQLite database and create all the relevant app instances
        and events. """
    def loadDb(self):
        self.cur = self.con.cursor()
        self.cur.execute('SELECT ev.*, (SELECT value \
                                     FROM interpretation \
                                     WHERE interpretation.id = \
                                           ev.interpretation) \
                                    AS interpretation_uri, \
                                     (SELECT value \
                                      FROM manifestation \
                                      WHERE manifestation.id = \
                                            ev.manifestation) \
                                     AS manifestation_uri \
                          FROM event_view AS ev \
                          WHERE ev.subj_uri LIKE "activity://%"')

        nopids = []
        zeropids = []
        eventsPerPid = dict()
        data = self.cur.fetchone()
        count = 0

        while data:
            count += 1
            if "pid://" not in data[EV_SUBJ_URI]:
                nopids.append(data)
            else:
                m = re.search('(?<=pid://)\d+', data[EV_SUBJ_URI])
                pid = m.group(0) if m else 0
                if pid:
                    try:
                        eventsPerPid[pid].append(data)
                    except KeyError as e:
                        eventsPerPid[pid] = [data]
                else:
                    zeropids.append(data)
            data = self.cur.fetchone()

        # for (pkey, pevent) in eventsPerPid:
        #     print(type(plist), plist)
        #     pevent.sort()

        print("Summary of events: %d events seen, %d accepted, %d rejected "
              "as having no PID. In total, %.02f%% rejected." % (
               count-len(nopids),
               count-len(nopids)-len(zeropids),
               len(zeropids),
               100*len(zeropids) / (count-len(nopids))))

        # TODO handle zeropids
        interpretations = []
        dates = []
        [interpretations.append(e[EV_ACTOR_URI]) for e in zeropids if
         e[EV_ACTOR_URI] not in interpretations]
        [dates.append(e[EV_SUBJ_URI]) for e in zeropids if
         e[EV_SUBJ_URI] not in dates]
        print(interpretations)
        print(dates)

        # TODO app = Application(desktopid=data[0][1])
