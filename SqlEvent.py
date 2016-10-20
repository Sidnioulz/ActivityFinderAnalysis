from utils import timestampZgPrint


class SqlEventSubject(object):
    uri = ''             # type: str
    interpretation = ''  # type: str
    manifestation = ''   # type: str
    origin_uri = ''      # type: str
    mimetype = ''        # type: str
    text = ''            # type: str
    storage_uri = ''     # type: str
    current_uri = ''     # type: str

    def __init__(self,
                 uri: str,
                 interpretation: str,
                 manifestation: str,
                 origin_uri: str,
                 mimetype: str,
                 text: str,
                 storage_uri: str,
                 current_uri: str):
        self.uri = uri
        self.interpretation = interpretation
        self.manifestation = manifestation
        self.origin_uri = origin_uri
        self.mimetype = mimetype
        self.text = text
        self.storage_uri = storage_uri
        self.current_uri = current_uri

    def __str__(self):
        return ("\t\turi: %s\n\t\tinterpretation: %s\n"
                "\t\tmanifestation: %s\n\t\tmime type: %s\n"
                "\t\ttext: %s\n\t\tstorage: %s\n\t\tcurrent uri: %s\n" % (
                 self.uri, self.interpretation, self.manifestation,
                 self.mimetype, self.text, self.storage_uri, self.current_uri))

# FIXME
# subj_uri
# ## subj_id
# subj_interpret
# subj_manifesta
# ## subj_origin
# subj_origin_ur
# subj_mimetype
# subj_text
# subj_storage
# subj_storage_s
# subj_current_u
# subj_id_current
# subj_text_id
# subj_storage_id
# subj_origin_cur
# subj_or_cur_uri


class SqlEvent(object):
    id = 0                # type: int
    pid = 0               # type: int
    timestamp = 0         # type: int
    interpretation = ''   # type: str
    manifestation = ''    # type: str
    origin_uri = ''       # type: str
    actor_uri = ''        # type: str
    subjects = []         # type: list

    def __init__(self,
                 id: int,
                 pid: int,
                 timestamp: int,
                 interpretation: str,
                 manifestation: str,
                 origin_uri: str,
                 actor_uri: str):
        self.id = id
        self.pid = pid
        self.timestamp = timestamp
        self.interpretation = interpretation
        self.manifestation = manifestation
        self.origin_uri = origin_uri
        self.actor_uri = actor_uri

    def addSubject(self, subj: SqlEventSubject):
        self.subjects.append(subj)

    def __str__(self):
        prnt = ("Sql Event: %d\n\tpid: %d\n\ttime: %s\n\tinterpretation: %s\n"
                "\tmanifestation: %s\n\tactor: %s\n\tsubjects:\n" % (
                 self.id, self.pid, timestampZgPrint(self.timestamp),
                 self.interpretation, self.manifestation,
                 self.actor_uri))
        for subject in self.subjects:
            prnt += "%s\n" % subject.__str__()
        return prnt + "\n"
