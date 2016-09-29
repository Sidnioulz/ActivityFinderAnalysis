from datetime import datetime


def timestampZgPrint(timestamp):
    """ Transforms a Zeitgeist timestamp with milliseconds into a
    human-readable string. """
    (timestamp, remainder) = divmod(timestamp, 1000)
    string = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    string += (".%d" % remainder)
    return string
