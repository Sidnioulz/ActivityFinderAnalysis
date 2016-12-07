"""An engine to mine patterns of frequently co-accessed Files."""
from FileStore import FileStore
from UserConfigLoader import UserConfigLoader
from utils import outputFsEnabled
from blist import sortedlist
import mimetypes


class FrequentFileEngine(object):
    """An engine to mine patterns of frequently co-accessed Files."""

    def __init__(self,
                 userConf: UserConfigLoader):
        """Construct a FrequentFileEngine."""
        super(FrequentFileEngine, self).__init__()
        mimetypes.init()
        self.outputDir = outputFsEnabled() or '/tmp/'
        self.userConf = userConf

    def mineFiles(self, differentiateAccesses: bool=True):
        """Mine for frequently co-accessed individual Files."""
        fileStore = FileStore.get()

        docs = sortedlist(key=lambda i: i.inode)  # Files we'll mine (columns)
        apps = set()                              # Apps we'll mine (rows)
        accessedDocsPerApp = dict()  # Format we need to write each row

        # List the data we'll use in a more useful format. Only user docs.
        for doc in fileStore:
            # Ignore non-documents.
            if not doc.isUserDocument(self.userConf.getSetting("HomeDir")):
                continue

            # Ignore folders, they tend to get open and read and traversed.
            if doc.isFolder():
                continue

            docs.add(doc)

            # For each app we must know what it accessed to write its row in
            # the output file.
            for acc in doc.getAccesses():
                actor = acc.getActor()
                apps.add(actor)
                l = accessedDocsPerApp.get(actor) or []
                l.append((doc, acc))
                accessedDocsPerApp[actor] = l

        # Write our Orange input file.
        with open(self.outputDir + '/' + 'filesPerInstance.tab', 'w') as f:
            # Print the header line.
            header = 'Application\t'
            for doc in docs:
                header += '"\%s"\t' % doc.getName()
            header = header.rstrip('\t')
            print(header, file=f)

            # Print the metadata line.
            header = 'd\t' + ('d\t' * (len(docs) - 1)) + 'd'
            print(header, file=f)
            header = 'c\t' + ('\t' * (len(docs) - 1))
            print(header, file=f)

            # Write each row of the input file.
            for app in apps:
                msg = '%s\t' % app.uid()
                l = accessedDocsPerApp.get(app) or []
                # Add a column for each user document of the entire FS.
                for doc in docs:
                    accessType = 0
                    # If we find the entry, add a number based on access type.
                    for entry in l:
                        if entry[0] == doc:
                            accessType |= (1 if entry[1].isReadOnly() else 2)

                    # If we don't differentiate accesses, flatten accessType.
                    if not differentiateAccesses and accessType:
                        accessType = 1

                    # If we find the entry, add a number based on access type,
                    # else add an empty column.
                    msg += '%d\t' % accessType if accessType else '\t'
                msg = msg.rstrip('\t')

                # Write down the input file to the FS.
                print(msg, file=f)

        print("Mining files done, check out '%s/filesPerInstance.tab'." %
              self.outputDir)

    def mineFileTypes(self, differentiateAccesses: bool=True):
        """Mine for frequently co-accessed file types."""
        fileStore = FileStore.get()

        types = set()                 # Columns are now MIME types
        apps = set()                  # Apps we'll mine (rows)
        accessedTypesPerApp = dict()  # Format we need to write each row

        # List the data we'll use in a more useful format. Only user docs.
        for doc in fileStore:
            # Ignore non-documents.
            if not doc.isUserDocument(self.userConf.getSetting("HomeDir")):
                continue

            # Ignore folders, they tend to get open and read and traversed.
            if doc.isFolder():
                continue

            fileType = mimetypes.guess_type(doc.getName())
            if fileType and fileType[0]:
                types.add(fileType[0])

                # For each app we must know what it accessed to write its row
                # in the output file.
                for acc in doc.getAccesses():
                    actor = acc.getActor()
                    apps.add(actor)
                    l = accessedTypesPerApp.get(actor) or []
                    l.append((fileType[0], acc))
                    accessedTypesPerApp[actor] = l

        # Write our Orange input file.
        with open(self.outputDir + '/' + 'typesPerInstance.tab', 'w') as f:
            # Print the header line.
            header = 'Application\t'
            for t in types:
                header += '"\%s"\t' % t
            header = header.rstrip('\t')
            print(header, file=f)

            # Print the metadata line.
            header = 'd\t' + ('d\t' * (len(types) - 1)) + 'd'
            print(header, file=f)
            header = 'c\t' + ('\t' * (len(types) - 1))
            print(header, file=f)

            # Write each row of the input file.
            for app in apps:
                msg = '%s\t' % app.uid()
                l = accessedTypesPerApp.get(app) or []
                # Add a column for each file type of the entire FS.
                for t in types:
                    accessType = 0
                    # If we find the entry, add a number based on access type.
                    for entry in l:
                        if entry[0] == t:
                            accessType |= (1 if entry[1].isReadOnly() else 2)

                    # If we don't differentiate accesses, flatten accessType.
                    if not differentiateAccesses and accessType:
                        accessType = 1

                    # If we find the entry, add a number based on access type,
                    # else add an empty column.
                    msg += '%d\t' % accessType if accessType else '\t'
                msg = msg.rstrip('\t')

                # Write down the input file to the FS.
                print(msg, file=f)

        print("Mining files done, check out '%s/typesPerInstance.tab'." %
              self.outputDir)
