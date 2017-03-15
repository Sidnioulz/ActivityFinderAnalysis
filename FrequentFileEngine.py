"""An engine to mine patterns of frequently co-accessed Files."""
from utils import outputFsEnabled, tprnt
import mimetypes


class FrequentFileEngine(object):
    """An engine to mine patterns of frequently co-accessed Files."""

    def __init__(self):
        """Construct a FrequentFileEngine."""
        super(FrequentFileEngine, self).__init__()
        self.outputDir = outputFsEnabled() or '/tmp/'

    def mineFiles(self, differentiateAccesses: bool=True):
        """Mine for frequently co-accessed individual Files."""
        from FileStore import FileStore
        from UserConfigLoader import UserConfigLoader
        from blist import sortedlist

        fileStore = FileStore.get()
        userConf = UserConfigLoader.get()

        docs = sortedlist(key=lambda i: i.inode)  # Files we'll mine (columns)
        apps = set()                              # Apps we'll mine (rows)
        accessedDocsPerApp = dict()  # Format we need to write each row

        # List the data we'll use in a more useful format. Only user docs.
        for doc in fileStore:
            # Ignore non-documents.
            if not doc.isUserDocument(userConf.getHomeDir(),
                                      allowHiddenFiles=True):
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

        # Write the other input file, for aggregation via Python API.
        with open(self.outputDir + '/' + 'filesPerInstance.list', 'w') as f:
            for app in apps:
                msg = '%s\t' % app.uid()
                l = accessedDocsPerApp.get(app) or []
                cols = set()

                # Add a column for each file type + access type combination.
                for entry in l:
                    cols.add(entry[0])
                    if differentiateAccesses:
                        if entry[1].isReadOnly():
                            cols.add(entry[0]+":r")
                        else:
                            cols.add(entry[0]+":w")

                # Write app line to the input file.
                msg += "\t".join(list(str(c) for c in cols))
                print(msg, file=f)

        print("Mining files done, check out '%s/filesPerInstance.list'." %
              self.outputDir)

    def mineFileTypes(self, differentiateAccesses: bool=True):
        """Mine for frequently co-accessed file types."""
        from FileStore import FileStore
        from UserConfigLoader import UserConfigLoader

        fileStore = FileStore.get()
        userConf = UserConfigLoader.get()

        types = set()                 # Columns are now MIME types
        apps = set()                  # Apps we'll mine (rows)
        accessedTypesPerApp = dict()  # Format we need to write each row

        # List the data we'll use in a more useful format. Only user docs.
        for doc in fileStore:
            # Ignore non-documents.
            if not doc.isUserDocument(userConf.getHomeDir(),
                                      allowHiddenFiles=True):
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

        print("Mining types done, check out '%s/typesPerInstance.tab'." %
              self.outputDir)

        # Write the other input file, for aggregation via Python API.
        with open(self.outputDir + '/' + 'typesPerInstance.list', 'w') as f:
            # TODO add desktopid
            # TODO add file paths / file names too. TODO add all folder elements to find folders that contain more of a file type
            for app in apps:
                msg = '%s\t' % app.uid()
                l = accessedTypesPerApp.get(app) or []
                cols = set()

                # Add a column for each file type + access type combination.
                for entry in l:
                    if not differentiateAccesses:
                        cols.add(entry[0])
                    elif entry[1].isReadOnly():
                        cols.add(entry[0]+":r")
                    else:
                        cols.add(entry[0]+":w")

                # Write app line to the input file.
                msg += "\t".join(list(str(c) for c in cols))
                print(msg, file=f)

        print("Mining types done, check out '%s/typesPerInstance.list'." %
              self.outputDir)


    def processFrequentItemLists(self, inputDirs: list):
        """Process frequent item lists found in a list of input folders."""
        from orangecontrib.associate.fpgrowth import frequent_itemsets
        from os.path import isfile

        inputPaths = [d + '/typesPerInstance.list' for d in 
            inputDirs.split(",")]

        # Check for missing files.
        for p in inputPaths:
            if not isfile(p):
                raise ValueError("File '%s' could not be found, please verify "
                                 "you have invoked the analysis software with "
                                 "the --related-files flag for this user." % p)

        # Read every file and aggregate transactions.
        tprnt("Aggregating transactions from input files...")
        transactions = []
        for p in inputPaths:
            with open(p, 'r') as f:
                for line in f:
                    transaction = line.rstrip("\n").split("\t")
                    transactions.append(transaction)
        tprnt("Done.")

        # Compute itemsets from transactions.
        tprnt("\nComputing frequent itemsets.")
        itemsets = frequent_itemsets(transactions, 2)
        tprnt("Done.")

        # Functions to sort itemsets.
        def _uniqueType(item):
            return len(item[0]) == 1

        def _uniqueTypeWithAccessVariations(item):
            # if len(item[0]) == 1:
            #     return False
            uniqueType = None
            for t in item[0]:
                if t.endswith(":r") or t.endswith(":w"):
                    t = t[:-2]
                if not uniqueType:
                    uniqueType = t
                elif uniqueType != t:
                    return False
            return True

        # Sort itemsets
        uniques = []
        rws = []
        patterns = []
        for item in itemsets:
            if _uniqueType(item):
                uniques.append(item)
            elif _uniqueTypeWithAccessVariations(item):
                rws.append(item)
            else:
                patterns.append(item)

        tprnt("\nMost commonly found types:")
        for item in sorted(uniques, key=lambda x: x[1], reverse=True):
            print("\t", item)

        tprnt("\nMost commonly found patterns:")
        for item in sorted(patterns, key=lambda x: x[1], reverse=True):
            print("\t", item)

        del itemsets

        # Match items in patterns to transactions, and print out app and file
        # names.
        #for t in transactions:
            # TODO check if in patterns
            # TODO if so, print it   
            
