"""An engine to mine patterns of frequently co-accessed Files."""
from utils import outputFsEnabled, tprnt, frequency
import mimetypes


class FrequentFileEngine(object):
    """An engine to mine patterns of frequently co-accessed Files."""

    def __init__(self):
        """Construct a FrequentFileEngine."""
        super(FrequentFileEngine, self).__init__()
        self.outputDir = outputFsEnabled() or '/tmp/'

    def mineFileTypes(self, differentiateAccesses: bool=True):
        """Mine for frequently co-accessed file types."""
        from FileStore import FileStore
        from UserConfigLoader import UserConfigLoader

        fileStore = FileStore.get()
        userConf = UserConfigLoader.get()

        home = userConf.getHomeDir() or "/MISSING-HOME-DIR"
        desk = userConf.getSetting("XdgDesktopDir") or "~/Desktop"
        down = userConf.getSetting("XdgDownloadsDir") or "~/Downloads"
        user = userConf.getSetting("Username") or "user"
        host = userConf.getSetting("Hostname") or "localhost"

        types = set()                 # Columns are file paths + MIME types
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

            fileType = mimetypes.guess_type(doc.path)
            if fileType and fileType[0]:

                # For each app we must know what it accessed to write its row
                # in the output file.
                for acc in doc.getAccesses():
                    actor = acc.getActor()

                    # Ignore system utilities.
                    if not actor.isUserlandApp():
                        continue

                    # Ignore file-searching or listing apps.
                    if actor.desktopid in ('catfish', 'dropbox'):
                        continue

                    apps.add(actor)
                    l = accessedTypesPerApp.get(actor) or []
                    l.append((doc.path, fileType[0], acc))
                    accessedTypesPerApp[actor] = l

        # Write the other input file, for aggregation via Python API.
        with open(self.outputDir + '/' + 'typesPerInstance.list', 'w') as f:
            # TODO add all folder elements to find folders that contain more of a file type
            # TODO       itemsets with two types are "co-frequent types".
            # TODO       itemsets without types must be searched for mutually exclusive folders (not parents of one another).
            # TODO then, itemsets with one type + folders are frequent types for those folders.
            # TODO       itemsets with just one folder are frequent folders.
            # TODO       itemsets with just one type are frequent types.
            for app in apps:
                msg = '%s\t' % (app.uid())
                l = accessedTypesPerApp.get(app) or []
                cols = set()

                # Add a column for each file type + access type combination.
                for entry in l:
                    path = entry[0]
                    path = path.replace(desk, '@XDG_DESKTOP_DIR@')
                    path = path.replace(down, '@XDG_DOWNLOADS_DIR@')
                    path = path.replace(host, '@HOSTNAME@')
                    path = path.replace(home, '~')
                    path = path.replace(user, '@USER@')
                    
                    cols.add(path)
                    if differentiateAccesses:
                        if entry[2].isReadOnly():
                            cols.add(entry[1]+":r")
                        else:
                            cols.add(entry[1]+":w")
                    else:
                        cols.add(entry[1])

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
            participantFolder = p.split("/")[-2]
            tprnt("%s: %s" % (participantFolder, p))
            with open(p, 'r') as f:
                for line in f:
                    transaction = line.rstrip("\n").split("\t")
                    transaction[0] = participantFolder + "/" + transaction[0] 
                    transactions.append(transaction)
        tprnt("Done.")

        # Compute itemsets from transactions.
        tprnt("\nComputing frequent itemsets.")
        itemsets = frequent_itemsets(transactions, frequency())
        tprnt("Done.")

        # Functions to sort itemsets.
        def _isPath(elem):
            return elem[0] in ['/', '~', '@']

        def _hasPath(item):
            typeCnt = 0

            for t in item[0]:
                if _isPath(t):
                    return True

            return False

        def _uniqueType(item):
            typeCnt = 0

            for t in item[0]:
                if not _isPath(t):
                    typeCnt += 1

                    # Save time.
                    if typeCnt > 1:
                        return False

            return typeCnt == 1

        def _uniqueTypeWithAccessVariations(item):
            uniqueType = None

            for t in item[0]:
                if not _isPath(t):
                    if t.endswith(":r") or t.endswith(":w"):
                        t = t[:-2]

                    if not uniqueType:
                        uniqueType = t
                    elif uniqueType != t:
                        return False

            return uniqueType != None

        def _multipleTypes(item):
            uniqueType = None

            for t in item[0]:
                if not _isPath(t):
                    if t.endswith(":r") or t.endswith(":w"):
                        t = t[:-2]

                    if not uniqueType:
                        uniqueType = t
                    elif uniqueType != t:
                        return True

            return False

        # Sort itemsets
        tprnt("\nSorting frequent itemsets to isolate mime type co-access "
              "patterns.")
        uniques = []
        patterns = dict()
        for item in itemsets:
            if _hasPath(item):
                pass
            elif _uniqueType(item):
                uniques.append(item)
            elif _uniqueTypeWithAccessVariations(item):
                pass
            elif _multipleTypes(item):
                patterns[item[0]] = item[1]
        tprnt("Done.")
        
        # displayPatterns = dict()
        # for p in patterns:
        #     disp = set()
        #     for elem in p:
        #         if elem.endswith(":r") or elem.endswith(":w"):
        #             disp.add(elem)
        #         elif elem+":w" not in p and elem+":r" not in p:
        #             disp.add(elem)
        #     displayPatterns[p] = disp

        tprnt("\nMost commonly found types:")
        for item in sorted(uniques, key=lambda x: x[1], reverse=True):
            print("\t", item)

        tprnt("\nMost commonly found patterns:")
        for item in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
            print("\t", item)

        del itemsets

        # Match items in patterns to transactions, and print out app and file
        # names.
        tprnt("\nMatching frequent patterns to transactions...")
        transactionsPerPattern = dict()
        for t in transactions:
            for p in patterns.keys():
                if p.issubset(t):
                    matches = transactionsPerPattern.get(p) or []
                    matches.append(t)
                    transactionsPerPattern[p] = matches
        tprnt("Done.")
            
        tprnt("\nPrinting matched transactions...")
        line = ""
        # Print all the transactions that match a pattern, for manual analysis.
        for (p, matches) in sorted(transactionsPerPattern.items()):
            tprnt("%s%d\tPATTERN: %s" % (line, patterns[p], p.__str__()))
            line = "\n"

            for matchedTransaction in matches:
                print("\tApp: %s" % matchedTransaction[0])
                for transactionElem in sorted(matchedTransaction[1:]):
                    print("\t* %s" % transactionElem)
                print("")

