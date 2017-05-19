"""An engine to mine patterns of frequently co-accessed Files."""
from File import File
from utils import outputFsEnabled, tprnt, frequency
import mimetypes
import itertools
import os


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

        # Make output directory.
        if os.path.exists(self.outputDir):
            backup = self.outputDir.rstrip("/") + ".backup"
            if os.path.exists(backup):
                shutil.rmtree(backup)
            os.replace(self.outputDir, backup)
        os.makedirs(self.outputDir, exist_ok=False)
        
        # displayPatterns = dict()
        # for p in patterns:
        #     disp = set()
        #     for elem in p:
        #         if elem.endswith(":r") or elem.endswith(":w"):
        #             disp.add(elem)
        #         elif elem+":w" not in p and elem+":r" not in p:
        #             disp.add(elem)
        #     displayPatterns[p] = disp

        # Print to files.
        with open(self.outputDir + '/' + 'patterns.out', 'w') as f:
            tprnt("\nMost commonly found types:")
            print("Most commonly found types:", file=f)
            for item in sorted(uniques,
                               key=lambda x: x[1],
                               reverse=True):
                print("\t", item)
                print("mcft\t", item, file=f)

            tprnt("\nMost commonly found patterns:")
            print("\nMost commonly found patterns:", file=f)
            for item in sorted(patterns.items(),
                               key=lambda x: x[1],
                               reverse=True):
                print("\t", item)
                print("mcfp\t", item, file=f)
            print("", file=f)

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

        def _printPattern(p, matches, counter, exclusiveCounter):
            msg = ""
            listing = ""
            summary = ""

            # Base pattern identity.
            msg += ("\n\nPATTERN: %d\t%s" % (patterns[p], p.__str__()))

            # Transaction listing.
            for matchedTransaction in matches:
                listing += ("App: %s\n" % matchedTransaction[0])
                for transactionElem in sorted(matchedTransaction[1:]):
                    listing += ("\t* %s\n" % transactionElem)
                listing += ("\n")

            # Counters of file extension co-occurrences.
            for (k, v) in sorted(counter.items()):
                summary += ("\t{%s} occurs %d times, in %d patterns\n" % (
                            ','.join(k), v, counterI[k]))
            summary += "\n"
            for (k, v) in sorted(exclusiveCounter.items()):
                summary += ("\t{%s} is exclusive %d times, in %d patterns\n" % (
                            ','.join(k), v, exclusiveCounterI[k]))

            # Print to files.
            with open(self.outputDir + '/' + 'patterns.out', 'a') as f:
                print(msg, file=f)
                print(summary, file=f)

            with open(self.outputDir + '/' + 'patternsListing.out', 'a') as f:
                print(msg, file=f)
                print(listing, file=f)

        # Pre-analyse the relationships between file endings in patterns.
        tprnt("\nPre-analysing the relationships between files in patterns...")
        for (p, matches) in sorted(transactionsPerPattern.items()):
            # Counter used to count combos of files with the same name and
            # different extensions.
            counter = dict()
            exclusiveCounter = dict()
            counterI = dict()
            exclusiveCounterI = dict()

            # Go through file accesses that match the pattern.
            for matchedTransaction in matches:
                # We collect sets of names for each encountered file extension.
                nameDict = dict()
                extensions = set()
                for transactionElem in sorted(matchedTransaction[1:]):
                    if not (transactionElem.startswith("/") or
                            transactionElem.startswith("~")):
                        continue


                    # Get the base name and file extension.
                    ftype = mimetypes.guess_type(transactionElem)[0]
                    fname = File.getFileNameFromPath(transactionElem)
                    fnoext = File.getNameWithoutExtensionFromPath(fname)
                    fext = File.getExtensionFromPath(fname, filterInvalid=True)

                    # Remember which exts were found for a name and overall.
                    if fext:
                        extensions.add(fext)
                        extSet = nameDict.get(fnoext) or set()
                        extSet.add(fext)
                        nameDict[fnoext] = extSet
                
                # Now check which extension combos exist, and how many times
                # they occur.
                extPairOccs = dict()
                for (fname, extSet) in nameDict.items():
                    fs = frozenset(extSet)
                    extPairOccs[fs] = (extPairOccs.get(fs) or 0) + 1

                # Compile list of all valid extension combos, and browse them
                # in reverse order of length as we first want to validate the
                # largest combinations.
                combos = list(extPairOccs.keys())
                combos.sort(key=len, reverse=True)

                # Count patterns which exclusively have one extension tied to
                # another (i.e. extension never appears on its own).
                exclusives = dict()
                nonExclusiveKeys = set()
                for k in combos:
                    # All the subsets of the current combo of filetypes are not
                    # exclusive since they're included in this set.
                    subcombos = list()
                    for i in range(1, len(k)):
                         subcombos.extend([frozenset(x) for x in 
                                           itertools.combinations(k, i)])
                    nonExclusiveKeys.update(subcombos)

                    # Also check if any of these subsets is itself in the list,
                    # if so the current set is not exclusive.
                    for sub in subcombos:
                        if sub in extPairOccs:
                            break
                    else:
                        # Remember: subsets of a previous set aren't exclusive.
                        if k not in nonExclusiveKeys:
                            exclusives[k] = extPairOccs[k]
                    
                # Now add the match's groups of filenames to counters for the
                # whole pattern. Count both number of cases where the pattern
                # is found / exclusively found, and the number of times it is
                # found.
                for (k, v) in extPairOccs.items():
                    counter[k] = (counter.get(k) or 0) + v
                    counterI[k] = (counterI.get(k) or 0) + 1
                for (k, v) in exclusives.items():
                    exclusiveCounter[k] = (exclusiveCounter.get(k) or 0) + v
                    exclusiveCounterI[k] = (exclusiveCounterI.get(k) or 0) + 1

            # Finally, print information on the pattern.
            _printPattern(p, matches, counter, exclusiveCounter)

             

#            fe type, if that type exists on its own
            
#            267 occs, .a .b .c
#            dict of all names for each extension
            
            
#            .a: 200 alone, 52 with .b, 15 with .b .c
#            .a name diversity (200 alone, 52 .b, 15 .b.c)
#            print lists of distinct filenames for each category.
#            distribution of folder depths overall
#            distribution of folder depths per ext (is there an ext always in the same folder?)
            
        
        
        
        
            # TODO add all folder elements to find folders that contain more of a file type
            # TODO       itemsets with two types are "co-frequent types".
            # TODO       itemsets without types must be searched for mutually exclusive folders (not parents of one another).
            # TODO then, itemsets with one type + folders are frequent types for those folders.
            # TODO       itemsets with just one folder are frequent folders.
            # TODO       itemsets with just one type are frequent types.


