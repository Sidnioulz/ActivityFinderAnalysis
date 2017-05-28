"""An engine that produces graphs and statistics for a prior analysis."""
from blist import sortedlist
import glob
import math
import os
import shutil
import pygal
import re
from pygal.style import Style
from utils import debugEnabled, skipEnabled
from LibraryManager import LibraryManager

plotWhitelist = ['abiword', 'acroread', 'android', 'atom', 'audacity', 'banshee', 'bibtex', 'blender', 'brackets', 'calibre', 'chromium', 'CMake', 'codeigniter', 'codelite', 'darktable', 'dropbox', 'ebook-viewer', 'eclipse', 'emacs24', 'empathy', 'eog', 'evince', 'evolution', 'file-roller', 'filezilla', 'firefox', 'gcc', 'gdb', 'g++', 'geany', 'gedit', 'gimp', 'git', 'gmusicbrowser', 'gnome-calculator', 'gpaint', 'gphoto2', 'inkscape', 'intellij', 'kodi', 'latex', 'libreoffice', 'Mathematica', 'midori', 'mpd', 'mplayer', 'mpv', 'mumble', 'octave', 'okular', 'parole', 'pcalendar', 'pcsx2', 'pcsx', 'pdftex', 'pidgin', 'pitivi', 'popcorn-time', 'qBittorrent', 'rhythmbox', 'ristretto', 'shotwell', 'shotwell-viewer', 'skype', 'smplayer', 'soundconverter', 'spotify', 'steam', 'sublime-text', 'teamspeak3', 'teamviewer', 'telegram', 'texmaker', 'texstudio', 'texworks', 'thunderbird', 'torbrowser', 'totem', 'transmission-gtk', 'tuxguitar', 'tuxpaint', 'vim', 'vlc', 'weechat', 'wine', 'xchat', 'xfburn', 'xournal', 'youtube-dl', 'zotero.desktop']

accessKeys = ["by designation", "file owned by app",
              "policy-allowed", "illegal"]

costKeys = ["configuration", "granting", "cumulative granting", "isolating",
            "splitting", "g-granting", "g-isolating", "g-splitting"]

costKeysNoG = ["configuration", "granting", "cumulative granting", "isolating",
               "splitting"]

costKeysNC = ["configuration", "granting", "isolating",
              "splitting", "g-granting", "g-isolating", "g-splitting"]

costKeysNoGNC = ["configuration", "granting", "isolating", "splitting"]

coloursDoubled = ('#F44336', '#F44336', '#3F51B5', '#3F51B5', '#009688',
                  '#009688', '#FFC107', '#FFC107', '#FF5722', '#FF5722',
                  '#9C27B0', '#9C27B0', '#03A9F4', '#03A9F4', '#8BC34A',
                  '#8BC34A', '#FF9800', '#FF9800', '#E91E63', '#E91E63',
                  '#2196F3', '#2196F3', '#4CAF50', '#4CAF50', '#FFEB3B',
                  '#FFEB3B', '#673AB7', '#673AB7', '#00BCD4', '#00BCD4',
                  '#CDDC39', '#CDDC39', '#9E9E9E', '#9E9E9E', '#607D8B',
                  '#607D8B', )


class AnalysisEngine(object):
    """An engine that produces graphs and statistics for a prior analysis."""

    def __init__(self, inputDir: str, outputDir: str='/tmp/analysis'):
        """Construct an AnalysisEngine."""
        super(AnalysisEngine, self).__init__()

        print("Intialising analysis engine...")

        # Input dir where the analysis data is stored.
        self.inputDir = inputDir.split(",")
        for iD in self.inputDir:
            if not os.path.exists(iD):
                raise ValueError("Path to input directory is not valid: %s" %
                                 iD)
        self.participantCount = len(self.inputDir)


        # Build directory to store analysis results.
        self.outputDir = outputDir

        if self.outputDir in self.inputDir:
            raise ValueError("The output directory for the post-analysis "
                             "engine is also one of the input directories. "
                             "This would result in the input directory being "
                             "overwritten. Aborting.")

        if os.path.exists(self.outputDir):
            backup = self.outputDir.rstrip("/") + ".backup"
            if os.path.exists(backup):
                shutil.rmtree(backup)
            os.replace(self.outputDir, backup)
        os.makedirs(self.outputDir, exist_ok=False)

        self.atkNameRe = re.compile("## Performing attack '(.*?)'")
        self.atkScoresRe = re.compile("Avg: ([0-9\.]+) \(([0-9\.]+)%\) apps infected; "
                                      "([0-9\.]+) \(([0-9\.]+)%\) weighted-apps infected; "
                                      "([0-9\.]+) \(([0-9\.]+)%\) files infected; "
                                      "([0-9\.]+) \(([0-9\.]+)%\) user-apps infected; "
                                      "([0-9\.]+) \(([0-9\.]+)%\) weighted-user-apps infected; "
                                      "([0-9\.]+) \(([0-9\.]+)%\) documents infected")
        self.statsRe = re.compile("Simulated: ([0-9\.]+) apps; "
                                  "([0-9\.]+) instances; "
                                  "([0-9\.]+) user apps; "
                                  "([0-9\.]+) user instances; "
                                  "([0-9\.]+) events; "
                                  "([0-9\.]+) files; "
                                  "([0-9\.]+) user documents")
        self.exclLineRe = re.compile("Exclusion list '(.*?)' defined.")
        self.preSlashRe = re.compile("(.*?)/")
        self.IntRe = re.compile(".*?([0-9]+).*")

        print("Collecting participant statistics...")

        self.stats = dict()
        for iD in self.inputDir:
            stats = self.parseParticipantStats(os.path.join(iD,
                                                            'statistics.txt'))
            self.stats[iD] = stats

        print("Collecting policies...")

        # List policies to parse.
        pFList = list(sorted(glob.glob(
                      os.path.join(iD, 'Policy*'))) for iD in self.inputDir)
        self.policyFolders = [item for sublist in pFList for item in sublist]
        policyNames = list(a[a.rfind("/")+10:-6] for a in self.policyFolders)

        # Skip policies in the skip list.
        skips = [s[:-6] if s.endswith('Policy') else s for s in \
            skipEnabled() or []]
        skipDels = []
        if skips:
            for (idx, name) in enumerate(policyNames):
                if name in skips:
                    skipDels.append(idx)
            for idx in reversed(skipDels):
                del self.policyFolders[idx]
                del policyNames[idx]

        # List folders matching the policies to parse.
        self.foldersPerName = dict()
        for (idx, name) in enumerate(policyNames):
            l = self.foldersPerName.get(name) or []
            l.append(self.policyFolders[idx])
            self.foldersPerName[name] = l
        self.policyCount = len(self.foldersPerName)

        print("Collecting applications...")

        # List apps and instances.
        allScores = set()
        userScores = set()
        for pol in self.policyFolders:
            polScores = glob.glob(os.path.join(pol, "App*.score"))
            for p in polScores:
                name = p.replace(pol, "@POLICY@")
                if name not in allScores and self.filterUsabilityScores(p):
                    userScores.add(name)
                allScores.add(name)

        print("Sorting applications and app instances...")

        self.appScores = list(a for a in allScores if "Instance" not in a)
        self.appNames = list(a[a.rfind("/")+7:-6] for a in self.appScores)
        self.userScores = list(a for a in userScores if "Instance" not in a)
        self.userNames = list(a[a.rfind("/")+7:-6] for a in self.userScores)
        self.instScores = list(a for a in allScores if "Instance" in a)
        self.instNames = list(a[a.rfind("/")+7:-6] for a in self.instScores)

        if debugEnabled():
            print("User applications being analysed:")
            for an in self.userScores:
                print(an)
            print("\n")

        self.uAppCount = len(userScores)
        if debugEnabled():
            print("%d/%d apps" % (self.uAppCount, len(self.appScores)))


        self.uInstCount = len(list(n for n in self.instNames if
            n.split(" - ")[0] in self.userNames))
        if debugEnabled():
            print("%d/%d instances" % (self.uInstCount, len(self.instScores)))

        # FIXME from here.
        # List exclusion scores.
        print("Collecting application exclusion scores...")
        exclScoresPW = set()
        exclScoresPROJ = set()
        exclScoresEXCL = set()
        for pol in self.policyFolders:
            polNP = pol[pol.find('/')+1:]
            polScores = glob.glob(os.path.join(pol, "App*.WorkPersonalSeparation.exclscore"))
            for p in polScores:
                exclScoresPW.add(p.replace(polNP, "@POLICY@"))
            polScores = glob.glob(os.path.join(pol, "App*.ProjectSeparation.exclscore"))
            for p in polScores:
                exclScoresPROJ.add(p.replace(polNP, "@POLICY@"))
            polScores = glob.glob(os.path.join(pol, "App*.ExplicitExclusion.exclscore"))
            for p in polScores:
                exclScoresEXCL.add(p.replace(polNP, "@POLICY@"))
        self.exclScoresPW = list(exclScoresPW)
        self.exclScoresPROJ = list(exclScoresPROJ)
        self.exclScoresEXCL = list(exclScoresEXCL)
        self.exclNames = list((a[a.rfind("/")+7:-len('.WorkPersonalSeparation.exclscore')] for a in self.exclScoresPW))

        print("Ready to analyse!\n")

    def parseParticipantStats(self, path: str):
        ret = dict()
        ret['exclusionlists'] = []
        try:
            with open(path) as f:
                for line in f:
                    if line.startswith("Simulated: "):
                        res = self.statsRe.match(line).groups()
                        ret['apps'] = int(res[0])
                        ret['instances'] = int(res[1])
                        ret['uapps'] = int(res[2])
                        ret['uinstances'] = int(res[3])
                        ret['events'] = int(res[4])
                        ret['files'] = int(res[5])
                        ret['udocs'] = int(res[6])
                    if line.startswith("Days: "):
                        ret['days'] = int(line[6:])
                    if line.startswith("Exclusion list "):
                        res = self.exclLineRe.match(line).groups()
                        ret['exclusionlists'].append(res[0])
        except (FileNotFoundError) as e:
            raise ValueError("Statistics file '%s' is missing" % path)

        return ret

    def getHighestCostSum(self, costs: dict, confCostDivider: int=1):
        m = 0
        for pol, s in costs.items():
            cSum = s["configuration"] / confCostDivider + \
                   s["granting"] + s["isolating"] + s["splitting"]
            m = max(m, cSum)
        return m

    def genRelativeCosts(self, costs: dict, maxCost: int):
        relCosts = dict()
        if maxCost:
            for pol, s in costs.items():
                t = dict()
                for key in costKeysNC:
                    t[key] = s[key] / maxCost
                relCosts[pol] = t
        else:
            for pol, s in costs.items():
                t = dict()
                for key in costKeysNC:
                    t[key] = 0
                relCosts[pol] = t\

        return relCosts

    def genUsabilityCostTable(self, costs: dict, filename: str, target: str,
                              confCostDivider: int=1):
        msg = "\\begin{table}\n" \
              "  \\begin{tabular}{rllllll}\n" \
              "  \\cmidrule[\\heavyrulewidth]{2-6}\n" \
              "  \\tabhead{Policy}&\\tabhead{Config}&\\multicolumn{2}{l}" \
              "{\\tabhead{Granting}}&\\tabhead{Isolating}&" \
              "\\tabhead{Splitting}&\\tabhead{Total} \\\\\n" \
              "  \\cmidrule{2-6}\n"

        for pol, costs in costs.items():
            cSum = costs["configuration"] / confCostDivider + \
                   costs["granting"] + costs["isolating"] + costs["splitting"]
            msg += "  %s&%.02f&%.02f&{\\small (%.02f)}&%.02f&%.02f&%.02f \\\\\n" % (
                pol,
                costs["configuration"] / confCostDivider,
                costs["granting"],
                costs["cumulative granting"],
                costs["isolating"],
                costs["splitting"],
                cSum)

        msg += "  \\cmidrule[\\heavyrulewidth]{2-6}\n" \
               "  \\end{tabular}\n" \
               "  \\caption{Usability costs of each policy for %s.}" \
               "  \\label{table:userland-usability-costs-%s}\n" \
               "\\end{table}\n" % (target, target)

        with open(os.path.join(self.outputDir, filename), 'a') as f:
            print(msg, file=f)

        return msg

    def genOETable(self, costs: dict, filename: str, target: str):
        msg = "\\begin{table}\n" \
              "  \\begin{tabular}{rlll}\n" \
              "  \\cmidrule[\\heavyrulewidth]{2-3}\n" \
              "  \\tabhead{Policy}&\\tabhead{Accessed}&\\tabhead{Reachable}&" \
              "\\tabhead{Ratio} \\\\\n" \
              "  \\cmidrule{2-3}\n"

        for pol, oe in costs.items():
            accessed = list(e[0] for e in oe)
            a = sum(accessed) / len(accessed) if accessed else 0
            reached = list(e[1] for e in oe)
            r = sum(reached) / len(reached) if reached else 0
            msg += "  %s&%d&%d&%d\\  \\\\\n" % (pol, a, r, a/r if r else 0)

        msg += "  \\cmidrule[\\heavyrulewidth]{2-3}\n" \
               "  \\end{tabular}\n" \
               "  \\caption{Average over-entitlements of app %s for each " \
               "policy.}" \
               "  \\label{table:oe-costs-%s}\n" \
               "\\end{table}\n" % (target, target)

        with open(os.path.join(self.outputDir, filename), 'a') as f:
            print(msg, file=f)

        return msg

    def parseUsabilityScores(self,
                             filenames: list,
                             confCostDivider: int=1,
                             scores: dict=None,
                             divPerDays: bool=False,
                             divParticipants: bool=False):

        if scores:
            s = scores
        else:
            s = dict()
            s["by designation"] = 0
            s["file owned by app"] = 0
            s["policy-allowed"] = 0
            s["illegal"] = 0
            s["configuration"] = 0
            s["granting"] = 0
            s["cumulative granting"] = 0
            s["isolating"] = 0
            s["splitting"] = 0
            s["g-granting"] = 0
            s["g-isolating"] = 0
            s["g-splitting"] = 0

        def _parseUsabilityScores(s: dict,
                                  filename: str,
                                  confCostDivider: int=1):
            div = 1
            if divPerDays:
                for (pName, stats) in self.stats.items():
                    if filename.startswith(pName):
                        div = stats['days']
                        break
            if divParticipants:
                div = div * self.participantCount

            try:
                with open(filename) as f:
                    for line in f:
                        if line.startswith("\t* by designation"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["by designation"] += d[0] / div
                        elif line.startswith("\t* file owned by app"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["file owned by app"] += d[0] / div
                        elif line.startswith("\t* policy-allowed"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["policy-allowed"] += d[0] / div
                        elif line.startswith("\t* illegal"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["illegal"] += d[0] / div
                        elif line.startswith("\t* configuration"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["configuration"] += d[0] / (div * confCostDivider)
                        elif line.startswith("\t* granting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["granting"] += d[0] / div
                        elif line.startswith("\t* cumulative granting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["cumulative granting"] += d[0] / div
                        elif line.startswith("\t* isolating"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["isolating"] += d[0] / div
                        elif line.startswith("\t* splitting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["splitting"] += d[0] / div
                        elif line.startswith("\t* g-granting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["g-granting"] += d[0] / div
                        elif line.startswith("\t* g-isolating"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["g-isolating"] += d[0] / div
                        elif line.startswith("\t* g-splitting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["g-splitting"] += d[0] / div
            except (FileNotFoundError) as e:
                pass

        for filename in filenames:
            _parseUsabilityScores(s, filename, confCostDivider)

        return s

    def filterUsabilityScores(self,
                              filename: str,
                              filterKey: str="APPTYPE",
                              filterValues: list=["Application"]):
        try:
            with open(filename) as f:
                for line in f:
                    if filterKey and line.startswith(filterKey+":"):
                        v = line[len(filterKey)+2:-1]
                        return v in filterValues
        except (FileNotFoundError) as e:
            return False
        return False

    def parseClusterScores(self, filenames: list):
        score = 0
        usersHaveScore = dict()

        pNames = list(self.preSlashRe.match(f).groups()[0] for f in filenames)

        def _parseClusterScores(self, filename: str):
            try:
                with open(filename) as f:
                    for line in f:
                        if line.startswith("# of clusters violating exclusion"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            return d[0]

            except (FileNotFoundError) as e:
                return -2

            # Now we have cases where there is no data available, must deal with it.
            return -1

        for (idx, filename) in enumerate(filenames):
            d = _parseClusterScores(self, filename)
            if d == -1:
                usersHaveScore[pNames[idx]] = False
            elif d >= 0:
                usersHaveScore[pNames[idx]] = True
                score += d

        return (score, sum(1 for x in usersHaveScore.values() if x is True))


    def parseOEScores(self, filenames: list):
        prfx = "Distribution of over-entitlements: "

        def _parseOEScores(filename: str):
            try:
                with open(filename) as f:
                    for line in f:
                        if line.startswith(prfx):
                            OEs = eval(line[len(prfx):])
                            return OEs

            except (FileNotFoundError) as e:
                return []

            return []

        retScores = []
        for filename in filenames:
            fScores = _parseOEScores(filename)
            retScores.append(fScores)

        return [item for sublist in retScores for item in sublist]

    def analyseOE(self):
        overallOEScores = dict()
        for (adx, app) in enumerate(self.userScores):
            scores = dict()
            appName = self.userNames[adx]

            for (name, folders) in sorted(self.foldersPerName.items()):
                paths = list(app.replace("@POLICY@", f) for f in folders)
                s = self.parseOEScores(paths)
                scores[name] = s

                overall = overallOEScores.get(name) or []
                for pair in s:
                    overall.append(pair)
                overallOEScores[name] = overall

            self.genOETable(scores, appName + ".OEScores.tex", appName)
            self.plotOEBoxes(scores, appName)

        return overallOEScores

    def plotAppCostsPerPolBoxes(self,
                                polRelCosts: dict,
                                polAbsCosts: dict):
        boxPlot = pygal.Box(box_mode="tukey")  # , range=(0, 30))
        absPlot = pygal.Box(box_mode="tukey")  # , range=(0, 30))
        boxPlot.title = "Distribution of costs for each user app, per " \
                        "policy, normalised."
        absPlot.title = "Distribution of costs for each user app, per policy."
        for (pol, costList) in sorted(polRelCosts.items()):
            sumList = list((s["configuration"] + s["granting"] +
                            s["isolating"] + s["splitting"] for s in costList))
            boxPlot.add(pol, sumList)
        for (pol, costList) in sorted(polAbsCosts.items()):
            sumList = list((s["configuration"] + s["granting"] +
                            s["isolating"] + s["splitting"] for s in costList))
            absPlot.add(pol, sumList)

        boxPlot.render_to_file(os.path.join(self.outputDir,
                                            'appRelCostPerPol.svg'))
        absPlot.render_to_file(os.path.join(self.outputDir,
                                            'appAbsCostPerPol.svg'))

    def plotCostDistribution(self,
                             polName: str,
                             costs: dict):
        pie = pygal.Pie()
        pie.title = "Types of costs for userland apps - %s Policy." % polName
        pie.add('Configuration', costs["configuration"])
        pie.add('Granting privileges', costs["granting"])
        pie.add('Isolating app', costs["isolating"])
        pie.add('Splitting app', costs["splitting"])

        pie.render_to_file(os.path.join(self.outputDir,
                                        'costDistPie-%s.svg' % polName))

    def plotDistCostsBoxes(self,
                           folders: str,
                           polName: str,
                           excludeZeroAccesses: bool=True):
        instCostDist = dict()
        for (udx, uapp) in enumerate(self.instScores):
            instName = self.instNames[udx]
            desktopid = instName[:instName.find("Instance") - 3]

            if desktopid in plotWhitelist:
                series = instCostDist.get(desktopid) or ([], [])
                paths = list(uapp.replace("@POLICY@", f) for f in folders)
                s = self.parseUsabilityScores(paths,
                                              confCostDivider=self.uInstCount,
                                              divPerDays=True,
                                              divParticipants=True)

                cSum = s["configuration"] + s["granting"] + \
                    s["isolating"] + s["splitting"]
                accSum = s["by designation"] + \
                    s["policy-allowed"] + s["illegal"]

                # Exclude instances without accesses, if asked to.
                if accSum or not excludeZeroAccesses:
                    series[0].append(cSum)
                    series[1].append(accSum)
                    instCostDist[desktopid] = series

        boxPlot = pygal.Box(box_mode="tukey")  # , range=(0, 30))
        boxPlot.title = "Distribution of costs across app instances, " \
                        "for each app - %s Policy." % polName
        boxPlotAvg = pygal.Box(box_mode="tukey")
        boxPlotAvg.title = "Distribution of average cost per access per app " \
                           "instance, for each app - %s Policy." % polName
        for (desktopid, series) in sorted(instCostDist.items()):
            ratios = list((series[0][i] / series[1][i] if series[1][i] else 0
                           for (i, __) in enumerate(series[0])))
            boxPlot.add(desktopid, series[0])
            boxPlotAvg.add(desktopid, ratios)

        boxPlot.render_to_file(os.path.join(self.outputDir,
                                            'instCostDist-%s.svg' % polName))
        boxPlotAvg.render_to_file(os.path.join(self.outputDir, 'instCostDist-'
                                               'normalised-%s.svg' % polName))


    def plotOEBoxes(self,
                    scores: dict,
                    appName: str,
                    excludeZeroAccesses: bool=True):
        # TODO review this function.
        if appName not in plotWhitelist:
            return

        oeDict = dict()
        for (polName, oe) in scores.items():
            series = [[], [], []]
            accessed = list(e[0] for e in oe)
            reached = list(e[1] for e in oe)

            # Exclude instances without accesses, if asked to.
            series[0] = (accessed)
            series[1] = (reached)
            series[2] = list((accessed[i]/r if r else 1 for (i, r) in
                             enumerate(reached)))
            oeDict[polName] = series

        customStyle = Style(colors=coloursDoubled)
        boxPlot = pygal.Box(box_mode="tukey", style=customStyle)
        boxPlot.title = "Files accessed and reachable, per policy - %s App" % \
            appName
        boxProp = pygal.Box(box_mode="tukey")
        boxProp.title = "Proportion of files accessed per files reachable, " \
                        "per policy - %s App" % appName
        boxProp.y_labels = ["0%", "10%", "20%", "30%", "40%", "50%", "60%",
                            "70%", "80%", "90%", "100%"]

        for (polName, series) in sorted(oeDict.items()):
            boxPlot.add(polName + " accessed", series[0])
            boxPlot.add(polName + " reachable", series[1])
            boxProp.add(polName, series[2])

        boxPlot.render_to_file(os.path.join(self.outputDir,
                                            'oeAccReach-%s.svg' % appName))
        boxProp.render_to_file(os.path.join(self.outputDir,
                                            'oeRatio-%s.svg' % appName))

    def plotMostUsableDots(self,
                           scores: dict,
                           maxes: dict,
                           xLabelSource: list,
                           title: str=None,
                           tag: str=None):
        dotPlot = pygal.Dot(show_legend=False)
        dotPlotN = pygal.Dot(show_legend=False)
        dotPlot.x_labels = sorted(xLabelSource)
        dotPlotN.x_labels = dotPlot.x_labels

        dotPlot.title = "Costs of each policy %s" % title
        dotPlotN.title = dotPlot.title + ", normalised"

        for (polName, pScores) in sorted(scores.items()):
            series = []
            for pName in sorted(pScores):
                series.append(pScores[pName])

            normalisedSeries = []
            for (idx, i) in enumerate(series):
                divider = maxes[dotPlot.x_labels[idx]]
                normalisedSeries.append(float(i) / divider if divider else 0)

            dotPlot.add(polName, series)
            dotPlotN.add(polName, normalisedSeries)

        filename = 'mostUsable-%s.svg' % tag if tag else 'mostUsable.svg'
        dotPlot.render_to_file(os.path.join(self.outputDir, filename))
        filename = 'mostUsable-%s-normalised.svg' % tag if tag \
            else 'mostUsable-normalised.svg'
        dotPlotN.render_to_file(os.path.join(self.outputDir, filename))

    def plotSecurityCosts(self, userlandScores: dict):
        sortable = sortedlist(key=lambda i: -i[0])
        for (pol, s) in userlandScores.items():
            rank = s["splitting"] + s["isolating"] + \
                   s["g-splitting"] + s["g-isolating"]

            sortable.add((rank, pol, s))

        lineChart = pygal.StackedBar()
        lineChartS = pygal.StackedBar()
        lineChart.title = 'Security costs per policy, including costs to ' \
                          'optimal graph configuration.'
        lineChartS.title = 'Security costs per policy.'

        lines = [[], [], [], []]
        labels = []
        for (rank, pol, s) in sortable:
            lines[0].append(s["splitting"])
            lines[1].append(s["g-splitting"])
            lines[2].append(s["isolating"])
            lines[3].append(s["g-isolating"])
            labels.append(pol)

        lineChart.add("Splitting", lines[0])
        lineChart.add("Splitting (extra cost to optimal security)", lines[1])
        lineChart.add("Isolating", lines[2])
        lineChart.add("Isolating (extra cost to optimal security)", lines[3])
        lineChartS.add("Splitting", lines[0])
        lineChartS.add("Isolating", lines[2])

        lineChart.x_labels = labels
        lineChart.show_x_labels = True
        lineChart.show_y_guides = False
        lineChartS.x_labels = labels
        lineChartS.show_x_labels = True
        lineChartS.show_y_guides = False

        lineChart.render_to_file(os.path.join(self.outputDir,
                                              'securityCosts-graph.svg'))
        lineChartS.render_to_file(os.path.join(self.outputDir,
                                               'securityCosts-simple.svg'))

    def plotClusterViolations(self, file: str, titleTag: str='', tag: str=''):
        clusterScores = dict()
        for (name, folders) in sorted(self.foldersPerName.items()):
            paths = list(os.path.join(f, file) for f in folders)
            clusterScores[name] = self.parseClusterScores(paths)

        sortable = sortedlist(key=lambda i: -i[0])
        for (pol, (rank, nbParticipants)) in clusterScores.items():
            sortable.add((rank/nbParticipants if nbParticipants else 0, pol))

        lineChart = pygal.Bar()
        lineChart.title = 'Number of connected-files clusters with exclusion' \
                          ' list violations%s per particpant for each policy.' % titleTag

        lines = [[], [], [], []]
        labels = []
        maxVal = 0
        for (s, pol) in sortable:
            lines[0].append(s)
            labels.append(pol)
            maxVal = max(maxVal, s)

        lineChart.add("Cluster #", lines[0])

        lineChart.x_labels = labels
        lineChart.show_x_labels = True
        lineChart.show_y_guides = False
        lineChart.y_labels = list(range(int(maxVal) + 1))
        lineChart.yrange = (0, int(maxVal) + 2)
        lineChart.value_formatter = lambda y: "%d %s" % \
          (y, "clusters" if y != 1 else "cluster")

        lineChart.render_to_file(os.path.join(self.outputDir,
                                              'exclusionLists-%s.svg' % tag))

    def parseExclFiles(self, paths):
        def _parseExclFile(path):
            nExcls = 0
            foundExcl = False

            try:
                with open(path) as f:
                    for line in f:
                        if line.startswith(" No"):
                            continue
                        elif "exclusive" in line:
                            res = self.IntRe.match(line)
                            lineStart = int(res.groups()[0])
                            nExcls += 1 if lineStart > 1 else 0  # lineStart - 1
                            foundExcl = lineStart > 1

            except (FileNotFoundError) as e:
                # Happens if policy forbad accesses that'd have generated a score.
                return (0, None)

            def _appid(path):
                app = path.find("App - ")
                if app < 0:
                    return path

                leftcut = path[app+6:]
                return leftcut[:leftcut.find(" - ")]

            return (nExcls, _appid(path) if foundExcl else None)

        exclCounters = dict()
        for (path, pid) in paths:
            (nExcls, appid) = _parseExclFile(path)
            exclCounter = exclCounters.get(pid) or 0
            exclCounters[pid] = exclCounter + nExcls

        counterSum = 0
        for (pid, counter) in exclCounters.items():
            counterSum += counter / self.stats[pid]['uinstances']

        return counterSum * 100

    def plotInstanceViolations(self, paths, exclName):
        print("%s..." % exclName)
        violations = dict()
        sortable = sortedlist(key=lambda i: i[1])

        participantCount = 0
        for iD in self.inputDir:
            exclLists = self.stats[iD]['exclusionlists']
            if exclName in exclLists:
                participantCount += 1

        for (name, folders) in sorted(self.foldersPerName.items()):
            folders = list(f[f.find('/')+1:] for f in folders)
            parse = []
            for path in paths:
                fP = list((path.replace("@POLICY@", f), path[:path.find('/')])
                          for f in set(folders))
                parse.extend(fP)

            violations[name] = self.parseExclFiles(parse) / participantCount

        for (name, exclProportion) in violations.items():
            sortable.add((name, exclProportion))

        chart = pygal.HorizontalBar()
        chart.title = 'Average proportion of user applications accessing ' \
                      'files which are mutually exclusive.'

        lines = []
        maxVal = 0
        labels = []
        for (polName, app) in sortable:
            lines.append(app)
            if maxVal < app:
                maxVal = app
            labels.append(polName)

        chart.add("Applications", lines)

        chart.x_labels = labels
        chart.show_x_labels = True
        chart.show_minor_x_labels = False
        chart.show_y_guides = False
        chart.value_formatter = lambda y: "%d%%" % y if int(y) == y else "%f%%" % y

        chart.render_to_file(os.path.join(self.outputDir,
                                          'exclViolations-inst-%s.svg' % exclName))

    def plotAttackHistogram(self, docAttacks: dict, appAttacks: dict):
        sortable = sortedlist(key=lambda i: - (i[0] + i[1]) / 2)
        sortableWorst = sortedlist(key=lambda i: - (i[0] + i[1]) / 2)
        for (polName, docScores) in docAttacks.items():
            appScores = appAttacks[polName]
            allPAvgDoc = []
            allPAvgApp = []
            allPDocWorst = []
            allPAppWorst = []

            for (participant, docVals) in docScores.items():
                appVals = appScores[participant]

                avgDoc = 0
                avgApp = 0
                worstDoc = 0
                worstApp = 0

                for (attack, docVal) in docVals.items():
                    appVal = appVals[attack]

                    avgDoc += docVal
                    avgApp += appVal
                    worstDoc = docVal if docVal > worstDoc else worstDoc
                    worstApp = appVal if appVal > worstApp else worstApp

                avgDoc = avgDoc / len(docScores)
                avgApp = avgApp / len(appScores)

                allPAvgDoc.append(avgDoc)
                allPAvgApp.append(avgApp)
                allPDocWorst.append(worstDoc)
                allPAppWorst.append(worstApp)

            sortable.add((sum(allPAvgDoc) / len(allPAvgDoc),
                          sum(allPAvgApp) / len(allPAvgApp),
                          polName))
            sortableWorst.add((sum(allPDocWorst) / len(allPDocWorst),
                               sum(allPAppWorst) / len(allPAppWorst),
                               polName))

        chart = pygal.HorizontalBar()
        chart.title = 'Percentage of infected user files and applications on' \
                      ' average, per policy.'
        chart.value_formatter = lambda y: "%d%%" % y if int(y) == y else "%f%%" % y

        chartw = pygal.HorizontalBar()
        chartw.title = 'Percentage of infected user files and applications ' \
                       'in the worst case scenario, per policy.'
        chartw.value_formatter = lambda y: "%d%%" % y if int(y) == y else "%f%%" % y

        lines = [[], []]
        maxVal = 0
        labels = []
        for (doc, app, polName) in sortable:
            lines[0].append(doc)
            lines[1].append(app)
            if maxVal < max(doc, app):
                maxVal = max(doc, app)
            labels.append(polName)

        chart.add("Documents", lines[0])
        chart.add("Applications", lines[1])

        chart.x_labels = labels
        chart.show_x_labels = True
        chart.show_minor_x_labels = False
        chart.show_y_guides = False
        chart.y_labels_major = list(str(4*n) for n in range(0, int(maxVal / 4)))
        chart.y_labels_major_every = 4  # TODO adjust manually...

        chart.render_to_file(os.path.join(self.outputDir,
                                          'attack-rates-avg.svg'))

        linesw = [[], []]
        maxVal = 0
        for (doc, app, polName) in sortableWorst:
            linesw[0].append(doc)
            linesw[1].append(app)
            if maxVal < max(doc, app):
                maxVal = max(doc, app)

        chartw.add("Documents", linesw[0])
        chartw.add("Applications", linesw[1])

        chartw.x_labels = labels
        chartw.show_x_labels = True
        chartw.show_minor_x_labels = False
        chartw.show_y_guides = False
        chartw.y_labels_major = list(str(4*n) for n in range(0, int(maxVal / 4)))
        chartw.y_labels_major_every = 2  # TODO adjust manually...

        chartw.render_to_file(os.path.join(self.outputDir,
                                           'attack-rates-worst.svg'))

    def parseAttacks(self, folders: list):
        """Parse attacks.out file."""
        docScores = dict()
        appScores = dict()
        avgScores = dict()

        # def float100(n):
        #     return float(float(n) / 100)

        # func = (float, float100, float, float100, float, float100,
        #         float, float100, float, float100, float, float100)

        def _addToDict(d, attackKey, participant, val):
            l = d.get(participant) or dict()
            l[attackKey] = val
            d[participant] = l

        def _parseAttacks(docScores, appScores, avgScores, folder):
            filename = os.path.join(folder, "attacks.out")
            participant = folder[:folder.rfind("/")]
            try:
                with open(filename) as f:
                    curAttack = None
                    curScores = None

                    for line in f:
                        if line.startswith("## Performing attack"):
                            if curAttack and curScores:
                                _addToDict(docScores, curAttack, participant, curScores[0])
                                _addToDict(appScores, curAttack, participant, curScores[1])
                                _addToDict(avgScores, curAttack, participant, curScores[2])

                            curAttack = self.atkNameRe.match(line).groups()[0]
                            curScores = None
                        elif line.startswith("Avg:"):
                            g = self.atkScoresRe.match(line).groups()
                            (a, apc, wa, wapc, f, fpc, u, upc, wu, wupc,
                             d, dpc) = map(lambda f: float(f), g)
                            # map(lambda f, d: f(d), func, g)

                            # FIXME: currently, using non-weighted user apps.
                            # curScores = [dpc, wupc, (dpc + wupc) / 2]
                            curScores = [dpc, upc, (dpc + upc) / 2]
            except (FileNotFoundError) as e:
                pass

        for folder in folders:
            _parseAttacks(docScores, appScores, avgScores, folder)

        return (docScores, appScores, avgScores)

    def genUsabilityScoreTablesPerApp(self):
        # Get usability scores for each app individually.
        appScores = dict()
        polAbsScores = dict()
        polRelScores = dict()
        j = 1
        for (adx, app) in enumerate(self.userScores):
            print("\t%d/%d: %s" % (j, self.uAppCount, app))
            j += 1

            scores = dict()

            i = 1
            for (name, folders) in sorted(self.foldersPerName.items()):
                print("\t\t%d/%d: %s" % (i, self.policyCount, name))
                i += 1

                paths = list(app.replace("@POLICY@", f) for f in folders)
                s = self.parseUsabilityScores(paths,
                                              confCostDivider=self.uAppCount,
                                              divPerDays=True,
                                              divParticipants=True)

                scores[name] = s

            name = self.userNames[adx]
            self.genUsabilityCostTable(scores,
                                       name + ".UsabScores.tex",
                                       name)

            if name in plotWhitelist:
                maxCost = self.getHighestCostSum(scores)
                relScores = self.genRelativeCosts(scores, maxCost)
                for pol, s in relScores.items():
                    polRelScoreList = polRelScores.get(pol) or []
                    polRelScoreList.append(s)
                    polRelScores[pol] = polRelScoreList
                for pol, s in scores.items():
                    polAbsScoreList = polAbsScores.get(pol) or []
                    polAbsScoreList.append(s)
                    polAbsScores[pol] = polAbsScoreList

            appScores[app] = scores

        return (appScores, polRelScores, polAbsScores)

    def pareto(self, attackScores, usabScores, dataType):
        """Plot a Pareto front graph."""

        # Setup chart bases.
        dotsSec = dict()
        dotsUsa = dict()

        colors = list(c for c in Style.colors)
        if self.policyCount < len(colors):
            colors[self.policyCount] = "#A0FFC8"  # "#75ff98"

        chart = pygal.XY(stroke=False,
                         print_labels=True,
                         style=Style(colors=colors),
                         show_minor_y_labels=False,
                         y_labels_major_count=4,
                         include_x_axis=True,
                         include_y_axis=True)

        # TODO filter out base not also in Fa (save Fa names and then purge bases not in fa names list before the .add loop)
        colorsFa = ['#333333', '#a6dba0', '#c2a5cf', '#008837', "#cccccc"]
        colorsFa = ['#333333', '#7570b3', '#1b9e77', '#e7298a', "#cccccc"]
        chartFa = pygal.XY(stroke=False,
                           print_labels=True,
                           style=Style(colors=colorsFa),
                           show_minor_y_labels=False,
                           y_labels_major_count=4,
                           include_x_axis=True,
                           include_y_axis=True)
        # FIXME improve label (more top-left)

        chart.title = 'Usability and Security Scoring of Policies'
        chart.x_title = '% of infected user files and apps'
        if dataType == "worst":
            chart.x_title += ' in worst-case attack'
            outname = 'pareto-worst.svg'
        elif dataType == "avg":
            chart.x_title += ' per attack in average'
            outname = 'pareto-avg.svg'
        elif dataType.startswith('oe'):
            chart.x_title = 'Average percentage of user documents reachable ' \
                            'but not accessed, per applications'
            outname = 'pareto-%s.svg' % dataType
            from copy import deepcopy
            oeScores = deepcopy(attackScores)
            for (key, val) in oeScores.items():
                oeScores[key] = (1 - val) * 100
            attackScores = oeScores
        elif dataType:
            chart.x_title += ' in worst-case attack, %s' % dataType
            outname = 'pareto-%s.svg' % dataType
        else:
            outname = 'pareto.svg'

        chart.x_value_formatter = lambda y: "%d%%" % y if int(y) == y else "%f%%" % y
        chart.y_title = 'User actions required per day on average'

        chartFa.title = chart.title
        chartFa.x_title = chart.x_title
        chartFa.y_title = chart.y_title
        chartFa.x_value_formatter = chart.x_value_formatter

        # Manage policy labels.
        polNames = dict()
        labelForRegion = dict()
        maxX = 0
        xRanges = 10
        for (polName, attackScore) in attackScores.items():
            maxX = max(maxX, attackScore)
        maxX += 0.000001  # Ensure the item with maximal value isn't isolated.
        chart.xrange = (0, maxX)
        chartFa.xrange = chart.xrange

        maxY = 0
        yRanges = 18
        for (polName, usabScore) in usabScores.items():
            maxY = max(maxY, sum([usabScore[key] for key in costKeysNC]))
        maxY += 0.000001
        chart.yrange = (0, maxY)
        chartFa.yrange = chart.yrange

        def _getRegion(sec, usa):
            return (int(sec / (maxX / xRanges)) * (maxX / xRanges),
                     int(usa / (maxY / yRanges)) * (maxY / yRanges))

        def _registerPolName(polName, sec, usa):
            key = (sec, usa)
            rKey = _getRegion(sec, usa)

            # Update the policy name for the region.
            namesForDot = polNames.get(rKey) or []
            namesForDot.append(polName)
            polNames[rKey] = namesForDot

            # Find the dot most centered in the region.
            halfX = (maxX / xRanges) / 2
            halfY = (maxY / yRanges) / 2

            diffX = key[0] - rKey[0]
            diffY = key[1] - rKey[1]

            (cur, _) = labelForRegion.get(rKey) or [rKey, '']
            diffCurX = cur[0] - rKey[0]
            diffCurY = cur[1] - rKey[1]

            curDistToCenter = abs(halfX - diffCurX) + abs(halfY - diffCurY)
            newDistToCenter = abs(halfX - diffX) + abs(halfY - diffY)

            if curDistToCenter > newDistToCenter:
                labelForRegion[rKey] = (key, polName)

        def _getPolNameLabel(x, polName):
            rKey = _getRegion(x[0], x[1])

            # Only print a label if we're the most centered dot of the region.
            (reprCoords, reprName) = labelForRegion[rKey]
            if (x[0] != reprCoords[0]) or (x[1] != reprCoords[1]) or \
                    polName != reprName:
                return ''

            labels = polNames.get(rKey) or []
            return ', '.join(sorted(tuple(labels)))

        def _getFaLabel(polName):
            if polName.endswith("SbFa"):
                return 'Future & Sticky'
            elif polName.endswith("Fa"):
                return 'Future Access'
            elif polName.endswith("Sb"):
                return 'Sticky Bit'
            else:
                return 'Base only'

        # We cannot normalise costs per user instance since we already aggregated
        # costs for each user.
        ## Get normalisation factor for usability costs.
        # for (name, folders) in sorted(self.foldersPerName.items()):
        #     for folder in folders:
        #         uAppCount = None
        #         for (pName, stats) in self.stats.items():
        #             if folder.startswith(pName):
        #                 uAppCount = stats['uinstances']
        #         if not uAppCount:
        #             raise ValueError("Could not find user app instance count for "
        #                              "folder '%s'." % folder)


        # Pre-compute policy dots.
        chart.x_labels = []
        chartFa.x_labels = []
        for (polName, attackScore) in attackScores.items():
            usabScore = usabScores[polName]
            sumScore = sum([usabScore[key] for key in costKeysNC])

            dotsSecL = dotsSec.get(attackScore) or []
            dotsSecL.append(polName)
            dotsSec[attackScore] = dotsSecL
            dotsUsa[polName] = sumScore

            _registerPolName(polName, attackScore, sumScore)

        # Pre-compute Pareto front.
        # sort solutions by sec, add the one with the lowest sec first.
        usaFront = math.inf
        front = []
        for (attackScore, pNames) in sorted(dotsSec.items()):
            for polName in sorted(pNames, key=lambda k: dotsUsa[k]):
                if dotsUsa[polName] < usaFront:
                    # Add initial point too.
                    if usaFront == math.inf:
                        # front.append((min(attackScore, 0.03), dotsUsa[polName]))
                        front.append((min(attackScore, 0.03), maxY))
                        front.append((attackScore-0.1, maxY))

                    usaFront = dotsUsa[polName]
                    front.append((attackScore, dotsUsa[polName]))

        # Add policy dots.
        chartFaData = dict()
        chartFaPoliciesWithFa = set()
        for (polName, attackScore) in attackScores.items():
            usabScore = usabScores[polName]
            sumScore = sum([usabScore[key] for key in costKeysNC])

            key = (attackScore, sumScore)
            dots_size = 4 if key in front else 3
            chart.add(polName,
                      [{'value': key,
                        'label': _getPolNameLabel(key, polName)}],
                      dots_size=dots_size)

            faLabel = _getFaLabel(polName)
            dataList = chartFaData.get(faLabel) or []
            dataList.append((polName, key))
            chartFaData[faLabel] = dataList

            if polName.endswith("Fa"):
                chartFaPoliciesWithFa.add(polName)

        for (faLabel, dataList) in chartFaData.items():

            # Filter out base policies without a Fa version.
            finalDataList = []
            for (polName, key) in dataList:
                if not polName.endswith("Fa") and \
                        not polName.endswith("Sb") and \
                        polName + "Fa" not in chartFaPoliciesWithFa:
                    continue

                finalDataList.append(key)

            # Chart the other ones for the Fa/SbFa/Sb/base comparison.
            chartFa.add(faLabel, finalDataList, dots_size=dots_size)

        # Add Pareto front.
        chart.add(None, front, stroke=True, show_dots=False, fill=True)
        chartFa.add(None, front, stroke=True, show_dots=False, fill=True)

        chart.render_to_file(os.path.join(self.outputDir, outname))
        chartFa.render_to_file(os.path.join(self.outputDir, outname.replace(".svg", "-color-fa.svg")))

    def analyse(self):
        """Perform the post-analysis."""

        if self.participantCount > 1:
            print("Generating plot of most usable policy per participant...")
            # FIXME reconsider how I normalise this data. I could normalise in
            # terms of cost per user application instance ran.
            mostUsable = dict()
            leastUsable = dict()
            leastUsableNoG = dict()
            sums = dict()
            sumsNoG = dict()

            i = 1

            for iD in sorted(self.inputDir):  # MUST BE SORTED! plot fn x label
                print("\t%d/%d: %s" % (i, self.participantCount, iD))
                i += 1
                # Get policies for this folder.
                pFList = sorted(glob.glob(os.path.join(iD, 'Policy*')))
                policyNames = list(a[a.rfind("/")+10:-6] for a in pFList)
                foldersPerName = dict()
                for (idx, name) in enumerate(policyNames):
                    l = foldersPerName.get(name) or []
                    l.append(pFList[idx])
                    foldersPerName[name] = l

                # Score them.
                perParticipantScores = dict()
                for (name, folders) in sorted(foldersPerName.items()):
                    # Score of userland apps on all userland files.
                    aggregate = self.parseUsabilityScores([])
                    p = list(os.path.join(f, "LibraryDesktop.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryDocuments.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryDownloads.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryImage.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryMusic.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryRemovable.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryProgramming.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryScores.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryUnclassifieduserdocument.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    p = list(os.path.join(f, "LibraryVideo.score") for f in folders)
                    self.parseUsabilityScores(p, confCostDivider=10, scores=aggregate, divPerDays=True, divParticipants=True)
                    perParticipantScores[name] = aggregate

                best = None
                bestScore = math.inf
                worstScore = 0
                worstScoreNoG = 0
                for (name, s) in perParticipantScores.items():
                    sumScore = sum([s[key] for key in costKeysNC])
                    sumScoreNoG = sum([s[key] for key in costKeysNoGNC])

                    sumsForPol = sums.get(name) or dict()
                    sumsForPol[iD] = sumScore
                    sums[name] = sumsForPol

                    sumsForPol = sumsNoG.get(name) or dict()
                    sumsForPol[iD] = sumScoreNoG
                    sumsNoG[name] = sumsForPol

                    if sumScore < bestScore:
                        best = name
                        bestScore = sumScore
                    if sumScore > worstScore:
                        worstScore = sumScore
                    if sumScoreNoG > worstScoreNoG:
                        worstScoreNoG = sumScoreNoG

                mostUsable[iD] = (best, bestScore)
                leastUsable[iD] = worstScore
                leastUsableNoG[iD] = worstScoreNoG

            # for (iD, (name, s)) in mostUsable.items():
            #     print("Participant '%s': Policy %s scoring %d" % (iD, name, s))

            # Plot dots for all costs with graphs, and without.
            self.plotMostUsableDots(sums,
                                    leastUsable,
                                    self.inputDir,
                                    "per participant")
            self.plotMostUsableDots(sumsNoG,
                                    leastUsableNoG,
                                    self.inputDir,
                                    "per participant, without graph"
                                    " optimisation costs",
                                    "nograph")
            print("Done.\n")

        # Generate exclusion list plots for app instances.
        print("Generating exclusion list plots for app instances...")
        self.plotInstanceViolations(self.exclScoresPW, 'WorkPersonalSeparation')
        self.plotInstanceViolations(self.exclScoresPROJ, 'ProjectSeparation')
        self.plotInstanceViolations(self.exclScoresEXCL, 'ExplicitExclusion')
        print("Done.\n")

        # Get usability scores for all userland apps.
        print("Generating table of usability scores for all userland apps...")
        userlandScores = dict()
        userlandUserdocScores = dict()
        libDesktopScores = dict()
        libDocumentsScores = dict()
        libDownloadsScores = dict()
        libImageScores = dict()
        libMusicScores = dict()
        libRemovableScores = dict()
        libProgrammingScores = dict()
        libUnclassifiedScores = dict()
        libVideoScores = dict()
        i = 1
        for (name, folders) in sorted(self.foldersPerName.items()):
            print("\t%d/%d: %s" % (i, self.policyCount, name))
            i += 1

            # Global score of userland apps.
            p = list(os.path.join(f, "UserlandApps.score") for f in folders)
            userlandScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            # Score of userland apps on all userland files.
            aggregate = self.parseUsabilityScores([])
            p = list(os.path.join(f, "LibraryDesktop.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            # small mismatch on actual config cost, but too hard to fix and unlikely to alter results
            libDesktopScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryDocuments.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libDocumentsScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryDownloads.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libDownloadsScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryImage.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libImageScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryMusic.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libMusicScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryRemovable.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libRemovableScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryProgramming.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libProgrammingScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryUnclassifieduserdocument.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libUnclassifiedScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            p = list(os.path.join(f, "LibraryVideo.score") for f in folders)
            self.parseUsabilityScores(p, confCostDivider=9, scores=aggregate, divPerDays=True, divParticipants=True)
            libVideoScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            userlandUserdocScores[name] = aggregate

        self.genUsabilityCostTable(userlandScores,
                                   "UserlandApps.UsabScores.tex",
                                   "all user applications per day and per participant")

        self.genUsabilityCostTable(userlandUserdocScores,
                                   "UserlandUserdocs.UsabScores.tex",
                                   "all user applications on user documents per day and per participant")
        print("Done.\n")

        # Get usability scores for each library separately.
        print("Generating table of usability scores for each library...")
        libraries = list(lib.capitalize() for lib in LibraryManager.CustomList)
        libraries.append("Unclassifieduserdocument")
        # libraries.append("Unclassified")
        lpCount = self.policyCount * len(libraries)
        i = 1
        for lib in libraries:
            libFile = "Library%s.score" % lib
            libScores = dict()
            for (name, folders) in sorted(self.foldersPerName.items()):
                print("\t%d/%d: %s for %s" % (i, lpCount, name, lib))
                i += 1

                p = list(os.path.join(f, libFile) for f in folders)
                libScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            self.genUsabilityCostTable(libScores,
                                       "Library%s.UsabScores.tex" % lib,
                                       "all user applications")
        print("Done.\n")

        # Plot dot graph of usability scores per library/policy.
        print("Generating table of usability scores for each library...")
        mostUsable = dict()
        leastUsable = dict()
        leastUsableNoG = dict()
        sums = dict()
        sumsNoG = dict()

        # Censoring (hard-coded) missing results.
        libraries.remove("Ebooks")
        libraries.remove("Scores")

        i = 1
        for lib in libraries:
            libScores = dict()
            libFile = "Library%s.score" % lib
            for (name, folders) in sorted(self.foldersPerName.items()):
                print("\t%d/%d: %s for %s" % (i, lpCount, name, lib))
                i += 1

                p = list(os.path.join(f, libFile) for f in folders)
                libScores[name] = self.parseUsabilityScores(p, divPerDays=True, divParticipants=True)

            best = None
            bestScore = math.inf
            worstScore = 0
            worstScoreNoG = 0
            for (name, s) in libScores.items():
                sumScore = sum([s[key] for key in costKeysNC])
                sumScoreNoG = sum([s[key] for key in costKeysNoGNC])

                sumsForPol = sums.get(name) or dict()
                sumsForPol[lib] = sumScore
                sums[name] = sumsForPol

                sumsForPol = sumsNoG.get(name) or dict()
                sumsForPol[lib] = sumScoreNoG
                sumsNoG[name] = sumsForPol

                if sumScore < bestScore:
                    best = name
                    bestScore = sumScore
                if sumScore > worstScore:
                    worstScore = sumScore
                if sumScoreNoG > worstScoreNoG:
                    worstScoreNoG = sumScoreNoG

            mostUsable[lib] = (best, bestScore)
            leastUsable[lib] = worstScore
            leastUsableNoG[lib] = worstScoreNoG

        for (libName, (name, s)) in mostUsable.items():
            print("Library '%s': Policy %s scoring %d" % (libName, name, s))

        # Plot dots for all costs with graphs, and without.
        self.plotMostUsableDots(sums,
                                leastUsable,
                                libraries,
                                "for each library",
                                "lib")
        self.plotMostUsableDots(sumsNoG,
                                leastUsableNoG,
                                libraries,
                                "for each library, without graph optimisation"
                                " costs",
                                "lib-nograph")
        print("Done.\n")

        print("Computing attack scores...")
        secScoresWorst = dict()
        secScoresAvg = dict()
        docAttacks = dict()
        appAttacks = dict()
        for (name, folders) in sorted(self.foldersPerName.items()):
            (docAtkS, appAtkS, avgAtkS) = self.parseAttacks(folders)
            docAttacks[name] = docAtkS
            appAttacks[name] = appAtkS

            # Get an array the size of the number of participants (which is the
            # number of entries in avgAtkS).
            worstAttacks = []
            avgAttacks = []

            # Pick the worst attack for each participant, and the average.
            for (participant, attackScores) in avgAtkS.items():
                worstAtk = 0
                worstAtkName = None
                avgAtk = sum(attackScores.values()) / len(attackScores)
                for (attackName, attack) in attackScores.items():
                    if attack > worstAtk:
                        worstAtk = attack
                        worstAtkName = attackName

                avgAttacks.append(avgAtk)
                worstAttacks.append(worstAtk)

            secScoresWorst[name] = sum(worstAttacks) / len(worstAttacks)
            secScoresAvg[name] = sum(avgAttacks) / len(avgAttacks)
        print("Done.\n")

        print("Plotting security graphs...")
        # Other possibility: plot whisker (col: policy; whisker: each attack)
        # Other possibility: plot lines (col: policy; lines: each attack)
        self.plotAttackHistogram(docAttacks, appAttacks)
        print("Done.\n")

        print("Plotting Pareto front of usability and security...")
        self.pareto(secScoresWorst, userlandUserdocScores, "worst")
        self.pareto(secScoresAvg, userlandUserdocScores, "avg")
        print("Done.\n")

        print("Plotting Pareto front for each library...")
        self.pareto(secScoresWorst, libDesktopScores, "lib-desktop")
        self.pareto(secScoresWorst, libDocumentsScores, "lib-documents")
        self.pareto(secScoresWorst, libDownloadsScores, "lib-downloads")
        self.pareto(secScoresWorst, libImageScores, "lib-image")
        self.pareto(secScoresWorst, libMusicScores, "lib-music")
        self.pareto(secScoresWorst, libRemovableScores, "lib-removable")
        self.pareto(secScoresWorst, libProgrammingScores, "lib-programming")
        self.pareto(secScoresWorst, libUnclassifiedScores, "lib-unclassified")
        self.pareto(secScoresWorst, libVideoScores, "lib-video")
        print("Done.\n")

        print("Plotting cost distribution for all userland apps...")
        for (i, name) in enumerate(sorted(self.foldersPerName)):
            print("\t%d/%d: %s" % (i+1, self.policyCount, name))
            self.plotCostDistribution(name, userlandUserdocScores[name])
        print("Done.\n")

        print("Generating table of usability scores for individual apps...")
        (appScores, polRelScores, polAbsScores) = \
            self.genUsabilityScoreTablesPerApp()
        print("Done.\n")

        print("Plot costs of accesses per policy, for every app...")
        self.plotAppCostsPerPolBoxes(polRelScores, polAbsScores)
        print("Done.\n")

        # Whisker plot of usability scores for each instance, per app.
        print("Plot whisker-boxes of costs for each app for every policy...")
        # for (name, folders) in sorted(self.foldersPerName.items()):
        #     self.plotDistCostsBoxes(folders, name, self.userNames)
        print("Done.\n")

        # Plot security costs for all the policies.
        print("Plot security costs for every policy...")
        self.plotSecurityCosts(userlandUserdocScores)
        print("Done.\n")

        # Plot policies' exclusion list scores across whole clusters.
        print("Plot cluster violations per app for every policy...")
        self.plotClusterViolations(file="clustersPerAppExcl.WorkPersonalSeparation.securityscore",
                                   titleTag=" for work-personal life separation", tag="work-app")
        self.plotClusterViolations(file="clustersPerAppExcl.ProjectSeparation.securityscore",
                                   titleTag=" for between-projects separation", tag="proj-app")
        self.plotClusterViolations(file="clustersPerAppExcl.ExplicitExclusion.securityscore",
                                   titleTag=" for explicitly excluded files", tag="excl-app")
        print("Done.\n")

        print("Plot cluster violations per app instance for every policy...")
        self.plotClusterViolations(file="clustersPerAppInstanceExcl.WorkPersonalSeparation.securityscore",
                                   titleTag=" for work-personal life separation (memoryless apps)", tag="work-inst")
        self.plotClusterViolations(file="clustersPerAppInstanceExcl.ProjectSeparation.securityscore",
                                   titleTag=" for between-projects separation (memoryless apps)", tag="proj-inst")
        self.plotClusterViolations(file="clustersPerAppInstanceExcl.ExplicitExclusion.securityscore",
                                   titleTag=" for explicitly excluded files (memoryless apps)", tag="excl-inst")
        print("Done.\n")

        # Plot over-entitlement whisker boxes.
        print("Plot over-entitlements for each user app...")
        overallOEScores = self.analyseOE()
        print("Done.\n")

        print("Plot summary of all apps' over-entitlements...")
        self.genOETable(overallOEScores,
                        "UserlandApps.OEScores.tex",
                        "all user applications")
        self.plotOEBoxes(overallOEScores, "UserlandApps")
        print("Done.\n")

        # Plot Pareto scores for over-entitlements.
        print("Plotting Pareto front of usability and over-entitlements...")
        sumOEScores = dict()
        for (name, scores) in overallOEScores.items():
            s = sum(o[0]/o[1] if o[1] else 1 for o in scores) / len(scores)
            sumOEScores[name] = s

        self.pareto(sumOEScores, userlandUserdocScores, "oe")
        print("Done.\n")

        print("Plotting over-entitlement Pareto front for each library...")
        self.pareto(sumOEScores, libDesktopScores, "oe-lib-desktop")
        self.pareto(sumOEScores, libDocumentsScores, "oe-lib-documents")
        self.pareto(sumOEScores, libDownloadsScores, "oe-lib-downloads")
        self.pareto(sumOEScores, libImageScores, "oe-lib-image")
        self.pareto(sumOEScores, libMusicScores, "oe-lib-music")
        self.pareto(sumOEScores, libRemovableScores, "oe-lib-removable")
        self.pareto(sumOEScores, libProgrammingScores, "oe-lib-programming")
        self.pareto(sumOEScores, libUnclassifiedScores, "oe-lib-unclassified")
        self.pareto(sumOEScores, libVideoScores, "oe-lib-video")
        print("Done.\n")

