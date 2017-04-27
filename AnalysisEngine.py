"""An engine that produces graphs and statistics for a prior analysis."""
from blist import sortedlist
import glob
import math
import os
import shutil
import pygal
from pygal.style import Style
from utils import debugEnabled
from LibraryManager import LibraryManager

plottingBlacklist = ['apt-get', 'cairo-dock', 'dbus-send', 'dpkg', 'gdb',
                     'gst-plugin-scanner', 'helper-dialog', 'indicator-applet',
                     'inictl', 'java', 'killall5', 'light-locker', 'mono-sgen',
                     'nm-applet', 'obex-data-server', 'ubuntu-sso-login',
                     'polkit-gnome-authentication-agent-1', 'upower',
                     'xfce4-display-settings', 'xfce4-taskmanager',
                     'xfwm4-settings']

accessKeys = ["by designation", "file owned by app",
              "policy-allowed", "illegal"]

costKeys = ["configuration", "granting", "cumulative granting", "isolating",
            "splitting", "g-granting", "g-isolating", "g-splitting"]

costKeysNoG = ["configuration", "granting", "cumulative granting", "isolating",
               "splitting"]

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

        print("Collecting policies...")

        # List policies to parse.
        pFList = list(sorted(glob.glob(
                      os.path.join(iD, 'Policy*'))) for iD in self.inputDir)
        self.policyFolders = [item for sublist in pFList for item in sublist]
        self.policyNames = list(a[a.rfind("/")+10:-6]
                                for a in self.policyFolders)
        self.foldersPerName = dict()
        for (idx, name) in enumerate(self.policyNames):
            l = self.foldersPerName.get(name) or []
            l.append(self.policyFolders[idx])
            self.foldersPerName[name] = l

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
        exclScores = set()
        for pol in self.policyFolders:
            polScores = glob.glob(os.path.join(pol, "App*.exclscore"))
            for p in polScores:
                exclScores.add(p.replace(pol, "@POLICY@"))
        self.exclScores = list(exclScores)
        self.exclNames = list((a[a.rfind("/")+7:-6] for a in self.exclScores))

        print("Ready to analyse!\n")

    def getHighestCostSum(self, costs: dict, confCostDivider: int=1):
        """TODO."""
        m = 0
        for pol, s in costs.items():
            cSum = s["configuration"] / confCostDivider + \
                   s["granting"] + s["isolating"] + s["splitting"]
            m = max(m, cSum)
        return m

    def genRelativeCosts(self, costs: dict, maxCost: int):
        """TODO."""
        relCosts = dict()
        if maxCost:
            for pol, s in costs.items():
                t = dict()
                for key in costKeys:
                    t[key] = s[key] / maxCost
                relCosts[pol] = t
        else:
            for pol, s in costs.items():
                t = dict()
                for key in costKeys:
                    t[key] = 0
                relCosts[pol] = t\

        return relCosts

    def genUsabilityCostTable(self, costs: dict, filename: str, target: str,
                              confCostDivider: int=1):
        """TODO."""
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
            msg += "  %s&%d&%d&{\\small (%d)}&%d&%d&%d \\\\\n" % (
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
        """TODO."""
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
            msg += "  %s&%d&%d&%d\\%% \\\\\n" % (pol, a, r, a/r if r else 0)

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
                             filenames: [],
                             confCostDivider: int=1):

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
            """TODO."""
            try:
                with open(filename) as f:
                    content = f.readlines()
                    for line in content:
                        if line.startswith("\t* by designation"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["by designation"] += d[0]
                        elif line.startswith("\t* file owned by app"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["file owned by app"] += d[0]
                        elif line.startswith("\t* policy-allowed"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["policy-allowed"] += d[0]
                        elif line.startswith("\t* illegal"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["illegal"] += d[0]
                        elif line.startswith("\t* configuration"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["configuration"] += d[0] / confCostDivider
                        elif line.startswith("\t* granting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["granting"] += d[0]
                        elif line.startswith("\t* cumulative granting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["cumulative granting"] += d[0]
                        elif line.startswith("\t* isolating"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["isolating"] += d[0]
                        elif line.startswith("\t* splitting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["splitting"] += d[0]
                        elif line.startswith("\t* g-granting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["g-granting"] += d[0]
                        elif line.startswith("\t* g-isolating"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["g-isolating"] += d[0]
                        elif line.startswith("\t* g-splitting"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            s["g-splitting"] += d[0]
            except (FileNotFoundError) as e:
                pass

        for filename in filenames:
            _parseUsabilityScores(s, filename, confCostDivider)

        return s

    def filterUsabilityScores(self,
                              filename: str,
                              filterKey: str="APPTYPE",
                              filterValues: list=["Application"]):
        """TODO."""
        try:
            with open(filename) as f:
                content = f.readlines()
                for line in content:
                    if filterKey and line.startswith(filterKey+":"):
                        v = line[len(filterKey)+2:-1]
                        return v in filterValues
        except (FileNotFoundError) as e:
            return False
        return False

    def parseClusterScores(self, filenames: list):
        """TODO."""
        score = 0

        def _parseClusterScores(self, filename: str):
            try:
                with open(filename) as f:
                    content = f.readlines()
                    for line in content:
                        if line.startswith("# of clusters violating exclusion"):
                            d = [int(s) for s in line[:-1].split(' ') if
                                 s.isdigit()]
                            return d[0]

            except (FileNotFoundError) as e:
                print(filename)
                return -2

            return -1

        for filename in filenames:
            d = _parseClusterScores(self, filename)
            if d == -1:
                return -1
            score += d

        return score


    def parseOEScores(self, filenames: list):
        """TODO."""

        prfx = "Distribution of over-entitlements: "

        def _parseOEScores(filename: str):
            try:
                with open(filename) as f:
                    content = f.readlines()
                    for line in content:
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

    def plotAppCostsPerPolBoxes(self,
                                polRelCosts: dict,
                                polAbsCosts: dict):
        """TODO."""
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
        """TODO."""
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
                           validApps: list,
                           excludeZeroAccesses: bool=True):
        """TODO."""
        instCostDist = dict()
        for (udx, uapp) in enumerate(self.instScores):
            instName = self.instNames[udx]
            desktopid = instName[:instName.find("Instance") - 3]

            if desktopid in validApps and desktopid not in plottingBlacklist:
                series = instCostDist.get(desktopid) or ([], [])
                paths = list(uapp.replace("@POLICY@", f) for f in folders)
                s = self.parseUsabilityScores(paths,
                                              confCostDivider=self.uInstCount)

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


    # TODO double whisker bar w/ one whisker for accessed and one for reachable
    # TODO whisker for proportion of reached?

    def plotOEBoxes(self,
                    scores: dict,
                    appName: str,
                    excludeZeroAccesses: bool=True):
        """TODO."""
        if appName in plottingBlacklist:
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
                           title: str=None,
                           tag: str=None):
        """TODO."""
        dotPlot = pygal.Dot()
        dotPlotN = pygal.Dot()
        dotPlot.x_labels = sorted(self.inputDir)
        dotPlotN.x_labels = dotPlot.x_labels

        if title:
            dotPlot.title = "Costs of each policy per participant, %s" % title
        else:
            dotPlot.title = "Costs of each policy per participant"
        dotPlotN.title = dotPlot.title + ", normalised"

        for (polName, pScores) in sorted(scores.items()):
            series = []
            for pName in sorted(pScores):
                series.append(pScores[pName])

            dotPlot.add(polName, series)
            dotPlotN.add(polName, [float(i)/maxes[dotPlot.x_labels[idx]] for (idx, i) in enumerate(series)])

        filename = 'mostUsable-%s.svg' % tag if tag else 'mostUsable.svg'
        dotPlot.render_to_file(os.path.join(self.outputDir, filename))
        filename = 'mostUsable-%s-normalised.svg' % tag if tag \
            else 'mostUsable-normalised.svg'
        dotPlotN.render_to_file(os.path.join(self.outputDir, filename))

    def plotSecurityCosts(self, userlandScores: dict):
        """TODO."""
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
        """TODO."""

        clusterScores = dict()
        for (name, folders) in sorted(self.foldersPerName.items()):
            paths = list(os.path.join(f, file) for f in folders)
            clusterScores[name] = self.parseClusterScores(paths)

        sortable = sortedlist(key=lambda i: -i[0])
        for (pol, rank) in clusterScores.items():
            sortable.add((rank, pol))

        lineChart = pygal.Bar()
        lineChart.title = 'Number of connected-files clusters with exclusion' \
                          ' list violations%s, per policy.' % titleTag

        lines = [[], [], [], []]
        labels = []
        for (s, pol) in sortable:
            lines[0].append(s)
            labels.append(pol)

        lineChart.add("Cluster #", lines[0])

        lineChart.x_labels = labels
        lineChart.show_x_labels = True
        lineChart.show_y_guides = False

        lineChart.render_to_file(os.path.join(self.outputDir,
                                              'exclusionLists-%s.svg' % tag))

    def analyse(self):
        """Perform the post-analysis."""
        policyCount = len(self.foldersPerName)

        if len(self.inputDir) > 1:
            print("Generating plot of most usable policy per participant...")
            mostUsable = dict()
            leastUsable = dict()
            leastUsableNoG = dict()
            sums = dict()
            sumsNoG = dict()

            i = 1
            iDCount = len(self.inputDir)
            for iD in sorted(self.inputDir):  # MUST BE SORTED! plot fn x label
                print("\t%d/%d: %s" % (i, iDCount, iD))
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
                userlandScores = dict()
                for (name, folders) in sorted(foldersPerName.items()):
                    p = list(os.path.join(f, "UserlandApps.score") for f in folders)
                    userlandScores[name] = self.parseUsabilityScores(p)

                best = None
                bestScore = math.inf
                worstScore = 0
                worstScoreNoG = 0
                for (name, s) in userlandScores.items():
                    sumScore = sum([s[key] for key in costKeys])
                    sumScoreNoG = sum([s[key] for key in costKeysNoG])

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

            for (iD, (name, s)) in mostUsable.items():
                print("Participant '%s': Policy %s scoring %d" % (iD, name, s))

            # Plot dots for all costs with graphs, and without.
            self.plotMostUsableDots(sums, leastUsable)
            self.plotMostUsableDots(sumsNoG, leastUsableNoG,
                                    "without graph optimisation costs",
                                    "nograph")
            print("Done.\n")

        # Get usability scores for all userland apps.
        print("Generating table of usability scores for all userland apps...")
        userlandScores = dict()
        i = 1
        for (name, folders) in sorted(self.foldersPerName.items()):
            print("\t%d/%d: %s" % (i, policyCount, name))
            i += 1

            p = list(os.path.join(f, "UserlandApps.score") for f in folders)
            userlandScores[name] = self.parseUsabilityScores(p)

        self.genUsabilityCostTable(userlandScores,
                                   "UserlandApps.UsabScores.tex",
                                   "all user applications")
        print("Done.\n")

        # Get usability scores for each library separately.
        print("Generating table of usability scores for each library...")
        libScores = dict()
        libraries = (lib.capitalize() for lib in LibraryManager.CustomList)
        # FIXME FIXME FIXME: DELETE
        libraries = ['Documents', 'Music', 'Video', 'Downloads', 'Image',
                     'Unclassified', 'Unclassifieduserdocument']
        # FIXME FIXME FIXME: END DELETE
        lpCount = policyCount * len(libraries)
        i = 1
        for lib in libraries:
            libFile = "Library%s.score" % lib
            for (name, folders) in sorted(self.foldersPerName.items()):
                print("\t%d/%d: %s for %s" % (i, lpCount, name, lib))
                i += 1

                p = list(os.path.join(f, libFile) for f in folders)
                libScores[name] = self.parseUsabilityScores(p)

            self.genUsabilityCostTable(libScores,
                                       "Library%s.UsabScores.tex" % lib,
                                       "all user applications")
        print("Done.\n")

        print("Plotting cost distribution for all userland apps...")
        i = 1
        for (name) in sorted(self.foldersPerName):
            print("\t%d/%d: %s" % (i, policyCount, name))
            i += 1
            self.plotCostDistribution(name, userlandScores[name])
        print("Done.\n")

        print("Generating table of usability scores for individual apps...")
        # Get usability scores for each app individually.
        appScores = dict()
        polAbsScores = dict()
        polRelScores = dict()
        validApps = []
        j = 1
        for (adx, app) in enumerate(self.userScores):
            print("\t%d/%d: %s" % (j, self.uAppCount, app))
            j += 1

            scores = dict()

            i = 1
            for (name, folders) in sorted(self.foldersPerName.items()):
                print("\t\t%d/%d: %s" % (i, policyCount, name))
                i += 1

                paths = list(app.replace("@POLICY@", f) for f in folders)
                s = self.parseUsabilityScores(paths,
                                              confCostDivider=self.uAppCount)

                scores[name] = s

            name = self.userNames[adx]
            self.genUsabilityCostTable(scores,
                                       name + ".UsabScores.tex",
                                       name)

            if name not in plottingBlacklist:
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
        print("Done.\n")

        print("Plot costs of accesses per policy, for every app...")
        self.plotAppCostsPerPolBoxes(polRelScores, polAbsScores)
        print("Done.\n")

        # Whisker plot of usability scores for each instance, per app.
        print("Plot whisker-boxes of costs for each app for every policy...")
        for (name, folders) in sorted(self.foldersPerName.items()):
            self.plotDistCostsBoxes(folders, name, self.userNames)
        print("Done.\n")

        # Plot security costs for all the policies.
        print("Plot security costs for every policy...")
        self.plotSecurityCosts(userlandScores)
        print("Done.\n")

        # Plot policies' exclusion list scores across whole clusters.
        print("Plot cluster violations per app for every policy...")
        self.plotClusterViolations(file="clustersPerApp.securityscore",
                                   titleTag="", tag="app")
        print("Done.\n")

        print("Plot cluster violations per app instance for every policy...")
        self.plotClusterViolations(file="clustersPerAppInstance.securityscore",
                                   titleTag=" (memoryless apps)", tag="inst")
        print("Done.\n")

        # Plot over-entitlement whisker boxes.
        print("Plot over-entitlements for each user app...")
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
        print("Done.\n")

        print("Plot summary of all apps' over-entitlements...")
        self.genOETable(overallOEScores,
                        "UserlandApps.OEScores.tex",
                        "all user applications")
        self.plotOEBoxes(overallOEScores, "UserlandApps")
        print("Done.\n")
