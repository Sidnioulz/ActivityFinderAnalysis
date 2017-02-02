"""An engine that produces graphs and statistics for a prior analysis."""
from blist import sortedlist
import glob
import os
import shutil
import pygal
from pygal.style import Style

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

    def __init__(self, inputDir: str):
        """Construct an AnalysisEngine."""
        super(AnalysisEngine, self).__init__()

        if not os.path.exists(inputDir):
            raise ValueError("Path to output directory is not valid.")

        # Input dir where the analysis data is stored.
        self.inputDir = inputDir

        # Build directory to store analysis results.
        self.outputDir = os.path.join(self.inputDir, "analysis")

        if os.path.exists(self.outputDir):
            backup = self.outputDir.rstrip("/") + ".backup"
            if os.path.exists(backup):
                shutil.rmtree(backup)
            os.replace(self.outputDir, backup)
        os.makedirs(self.outputDir, exist_ok=False)

        # List policies to parse.
        self.policyFolders = sorted(glob.glob(
            os.path.join(self.inputDir, 'Policy*')))
        self.policyNames = list(a[a.rfind("/")+10:-6] for
                                a in self.policyFolders)

        # List apps and instances.
        allScores = set()
        for pol in self.policyFolders:
            polScores = glob.glob(os.path.join(pol, "App*.score"))
            for p in polScores:
                allScores.add(p.replace(pol, "@POLICY@"))
        self.appScores = list((a for a in allScores if "Instance" not in a))
        self.appNames = list((a[a.rfind("/")+7:-6] for a in self.appScores))
        self.instScores = list((a for a in allScores if "Instance" in a))
        self.instNames = list((a[a.rfind("/")+7:-6] for a in self.instScores))

        # List exclusion scores.
        exclScores = set()
        for pol in self.policyFolders:
            polScores = glob.glob(os.path.join(pol, "App*.exclscore"))
            for p in polScores:
                exclScores.add(p.replace(pol, "@POLICY@"))
        self.exclScores = list(exclScores)
        self.exclNames = list((a[a.rfind("/")+7:-6] for a in self.exclScores))

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
                             filename: str,
                             filterKey: str=None,
                             filterValues: list=[],
                             confCostDivider: int=1):
        """TODO."""
        s = dict()
        s["__VALID"] = True

        try:
            with open(filename) as f:
                content = f.readlines()
                for line in content:
                    if filterKey and line.startswith(filterKey+":"):
                        v = line[len(filterKey)+2:-1]
                        s["__VALID"] = v in filterValues
                    elif line.startswith("\t* by designation"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["by designation"] = d[0]
                    elif line.startswith("\t* file owned by app"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["file owned by app"] = d[0]
                    elif line.startswith("\t* policy-allowed"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["policy-allowed"] = d[0]
                    elif line.startswith("\t* illegal"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["illegal"] = d[0]
                    elif line.startswith("\t* configuration"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["configuration"] = d[0] / confCostDivider
                    elif line.startswith("\t* granting"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["granting"] = d[0]
                    elif line.startswith("\t* cumulative granting"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["cumulative granting"] = d[0]
                    elif line.startswith("\t* isolating"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["isolating"] = d[0]
                    elif line.startswith("\t* splitting"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["splitting"] = d[0]
                    elif line.startswith("\t* g-granting"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["g-granting"] = d[0]
                    elif line.startswith("\t* g-isolating"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["g-isolating"] = d[0]
                    elif line.startswith("\t* g-splitting"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        s["g-splitting"] = d[0]
        except (FileNotFoundError) as e:
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
            return s

        return s

    def parseClusterScores(self, filename: str):
        """TODO."""

        try:
            with open(filename) as f:
                content = f.readlines()
                for line in content:
                    if line.startswith("# of clusters violating exclusion"):
                        d = [int(s) for s in line[:-1].split(' ') if
                             s.isdigit()]
                        return d[0]

        except (FileNotFoundError) as e:
            return -1

        return -1

    def parseOEScores(self, filename: str):
        """TODO."""

        prfx = "Distribution of over-entitlements: "

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
                             polFolder: str,
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
                           polFolder: str,
                           polName: str,
                           validApps: list,
                           excludeZeroAccesses: bool=True):
        """TODO."""
        instCostDist = dict()
        instCnt = len(self.instScores)
        for (udx, uapp) in enumerate(self.instScores):
            instName = self.instNames[udx]
            desktopid = instName[:instName.find("Instance") - 3]

            if desktopid in validApps and desktopid not in plottingBlacklist:
                series = instCostDist.get(desktopid) or ([], [])
                path = uapp.replace("@POLICY@", polFolder)
                s = self.parseUsabilityScores(path,
                                              confCostDivider=instCnt)

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
        boxPlot.title = "Distribution of costs per app instance, " \
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
        for (idx, folder) in enumerate(self.policyFolders):
            clusterScores[self.policyNames[idx]] = \
                self.parseClusterScores(
                    os.path.join(folder, file))

        sortable = sortedlist(key=lambda i: -i[0])
        for (pol, s) in clusterScores.items():
            rank = s

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

        # Get usability scores for all userland apps.
        userlandScores = dict()
        for (idx, folder) in enumerate(self.policyFolders):
            userlandScores[self.policyNames[idx]] = \
                self.parseUsabilityScores(os.path.join(folder,
                                                       "UserlandApps.score"))
        self.genUsabilityCostTable(userlandScores,
                                   "UserlandApps.UsabScores.tex",
                                   "all user applications")

        for (idx, folder) in enumerate(self.policyFolders):
            polName = self.policyNames[idx]
            self.plotCostDistribution(folder,
                                      polName,
                                      userlandScores[polName])

        # Get usability scores for each app individually.
        appScores = dict()
        polAbsScores = dict()
        polRelScores = dict()
        validApps = []
        appCnt = len(self.appScores)
        for (adx, app) in enumerate(self.appScores):
            scores = dict()

            for (idx, folder) in enumerate(self.policyFolders):
                path = app.replace("@POLICY@", folder)
                s = self.parseUsabilityScores(path,
                                              filterKey="APPTYPE",
                                              filterValues=["Application"],
                                              confCostDivider=appCnt)
                if s["__VALID"] is True:
                    scores[self.policyNames[idx]] = s
                else:
                    break

            if len(scores):
                name = self.appNames[adx]
                validApps.append(name)
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

        self.plotAppCostsPerPolBoxes(polRelScores, polAbsScores)

        # Whisker plot of usability scores for each instance, per app.
        for (idx, folder) in enumerate(self.policyFolders):
            self.plotDistCostsBoxes(folder, self.policyNames[idx], validApps)

        # Plot security costs for all the policies.
        self.plotSecurityCosts(userlandScores)

        # Plot policies' exclusion list scores across whole clusters.
        self.plotClusterViolations(file="clustersPerApp.securityscore",
                                   titleTag="", tag="app")
        self.plotClusterViolations(file="clustersPerAppInstance.securityscore",
                                   titleTag=" (memoryless apps)", tag="inst")

        # Plot over-entitlement whisker boxes.
        overallOEScores = dict()
        for (adx, app) in enumerate(self.appScores):
            scores = dict()
            name = self.appNames[adx]
            if name not in validApps:
                continue

            for (idx, folder) in enumerate(self.policyFolders):
                path = app.replace("@POLICY@", folder)
                s = self.parseOEScores(path)
                scores[self.policyNames[idx]] = s

                overall = overallOEScores.get(self.policyNames[idx]) or []
                for pair in s:
                    overall.append(pair)
                overallOEScores[self.policyNames[idx]] = overall

            self.genOETable(scores, name + ".OEScores.tex", name)
            self.plotOEBoxes(scores, name)

        name = "all userland apps"
        self.genOETable(overallOEScores, name + ".OEScores.tex", name)
        self.plotOEBoxes(overallOEScores, name)
