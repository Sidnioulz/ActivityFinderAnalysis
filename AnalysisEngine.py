"""An engine that produces graphs and statistics for a prior analysis."""
from blist import sortedlist
import glob
import os
import shutil
import pygal

plottingBlacklist = ['apt-get', 'cairo-dock', 'dbus-send', 'dpkg', 'gdb',
                     'gst-plugin-scanner', 'helper-dialog', 'indicator-applet',
                     'inictl', 'java', 'killall5', 'light-locker', 'mono-sgen',
                     'nm-applet', 'obex-data-server', 'ubuntu-sso-login',
                     'polkit-gnome-authentication-agent-1', 'upower',
                     'xfce4-display-settings', 'xfce4-taskmanager',
                     'xfwm4-settings']


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

    def genUsabilityCostTable(self, costs: dict, filename: str):
        """TODO."""
        msg = "\\begin{table}\n" \
              "  \\begin{tabular}{rlllll}\n" \
              "  \\cmidrule[\\heavyrulewidth]{2-5}\n" \
              "  \\tabhead{Policy}&\\tabhead{Config}&\\multicolumn{2}{l}" \
              "{\\tabhead{Granting}}&\\tabhead{Isolating}&" \
              "\\tabhead{Splitting}&\\tabhead{Total} \\\\\n" \
              "  \\cmidrule{2-5}\n"

        for pol, costs in costs.items():
            cSum = costs["configuration"] + costs["granting"] + \
                   costs["isolating"] + costs["splitting"]
            msg += "  %s&%d&%d&{\\small (%d)}&%d&%d&%d \\\\\n" % (
                pol,
                costs["configuration"],
                costs["granting"],
                costs["cumulative granting"],
                costs["isolating"],
                costs["splitting"],
                cSum)

        msg += "  \\cmidrule[\\heavyrulewidth]{2-5}\n" \
               "  \\end{tabular}\n" \
               "  \\caption{Usability costs of each policy for all user " \
               "applications.}\\label{table:userland-usability-costs}\n" \
               "\\end{table}\n"

        with open(os.path.join(self.outputDir, filename), 'a') as f:
            print(msg, file=f)

        return msg

    def parseUsabilityScores(self,
                             filename: str,
                             filterKey: str=None,
                             filterValues: list=[]):
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
                        s["configuration"] = d[0]
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

    def plotDistCostsBoxes(self,
                           polFolder: str,
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
                path = uapp.replace("@POLICY@", polFolder)
                s = self.parseUsabilityScores(path)

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
                        "for each app - %s Policy" % polName
        boxPlotAvg = pygal.Box(box_mode="tukey")
        boxPlotAvg.title = "Distribution of average cost per access per app " \
                           "instance, for each app - %s Policy" % polName
        for (desktopid, series) in sorted(instCostDist.items()):
            ratios = list((series[0][i] / series[1][i] if series[1][i] else 0
                           for (i, __) in enumerate(series[0])))
            boxPlot.add(desktopid, series[0])
            boxPlotAvg.add(desktopid, ratios)

        boxPlot.render_to_file(os.path.join(self.outputDir,
                                            'instCostDist-%s.svg' % polName))
        boxPlotAvg.render_to_file(os.path.join(self.outputDir, 'instCostDist-'
                                               'normalised-%s.svg' % polName))

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
        lineChartS.title = 'Security costs per policy'

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

    def analyse(self):
        """Perform the post-analysis."""

        # Get usability scores for all userland apps.
        userlandScores = dict()
        for (idx, folder) in enumerate(self.policyFolders):
            userlandScores[self.policyNames[idx]] = \
                self.parseUsabilityScores(os.path.join(folder,
                                                       "UserlandApps.score"))
        self.genUsabilityCostTable(userlandScores,
                                   "UserlandApps.UsabScores.tex")

        # Get usability scores for each app individually.
        appScores = dict()
        validApps = []
        for (adx, app) in enumerate(self.appScores):
            scores = dict()

            for (idx, folder) in enumerate(self.policyFolders):
                path = app.replace("@POLICY@", folder)
                s = self.parseUsabilityScores(path,
                                              filterKey="APPTYPE",
                                              filterValues=["Application"])
                if s["__VALID"] is True:
                    scores[self.policyNames[idx]] = s
                else:
                    break

            if len(scores):
                validApps.append(self.appNames[adx])
                self.genUsabilityCostTable(scores,
                                           self.appNames[adx] +
                                           ".UsabScores.tex")
            appScores[app] = scores

        # Whisker plot of usability scores for each instance, per app.
        for (idx, folder) in enumerate(self.policyFolders):
            self.plotDistCostsBoxes(folder, self.policyNames[idx], validApps)

        # Plot security costs for all the policies.
        self.plotSecurityCosts(userlandScores)
