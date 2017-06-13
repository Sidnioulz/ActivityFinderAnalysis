"""A graph representation of user document accesses by userland apps."""

from igraph import Graph, UniqueIdGenerator, plot, VertexClustering
from File import File, FileAccess
from Application import Application
from ApplicationStore import ApplicationStore
from FileStore import FileStore
from FileFactory import FileFactory
from UserConfigLoader import UserConfigLoader
from PolicyEngine import Policy
from utils import intersection, outputFsEnabled, plottingDisabled, tprnt
import itertools
import sys
import os


def applyCommunities(graph, membership, names, intersect=False):
    """Apply the communities passed as a parameter to this Graph."""
    # membership = parent.clusters.membership
    # names = parent.g.vs['name']

    members = [0] * len(membership)
    assigned = [0] * len(membership)
    maxM = 0

    for idx, n in enumerate(membership):
        members[graph.idgen[names[idx]]] = n
        assigned[graph.idgen[names[idx]]] = 1
        maxM = max(maxM, n)

    if intersect:
        oldMembership = graph.g.clusters().membership
        newMembership = members[:len(graph.g.vs)]

        uniquePairs = set(zip(oldMembership, newMembership))
        mapper = dict()
        for (i, pair) in enumerate(uniquePairs):
            mapper[pair] = i

        graph.membership = list(mapper[(oldMembership[i], e)] for i, e in enumerate(newMembership))
    else:
        graph.membership = members[:len(graph.g.vs)]

    graph.clusters = VertexClustering(graph.g, membership=graph.membership)


class CommonGraph(object):
    """A graph representation of document accesses by userland apps."""

    # Styling dictionaries.
    cd = {"file": "blue", "app": "pink", "appstate": "red"}
    sd = {"file": "circle", "app": "triangle-up", "appstate": "diamond"}

    def __init__(self, outputDir: str=None):
        """Construct a CommonGraph."""
        super(CommonGraph, self).__init__()
        self.g = None
        self.clusters = None
        self.editCount = None
        self.outputDir = outputDir or '/tmp/'
        self.printClusterInstances = False

        self.vertices = dict()
        self.edges = set()
        self.weights = dict()
        self.instances = dict()

    def _addFileNode(self, f: File):
        """Add a File vertex to the graph."""
        # Add a vertex for the file.
        self.vertices[str(f.inode)] = "file"

    def _addAppNode(self, app: Application):
        """Add an Application vertex to the graph."""
        raise NotImplementedError
        # self.weights[(app.desktopid, app.uid())] = 0

    def _addAccess(self, f: File, acc: FileAccess):
        """Add a FileAccess edge to the graph."""
        raise NotImplementedError

    def populate(self, policy: Policy=None, quiet: bool=False):
        """Populate the AccessGraph, filtering it based on a Policy."""
        appStore = ApplicationStore.get()
        fileStore = FileStore.get()
        fileFactory = FileFactory.get()
        userConf = UserConfigLoader.get()

        # Add all user apps.
        if not quiet:
            tprnt("\t\tAdding apps...")
        for app in appStore:
            if app.isUserlandApp():
                self._addAppNode(app)

        def _allowed(policy, f, acc):
            return acc.actor.isUserlandApp() and \
                (acc.isByDesignation() or not policy or
                 policy.allowedByPolicy(f, acc.actor))

        # Add all user documents.
        if not quiet:
            tprnt("\t\tAdding user documents...")
        for f in fileStore:
            if not f.isUserDocument(userHome=userConf.getHomeDir(),
                                    allowHiddenFiles=True):
                continue
            if f.isFolder():
                continue

            # Provided they have userland apps accessing them.
            hasUserlandAccesses = False
            for acc in f.getAccesses():
                if _allowed(policy, f, acc):
                    hasUserlandAccesses = True
                    break

            # And then add such userland apps to user document accesses.
            if hasUserlandAccesses:
                self._addFileNode(f)
                for acc in f.getAccesses():
                    if _allowed(policy, f, acc):
                        self._addAccess(f, acc)

        if not quiet:
            tprnt("\t\tAdding file links...")
        links = fileFactory.getFileLinks()
        for (pred, follow) in links.items():
            source = str(pred.inode)
            dest = str(follow)
            if source in self.vertices and dest in self.vertices:
                tprnt("Info: adding link from File %s to File %s in graph "
                      "as there is a file move/copy event between those." % (
                       source, dest))
                edge = (source, dest) if source <= dest else (dest, source)
                self.edges.add(edge)
                self.weights[edge] = 999999999

        if not quiet:
            tprnt("\t\tConstructing graph...")
        self._construct()

    def _linkInstances(self):
        """Link application instance vertices together."""
        raise NotImplementedError

    def _construct(self):
        """Construct the graph after it was populated."""
        self.g = None
        self.idgen = UniqueIdGenerator()

        self._linkInstances()

        edgelist = [(self.idgen[s], self.idgen[d]) for s, d in self.edges]
        self.g = Graph(edgelist)
        del edgelist
        self.g.es["weight"] = list((self.weights[e] for e in self.edges))
        del self.edges
        self.g.vs["name"] = self.idgen.values()
        self.g.vs["type"] = list((self.vertices[n] for n in self.g.vs["name"]))
        del self.vertices

    def computeClusters(self):
        """Compute the clusters for this graph."""
        comm = self.g.community_fastgreedy(weights=self.g.es["weight"])
        self.clusters = comm.as_clustering()

    def plot(self, output: str=None):
        """Plot the graph and its communities to an output file."""

        # Get style options set for the base graph plot.
        vs = {}
        vs["vertex_size"] = 5
        vs["vertex_color"] = [CommonGraph.cd[t] for t in self.g.vs["type"]]
        vs["vertex_shape"] = [CommonGraph.sd[t] for t in self.g.vs["type"]]
        labels = list(self.g.vs["name"])
        for (idx, label) in enumerate(labels):
            if self.g.vs["type"][idx] not in ("file", "appstate"):
                labels[idx] = None
        vs["vertex_label"] = labels
        vs["edge_width"] = [.5 * (1+int(c)) for c in self.g.es["weight"]]
        vs["layout"] = self.g.layout("fr")
        vs["bbox"] = (2400, 1600)
        vs["margin"] = 20

        # Plot the base graph.
        try:
            if output:
                path = self.outputDir + "/" + output + ".graph.svg"
                plot(self.g, path, **vs)
            else:
                plot(self.g, **vs)
        except(OSError) as e:
            print("Error while plotting to %s: %s " % (
                  self.outputDir + "/" + output + ".graph.svg",
                  e))
        except(MemoryError) as e:
            print("Error (MemoryError) while plotting to %s: %s " % (
                  self.outputDir + "/" + output + ".graph.svg",
                  e))

    def plotClusters(self, output: str=None):
        # Plot the base graph with colours based on the communities.
        vs = {}
        vs["vertex_size"] = 5
        vs["vertex_shape"] = [CommonGraph.sd[t] for t in self.g.vs["type"]]
        vs["layout"] = self.g.layout("fr")
        vs["bbox"] = (2400, 1600)
        vs["margin"] = 20
        vs["vertex_color"] = self.clusters.membership
        edge_widths = []
        for (s, d) in self.g.get_edgelist():
            if self.clusters.membership[s] == self.clusters.membership[d]:
                edge_widths.append(1)
            else:
                edge_widths.append(3)
        vs["edge_width"] = edge_widths

        # Only keep labels for community-bridging vertices.
        minimal_labels = list(self.g.vs["name"])
        for (idx, label) in enumerate(minimal_labels):
            if self.g.vs["type"][idx] not in ("file", "appstate") and not \
                    self.printClusterInstances:
                minimal_labels[idx] = None
                continue

            for neighbour in self.g.neighbors(label):
                if self.clusters.membership[neighbour] != \
                        self.clusters.membership[idx]:
                    break
            else:
                minimal_labels[idx] = None

        vs["vertex_label"] = minimal_labels

        try:
            if output:
                path = self.outputDir + "/" + output + ".clusters.svg"
                plot(self.clusters, path, **vs)
            else:
                plot(self.clusters, **vs)
        except(OSError) as e:
            print("Error while plotting to %s: %s " % (
                  self.outputDir + "/" + output + ".clusters.svg",
                  e))
        except(MemoryError) as e:
            print("Error (MemoryError) while plotting to %s: %s " % (
                  self.outputDir + "/" + output + ".graph.svg",
                  e))

    def calculateCosts(self,
                       output: str=None,
                       quiet: bool=False,
                       policy: Policy=None):
        """Model the usability costs needed to reach found communities."""
        if not self.clusters:
            raise ValueError("Clusters for a graph must be computed "
                             "before calculating its cost.")

        msg = ""
        appStore = ApplicationStore.get()

        crossing = self.clusters.crossing()
        grantingCost = 0
        isolationCost = 0
        splittingCost = 0
        for (index, x) in enumerate(crossing):
            if not x:
                continue

            edge = self.g.es[index]
            source = self.g.vs[edge.source]
            target = self.g.vs[edge.target]
            sourceType = source.attributes()['type']
            targetType = target.attributes()['type']
            sourceName = source.attributes()['name']
            targetName = target.attributes()['name']

            # Case where a file-file node was removed. Should normally not
            # happen so we will not write support for it yet.
            if sourceType == "file":
                if targetType == "app":
                    grantingCost += 1
                    if policy:
                        app = appStore.lookupUid(targetName)
                        policy.incrementScore('graphGrantingCost',
                                              None, app)
                else:
                    # Check if an app co-accessed the files. If so, increase the
                    # cost of splitting that app instance into two.
                    sAccessors = []
                    for n in source.neighbors():
                        if n.attributes()['type'] == 'app':
                            sAccessors.append(n)
                    tAccessors = []
                    for n in target.neighbors():
                        if n.attributes()['type'] == 'app':
                            tAccessors.append(n)

                    inter = intersection(sAccessors, tAccessors)

                    for i in inter:
                        splittingCost += 1
                        if policy:
                            app = appStore.lookupUid(sourceName)
                            policy.incrementScore('graphSplittingCost',
                                                  None, app)
                    if not inter:
                        print("Warning: file-file node removed by graph "
                              "community finding algorithm. Not supported.",
                              file=sys.stderr)
                        print(source, target)
                        raise NotImplementedError
            elif targetType == "file":  # sourceType in "app", "appstate"
                grantingCost += 1
                if sourceType == "app" and policy:
                    app = appStore.lookupUid(sourceName)
                    policy.incrementScore('graphGrantingCost',
                                          None, app)
                elif policy:
                    policy.incrementScore('graphGranting', None, None)
            else:
                # app-app links are just noise in the UnifiedGraph
                if sourceType != "app" and targetType == "app":
                    isolationCost += 1
                    if policy:
                        app = appStore.lookupUid(targetName)
                        policy.incrementScore('graphIsolationCost',
                                              None, app)
                elif sourceType == "app" and targetType != "app":
                    isolationCost += 1
                    if policy:
                        app = appStore.lookupUid(sourceName)
                        policy.incrementScore('graphIsolationCost',
                                              None, app)

        editCount = grantingCost+isolationCost+splittingCost
        msg += ("%d edits performed: %d apps isolated, %d apps split and "
                "%d accesses revoked.\n" % (
                 editCount,
                 isolationCost,
                 splittingCost,
                 grantingCost))

        if not quiet:
            tprnt(msg)

        if output:
            path = self.outputDir + "/" + output + ".graphstats.txt"
            os.makedirs(File.getParentNameFromName(path),
                        exist_ok=True)
            with open(path, "w") as f:
                print(msg, file=f)

        self.editCount = editCount

    def calculateReachability(self, output: str=None, quiet: bool=False):
        """Model the reachability improvement of community finding."""
        if self.clusters is None:
            raise ValueError("Clusters for a graph must be computed "
                             "before modelling how community isolation "
                             "decreases its average reachability.")
        if self.editCount is None:
            raise ValueError("Costs for a graph must be calculated "
                             "before modelling how community isolation "
                             "decreases its average reachability.")

        msg = ""

        def _print(clusters, header, tag):
            msg = "\nGraph statistics %s:\n" % header

            if len(clusters) == 0:
                msg += "no clusters for this graph."
                return (msg, 0, 1)

            sizes = [x for x in sorted(list((len(x) for x in clusters)))
                     if x != 0]
            msg += ("* %s-size distribution: %s\n" % (tag,
                                                      sizes.__str__()))
            msg += ("* %s-cluster count: %d\n" % (tag, len(sizes)))
            msg += ("* %s-smallest cluster: %d\n" % (tag, min(sizes)))
            msg += ("* %s-largest cluster: %d\n" % (tag, max(sizes)))
            avgSize = sum(sizes) / len(sizes)
            msg += ("* %s-average size: %f\n" % (tag, avgSize))
            vertexSum = sum(sizes)
            reach = sum([i ** 2 for i in sizes]) / vertexSum
            msg += ("* %s-average reachability: %f\n" % (tag, reach))

            return (msg, avgSize, reach)

        def _printAndSum(g, editCount, tagPrefix=None):
            msg = "\n"

            preTag = tagPrefix+"-pre" if tagPrefix else "pre"
            _m, avgPreSize, preReach = _print(g.g.clusters(),
                                              "pre community finding",
                                              preTag)
            msg += _m

            postTag = tagPrefix+"-post" if tagPrefix else "post"
            _m, avgPostSize, postReach = _print(g.clusters,
                                                "post community finding",
                                                postTag)
            msg += _m

            if avgPreSize:
                deltaSize = 1 - (avgPostSize / avgPreSize)
                sizeEfficiency = deltaSize / editCount if editCount else 1
                msg += "\nEvol. of avg. cluster size: {:.2%}\n".format(deltaSize)
                msg += ("Efficiency of edits wrt. average size: %f\n" %
                        sizeEfficiency)
            else:
                msg += "\nEvol. of avg. cluster size: N/A\n"

            if preReach:
                deltaReach = 1 - (postReach / preReach)
                reachEfficiency = deltaReach / editCount if editCount else 1
                msg += "\nEvol. of reachability: {:.2%}\n".format(deltaReach)
                msg += ("Efficiency of edits wrt. reachability: %f\n" %
                        reachEfficiency)
            else:
                msg += "\nEvol. of reachability: N/A\n"

            return msg

        if not quiet:
            tprnt("\t\tPrinting statistics on whole graph...")
        msg += _printAndSum(self, self.editCount)

        if not quiet:
            tprnt("\t\tBuilding flat file graph...")
        fg = FlatGraph(parent=self, quiet=quiet)
        if not plottingDisabled():
          if not quiet:
              tprnt("\t\tPlotting flat file graph...")
          fg.plot(output=output)
        if not quiet:
            tprnt("\t\tPrinting statistics on flat file graph...")
        msg += _printAndSum(fg, self.editCount, tagPrefix="flat")

        if not quiet:
            tprnt(msg)

        if output:
            path = self.outputDir + "/" + output + ".graphstats.txt"
            os.makedirs(File.getParentNameFromName(path),
                        exist_ok=True)
            with open(path, "a") as f:
                print(msg, file=f)


class FlatGraph(object):
    """An internal class for graph flattening."""

    def __init__(self, parent: CommonGraph, quiet: bool=False):
        """Construct a FlatGraph."""
        super(FlatGraph, self).__init__()
        if not isinstance(parent, CommonGraph):
            raise TypeError("FlatGraph constructor needs a CommonGraph "
                            "parent, received a %s." %
                            parent.__class__.__name__)

        self.g = None
        self.clusters = None
        self.outputDir = parent.outputDir
        self.vertices = dict()
        self.edges = set()
        self.weights = dict()

        # Step 1. make a copy of the graph without file-file nodes, to
        # find paths between files that go through apps.
        if not quiet:
            tprnt("\t\t\tStep 1: copy graph, excluding file-file nodes...")
            tprnt("\t\t\t\tCopy graph...")
        copy = parent.g.copy()  # type: Graph
        types = parent.g.vs['type']
        names = parent.g.vs['name']
        toBeRemoved = []
        namesRemoved = []
        if not quiet:
            tprnt("\t\t\t\tFind edges to delete...")
        for edge in copy.es:
            if types[edge.source] == "file" and \
                    types[edge.target] == "file":
                toBeRemoved.append(edge)
                namesRemoved.append((names[edge.source],
                                     names[edge.target]))

        if not quiet:
            tprnt("\t\t\t\tDelete edges...")
        copy.delete_edges(toBeRemoved)

        # Step 2. run an all-pairs shortest path algorithm.
        # Step 2. pick out file-file paths with no intermediary files.
        # Step 2. save this info in the form of an edge list.
        if not quiet:
            tprnt("\t\t\tStep 2: run an all-pairs shortest path "
                  "algorithm, remove file-file paths with intermediary "
                  "files and gather final file-file edges...")
            tprnt("\t\t\t\tCopy file nodes...")
        fileNodes = list((copy.vs[i] for i, t in enumerate(types) if
                          t == "file"))

        edges = set()
        # weights = dict()
        self.idgen = UniqueIdGenerator()

        fileNodeCount = len(fileNodes)
        if not quiet:
            tprnt("\t\t\t\tGet shortest paths for each of %d file nodes..." %
                   fileNodeCount)
        threshold = int(fileNodeCount / 100)
        nodeI = 0
        nodePct = 0
        for v in fileNodes:
            nodeI += 1
            if nodeI == threshold:
                nodeI = 0
                nodePct += 1
                print("\t\t\t\t\t... (%d%% done)" % nodePct)

            # Get shortest paths.
            vPaths = copy.get_shortest_paths(v, to=fileNodes)

            # Remove unnecessary bits.
            delSet = set()
            for (idx, p) in enumerate(vPaths):
                if len(p) < 1:
                    continue

                # Ignore paths with intermediary files.
                for node in p[1:-1]:
                    if types[node] == "file":
                        delSet.add(idx)

            # Remove unsuitable paths.
            for i in sorted(list(delSet), reverse=True):
                del vPaths[i]
            del delSet

            # Save the shortest paths remaining as edges.
            for p in vPaths:
                if len(p) <= 1:
                    continue
                key = (self.idgen[names[p[0]]], self.idgen[names[p[-1]]])
                edges.add(key)
                # weights[key] = 1 / (len(p) - 1)

        # Add edges for removed names
        if not quiet:
            tprnt("\t\t\t\tRe-add file-file direct nodes into graph...")
        for (src, dest) in namesRemoved:
            edges.add((self.idgen[src], self.idgen[dest]))

        # Step 3. construct a graph with only file nodes.
        if not quiet:
            tprnt("\t\t\tStep 3: construct a graph with only file nodes...")
        edges = list(edges)
        self.g = Graph(edges)
        del edges
        # self.g.es["weight"] = list((weights[e] for e in edges))
        self.g.vs["name"] = self.idgen.values()

        # Steph 4. apply community information to the nodes.
        if not quiet:
            tprnt("\t\t\tStep 4: apply communities to flat graph...")
        applyCommunities(self, parent.clusters.membership, names)

    def plot(self, output: str=None):
        """Plot the graph and its communities to an output file."""

        # Get style options set for the base graph plot.
        vs = {}
        vs["vertex_size"] = 5
        vs["vertex_shape"] = "circle"
        vs["layout"] = self.g.layout("fr")
        vs["bbox"] = (2400, 1600)
        vs["margin"] = 20

        # Plot the base graph with colours based on the communities.
        vs["vertex_color"] = self.membership
        edge_widths = []
        for (s, d) in self.g.get_edgelist():
            if self.membership[s] == self.membership[d]:
                edge_widths.append(1)
            else:
                edge_widths.append(3)
        vs["edge_width"] = edge_widths

        # Only keep labels for community-bridging vertices.
        minimal_labels = list(self.g.vs["name"])
        for (idx, label) in enumerate(minimal_labels):
            for neighbour in self.g.neighbors(label):
                if self.membership[neighbour] != self.membership[idx]:
                    break
            else:
                minimal_labels[idx] = None

        vs["vertex_label"] = minimal_labels

        try:
            if output:
                path = self.outputDir + "/" + output + ".flat.svg"
                plot(self.clusters, path, **vs)
            else:
                plot(self.clusters, **vs)
        except(OSError) as e:
            print("Error while plotting to %s: %s " % (
                  self.outputDir + "/" + output + ".flat.svg",
                  e))


class AccessGraph(CommonGraph):
    """A graph modelling accesses for individual Applications."""

    def __init__(self, outputDir: str=None):
        """Construct an AccessGraph."""
        super(AccessGraph, self).__init__(outputDir)

    def _addAppNode(self, app: Application):
        """Add an Application vertex to the graph."""
        # Add a vertex for the app.
        self.vertices[app.uid()] = "app"

        # Remember instances of an app so we can connect them.
        inst = self.instances.get(app.desktopid) or []
        inst.append(app.uid())
        self.instances[app.desktopid] = inst

        # Ensure there is a node modelling the app's state.
        self.vertices[app.desktopid] = "appstate"
        self.edges.add((app.desktopid, app.uid()))
        self.weights[(app.desktopid, app.uid())] = 1

    def _addAccess(self, f: File, acc: FileAccess):
        """Add a FileAccess edge to the graph."""
        # Get the source and destination vertex ids.
        source = acc.actor.uid()
        dest = str(f.inode)

        # Add the edge, and count a single access (unweighted clustering).
        self.edges.add((source, dest))
        self.weights[(source, dest)] = 1

    def _linkInstances(self):
        """Link application instance vertices together."""
        for (app, insts) in self.instances.items():
            edges = list(itertools.combinations(insts, 2))
            for edge in edges:
                self.edges.add(edge)
                self.weights[edge] = 1


class ActivityGraph(CommonGraph):
    """A graph modelling co-accessed files for overall Applications."""

    # TODO ensure we link files co-accessed by an instance. and then we can see
    # if diff instances access diff files. also show number of instances who
    # accessed using edge thickness / weight

    def __init__(self, outputDir: str=None):
        """Construct an ActivityGraph."""
        super(ActivityGraph, self).__init__(outputDir)
        self.instancesPerFile = dict()

    def _addAppNode(self, app: Application):
        """Add an Application vertex to the graph."""
        self.vertices[app.desktopid] = "appstate"

    def _addAccess(self, f: File, acc: FileAccess):
        """Add a FileAccess edge to the graph."""
        # Get the source and destination vertex ids.
        source = acc.actor.desktopid
        dest = str(f.inode)

        # Add the edge.
        self.edges.add((source, dest))

        # Calculate the number of individual instances who accessed the file.
        insts = self.instancesPerFile.get(source+dest) or set()
        insts.add(acc.actor.uid())
        self.instancesPerFile[source+dest] = insts
        self.weights[(source, dest)] = len(insts)

    def _linkInstances(self):
        """Link application instance vertices together."""
        pass


class InstanceGraph(CommonGraph):
    """A graph modelling communities where instances are disjoint."""

    def __init__(self, outputDir: str=None):
        """Construct an ActivityGraph."""
        super(InstanceGraph, self).__init__(outputDir)
        self.filesPerInstance = dict()
        self.printClusterInstances = True

    def _addAppNode(self, app: Application):
        """Add an Application vertex to the graph."""
        # Add a vertex for the app.
        self.vertices[app.uid()] = "app"

        # Remember instances of an app so we can connect them.
        inst = self.instances.get(app.desktopid) or []
        inst.append(app.uid())
        self.instances[app.desktopid] = inst

        # Ensure there is a node modelling the app's state.
        self.vertices[app.desktopid] = "appstate"
        self.edges.add((app.desktopid, app.uid()))
        self.weights[(app.desktopid, app.uid())] = 0.0000000001

    def _addAccess(self, f: File, acc: FileAccess):
        """Add a FileAccess edge to the graph."""
        # Get the source and destination vertex ids.
        source = acc.actor.uid()
        dest = str(f.inode)

        # Add the edge.
        self.edges.add((source, dest))
        self.weights[(source, dest)] = 1

        # Collect the individual files accessed by every instance.
        insts = self.filesPerInstance.get(source) or set()
        insts.add(str(f.inode))
        self.filesPerInstance[source] = insts

    def _linkInstances(self):
        """Link file vertices of an instance together."""
        filePairs = dict()

        for (source, files) in self.filesPerInstance.items():
            # We'll have duplicate edges in the edges set (e.g. 6->4 and 4->6)
            # if we don't sort inodes prior to listing inode pairs.
            edges = list(itertools.combinations(sorted(files), 2))
            for edge in edges:
                cnt = filePairs.get(edge) or 0
                filePairs[edge] = cnt+1

        for (pair, count) in filePairs.items():
            self.edges.add(pair)
            self.weights[pair] = count


class UnifiedGraph(CommonGraph):
    """A graph modelling accesses for individual Applications."""

    def __init__(self, outputDir: str=None):
        """Construct an UnifiedGraph."""
        super(UnifiedGraph, self).__init__(outputDir)
        self.filesPerInstance = dict()

    def _addAppNode(self, app: Application):
        """Add an Application vertex to the graph."""
        # Add a vertex for the app.
        self.vertices[app.uid()] = "app"

        # Remember instances of an app so we can connect them.
        inst = self.instances.get(app.desktopid) or []
        inst.append(app.uid())
        self.instances[app.desktopid] = inst

        # Ensure there is a node modelling the app's state.
        self.vertices[app.desktopid] = "appstate"
        self.edges.add((app.desktopid, app.uid()))
        self.weights[(app.desktopid, app.uid())] = 1

    def _addAccess(self, f: File, acc: FileAccess):
        """Add a FileAccess edge to the graph."""
        # Get the source and destination vertex ids.
        source = acc.actor.uid()
        dest = str(f.inode)

        self.edges.add((source, dest))
        self.weights[(source, dest)] = 1

        # Collect the individual files accessed by every instance.
        insts = self.filesPerInstance.get(source) or set()
        insts.add(str(f.inode))
        self.filesPerInstance[source] = insts

    def _linkInstances(self):
        """Link application instance vertices together."""
        for (app, insts) in self.instances.items():
            weight = 0.1 / len(insts)
            edges = list(itertools.combinations(insts, 2))
            for (s, d) in edges:
                edge = (s, d) if s <= d else (d, s)
                self.edges.add(edge)
                self.weights[edge] = weight

        filePairs = dict()
        for (source, files) in self.filesPerInstance.items():
            # We'll have duplicate edges in the edges set (e.g. 6->4 and 4->6)
            # if we don't sort inodes prior to listing inode pairs.
            edges = list(itertools.combinations(sorted(files), 2))
            for edge in edges:
                cnt = filePairs.get(edge) or 0
                filePairs[edge] = cnt+1

        for ((s, d), count) in filePairs.items():
            pair = (s, d) if s <= d else (d, s)
            self.edges.add(pair)
            self.weights[pair] = count  # FIXME 999999999?


class GraphEngine(object):
    """An engine for creating graphs given a file AC policy."""

    __engine = None

    @staticmethod
    def get():
        """Return the GraphEngine for the entire application."""
        if GraphEngine.__engine is None:
            GraphEngine.__engine = GraphEngine()
        return GraphEngine.__engine

    @staticmethod
    def reset():
        GraphEngine.__engine = None

    def __init__(self):
        """Construct a GraphEngine."""
        super(GraphEngine, self).__init__()
        self.globMembership = None
        self.globNames = None

    def runGraph(self,
                 policy: Policy=None,
                 outputDir: str=None,
                 quiet: bool=False):
        """Build a graph of IFs in the simulation given a policy."""
        outputDir = policy.getOutputDir(parent=outputFsEnabled()) if \
            policy else outputFsEnabled()

        if not quiet:
            tprnt("\nCompiling the Unified Graph...")
        if not quiet:
            tprnt("\tMaking graph...")
        g = UnifiedGraph(outputDir=outputDir)
        if not quiet:
            tprnt("\tPopulating graph...")
        g.populate(policy=policy, quiet=quiet)
        output = policy.name+"-graph-unified" if policy else \
            "graph-unified"
        if not plottingDisabled():
          if not quiet:
              tprnt("\tPlotting graph...")
          g.plot(output=output)
        if not quiet:
            tprnt("\tComputing community clusters...")
        if not policy:
            g.computeClusters()
            self.globMembership = g.clusters.membership
            self.globNames = g.g.vs['name']
        else:
            if not self.globMembership:
                if not quiet:
                    tprnt("\t\tWarning: cannot re-use global communities as "
                          "they aren't computed yet, computing local ones "
                          "instead.")
                g.computeClusters()
            else:
                if not quiet:
                    tprnt("\t\tUsing global community memberships to refine "
                          "clusters.")
                applyCommunities(g, self.globMembership, self.globNames, True)
        if not plottingDisabled():
          if not quiet:
              tprnt("\tPlotting communities...")
          g.plotClusters(output=output)
        if not quiet:
            tprnt("\tCalculating costs to optimal communities...")
        g.calculateCosts(output=output, policy=policy, quiet=quiet)
        if not quiet:
            tprnt("\tCalculating potential reachability improvement...")
        g.calculateReachability(output=output, quiet=quiet)
        if not quiet:
            tprnt("Done.")
