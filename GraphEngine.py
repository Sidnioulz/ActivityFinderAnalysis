"""A graph representation of user document accesses by userland apps."""

from igraph import Graph, UniqueIdGenerator, plot, VertexClustering
from File import File, FileAccess
from Application import Application
from ApplicationStore import ApplicationStore
from FileStore import FileStore
from FileFactory import FileFactory
from UserConfigLoader import UserConfigLoader
from PolicyEngine import Policy
from utils import intersection, outputFsEnabled
import itertools
import sys
import os


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

    def populate(self, policy: Policy=None):
        """Populate the AccessGraph, filtering it based on a Policy."""
        appStore = ApplicationStore.get()
        fileStore = FileStore.get()
        fileFactory = FileFactory.get()
        userConf = UserConfigLoader.get()

        # Add all user apps.
        for app in appStore:
            if app.isUserlandApp():
                self._addAppNode(app)

        def _allowed(policy, f, acc):
            return acc.actor.isUserlandApp() and \
                (acc.isByDesignation() or not policy or
                 policy.allowedByPolicy(f, acc.actor))

        # Add all user documents.
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

        links = fileFactory.getFileLinks()
        for (pred, follow) in links.items():
            source = str(pred)
            dest = str(follow)
            if source in self.vertices and dest in self.vertices:
                print("Info: adding link from File %s to File %s in graph "
                      "as there is a file move/copy event between those." % (
                       source, dest))
                self.edges.add((source, dest))
                self.weights[(source, dest)] = 9999

        self._construct()

    def _linkInstances(self):
        """Link application instance vertices together."""
        raise NotImplementedError

    def _construct(self):
        """Construct the graph after it was populated."""
        self.g = None
        idgen = UniqueIdGenerator()

        self._linkInstances()

        edgelist = [(idgen[s], idgen[d]) for s, d in self.edges]
        self.g = Graph(edgelist)
        self.g.es["weight"] = list((self.weights[e] for e in self.edges))
        self.g.vs["name"] = idgen.values()
        self.g.vs["type"] = list((self.vertices[n] for n in self.g.vs["name"]))

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
            if self.vertices[label] not in ("file", "appstate"):
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

        # Detect communities in the graph.
        self.computeClusters()

        # Plot the base graph with colours based on the communities.
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
            if self.vertices[label] not in ("file", "appstate") and not \
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
            print(msg)

        if output:
            path = self.outputDir + "/" + output + ".graphstats.txt"
            os.makedirs(File.getParentNameFromName(path),
                        exist_ok=True)
            with open(path, "a") as f:
                print(msg, file=f)

        self.editCount = editCount

    def calculateReachability(self, output: str=None, quiet: bool=False):
        """Model the reachability improvement of community finding."""
        if not self.clusters:
            raise ValueError("Clusters for a graph must be computed "
                             "before modelling how community isolation "
                             "decreases its average reachability.")
        if not self.editCount:
            raise ValueError("Costs for a graph must be calculated "
                             "before modelling how community isolation "
                             "decreases its average reachability.")

        msg = ""

        def _print(clusters, header, tag):
            msg = "\nGraph statistics %s:\n" % header
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

            deltaSize = 1 - (avgPostSize / avgPreSize)
            sizeEfficiency = deltaSize / editCount
            msg += "\nEvol. of avg. cluster size: {:.2%}\n".format(deltaSize)
            msg += ("Efficiency of edits wrt. average size: %f\n" %
                    sizeEfficiency)

            deltaReach = 1 - (postReach / preReach)
            reachEfficiency = deltaReach / editCount
            msg += "\nEvol. of reachability: {:.2%}\n".format(deltaReach)
            msg += ("Efficiency of edits wrt. reachability: %f\n" %
                    reachEfficiency)

            return msg

        msg += _printAndSum(self, self.editCount)

        fg = FlatGraph(parent=self)
        fg.plot(output=output)
        msg += _printAndSum(fg, self.editCount, tagPrefix="flat")

        if not quiet:
            print(msg)

        if output:
            path = self.outputDir + "/" + output + ".graphstats.txt"
            os.makedirs(File.getParentNameFromName(path),
                        exist_ok=True)
            with open(path, "a") as f:
                print(msg, file=f)


class FlatGraph(object):
    """An internal class for graph flattening."""

    def __init__(self, parent: CommonGraph):
        """Construct a FlatGraph."""
        super(FlatGraph, self).__init__()
        if not isinstance(parent, CommonGraph):
            raise TypeError("FlatGraph constructor needs a CommonGraph "
                            "parent, received a %s." %
                            parent.__class__.__name__)

        self.g = None
        self.outputDir = parent.outputDir
        self.vertices = dict()
        self.edges = set()
        self.weights = dict()

        # Step 1. make a copy of the graph without file-file nodes, to
        # find paths between files that go through apps.
        copy = parent.g.copy()  # type: Graph
        types = parent.g.vs['type']
        names = parent.g.vs['name']
        toBeRemoved = []
        namesRemoved = []
        for edge in copy.es:
            if types[edge.source] == "file" and \
                    types[edge.target] == "file":
                toBeRemoved.append(edge)
                namesRemoved.append((names[edge.source],
                                     names[edge.target]))

        copy.delete_edges(toBeRemoved)

        # Step 2. run an all-pairs shortest path algorithm.
        fileNodes = list((copy.vs[i] for i, t in enumerate(types) if
                          t == "file"))

        shortestPaths = dict()
        for v in fileNodes:
            shortestPaths[v] = copy.get_shortest_paths(v, to=fileNodes)

        # Step 3. pick out file-file paths with no intermediary files.
        for (v, vPaths) in shortestPaths.items():
            delList = []
            for (idx, p) in enumerate(vPaths):
                if len(p) < 1:
                    continue

                # Ignore paths with intermediary files.
                for node in p[1:-1]:
                    if types[node] == "file":
                        delList.append(idx)

            # Remove unsuitable paths.
            for i in sorted(delList, reverse=True):
                del vPaths[i]
            shortestPaths[v] = vPaths

        # Step 4. construct a graph with only file nodes.
        # First, gather the edges.
        edges = []
        weights = dict()
        idgen = UniqueIdGenerator()

        for (v, vPaths) in shortestPaths.items():
            for p in vPaths:
                if len(p) <= 1:
                    continue
                key = (names[p[0]], names[p[-1]])
                edges.append(key)
                weights[key] = 1 / (len(p) - 1)

        for edge in namesRemoved:
            edges.append(edge)
            weights[edge] = 1

        # Next, build the graph.
        edgelist = [(idgen[s], idgen[d]) for s, d in edges]
        self.g = Graph(edgelist)
        self.g.es["weight"] = list((weights[e] for e in edges))
        self.g.vs["name"] = idgen.values()

        # Steph 5. apply community information to the nodes.
        parentMembers = parent.clusters.membership
        members = [0] * len(parentMembers)
        assigned = [0] * len(parentMembers)
        for idx, n in enumerate(parentMembers):
            members[idgen[names[idx]]] = n
            assigned[idgen[names[idx]]] = 1
        self.membership = members[:len(self.g.vs)]
        self.clusters = VertexClustering(self.g,
                                         membership=self.membership)

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
        print(len(self.membership), len(self.g.vs))
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
            for edge in edges:
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

        for (pair, count) in filePairs.items():
            self.edges.add(pair)
            self.weights[pair] = count


class GraphEngine(object):
    """An engine for creating graphs given a file AC policy."""

    def __init__(self):
        """Construct a GraphEngine."""
        super(GraphEngine, self).__init__()

    def runGraph(self,
                 policy: Policy=None,
                 outputDir: str=None,
                 quiet: bool=False):
        """Build a graph of IFs in the simulation given a policy."""
        outputDir = policy.getOutputDir(parent=outputFsEnabled()) if \
            policy else outputFsEnabled()

        if not quiet:
            print("\nCompiling the Unified Graph...")
        g = UnifiedGraph(outputDir=outputDir)
        g.populate(policy=policy)
        output = policy.name+"-graph-unified" if policy else \
            "graph-unified"
        g.plot(output=output)
        g.calculateCosts(output=output, policy=policy, quiet=quiet)
        g.calculateReachability(output=output, quiet=quiet)
        if not quiet:
            print("Done.")
