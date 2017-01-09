"""A graph representation of user document accesses by userland apps."""

from igraph import Graph, UniqueIdGenerator, plot
from File import File, FileAccess
from Application import Application
from ApplicationStore import ApplicationStore
from FileStore import FileStore
from UserConfigLoader import UserConfigLoader
from PolicyEngine import Policy
from utils import outputFsEnabled
import itertools

# TODO policy allowed filter
# TODO use appsHaveMemory for instance links


class CommonGraph(object):
    """A graph representation of user document accesses by userland apps."""

    # Styling dictionaries.
    cd = {"file": "blue", "app": "pink", "appstate": "red"}
    sd = {"file": "circle", "app": "triangle-up", "appstate": "diamond"}

    def __init__(self, outputDir: str=None):
        """Construct a CommonGraph."""
        super(CommonGraph, self).__init__()
        self.g = None
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

    def populate(self, userConf: UserConfigLoader, policy: Policy=None):
        """Populate the AccessGraph, filtering it based on a Policy."""
        appStore = ApplicationStore.get()
        fileStore = FileStore.get()

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
            if not f.isUserDocument(userHome=userConf.getSetting("HomeDir"),
                                    allowHiddenFiles=True):
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

    def plot(self, output: str=None):
        """Plot the graph and its communities, possibly to an output file."""

        # Get style options set for the base graph plot.
        vs = {}
        vs["vertex_size"] = 5
        vs["vertex_color"] = [AccessGraph.cd[t] for t in self.g.vs["type"]]
        vs["vertex_shape"] = [AccessGraph.sd[t] for t in self.g.vs["type"]]
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
            print(self.outputDir + "/" + output + ".graph.svg")

        # Detect communities in the graph.
        comm = self.g.community_fastgreedy(weights=self.g.es["weight"])
        clusters = comm.as_clustering()

        # Plot the base graph with colours based on the communities.
        vs["vertex_color"] = clusters.membership
        edge_widths = []
        for (s, d) in self.g.get_edgelist():
            if clusters.membership[s] == clusters.membership[d]:
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
                if clusters.membership[neighbour] != clusters.membership[idx]:
                    break
            else:
                minimal_labels[idx] = None

        vs["vertex_label"] = minimal_labels

        if output:
            path = self.outputDir + "/" + output + ".clusters.svg"
            plot(clusters, path, **vs)
        else:
            plot(clusters, **vs)


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

        self.edges.add((source, dest))

        # Add the edge, and count a single access (unweighted clustering).
        # self.edges.add((source, dest))
        # cnt = self.weights.get((source, dest)) or 0
        # self.weights[(source, dest)] = cnt + 1  # FIXME always 1 here?
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
