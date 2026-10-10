import networkx as nx
from typing import Dict, List, Set, Optional, Tuple, Any
from app.core.models import ComponentNode

ROOT_NODE_ID = "root:project"

class DependencyGraph:
    """
    High-performance dependency DAG backed by NetworkX.
    Nodes: Components (keyed by canonical PURL) + ROOT_NODE_ID.
    Edges: A -> B means A depends on B.
    """

    def __init__(self, project_name: str = "project"):
        self.project_name = project_name
        self.graph = nx.DiGraph()
        self.graph.add_node(ROOT_NODE_ID, name=project_name, is_root=True)
        self._components_by_purl: Dict[str, ComponentNode] = {}
        self._purl_by_coord: Dict[Tuple[str, str, str], str] = {} # (eco, name, ver) -> purl

    def add_component(self, component: ComponentNode) -> None:
        """Add a component node to the graph."""
        self._components_by_purl[component.purl] = component
        self._purl_by_coord[(component.ecosystem, component.name, component.version)] = component.purl
        self.graph.add_node(
            component.purl,
            name=component.name,
            version=component.version,
            ecosystem=component.ecosystem,
            is_direct=component.is_direct,
            scope=component.scope,
            integrity=component.integrity,
            lockfile_path=component.lockfile_path,
        )

        if component.is_direct:
            # Direct dependency edge from project root
            self.graph.add_edge(ROOT_NODE_ID, component.purl, type="DECLARES")

    def add_dependency_edge(self, parent_purl: str, child_purl: str, edge_type: str = "DEPENDS_ON") -> None:
        """Add directed dependency edge from parent to child."""
        if parent_purl in self.graph and child_purl in self.graph:
            self.graph.add_edge(parent_purl, child_purl, type=edge_type)

    def add_dependency(self, parent_purl: str, child_purl: str, edge_type: str = "DEPENDS_ON") -> None:
        """Alias for add_dependency_edge."""
        self.add_dependency_edge(parent_purl, child_purl, edge_type)

    def get_component(self, purl: str) -> Optional[ComponentNode]:
        return self._components_by_purl.get(purl)

    def get_all_components(self) -> List[ComponentNode]:
        return list(self._components_by_purl.values())

    def get_direct_components(self) -> List[ComponentNode]:
        return [c for c in self._components_by_purl.values() if c.is_direct]

    def get_transitive_components(self) -> List[ComponentNode]:
        return [c for c in self._components_by_purl.values() if not c.is_direct]

    def find_purl(self, ecosystem: str, name: str, version: str) -> Optional[str]:
        return self._purl_by_coord.get((ecosystem, name, version))

    def get_propagation_paths(self, target_purl: str, max_paths: int = 5, max_depth: int = 10) -> List[List[str]]:
        """
        Traverse graph to find propagation paths from direct project dependencies to target_purl.
        Returns paths formatted with readable package coordinates.
        """
        if target_purl not in self.graph or not nx.has_path(self.graph, ROOT_NODE_ID, target_purl):
            return []

        paths: List[List[str]] = []
        try:
            # Find simple paths from root to target
            for path in nx.all_simple_paths(self.graph, source=ROOT_NODE_ID, target=target_purl, cutoff=max_depth):
                # Omit ROOT_NODE_ID from presentation
                readable_path = [p for p in path if p != ROOT_NODE_ID]
                paths.append(readable_path)
                if len(paths) >= max_paths:
                    break
        except Exception:
            # Fallback to shortest path if all_simple_paths encounters cycles/recursion
            try:
                sp = nx.shortest_path(self.graph, source=ROOT_NODE_ID, target=target_purl)
                paths = [[p for p in sp if p != ROOT_NODE_ID]]
            except Exception:
                paths = []

        return paths

    def get_root_dependents(self, target_purl: str) -> List[str]:
        """
        Identify which direct project dependencies bring in this target package.
        """
        if target_purl not in self.graph:
            return []

        # If it's directly required, it is its own direct root
        target_comp = self._components_by_purl.get(target_purl)
        if target_comp and target_comp.is_direct:
            return [target_purl]

        direct_ancestors: Set[str] = set()
        # Find all ancestors of target_purl
        try:
            ancestors = nx.ancestors(self.graph, target_purl)
            for anc in ancestors:
                comp = self._components_by_purl.get(anc)
                if comp and comp.is_direct:
                    direct_ancestors.add(anc)
        except Exception:
            pass

        return sorted(list(direct_ancestors))

    def get_shortest_depth(self, target_purl: str) -> int:
        """Calculate minimum transitive distance from root project."""
        if target_purl not in self.graph:
            return 0
        try:
            return nx.shortest_path_length(self.graph, source=ROOT_NODE_ID, target=target_purl)
        except Exception:
            return 0

    def detect_cycles_tarjan(self) -> Dict[str, Any]:
        """
        Detects cycles and strongly connected components using Tarjan's algorithm.
        Rules:
        - A component with multiple nodes is cyclic.
        - A single-node component is cyclic only if it has a self-loop.
        Returns:
            - cyclic_purls: Set of all node IDs involved in a cycle
            - cycle_groups: List of cycle components (each a list of purls)
            - cyclic_edges: Set of (u, v) edge pairs forming the cycles
        """
        # Build subgraph excluding ROOT_NODE_ID
        comp_nodes = [n for n in self.graph.nodes if n != ROOT_NODE_ID]
        subgraph = self.graph.subgraph(comp_nodes)

        # Strongly connected components via Tarjan's algorithm
        sccs = list(nx.strongly_connected_components(subgraph))

        cyclic_purls: Set[str] = set()
        cycle_groups: List[List[str]] = []
        cyclic_edges: Set[Tuple[str, str]] = set()

        for group in sccs:
            group_list = sorted(list(group))
            if len(group_list) > 1:
                # Multi-node cycle
                cyclic_purls.update(group_list)
                cycle_groups.append(group_list)
                # Find all edges between members of this SCC
                for u in group_list:
                    for v in group_list:
                        if self.graph.has_edge(u, v):
                            cyclic_edges.add((u, v))
            elif len(group_list) == 1:
                # Single-node component is cyclic only if it has a self-loop
                node = group_list[0]
                if self.graph.has_edge(node, node):
                    cyclic_purls.add(node)
                    cycle_groups.append([node])
                    cyclic_edges.add((node, node))

        return {
            "cyclic_purls": cyclic_purls,
            "cycle_groups": cycle_groups,
            "cyclic_edges": cyclic_edges,
            "cyclic_components_count": len(cycle_groups)
        }

    def get_all_edges(self) -> List[Tuple[str, str, str]]:
        """Return all directed edges in the dependency graph as (u, v, type)."""
        edges = []
        for u, v, data in self.graph.edges(data=True):
            edge_type = data.get("type", "DEPENDS_ON")
            edges.append((u, v, edge_type))
        return edges

    def compute_metrics(self) -> None:
        """Calculate direct/transitive dependent counts and detect cycles."""
        cycle_info = self.detect_cycles_tarjan()
        cyclic_purls = cycle_info["cyclic_purls"]
        cycle_groups = cycle_info["cycle_groups"]

        purl_to_group_id: Dict[str, str] = {}
        for g_idx, group in enumerate(cycle_groups, start=1):
            for purl in group:
                purl_to_group_id[purl] = f"cycle-{g_idx}"

        for purl, comp in self._components_by_purl.items():
            if purl in self.graph:
                comp.direct_dependents_count = self.graph.in_degree(purl)
                try:
                    comp.transitive_dependents_count = len(nx.ancestors(self.graph, purl))
                except Exception:
                    comp.transitive_dependents_count = 0

                # Cycle metadata
                comp.in_cycle = purl in cyclic_purls
                comp.cycle_group_id = purl_to_group_id.get(purl)


