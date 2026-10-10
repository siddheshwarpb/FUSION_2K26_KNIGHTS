from typing import List, Dict, Any, Set, Optional, Tuple
from app.core.models import ComponentNode, VulnerableFinding, CytoscapeElement, CytoscapeGraph

def build_cytoscape_graph(
    components: List[ComponentNode],
    findings: List[VulnerableFinding],
    project_name: str = "project-root",
    all_edges: Optional[List[Tuple[str, str, str]]] = None,
    resolved_vuln_ids: Optional[Set[str]] = None,
    cyclic_purls: Optional[Set[str]] = None,
    cyclic_edges: Optional[Set[Tuple[str, str]]] = None
) -> CytoscapeGraph:
    """
    Builds structured Cytoscape.js elements (nodes and edges) with complete metadata:
    - Root nodes with correct non-vulnerable semantics (affected if downstream vulns exist).
    - Preserves all direct and transitive dependency edges, including cycles (A -> B -> A).
    - Preserves cycle membership (in_cycle, cycle_id) independently from vulnerability status.
    - Highlights affected propagation paths in red/orange.
    - Highlights simulated resolved nodes in green (simulated_resolved).
    """
    resolved_set = resolved_vuln_ids or set()
    cy_purls = cyclic_purls or {c.purl for c in components if c.in_cycle}
    cy_edges = cyclic_edges or set()

    nodes: List[CytoscapeElement] = []
    edges: List[CytoscapeElement] = []

    # Map vulnerable packages
    vuln_by_purl: Dict[str, List[VulnerableFinding]] = {}
    for f in findings:
        vuln_by_purl.setdefault(f.component.purl, []).append(f)

    # 1. Project Root Node
    root_id = "root:project"
    has_any_vuln = len(findings) > 0
    root_status = "affected" if has_any_vuln else "clean"
    nodes.append(CytoscapeElement(
        data={
            "id": root_id,
            "label": project_name,
            "name": project_name,
            "type": "root",
            "is_vulnerable": False, # Root project itself is NOT a vulnerable package
            "is_affected": has_any_vuln,
            "vuln_count": len(findings),
            "status": root_status,
            "in_cycle": False
        },
        classes="root-node " + root_status
    ))

    # Collect all affected edge pairs (u, v) from propagation paths
    affected_edges: Set[Tuple[str, str]] = set()
    for f in findings:
        for path in f.propagation_paths_to_root:
            if not path:
                continue
            # Edge from root to first element
            affected_edges.add((root_id, path[0]))
            # Edges along the chain
            for i in range(len(path) - 1):
                affected_edges.add((path[i], path[i + 1]))

    # 2. Component Nodes
    for comp in components:
        is_vuln = comp.purl in vuln_by_purl
        pkg_findings = vuln_by_purl.get(comp.purl, [])
        has_kev = any(f.vulnerability.in_kev for f in pkg_findings)
        max_priority = max([f.priority_score for f in pkg_findings], default=0.0)
        in_cy = comp.purl in cy_purls or comp.in_cycle

        # Check if resolved in simulation
        is_simulated_resolved = False
        if not is_vuln and resolved_set:
            is_simulated_resolved = True

        status = "vulnerable" if is_vuln else ("simulated_resolved" if is_simulated_resolved else "clean")
        classes = f"component-node {'direct' if comp.is_direct else 'transitive'} {status} {comp.scope}"
        if has_kev:
            classes += " kev-alert"
        if in_cy:
            classes += " in-cycle"

        # Fixed version recommendations
        fixes = [f.vulnerability.first_fixed_version for f in pkg_findings if f.vulnerability.first_fixed_version]
        recommended_fix = fixes[0] if fixes else None

        # Build mapped identifiers and vulnerability_details
        from app.services.osv_client import parse_vulnerability_identity
        identifiers_list: List[Dict[str, Any]] = []
        vuln_details_list: List[Dict[str, Any]] = []

        for f in pkg_findings:
            vrec = f.vulnerability
            if vrec.vulnerability_type and vrec.vulnerability_name:
                ident = {
                    "unique_id": vrec.id,
                    "cve_alias": vrec.cve_id or (vrec.aliases[0] if vrec.aliases else "No CVE Alias"),
                    "cwe_id": vrec.cwe_id,
                    "vulnerability_name": vrec.vulnerability_name or vrec.summary or "Unclassified Security Flaw",
                    "vulnerability_type": vrec.vulnerability_type or "General Security Weakness"
                }
            else:
                ident = parse_vulnerability_identity({
                    "id": vrec.id,
                    "aliases": vrec.aliases,
                    "cve_id": vrec.cve_id,
                    "summary": vrec.summary or vrec.details,
                    "cwe_id": vrec.cwe_id,
                })

            identifiers_list.append({
                "unique_id": ident["unique_id"],
                "cve_alias": ident["cve_alias"],
                "cwe_id": ident["cwe_id"],
            })

            vuln_details_list.append({
                "unique_id": ident["unique_id"],
                "cve_alias": ident["cve_alias"],
                "cwe_id": ident["cwe_id"],
                "vulnerability_name": ident["vulnerability_name"],
                "vulnerability_type": ident["vulnerability_type"],
                "severity": f.priority_tier,
                "priority_score": f.priority_score,
                "in_kev": vrec.in_kev,
                "epss_score": vrec.epss_score,
                "fixed_version": vrec.first_fixed_version,
                "summary": vrec.summary or vrec.details,
            })

        # Primary mapped fields for selected node
        primary_ident = vuln_details_list[0] if vuln_details_list else None

        node_data = {
            "id": comp.purl,
            "label": f"{comp.name}@{comp.version}",
            "name": comp.name,
            "version": comp.version,
            "ecosystem": comp.ecosystem,
            "purl": comp.purl,
            "type": "direct_dependency" if comp.is_direct else "transitive_dependency",
            "is_direct": comp.is_direct,
            "scope": comp.scope,
            "in_cycle": in_cy,
            "cycle_id": comp.cycle_group_id,
            "is_vulnerable": is_vuln,
            "vuln_count": len(pkg_findings),
            "in_kev": has_kev,
            "priority_score": max_priority,
            "fixed_version": recommended_fix,
            "integrity": comp.integrity or "N/A",
            "lockfile_path": comp.lockfile_path or "N/A",
            "status": status,
            "lookup_status": comp.lookup_status,
            # Mapped identity fields required by graph endpoint
            "identifiers": identifiers_list,
            "vulnerability_details": vuln_details_list,
            "unique_id": primary_ident["unique_id"] if primary_ident else None,
            "cve_alias": primary_ident["cve_alias"] if primary_ident else None,
            "cwe_id": primary_ident["cwe_id"] if primary_ident else None,
            "vulnerability_name": primary_ident["vulnerability_name"] if primary_ident else None,
            "vulnerability_type": primary_ident["vulnerability_type"] if primary_ident else None,
            "advisories": [
                {
                    "id": f.vulnerability.id,
                    "cve": f.vulnerability.cve_id,
                    "summary": f.vulnerability.summary,
                    "fixed": f.vulnerability.first_fixed_version,
                    "in_kev": f.vulnerability.in_kev,
                    "epss": f.vulnerability.epss_score,
                    "unique_id": det["unique_id"],
                    "cve_alias": det["cve_alias"],
                    "cwe_id": det["cwe_id"],
                    "vulnerability_name": det["vulnerability_name"],
                    "vulnerability_type": det["vulnerability_type"],
                }
                for f, det in zip(pkg_findings, vuln_details_list)
            ]
        }
        nodes.append(CytoscapeElement(data=node_data, classes=classes))

    # 3. Edges
    seen_edge_pairs: Set[Tuple[str, str]] = set()

    if all_edges is not None:
        # Use full graph topology from DependencyGraph
        for u, v, edge_type in all_edges:
            pair = (u, v)
            if pair in seen_edge_pairs:
                continue
            seen_edge_pairs.add(pair)

            is_affected = pair in affected_edges
            is_cyclic = pair in cy_edges or (u in cy_purls and v in cy_purls)
            edge_id = f"e:{u}->{v}"

            edge_classes = f"edge-{edge_type.lower()}"
            if is_affected:
                edge_classes += " affected-path"
            else:
                edge_classes += " normal-path"
            if is_cyclic:
                edge_classes += " cycle-edge in-cycle"

            edges.append(CytoscapeElement(
                data={
                    "id": edge_id,
                    "source": u,
                    "target": v,
                    "type": edge_type,
                    "is_affected": is_affected,
                    "is_cyclic": is_cyclic
                },
                classes=edge_classes
            ))
    else:
        # Fallback: Edges from Root to Direct Dependencies + propagation paths
        for comp in components:
            if comp.is_direct:
                pair = (root_id, comp.purl)
                seen_edge_pairs.add(pair)
                is_affected = pair in affected_edges
                edge_classes = "edge-declares " + ("affected-path" if is_affected else "normal-path")
                edges.append(CytoscapeElement(
                    data={
                        "id": f"e:{root_id}->{comp.purl}",
                        "source": root_id,
                        "target": comp.purl,
                        "type": "DECLARES",
                        "is_affected": is_affected,
                        "is_cyclic": False
                    },
                    classes=edge_classes
                ))

        for f in findings:
            for path in f.propagation_paths_to_root:
                for i in range(len(path) - 1):
                    u, v = path[i], path[i + 1]
                    pair = (u, v)
                    if pair not in seen_edge_pairs:
                        seen_edge_pairs.add(pair)
                        is_cyclic = pair in cy_edges or (u in cy_purls and v in cy_purls)
                        edge_classes = "edge-depends affected-path"
                        if is_cyclic:
                            edge_classes += " cycle-edge in-cycle"
                        edges.append(CytoscapeElement(
                            data={
                                "id": f"e:{u}->{v}",
                                "source": u,
                                "target": v,
                                "type": "DEPENDS_ON",
                                "is_affected": True,
                                "is_cyclic": is_cyclic
                            },
                            classes=edge_classes
                        ))

    cyclic_nodes_count = sum(1 for n in nodes if n.data.get("in_cycle"))
    cyclic_edges_count = sum(1 for e in edges if e.data.get("is_cyclic"))

    return CytoscapeGraph(
        nodes=nodes,
        edges=edges,
        total_nodes=len(nodes),
        total_edges=len(edges),
        affected_paths_count=len(affected_edges),
        cyclic_nodes_count=cyclic_nodes_count,
        cyclic_edges_count=cyclic_edges_count
    )
