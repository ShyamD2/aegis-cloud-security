"""
Project AEGIS - Graph Engine & Path Analysis
Provides high-performance in-memory graph representation, openCypher/Gremlin serialization,
path traversal, cycle avoidance, and blast-radius score computation.
"""

from __future__ import annotations

from collections import deque

from services.attack_path.models import (
    AttackPath,
    BlastRadiusReport,
    GraphEdge,
    GraphNode,
    NodeType,
)


class SecurityGraph:
    """
    In-memory directed graph modeling identities, permissions, accounts, and cloud resources.
    Serializes to and synchronizes with Amazon Neptune openCypher/Gremlin engines.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        # Adjacency list: node_id -> list[GraphEdge]
        self.adjacency: dict[str, list[GraphEdge]] = {}
        # Reverse adjacency list: node_id -> list[GraphEdge]
        self.reverse_adjacency: dict[str, list[GraphEdge]] = {}

    def add_node(self, node: GraphNode) -> None:
        """Register a node in the security graph."""
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []
        if node.id not in self.reverse_adjacency:
            self.reverse_adjacency[node.id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        """Register a directed relationship in the security graph."""
        if edge.source not in self.adjacency:
            self.adjacency[edge.source] = []
        if edge.target not in self.reverse_adjacency:
            self.reverse_adjacency[edge.target] = []

        self.adjacency[edge.source].append(edge)
        self.reverse_adjacency[edge.target].append(edge)

    def get_node(self, node_id: str) -> GraphNode | None:
        """Retrieve node by ID or ARN."""
        return self.nodes.get(node_id)

    def export_cypher(self) -> list[str]:
        """
        Generate Amazon Neptune openCypher DDL/DML statements.
        Allows bulk or incremental loading into Neptune graph clusters.
        """
        statements: list[str] = []

        # Generate node merge statements
        for node in self.nodes.values():
            safe_name = node.name.replace("'", "\\'")
            safe_id = node.id.replace("'", "\\'")
            stmt = (
                f"MERGE (n:{node.node_type.value} {{id: '{safe_id}'}}) "
                f"SET n.name = '{safe_name}', "
                f"n.account_id = '{node.account_id}', "
                f"n.region = '{node.region}', "
                f"n.is_sensitive = {str(node.is_sensitive).lower()}, "
                f"n.criticality = {node.criticality}"
            )
            statements.append(stmt)

        # Generate edge merge statements
        for _source_id, edges in self.adjacency.items():
            for edge in edges:
                safe_src = edge.source.replace("'", "\\'")
                safe_tgt = edge.target.replace("'", "\\'")
                action_prop = f", r.action = '{edge.action}'" if edge.action else ""
                stmt = (
                    f"MATCH (s {{id: '{safe_src}'}}), (t {{id: '{safe_tgt}'}}) "
                    f"MERGE (s)-[r:{edge.edge_type.value}]->(t)"
                )
                if action_prop:
                    stmt += f" SET {action_prop[2:]}"
                statements.append(stmt)

        return statements

    def export_gremlin(self) -> list[str]:
        """
        Generate Apache TinkerPop Gremlin traversals for Amazon Neptune.
        """
        steps: list[str] = []
        for node in self.nodes.values():
            steps.append(
                f"g.mergeV([(T.id): '{node.id}'])"
                f".property(T.label, '{node.node_type.value}')"
                f".property('name', '{node.name}')"
                f".property('account_id', '{node.account_id}')"
                f".property('criticality', {node.criticality})"
            )
        for _source_id, edges in self.adjacency.items():
            for edge in edges:
                steps.append(
                    f"g.V('{edge.source}').as('s')"
                    f".V('{edge.target}')"
                    f".coalesce(__.inE('{edge.edge_type.value}').where(outV().as('s')), "
                    f"__.addE('{edge.edge_type.value}').from('s'))"
                )
        return steps

    def find_all_attack_paths(
        self,
        start_node_id: str,
        max_depth: int = 5,
    ) -> list[AttackPath]:
        """
        Traverse graph starting from compromised principal using Breadth-First Search (BFS)
        with strict cycle detection to avoid circular role-assumption loops.
        """
        if start_node_id not in self.nodes:
            return []

        discovered_paths: list[AttackPath] = []

        # Queue contains tuple: (current_node_id, path_nodes_list, actions_list)
        queue: deque[tuple[str, list[str], list[str]]] = deque(
            [(start_node_id, [start_node_id], [])]
        )

        while queue:
            current_id, current_path, current_actions = queue.popleft()

            if len(current_path) - 1 >= max_depth:
                continue

            for edge in self.adjacency.get(current_id, []):
                next_id = edge.target
                action_str = edge.action or edge.edge_type.value

                # Avoid cycles (e.g. A assumes B, B assumes A)
                if next_id in current_path:
                    continue

                new_path = list(current_path) + [next_id]
                new_actions = list(current_actions) + [action_str]

                target_node = self.nodes.get(next_id)
                if not target_node:
                    continue

                # Determine cross-account status
                path_accounts = {
                    self.nodes[n_id].account_id for n_id in new_path if n_id in self.nodes
                }
                is_cross_account = len(path_accounts) > 1

                # Record path if target is a workload resource or assumable role
                if target_node.node_type not in (
                    NodeType.ACCOUNT,
                    NodeType.SECURITY_GROUP,
                    NodeType.POLICY,
                ):
                    discovered_paths.append(
                        AttackPath(
                            source_node=start_node_id,
                            target_node=next_id,
                            path=new_path,
                            hops=len(new_path) - 1,
                            actions=new_actions,
                            is_cross_account=is_cross_account,
                            target_is_sensitive=target_node.is_sensitive,
                        )
                    )

                # Continue traversing if target is a Role or User (privilege escalation chain)
                if target_node.node_type in (NodeType.ROLE, NodeType.USER):
                    queue.append((next_id, new_path, new_actions))

        return discovered_paths

    def calculate_blast_radius(self, principal_id: str) -> BlastRadiusReport:
        """
        Calculate deterministic 0.0 - 100.0 blast radius report for a compromised identity.
        """
        principal = self.nodes.get(principal_id)
        if not principal:
            return BlastRadiusReport(
                principal_id=principal_id,
                score=0.0,
                explanation=f"Principal {principal_id} not found in security graph.",
            )

        all_paths = self.find_all_attack_paths(principal_id, max_depth=6)

        direct_resources: set[str] = set()
        indirect_resources: set[str] = set()
        assumable_roles: set[str] = set()
        affected_accounts: set[str] = {principal.account_id}
        sensitive_resources: set[str] = set()
        total_reachable_nodes: set[str] = set()

        for path in all_paths:
            total_reachable_nodes.add(path.target_node)
            target_node = self.nodes.get(path.target_node)
            if not target_node:
                continue

            affected_accounts.add(target_node.account_id)

            if target_node.is_sensitive:
                sensitive_resources.add(target_node.id)

            if target_node.node_type == NodeType.ROLE:
                assumable_roles.add(target_node.id)
            elif target_node.node_type in (
                NodeType.S3_BUCKET,
                NodeType.EC2_INSTANCE,
                NodeType.RDS_DATABASE,
                NodeType.LAMBDA_FUNCTION,
                NodeType.SECRETS_MANAGER_SECRET,
            ):
                if path.hops == 1:
                    direct_resources.add(target_node.id)
                else:
                    indirect_resources.add(target_node.id)

        # Indirect excludes any direct resources to avoid double counting
        indirect_resources = indirect_resources - direct_resources

        # Deterministic Blast Radius Formulation
        direct_component = len(direct_resources) * 3.0
        indirect_component = len(indirect_resources) * 4.5
        role_component = len(assumable_roles) * 8.0

        sensitive_criticality_sum = sum(
            self.nodes[res_id].criticality for res_id in sensitive_resources
        )
        sensitive_component = sensitive_criticality_sum * 5.0

        extra_accounts = max(0, len(affected_accounts) - 1)
        cross_account_component = extra_accounts * 15.0

        raw_score = (
            direct_component
            + indirect_component
            + role_component
            + sensitive_component
            + cross_account_component
        )
        final_score = min(100.0, round(raw_score, 2))

        cross_account_traversal = extra_accounts > 0

        # Detailed explainability narrative
        factors: list[str] = []
        if direct_resources:
            factors.append(f"{len(direct_resources)} directly accessible resource(s)")
        if indirect_resources:
            factors.append(f"{len(indirect_resources)} indirect resource(s) via role chains")
        if assumable_roles:
            factors.append(f"{len(assumable_roles)} assumable role(s)")
        if sensitive_resources:
            factors.append(
                f"{len(sensitive_resources)} sensitive asset(s) (criticality weight: {round(sensitive_criticality_sum, 1)})"
            )
        if cross_account_traversal:
            factors.append(
                f"cross-account reach into {extra_accounts} external account(s): {list(affected_accounts)}"
            )

        if not factors:
            explanation = "Isolated identity with zero discovered downstream resource permissions."
        else:
            explanation = f"Score {final_score}/100 driven by: " + "; ".join(factors) + "."

        return BlastRadiusReport(
            principal_id=principal_id,
            score=final_score,
            assumable_roles=sorted(assumable_roles),
            affected_accounts=sorted(affected_accounts),
            directly_accessible_resources=sorted(direct_resources),
            indirectly_accessible_resources=sorted(indirect_resources),
            sensitive_resources=sorted(sensitive_resources),
            attack_paths=all_paths,
            total_reachable_nodes=len(total_reachable_nodes),
            cross_account_traversal=cross_account_traversal,
            explanation=explanation,
        )
