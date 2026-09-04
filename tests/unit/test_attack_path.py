"""
Project AEGIS - Attack-Path & Blast-Radius Engine Unit Tests
Validates graph modeling, Neptune query serialization, multi-account path traversal,
cycle detection, and explainable blast-radius calculations.
"""

from __future__ import annotations

import pytest

from services.attack_path import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NeptuneAdapter,
    NodeType,
    SecurityGraph,
    build_enterprise_attack_graph,
)


@pytest.fixture
def enterprise_graph() -> SecurityGraph:
    """Fixture providing a standard multi-account enterprise topology."""
    return build_enterprise_attack_graph()


def test_attack_graph_construction(enterprise_graph: SecurityGraph) -> None:
    """Verify nodes, edges, accounts, and sensitivity attributes are properly registered."""
    assert len(enterprise_graph.nodes) >= 12
    alice = enterprise_graph.get_node("arn:aws:iam::333333333333:user/contractor-alice")
    assert alice is not None
    assert alice.node_type == NodeType.USER
    assert alice.account_id == "333333333333"

    pii_bucket = enterprise_graph.get_node("arn:aws:s3:::prod-customer-pii-vault")
    assert pii_bucket is not None
    assert pii_bucket.is_sensitive is True
    assert pii_bucket.criticality >= 9.0


def test_attack_path_traversal_alice(enterprise_graph: SecurityGraph) -> None:
    """
    Verify full attack path discovery for compromised contractor Alice:
    Alice -> DevEngineer -> CrossAccountProdReader -> PII Bucket & DB Secret -> ProdDatabaseAdmin -> RDS
    """
    alice_id = "arn:aws:iam::333333333333:user/contractor-alice"
    paths = enterprise_graph.find_all_attack_paths(alice_id, max_depth=6)

    assert len(paths) >= 6

    # Verify direct access to dev-build-artifacts
    direct_path = [p for p in paths if p.target_node == "arn:aws:s3:::dev-build-artifacts"]
    assert len(direct_path) == 1
    assert direct_path[0].hops == 1
    assert direct_path[0].is_cross_account is False

    # Verify indirect attack path to sensitive PII vault
    pii_path = [p for p in paths if p.target_node == "arn:aws:s3:::prod-customer-pii-vault"]
    assert len(pii_path) == 1
    assert pii_path[0].hops == 3
    assert pii_path[0].is_cross_account is True
    assert pii_path[0].target_is_sensitive is True
    assert pii_path[0].path == [
        alice_id,
        "arn:aws:iam::333333333333:role/DevEngineer",
        "arn:aws:iam::111111111111:role/CrossAccountProdReader",
        "arn:aws:s3:::prod-customer-pii-vault",
    ]

    # Verify deep attack path to production RDS database
    rds_path = [
        p
        for p in paths
        if p.target_node == "arn:aws:rds:us-east-1:111111111111:db:prod-core-aurora"
    ]
    assert len(rds_path) == 1
    assert rds_path[0].hops == 4
    assert rds_path[0].is_cross_account is True
    assert rds_path[0].target_is_sensitive is True


def test_blast_radius_calculation_alice(enterprise_graph: SecurityGraph) -> None:
    """Verify blast radius computation for high-privilege escalation target."""
    alice_id = "arn:aws:iam::333333333333:user/contractor-alice"
    report = enterprise_graph.calculate_blast_radius(alice_id)

    assert report.principal_id == alice_id
    assert report.score >= 70.0
    assert "arn:aws:iam::333333333333:role/DevEngineer" in report.assumable_roles
    assert "arn:aws:iam::111111111111:role/CrossAccountProdReader" in report.assumable_roles
    assert "arn:aws:iam::111111111111:role/ProdDatabaseAdmin" in report.assumable_roles

    assert "333333333333" in report.affected_accounts
    assert "111111111111" in report.affected_accounts
    assert report.cross_account_traversal is True

    assert "arn:aws:s3:::dev-build-artifacts" in report.directly_accessible_resources
    assert "arn:aws:s3:::prod-customer-pii-vault" in report.indirectly_accessible_resources
    assert "arn:aws:s3:::prod-customer-pii-vault" in report.sensitive_resources
    assert (
        "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db-master-creds"
        in report.sensitive_resources
    )
    assert "Score" in report.explanation


def test_blast_radius_calculation_bob(enterprise_graph: SecurityGraph) -> None:
    """Verify isolated intern identity has a low blast-radius impact score."""
    bob_id = "arn:aws:iam::333333333333:user/intern-bob"
    report = enterprise_graph.calculate_blast_radius(bob_id)

    assert report.principal_id == bob_id
    assert report.score < 20.0
    assert len(report.assumable_roles) == 0
    assert report.affected_accounts == ["333333333333"]
    assert report.cross_account_traversal is False
    assert len(report.sensitive_resources) == 0
    assert "arn:aws:s3:::dev-build-artifacts" in report.directly_accessible_resources


def test_cypher_and_gremlin_export(enterprise_graph: SecurityGraph) -> None:
    """Verify openCypher and Gremlin export statements match Neptune schema specs."""
    cypher_queries = enterprise_graph.export_cypher()
    assert len(cypher_queries) > 0
    assert any("MERGE (n:USER" in q for q in cypher_queries)
    assert any("MERGE (s)-[r:ASSUME_ROLE]->(t)" in q for q in cypher_queries)

    gremlin_queries = enterprise_graph.export_gremlin()
    assert len(gremlin_queries) > 0
    assert any("g.mergeV" in q for q in gremlin_queries)


def test_neptune_adapter_simulation(enterprise_graph: SecurityGraph) -> None:
    """Verify NeptuneAdapter bulk loading and openCypher query simulation."""
    adapter = NeptuneAdapter()
    loaded_count = adapter.bulk_load_graph(enterprise_graph)
    assert loaded_count > 0

    count_result = adapter.execute_cypher("MATCH (n) RETURN count(n)")
    assert "results" in count_result
    assert count_result["results"][0]["count"] >= 12

    nodes_result = adapter.execute_cypher("MATCH (n) RETURN n")
    assert len(nodes_result["results"]) >= 12


def test_cycle_prevention() -> None:
    """Verify that circular role assumption (A -> B -> A) terminates safely without infinite loop."""
    graph = SecurityGraph()
    role_a = GraphNode(id="role-a", node_type=NodeType.ROLE, name="RoleA", account_id="111")
    role_b = GraphNode(id="role-b", node_type=NodeType.ROLE, name="RoleB", account_id="111")
    bucket = GraphNode(
        id="target-bucket", node_type=NodeType.S3_BUCKET, name="Bucket", account_id="111"
    )

    graph.add_node(role_a)
    graph.add_node(role_b)
    graph.add_node(bucket)

    # Circular edges
    graph.add_edge(GraphEdge(source="role-a", target="role-b", edge_type=EdgeType.ASSUME_ROLE))
    graph.add_edge(GraphEdge(source="role-b", target="role-a", edge_type=EdgeType.ASSUME_ROLE))
    graph.add_edge(
        GraphEdge(source="role-b", target="target-bucket", edge_type=EdgeType.CAN_ACCESS)
    )

    # Path discovery must terminate without recursion error or memory exhaustion
    paths = graph.find_all_attack_paths("role-a", max_depth=5)
    assert len(paths) >= 1
    target_paths = [p for p in paths if p.target_node == "target-bucket"]
    assert len(target_paths) == 1
    assert target_paths[0].path == ["role-a", "role-b", "target-bucket"]
