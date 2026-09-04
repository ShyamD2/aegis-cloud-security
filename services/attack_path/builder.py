"""
Project AEGIS - Attack Path & Topology Builder
Constructs enterprise multi-account AWS resource graphs including IAM trust, privilege escalation,
and sensitive resource relationships for deterministic attack-path verification.
"""

from __future__ import annotations

from services.attack_path.graph import SecurityGraph
from services.attack_path.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)


def build_enterprise_attack_graph() -> SecurityGraph:
    """
    Build a realistic enterprise multi-account AWS topology:
    - Dev Account (333333333333)
    - Prod Account (111111111111)
    - Security Account (222222222222)
    Features an intentional cross-account role chaining path leading to sensitive customer PII
    and production database credentials.
    """
    graph = SecurityGraph()

    # Accounts
    dev_account = GraphNode(
        id="333333333333",
        node_type=NodeType.ACCOUNT,
        name="Development-Workloads",
        account_id="333333333333",
        criticality=2.0,
    )
    prod_account = GraphNode(
        id="111111111111",
        node_type=NodeType.ACCOUNT,
        name="Production-Core",
        account_id="111111111111",
        criticality=10.0,
    )
    sec_account = GraphNode(
        id="222222222222",
        node_type=NodeType.ACCOUNT,
        name="Security-Central",
        account_id="222222222222",
        criticality=9.0,
    )
    graph.add_node(dev_account)
    graph.add_node(prod_account)
    graph.add_node(sec_account)

    # Identities
    alice_user = GraphNode(
        id="arn:aws:iam::333333333333:user/contractor-alice",
        node_type=NodeType.USER,
        name="contractor-alice",
        account_id="333333333333",
        criticality=2.0,
    )
    bob_user = GraphNode(
        id="arn:aws:iam::333333333333:user/intern-bob",
        node_type=NodeType.USER,
        name="intern-bob",
        account_id="333333333333",
        criticality=1.0,
    )
    dev_role = GraphNode(
        id="arn:aws:iam::333333333333:role/DevEngineer",
        node_type=NodeType.ROLE,
        name="DevEngineer",
        account_id="333333333333",
        criticality=3.0,
    )
    prod_reader_role = GraphNode(
        id="arn:aws:iam::111111111111:role/CrossAccountProdReader",
        node_type=NodeType.ROLE,
        name="CrossAccountProdReader",
        account_id="111111111111",
        criticality=7.0,
    )
    prod_admin_role = GraphNode(
        id="arn:aws:iam::111111111111:role/ProdDatabaseAdmin",
        node_type=NodeType.ROLE,
        name="ProdDatabaseAdmin",
        account_id="111111111111",
        criticality=9.5,
    )
    graph.add_node(alice_user)
    graph.add_node(bob_user)
    graph.add_node(dev_role)
    graph.add_node(prod_reader_role)
    graph.add_node(prod_admin_role)

    # Workload Resources
    dev_bucket = GraphNode(
        id="arn:aws:s3:::dev-build-artifacts",
        node_type=NodeType.S3_BUCKET,
        name="dev-build-artifacts",
        account_id="333333333333",
        is_sensitive=False,
        criticality=2.0,
    )
    pii_bucket = GraphNode(
        id="arn:aws:s3:::prod-customer-pii-vault",
        node_type=NodeType.S3_BUCKET,
        name="prod-customer-pii-vault",
        account_id="111111111111",
        is_sensitive=True,
        sensitivity_reason="Customer Financial and Identity Records",
        criticality=9.5,
    )
    db_secret = GraphNode(
        id="arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db-master-creds",
        node_type=NodeType.SECRETS_MANAGER_SECRET,
        name="prod-db-master-creds",
        account_id="111111111111",
        region="us-east-1",
        is_sensitive=True,
        sensitivity_reason="Production Database Superuser Master Password",
        criticality=10.0,
    )
    prod_rds = GraphNode(
        id="arn:aws:rds:us-east-1:111111111111:db:prod-core-aurora",
        node_type=NodeType.RDS_DATABASE,
        name="prod-core-aurora",
        account_id="111111111111",
        region="us-east-1",
        is_sensitive=True,
        sensitivity_reason="Primary Production Transaction Database",
        criticality=10.0,
    )
    graph.add_node(dev_bucket)
    graph.add_node(pii_bucket)
    graph.add_node(db_secret)
    graph.add_node(prod_rds)

    # Account Membership Edges
    for node_id in [alice_user.id, bob_user.id, dev_role.id, dev_bucket.id]:
        graph.add_edge(
            GraphEdge(source=node_id, target=dev_account.id, edge_type=EdgeType.IN_ACCOUNT)
        )

    for node_id in [
        prod_reader_role.id,
        prod_admin_role.id,
        pii_bucket.id,
        db_secret.id,
        prod_rds.id,
    ]:
        graph.add_edge(
            GraphEdge(source=node_id, target=prod_account.id, edge_type=EdgeType.IN_ACCOUNT)
        )

    # Permissions and Trust Edges (Attack Chains)
    # Alice -> Direct access to dev bucket
    graph.add_edge(
        GraphEdge(
            source=alice_user.id,
            target=dev_bucket.id,
            edge_type=EdgeType.CAN_ACCESS,
            action="s3:GetObject",
        )
    )

    # Alice -> AssumeRole -> DevEngineer
    graph.add_edge(
        GraphEdge(
            source=alice_user.id,
            target=dev_role.id,
            edge_type=EdgeType.ASSUME_ROLE,
            action="sts:AssumeRole",
        )
    )

    # DevEngineer -> AssumeRole -> CrossAccountProdReader
    graph.add_edge(
        GraphEdge(
            source=dev_role.id,
            target=prod_reader_role.id,
            edge_type=EdgeType.ASSUME_ROLE,
            action="sts:AssumeRole",
        )
    )

    # CrossAccountProdReader -> Access PII Bucket & DB Secret
    graph.add_edge(
        GraphEdge(
            source=prod_reader_role.id,
            target=pii_bucket.id,
            edge_type=EdgeType.CAN_ACCESS,
            action="s3:GetObject",
        )
    )
    graph.add_edge(
        GraphEdge(
            source=prod_reader_role.id,
            target=db_secret.id,
            edge_type=EdgeType.CAN_ACCESS,
            action="secretsmanager:GetSecretValue",
        )
    )

    # CrossAccountProdReader -> Privilege Escalation -> ProdDatabaseAdmin
    graph.add_edge(
        GraphEdge(
            source=prod_reader_role.id,
            target=prod_admin_role.id,
            edge_type=EdgeType.ASSUME_ROLE,
            action="sts:AssumeRole",
        )
    )

    # ProdDatabaseAdmin -> Access RDS Core Aurora
    graph.add_edge(
        GraphEdge(
            source=prod_admin_role.id,
            target=prod_rds.id,
            edge_type=EdgeType.CAN_ACCESS,
            action="rds-db:connect",
        )
    )

    # Intern Bob has only direct access to dev bucket (isolated control group)
    graph.add_edge(
        GraphEdge(
            source=bob_user.id,
            target=dev_bucket.id,
            edge_type=EdgeType.CAN_ACCESS,
            action="s3:GetObject",
        )
    )

    return graph
