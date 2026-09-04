"""
Project AEGIS - Security Operations War Room API Unit Tests
Validates posture calculations, incident retrieval, attack chain schemas,
strict RBAC approval gating, and zero browser credential exposure invariants.
"""

from __future__ import annotations

from services.war_room import (
    ApprovalActionRequest,
    IncidentState,
    UserRole,
    WarRoomAPI,
)


def test_war_room_posture_summary() -> None:
    """Verify organization security posture score and incident metrics."""
    api = WarRoomAPI()
    summary = api.get_posture_summary()

    assert 0.0 <= summary.posture_score <= 100.0
    assert summary.critical_findings_count >= 1
    assert summary.high_findings_count >= 1
    assert summary.active_incidents_count >= 1
    assert summary.mean_time_to_detect_seconds > 0.0
    assert summary.mean_time_to_contain_seconds > 0.0
    assert summary.total_protected_accounts == 5


def test_incident_listing_and_filtering() -> None:
    """Verify incident listing and state-based filtering."""
    api = WarRoomAPI()
    all_incidents = api.list_incidents()
    assert len(all_incidents) >= 2

    # Incidents should be ordered by risk score descending
    scores = [inc.risk_score for inc in all_incidents]
    assert scores == sorted(scores, reverse=True)

    # Filter by state
    containing_incidents = api.list_incidents(state=IncidentState.CONTAINING)
    assert all(inc.current_state == IncidentState.CONTAINING for inc in containing_incidents)


def test_incident_detail_and_attack_chain_structure() -> None:
    """Verify detailed incident dossier contains visual attack chain nodes and edges."""
    api = WarRoomAPI()
    detail = api.get_incident_detail("INC-2026-0904-001")
    assert detail is not None
    assert detail.incident_id == "INC-2026-0904-001"
    assert detail.risk_score >= 90.0
    assert len(detail.attack_chain_nodes) >= 4
    assert len(detail.attack_chain_edges) >= 3

    # Confirm compromised node and sensitive node flags
    compromised_nodes = [n for n in detail.attack_chain_nodes if n.is_compromised]
    assert len(compromised_nodes) == 1
    assert compromised_nodes[0].label == "contractor-alice"

    sensitive_nodes = [n for n in detail.attack_chain_nodes if n.is_sensitive]
    assert len(sensitive_nodes) == 1
    assert sensitive_nodes[0].label == "prod-customer-pii-vault"


def test_rbac_approval_authorization_gates() -> None:
    """Verify RBAC: SOC_ANALYST cannot authorize critical containment; SOC_LEAD can."""
    api = WarRoomAPI()

    # Attempt 1: SOC_ANALYST attempts to authorize critical incident containment -> REJECTED
    analyst_req = ApprovalActionRequest(
        incident_id="INC-2026-0904-001",
        action="REVOKE_IAM_SESSIONS",
        operator_role=UserRole.SOC_ANALYST,
        operator_id="analyst-102",
        decision="APPROVE",
        rationale="Attempting containment authorization",
        mfa_code="123456",
    )
    resp_analyst = api.process_approval(analyst_req)
    assert resp_analyst.approved is False
    assert "requires SOC_LEAD" in resp_analyst.status
    assert resp_analyst.approval_token is None

    # Attempt 2: SOC_LEAD authorizes critical incident containment -> APPROVED with token
    lead_req = ApprovalActionRequest(
        incident_id="INC-2026-0904-001",
        action="REVOKE_IAM_SESSIONS",
        operator_role=UserRole.SOC_LEAD,
        operator_id="lead-001",
        decision="APPROVE",
        rationale="Confirmed cross-account breach; authorized session revocation",
        mfa_code="654321",
    )
    resp_lead = api.process_approval(lead_req)
    assert resp_lead.approved is True
    assert "APPROVED" in resp_lead.status
    assert resp_lead.approval_token is not None
    assert resp_lead.approval_token.startswith("AEGIS-AUTH-LEAD-")


def test_zero_credentials_in_payload_audit() -> None:
    """Verify payload auditor rejects payloads containing exposed AWS keys."""
    # Benign payload without credentials
    benign_payload = {
        "incident_id": "INC-001",
        "principal": "arn:aws:iam::111:user/alice",
        "status": "CONTAINED",
    }
    assert WarRoomAPI.audit_zero_credentials_in_payload(benign_payload) is True

    # Malicious or leaked payload with access key
    leaked_payload = {
        "incident_id": "INC-002",
        "key_leak": "AKIAIOSFODNN7EXAMPLE",
    }
    assert WarRoomAPI.audit_zero_credentials_in_payload(leaked_payload) is False
