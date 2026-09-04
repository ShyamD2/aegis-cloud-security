"""Rule AEGIS-DET-010: Suspicious API-Call Sequence Engine."""

from datetime import datetime

from detection_engine.models import EnrichedSecurityEvent
from detection_engine.rules.base import DetectionRule
from services.common.models import FindingSeverity, SecurityFinding


class Rule010APISequence(DetectionRule):
    """Detects multi-step attack sequences executed in rapid succession by the same principal."""

    rule_id = "AEGIS-DET-010"
    name = "Suspicious API-Call Sequence: Key Creation -> Privilege Escalation -> Data Access"
    description = (
        "A principal executed a high-risk multi-step attack sequence: CreateAccessKey followed by "
        "privilege modification and sensitive secret/data access within 5 minutes."
    )
    severity = FindingSeverity.CRITICAL
    confidence = 0.95
    mitre_attack_technique = "T1078 / T1098"
    recommended_response = (
        "High-confidence attack sequence detected. Revoke created keys, attach quarantine deny policy, "
        "and alert SOC immediately."
    )

    # Window in seconds (5 minutes)
    SEQUENCE_WINDOW_SECONDS = 300

    def __init__(self) -> None:
        # Maps principal_arn -> list of (action, timestamp)
        self._history: dict[str, list[tuple[str, datetime]]] = {}

    def _clean_history(self, principal: str, current_time: datetime) -> None:
        """Remove expired sequence steps."""
        if principal in self._history:
            self._history[principal] = [
                (act, ts)
                for act, ts in self._history[principal]
                if (current_time - ts).total_seconds() <= self.SEQUENCE_WINDOW_SECONDS
            ]

    def evaluate(self, enriched: EnrichedSecurityEvent) -> SecurityFinding | None:
        ev = enriched.event
        principal = ev.principal_arn
        action = ev.action
        timestamp = ev.timestamp

        # Only track relevant actions in sequence
        relevant_actions = [
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "iam:AttachRolePolicy",
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter",
        ]
        if action not in relevant_actions:
            return None

        self._clean_history(principal, timestamp)

        if principal not in self._history:
            self._history[principal] = []

        self._history[principal].append((action, timestamp))
        recorded_actions = [act for act, _ in self._history[principal]]

        # Check for sequence: CreateAccessKey -> (Attach/Put Policy) -> GetSecret
        has_key_create = "iam:CreateAccessKey" in recorded_actions
        has_priv_esc = any(
            act in recorded_actions
            for act in ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy"]
        )
        has_secret_access = any(
            act in recorded_actions for act in ["secretsmanager:GetSecretValue", "ssm:GetParameter"]
        )

        if has_key_create and has_priv_esc and has_secret_access:
            return self.build_finding(
                enriched,
                custom_evidence={
                    "sequence_matched": [
                        "iam:CreateAccessKey",
                        "privilege_escalation",
                        "secret_access",
                    ],
                    "window_seconds": self.SEQUENCE_WINDOW_SECONDS,
                    "recorded_actions": recorded_actions,
                    "reason": "Complete credential weaponization sequence detected within 5-minute window",
                },
                severity_override=FindingSeverity.CRITICAL,
                confidence_override=0.97,
            )

        return None
