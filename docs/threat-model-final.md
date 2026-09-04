# Project AEGIS - Threat Model & STRIDE Analysis
## Enterprise Cloud Defense Threat Modeling & Adversary Countermeasure Specification

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                         STRIDE Threat Categories                        │
  │                                                                         │
  │  [S] Spoofing Identity          ──► OIDC Federation & Replay Validation │
  │  [T] Tampering with Data        ──► S3 Object Lock & SCP Immutable Logs │
  │  [R] Repudiation                ──► Multi-Account CloudTrail & Hashing  │
  │  [I] Information Disclosure     ──► KMS CMK Envelope & PrivateLink      │
  │  [D] Denial of Service          ──► Circuit Breaker & Kinesis Shards    │
  │  [E] Elevation of Privilege     ──► Graph Analysis & Rule AEGIS-DET-004 │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

A comprehensive threat model is required to ensure an autonomous security platform effectively protects against both external cloud adversaries and internal compromised identities. This document details the formal **STRIDE threat model** applied to Project AEGIS.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Specific Threat Scenario | Affected Component | Threat Actor | AEGIS Mitigation & Control | Rule / Architecture Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Replaying historical CloudTrail events to induce false containment. | Telemetry Ingestion | External Adversary | `ReplayDetector` enforces 15m time window and SHA-256 event fingerprint tracking. | `services/resilience/replay_defense.py` |
| **Spoofing** | Assuming unauthorized IAM role across account boundaries without ExternalId. | Identity Layer | Compromised Contractor | `Rule009CrossAccountAbuse` flags external assumptions lacking ExternalId conditions. | `AEGIS-DET-009` |
| **Tampering** | Rogue admin calls `cloudtrail:StopLogging` or deletes audit trail. | Audit Logging | Malicious Insider | Organization SCP blocks `StopLogging`; Rule `AEGIS-DET-006` triggers autonomous session revocation. | `AEGIS-DET-006` / `scps/` |
| **Tampering** | Overwriting captured forensic telemetry to hide evidence of exfiltration. | Digital Forensics | Advanced Persistent Threat | S3 Object Lock in `COMPLIANCE` mode prevents deletion or modification even by account root. | `services/forensics/collector.py` |
| **Repudiation** | Attacker executes unauthorized EC2 API actions from non-corporate IP. | Compute Fabric | Compromised User Key | Organization CloudTrail multi-region logging; canonical forensic manifests record non-repudiable timeline. | `services/forensics/timeline.py` |
| **Information Disclosure** | Modifying S3 bucket policy to grant `Principal: *` on customer PII. | Storage | Misconfigured Identity / Adversary | `Rule007S3SecurityDrift` detects wildcard policies; `S3Remediator` immediately enforces Block Public Access. | `AEGIS-DET-007` / `services/remediation/` |
| **Information Disclosure** | Eavesdropping on telemetry in transit across AWS network. | Data Transit | Network Snooper | All communication enforces TLS 1.3; VPC Endpoints (PrivateLink) keep traffic on AWS private backbone. | `terraform/modules/telemetry/` |
| **Denial of Service** | Flooding telemetry pipeline with corrupted JSON or malformed records. | Ingestion Pipeline | External Attacker | Strict Pydantic v2 schemas reject unexpected fields; malformed records route directly to SQS DLQ. | `services/pipeline/processor.py` |
| **Denial of Service** | Inducing infinite remediation flapping on production compute instances. | Remediation Engine | Adversarial Manipulator | `CircuitBreaker` trips to `OPEN` state after 5 consecutive failures, halting active mutations. | `services/resilience/circuit_breaker.py` |
| **Elevation of Privilege** | Attaching `AdministratorAccess` to standard developer role or user. | IAM Permissions | Privilege Escalator | `Rule004PrivilegeEscalation` triggers CRITICAL finding; Step Functions detaches policy and revokes session. | `AEGIS-DET-004` / `services/remediation/` |
| **Elevation of Privilege** | Chaining unprivileged role into high-privilege cross-account DB admin role. | Identity Graph | Lateral Threat | Graph Engine calculates blast radius and identifies indirect paths to sensitive database assets. | `services/attack_path/graph.py` |

---

## 3. Residual Risk & Countermeasure Verification

1. **Zero Unhandled Single Points of Failure**: In the event that Amazon Neptune or SageMaker becomes unavailable, deterministic fallback evaluators (`ResilientGraphEvaluator`, `ResilientAnomalyEvaluator`) provide continuous security coverage without dropping findings.
2. **Mutual Exclusion Invariant**: Distributed race conditions are defended via conditional DynamoDB mutations (`attribute_not_exists`), preventing multiple containment executions on identical resources.
3. **Continuous Auditing**: Every containment action generates an immutable audit record and triggers automated post-containment verification before marking an incident resolved.
