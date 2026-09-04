# Purple-Team Attack Lab Scenarios
## Project AEGIS - Master Scenario Catalog

```
          ┌─────────────────────────────────────────────────────────────┐
          │               AEGIS Purple-Team Validation                  │
          │                                                             │
          │   [ATTACK] ──► [TELEMETRY] ──► [DETECTION] ──► [CORRELATION]│
          │                                                    │        │
          │   [CLEANUP] ◄── [VERIFY] ◄── [RESPONSE] ◄── [RISK]◄┘        │
          └─────────────────────────────────────────────────────────────┘
```

The AEGIS Purple-Team Attack Lab provides safe, deterministic, and fully reversible cloud attack simulations designed to prove that detection and autonomous self-healing engines operate with empirical precision.

### Scenario Matrix

| Scenario ID | Attack Category | Detection Rule | Target Resource | Containment Action |
| :--- | :--- | :--- | :--- | :--- |
| [`SCENARIO-01`](scenario-01.md) | IAM Credential Compromise | `AEGIS-001` | IAM User Access Key | `DEACTIVATE_ACCESS_KEY` |
| [`SCENARIO-02`](scenario-02.md) | Suspicious AssumeRole | `AEGIS-003` | Workload IAM Role | `REVOKE_IAM_SESSIONS` |
| [`SCENARIO-03`](scenario-03.md) | Privilege Escalation | `AEGIS-004` | IAM User Policy Attachment | `REVOKE_IAM_SESSIONS` |
| [`SCENARIO-04`](scenario-04.md) | S3 Security Misconfiguration | `AEGIS-007` | Production S3 Bucket | `ENFORCE_S3_BLOCK_PUBLIC` |
| [`SCENARIO-05`](scenario-05.md) | Security Group Ingress Exposure | `AEGIS-005` | EC2 Bastion Security Group | `ISOLATE_EC2_INSTANCE` |
| [`SCENARIO-06`](scenario-06.md) | Atypical Key Geo-Activity | `AEGIS-002` | EC2 Management API | `DEACTIVATE_ACCESS_KEY` |
| [`SCENARIO-07`](scenario-07.md) | Cross-Account Role Abuse | `AEGIS-009` | Cross-Account Production Role| `REVOKE_IAM_SESSIONS` |
| [`SCENARIO-08`](scenario-08.md) | CloudTrail Evasion / Tampering | `AEGIS-006` | Organization CloudTrail | `REVOKE_IAM_SESSIONS` |

### Safety Invariants
1. **Zero Real Malicious Payloads**: All simulations execute safe AWS API calls with simulated indicators.
2. **Strict Lab Account Isolation**: Simulations target only the designated Security Lab (`555555555555`) or isolated lab sandboxes.
3. **Guaranteed Cleanup**: Every scenario captures pre-remediation state and restores the original configuration post-verification.
