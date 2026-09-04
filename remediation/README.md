# Automated Remediation & Containment Engine
## Project AEGIS - Phase 10

Implements least-privilege, idempotent, and reversible self-healing actions orchestrated via AWS Step Functions.

### Sub-Remediators
- `IAMRemediator`: Inactivates compromised access keys, attaches zero-trust session deny policies.
- `EC2Remediator`: Disassociates active security groups, assigns isolated quarantine SG, captures EBS forensic snapshots.
- `S3Remediator`: Enforces S3 Block Public Access and strips wildcard public policies.
- `AccountQuarantine`: Attaches restrictive containment SCP (defaulted to Security Lab).
