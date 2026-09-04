# AEGIS Terraform Modules
## Reusable Least-Privilege Cloud Security Infrastructure Modules

This directory contains modular Terraform components for Project AEGIS:

- `organization/`: AWS Organizations, Account hierarchy, and Service Control Policies (SCPs) - (Phase 02)
- `iam/`: Role definitions, trust policies, and permission boundaries - (Phase 02)
- `telemetry/`: Centralized CloudTrail, S3 Log Archive, and Kinesis pipelines - (Phase 03 / Phase 06)
- `detection/`: GuardDuty, Security Hub, Config, and custom detection Lambda resources - (Phase 04 / Phase 05)
- `remediation/`: Step Functions state machines and scoped remediator Lambdas - (Phase 10)
- `forensics/`: S3 Object Lock evidence vault and Athena workgroups - (Phase 11)
