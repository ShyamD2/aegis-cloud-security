# Changelog

All notable changes to Project AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-25

### Added
- **OCSF Telemetry Normalization**: Full Open Cybersecurity Schema Framework v1.1.0 engine mapping CloudTrail, VPC Flow, DNS, GuardDuty, and Security Hub into canonical OCSF events.
- **KMS Asymmetric Manifest Signing**: Upgraded forensic evidence engine from SHA-256 digests to RSA-PSS / ECDSA KMS asymmetric digital signatures, guaranteeing non-repudiation and legal authenticity.
- **Remediation Safety Controls & Governance**:
  - Configurable execution modes: `RECOMMENDATION` (default), `DRY_RUN`, and `ENFORCE`.
  - Automated emergency kill switch (`AEGIS_KILL_SWITCH_ACTIVE`).
  - Account-level blast-radius rate limiting.
  - Formal `ContainmentSafetyPolicy` evaluating reversibility, confidence, and human approval gates.
- **Attack Replay & Verified Response Engine**: New CLI tool `scripts/aegis_replay.py` simulating real attack scenarios and verifying end-to-end detection, containment, and forensic sealing.
- **Risk Calibration Framework**: Complete mathematical documentation and empirical justification for the 0–100 risk score and operational action tiers.
- **ML Anomaly Benchmark & Research Matrix**: Comprehensive dataset generator and evaluation suite comparing Rules Only, ML Only, Hybrid, and Graph-Enriched detection.
- **Interactive Cost Calculator**: CLI tool `scripts/cost_calculator.py` estimating AWS monthly costs across event volumes for both Enterprise Full and Lite architectures.
- **Single-Account "Lite" Quick Start**: Detailed deployment guide for low-cost, minimal AWS environments.
- **MITRE ATT&CK Matrix**: Comprehensive coverage mapping across 8 core attack scenarios.
- **Open-Source Community Hygiene**: Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, PR template, and Dependabot.

### Changed
- Clarified performance metrics: strictly separated in-memory local engine latency (p50: 0.285 ms) from live AWS telemetry ingestion latency, API containment latency, and end-to-end attack containment time.
- Updated compliance claims: refined "SEC Rule 17a-4 compliant" to "SEC Rule 17a-4-oriented immutable evidence architecture".
- Clarified S3 Object Lock modes: Governance mode for staging/testing vs Compliance mode for production WORM storage.
- Retitled internal security assessment to "AEGIS Internal Technical Security Assessment & Codebase Audit Review" with transparent STRIDE / CIS / OWASP methodology.
- Cleaned up root package duplication by removing legacy `detection-engine/`.

---

## [0.1.0] - Initial Prototype

### Added
- Multi-account Terraform infrastructure codifying Organizations, SCPs, KMS, Kinesis, DynamoDB, and S3.
- Core Python services: Telemetry parsing, 10 deterministic detection rules, Neptune attack-path graph traversal, SageMaker anomaly scoring, 6-factor risk engine, and Step Functions SOAR orchestrator.
- S3 Object Lock forensic vault with canonical SHA-256 evidence assembly.
- React + Cognito SOC War Room API.
- 8 automated purple-team attack scenarios and initial unit test suite (110 tests).
