# Digital Forensics & Immutable Evidence Engine
## Project AEGIS - Phase 11

Captures cryptographic evidence manifests, stores forensic artifacts in S3 Object Lock (Compliance Mode), and provides Athena/OpenSearch incident timeline queries.

### Components
- Evidence collector and manifest generator (SHA-256 state hashing).
- KMS-encrypted forensic evidence vault.
- Amazon Athena queries for reconstructed attack timelines.
