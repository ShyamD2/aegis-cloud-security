# SCENARIO-07: Cross-Account Role Abuse & Lateral Pivot

### 1. Scenario ID
`SCENARIO-07`

### 2. Threat Model
- **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism) & T1078 (Valid Accounts)
- **Threat Actor**: Principal from an untrusted external AWS account attempting to assume sensitive cross-account roles in the production environment.

### 3. Prerequisites
- Production role `CrossAccountProdReader` in account `111111111111`.

### 4. Simulation
`sts:AssumeRole` invoked by principal `arn:aws:sts::999999999999:assumed-role/UnknownExternalRole` targeting production role.

### 5. Expected Telemetry
CloudTrail record in `111111111111` with caller identity from external untrusted account `999999999999`.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-009` (Cross-Account Role Abuse)
- **Severity**: `CRITICAL`
- **Confidence**: `0.90`

### 7. Expected Correlation
Identifies unauthorized foreign account attempting lateral entry into production tier.

### 8. Expected Risk
- **Risk Score**: `90.0` (`CRITICAL`)
- **Primary Drivers**: Cross-Account Breach Modifier (+5.0), Production Environment Bonus (+5.0).

### 9. Expected Blast Radius
- **Blast Score**: `90.0 / 100`

### 10. Expected Response
`IAMRemediator` invalidates active sessions on `CrossAccountProdReader`.

### 11. Expected Verification
Verification validates session revocation policy with `aws:TokenIssueTime` condition is active.

### 12. Cleanup
Rollback removes temporary inline revocation policy.
