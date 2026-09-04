# SCENARIO-04: S3 Security Misconfiguration

### 1. Scenario ID
`SCENARIO-04`

### 2. Threat Model
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object) & T1565 (Data Manipulation)
- **Threat Actor**: Malicious insider or rogue automation attempting to expose customer PII storage to public internet by disabling Block Public Access.

### 3. Prerequisites
- Target bucket `prod-customer-pii-vault`.

### 4. Simulation
`s3:DeleteAccountPublicAccessBlock` or `s3:PutBucketPolicy` granting `Principal: *` and `s3:GetObject`.

### 5. Expected Telemetry
CloudTrail record with `eventSource`: `s3.amazonaws.com`, `eventName`: `DeleteAccountPublicAccessBlock` or `PutBucketPolicy`.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-007` (S3 Security Configuration Modification)
- **Severity**: `CRITICAL`
- **Confidence**: `0.90`

### 7. Expected Correlation
Correlates action to sensitive customer PII storage asset with criticality 9.5.

### 8. Expected Risk
- **Risk Score**: `92.0` (`CRITICAL`)
- **Primary Drivers**: Sensitive Asset Criticality, Internet Exposure Posture.

### 9. Expected Blast Radius
- **Blast Score**: `85.0 / 100`

### 10. Expected Response
`S3Remediator` applies `put_public_access_block` enforcing all 4 protection flags.

### 11. Expected Verification
Verification validates `GetPublicAccessBlock` returns True for all 4 flags.

### 12. Cleanup
Rollback restores original configuration if required by test harness.
