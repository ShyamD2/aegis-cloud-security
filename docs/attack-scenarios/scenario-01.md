# SCENARIO-01: IAM Credential Compromise & Key Generation

### 1. Scenario ID
`SCENARIO-01`

### 2. Threat Model
- **MITRE ATT&CK**: T1098.001 (Account Manipulation: Additional Cloud Credentials)
- **Threat Actor**: External attacker with compromised developer console credentials attempting to establish secondary persistence via permanent access keys.

### 3. Prerequisites
- Target IAM user exists (`contractor-alice`) in Development/Lab account (`333333333333`).
- Telemetry pipeline active on `iam.amazonaws.com`.

### 4. Simulation
Attacker invokes AWS CLI `aws iam create-access-key --user-name contractor-alice` from an external public IP (`198.51.100.45`).

### 5. Expected Telemetry
CloudTrail record with:
- `eventName`: `CreateAccessKey`
- `eventSource`: `iam.amazonaws.com`
- `sourceIPAddress`: `198.51.100.45` (External)
- `responseElements.accessKey.accessKeyId`: Created key ID.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-001` (Suspicious IAM Access-Key Creation)
- **Severity**: `HIGH`
- **Confidence**: `0.85`

### 7. Expected Correlation
Attack-path engine links `contractor-alice` to potential role assumption chains leading to the Production environment.

### 8. Expected Risk
- **Risk Score**: `84.5` (`CRITICAL`)
- **Primary Drivers**: High Severity Detection, External IP Source, Active Attack Path Reachability.

### 9. Expected Blast Radius
- **Blast Score**: `78.0 / 100`
- **Exposed Assets**: Assumable `DevEngineer` role and S3 build buckets.

### 10. Expected Response
Step Functions invokes `IAMRemediator` with action `DEACTIVATE_ACCESS_KEY` for the newly minted credential.

### 11. Expected Verification
`IAMRemediator.verify()` queries IAM API and confirms key status is `Inactive`.

### 12. Cleanup
Rollback deactivation or delete the lab test key.
