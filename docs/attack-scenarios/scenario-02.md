# SCENARIO-02: Suspicious AssumeRole Invocation

### 1. Scenario ID
`SCENARIO-02`

### 2. Threat Model
- **MITRE ATT&CK**: T1548.005 (Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access)
- **Threat Actor**: Compromised identity executing lateral movement by assuming internal service or development roles.

### 3. Prerequisites
- Workload IAM role `DevEngineer` with trust policy allowing assumption by `contractor-alice`.

### 4. Simulation
`sts:AssumeRole` invoked from an external IP address targeting `arn:aws:iam::333333333333:role/DevEngineer`.

### 5. Expected Telemetry
CloudTrail record with `eventSource`: `sts.amazonaws.com`, `eventName`: `AssumeRole`, and target role ARN in `requestParameters`.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-003` (Unusual AssumeRole Invocation)
- **Severity**: `HIGH`
- **Confidence**: `0.80`

### 7. Expected Correlation
Correlator maps lateral hop from user `contractor-alice` to role `DevEngineer`.

### 8. Expected Risk
- **Risk Score**: `76.2` (`CRITICAL`)
- **Primary Drivers**: Elevated Role Privilege, External IP Origin.

### 9. Expected Blast Radius
- **Blast Score**: `65.0 / 100`

### 10. Expected Response
`IAMRemediator` attaches an inline policy with `Condition: {"DateLessThan": {"aws:TokenIssueTime": "<timestamp>"}}` invalidating older sessions.

### 11. Expected Verification
Verification checks role inline policies to confirm the session revocation policy is attached.

### 12. Cleanup
Rollback detaches the temporary inline session revocation policy.
