# SCENARIO-06: Suspicious EC2 API Activity Across Regions

### 1. Scenario ID
`SCENARIO-06`

### 2. Threat Model
- **MITRE ATT&CK**: T1078 (Valid Accounts) & T1526 (Cloud Service Discovery)
- **Threat Actor**: Compromised developer key used from an atypical geographic region (`ap-southeast-1`) to enumerate compute infrastructure.

### 3. Prerequisites
- Valid developer access key `AKIAEXAMPLEUNUSUAL`.

### 4. Simulation
`ec2:DescribeInstances` invoked from atypical public IP in an unapproved AWS region.

### 5. Expected Telemetry
CloudTrail event in `ap-southeast-1` from public IP `198.51.100.22`.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-002` (Suspicious Access-Key Misuse)
- **Severity**: `HIGH`
- **Confidence**: `0.80`

### 7. Expected Correlation
Identifies behavioral anomaly deviation across region and source IP dimensions.

### 8. Expected Risk
- **Risk Score**: `65.0` (`HIGH`)
- **Primary Drivers**: Atypical Region, High Behavioral Anomaly Score.

### 9. Expected Blast Radius
- **Blast Score**: `35.0 / 100`

### 10. Expected Response
`IAMRemediator` deactivates compromised access key `AKIAEXAMPLEUNUSUAL`.

### 11. Expected Verification
Verification validates access key status is `Inactive`.

### 12. Cleanup
Rollback returns key status to `Active`.
