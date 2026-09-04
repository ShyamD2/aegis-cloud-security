# SCENARIO-03: Administrative Privilege Escalation

### 1. Scenario ID
`SCENARIO-03`

### 2. Threat Model
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts) & T1098 (Account Manipulation)
- **Threat Actor**: Compromised developer account attempting to escalate permissions by attaching `AdministratorAccess` policy to self.

### 3. Prerequisites
- Target user `contractor-alice`.

### 4. Simulation
`iam:AttachUserPolicy` invoked with `policyArn: arn:aws:iam::aws:policy/AdministratorAccess`.

### 5. Expected Telemetry
CloudTrail record with `eventName`: `AttachUserPolicy`, `policyArn`: `AdministratorAccess`.

### 6. Expected Detection
- **Detection Rule**: `AEGIS-004` (Privilege Escalation Indicators)
- **Severity**: `CRITICAL`
- **Confidence**: `0.95`

### 7. Expected Correlation
Identifies self-privilege escalation loop on an active developer account.

### 8. Expected Risk
- **Risk Score**: `96.0` (`CRITICAL`)
- **Primary Drivers**: Administrator Policy Escalation, High Confidence.

### 9. Expected Blast Radius
- **Blast Score**: `100.0 / 100` (Full cloud administrator reach).

### 10. Expected Response
`IAMRemediator` invalidates all active user sessions and detaches the unauthorized admin policy.

### 11. Expected Verification
Verification confirms policy detachment and session cutoff policy presence.

### 12. Cleanup
Rollback verifies user returned to standard unprivileged role.
