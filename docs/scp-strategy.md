# AEGIS Service Control Policy (SCP) Strategy
## Enterprise Guardrails, Invariant Enforcement & Rollback Procedures

### 1. Guardrail Philosophy & Design Rules

Service Control Policies (SCPs) are organizational guardrails managed by AWS Organizations that define the maximum available permissions across an account or OU. 

**Critical Design Rules**:
1. **Never Lock Out the Management Account**: SCPs do not affect principals in the Management Account. However, to prevent self-inflicted lockouts, SCPs must never deny root break-glass or service-linked roles.
2. **Explicit Whitelisting / Blacklisting**: Use explicit `Deny` with condition exclusions (`StringNotLike`, `ArnNotLike`) rather than aggressive global deny rules.
3. **Every SCP Must Have an Operational Impact & Rollback Plan**: Guardrails must be documented with explicit business risk assessments before attachment.

---

### 2. Core Guardrail Policies

#### SCP 01: Prevent Disabling Security Services (`protect-security-controls`)
- **Purpose**: Deny any principal from stopping or deleting foundational security services.
- **Protected APIs**:
  - `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`
  - `guardduty:DeleteDetector`, `guardduty:DisassociateFromMasterAccount`, `guardduty:StopMonitoringMembers`
  - `securityhub:DisableSecurityHub`, `securityhub:DeleteMembers`
  - `config:DeleteDeliveryChannel`, `config:StopConfigurationRecorder`
- **Security Benefit**: Prevents an attacker with stolen administrative credentials from blinding the SOC prior to lateral movement.
- **Operational Impact**: Infrastructure automation cannot tear down or reconfigure security tools without explicit temporary SCP detachment.
- **Rollback Strategy**: Detach the policy from the target OU via the Management account console or Terraform pipeline.

#### SCP 02: Protect Centralized Logging & Evidence (`protect-log-archive`)
- **Purpose**: Prevent any principal in member accounts from tampering with, deleting, or altering centralized logging buckets, S3 Object Lock retention, or KMS encryption keys.
- **Protected APIs**:
  - `s3:DeleteBucket`, `s3:DeleteObject`, `s3:DeleteObjectVersion` on central log buckets
  - `s3:PutBucketPolicy` on centralized logging S3 buckets
  - `kms:ScheduleKeyDeletion`, `kms:DisableKey` on central logging KMS CMKs
- **Security Benefit**: Guarantees non-repudiation and prevents anti-forensics tampering during incident containment.
- **Operational Impact**: Storage administrators cannot prune log files manually; retention must rely strictly on S3 Lifecycle configurations.
- **Rollback Strategy**: Modify policy condition block in Terraform to add specific emergency maintenance IAM role ARN.

#### SCP 03: Restrict Unapproved AWS Regions (`restrict-regions`)
- **Purpose**: Restrict infrastructure provisioning and API calls to approved operational regions (`us-east-1`, `us-west-2`).
- **Protected APIs**: All EC2, RDS, Lambda, VPC actions where `aws:RequestedRegion` is not in approved list.
- **Security Benefit**: Blocks adversaries from launching rogue cryptominers or backdoor instances in obscure AWS regions (e.g. `ap-northeast-3`, `me-central-1`) where security monitoring may be unmonitored.
- **Operational Impact**: Global services (CloudFront, Route 53, IAM, STS) must be exempt (`aws:PrincipalARN`, global service actions exempt).
- **Rollback Strategy**: Add the newly approved region to the `StringNotEquals` list in the Terraform SCP module.

#### SCP 04: Prevent Accounts from Leaving the Organization (`deny-leaving-org`)
- **Purpose**: Deny member accounts from executing `organizations:LeaveOrganization`.
- **Security Benefit**: Prevents a rogue actor or malicious insider from detaching a workload account from organizational oversight, logging, and billing control.
- **Operational Impact**: Legitimate account decommissioning requires administrator intervention from the Management account.
- **Rollback Strategy**: Detach policy via Management account.

#### SCP 05: Emergency Account Quarantine (`quarantine-account`)
- **Purpose**: Extreme containment guardrail attached dynamically during high-confidence severe incidents.
- **Protected APIs**: Denies all actions except read-only inspection and AEGIS remediation roles.
- **Security Benefit**: Instantly halts all active data exfiltration and credential misuse across an entire AWS account.
- **Operational Impact**: Complete operational stoppage for workloads running in that account.
- **Rollback Strategy**: Detach the quarantine SCP from the account and re-attach standard OU policy.

---

### 3. Attachment Matrix

| Policy | Core Security OU | Workloads OU | Security Lab OU | Target Entity |
|---|---|---|---|---|
| `deny-leaving-org` | **Enforced** | **Enforced** | **Enforced** | Root |
| `protect-security-controls` | **Enforced** | **Enforced** | Optional (for tests) | Core & Workloads OU |
| `protect-log-archive` | **Enforced** | **Enforced** | **Enforced** | Log Archive & Workloads |
| `restrict-regions` | **Enforced** | **Enforced** | **Enforced** | Root / All OUs |
| `quarantine-account` | Standby | Standby | Standby (Tested in Lab) | Dynamic attachment per account |
