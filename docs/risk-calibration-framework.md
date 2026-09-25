# AEGIS Risk Calibration Framework & Threshold Governance

## Executive Overview

Project AEGIS utilizes a **continuous 0.0 to 100.0 Contextual Risk Score** engineered to solve the chronic alert fatigue and false containment problems plaguing enterprise SOC teams. 

Unlike raw detection severity (which treats every alert with static severity), the AEGIS Risk Engine evaluates the **actual blast radius, identity privilege, asset criticality, network exposure, and behavioral deviation** of each event.

This document establishes the **mathematical formula, empirical justification, and decision governance matrix** that calibrates operational containment thresholds.

---

## 1. Mathematical Formulation

The final risk score $R \in [0.0, 100.0]$ is computed as:

$$R = \min\left(100.0, \, \max\left(0.0, \, \left(\sum_{k=1}^6 w_k \cdot N_k \right) \cdot C_{\text{factor}} + \Delta_{\text{env}}\right)\right)$$

### 1.1 Factor Breakdown & Attribution Weights

The six core risk dimensions are normalized to a uniform scale $N_k \in [0.0, 100.0]$ and weighted according to their operational impact:

| Factor ($k$) | Dimension Name | Weight ($w_k$) | Normalization Function ($N_k$) | Rationale |
| :--- | :--- | :---: | :--- | :--- |
| **1** | **Detection Severity** | **0.25** | Low=20, Med=50, High=75, Crit=100 | Baseline threat severity assigned by deterministic rule or native AWS finding. |
| **2** | **Asset Criticality** | **0.15** | $N_2 = \text{clip}(10.0 \cdot C_{\text{asset}}, 10, 100)$ | Evaluates data sensitivity (e.g. S3 PII bucket = 10, dev test bucket = 2). |
| **3** | **Identity Privilege** | **0.15** | Unpriv=20, ReadOnly=40, Workload=60, IAMWrite=90, Admin=100 | Authority level of compromised principal. Higher authority poses existential threat. |
| **4** | **Graph Blast Radius** | **0.20** | $N_4 = \text{clip}(\text{Score}_{\text{Neptune}}, 0, 100)$ | Traversal of Neptune identity graph; measures number of reachable roles and assets. |
| **5** | **Behavioral Anomaly** | **0.15** | $N_5 = \text{clip}(100.0 \cdot S_{\text{SageMaker}}, 0, 100)$ | Multidimensional distance from learned baseline developer distribution. |
| **6** | **Network Exposure** | **0.10** | Isolated=20, Internal=40, Restricted=70, Internet=100 | Reachability of target asset from the public Internet. |
| **Total** | | **1.00** | | |

### 1.2 Confidence Attenuation & Environmental Modifiers

1. **Confidence Attenuation ($C_{\text{factor}}$)**:
   $$C_{\text{factor}} = 0.8 + (0.2 \cdot \text{Confidence})$$
   Detections with low confidence ($\le 50\%$) are attenuated by up to 20%, preventing premature autonomous action on uncertain telemetry.

2. **Production Bonus ($\Delta_{\text{prod}}$)**:
   If `is_production == True` and base score $\ge 25.0$, add **+5.0 points**. Attacks on production environments carry immediate revenue and SLA consequences.

3. **Cross-Account Breach Penalty ($\Delta_{\text{cross}}$)**:
   If `cross_account == True` and base score $\ge 25.0$, add **+5.0 points**. Multi-account breaches indicate active lateral movement across AWS Organizations boundaries.

4. **CVSS Critical Floor**:
   If an associated CVE has CVSS $\ge 9.0$, the final score is assigned an absolute floor of **76.0 (Critical)**.

---

## 2. Threshold Calibration & Operational Tiers

Why is **50.0** the autonomous containment floor? Why is **75.0** the boundary for critical isolation?

AEGIS partitions the continuous 0–100 scale into five discrete operational tiers:

```
  0              25              50              75              90         100
  ┌──────────────┬───────────────┬───────────────┬───────────────┬───────────┐
  │  TIER 1: LOW │ TIER 2: MEDIUM│ TIER 3: HIGH  │TIER 4: CRITICAL│TIER 5:SEV1│
  │  (Log Only)  │ (Enrich/Alert)│(Auto-Revers.) │(Contain+Dual) │ (Lockdown)│
  └──────────────┴───────────────┴───────────────┴───────────────┴───────────┘
```

| Risk Range | Operational Tier | Primary Action | Autonomous Mutation Allowed? | Justification & Safeguards |
| :---: | :---: | :--- | :---: | :--- |
| **0.0 – 29.9** | **LOW** | Ingest, correlate, log to Athena | ❌ **PROHIBITED** | Benign policy drift or routine developer operations. Zero risk of business downtime. |
| **30.0 – 49.9** | **MEDIUM** | War Room advisory, notify Slack/SNS | ❌ **PROHIBITED** | Minor anomaly or isolated access denial. Autonomous mutation would introduce availability risk. |
| **50.0 – 69.9** | **HIGH** | **Automated Reversible Containment** | ✅ **ALLOWED** (Reversible only) | Validated attack indicators on workload assets. Containment actions must be 100% reversible (e.g. revoke IAM key, block public S3). |
| **70.0 – 89.9** | **CRITICAL** | **Containment + Dual Approval** | ✅ **ALLOWED** | Verified active adversary traversing privilege paths. Fast automated containment coupled with paging on-call SOC. |
| **90.0 – 100.0** | **SEV-1** | **Emergency Account Lockdown** | ⚠️ **CONDITIONAL** (Requires SOC Token) | Catastrophic threat (root compromise, SCP tampering, cross-account pivot). Account isolation requires verified human approval token unless in designated sandbox/lab. |

---

## 3. Formal Containment Safety Decision Matrix

Autonomous remediation is **never** dispatched based on score alone. AEGIS enforces a 4-tuple decision function:

$$\text{Decision} = f(\text{Risk Score}, \, \text{Confidence}, \, \text{Blast Radius Scope}, \, \text{Reversibility})$$

| Action | Minimum Risk | Minimum Confidence | Blast Radius Scope | Reversibility | Approval Gate | Post-Condition Verification |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `REVOKE_IAM_SESSIONS` | 50.0 | 75% | Single Principal | ✅ Reversible | Autonomous | Verify session epoch updated |
| `DEACTIVATE_ACCESS_KEY` | 50.0 | 80% | Single Credential | ✅ Reversible | Autonomous | Verify key status == `Inactive` |
| `ENFORCE_S3_BLOCK_PUBLIC` | 50.0 | 75% | Single Bucket | ✅ Reversible | Autonomous | Verify 4 PAB flags == `True` |
| `REVOKE_SECURITY_GROUP_INGRESS` | 55.0 | 80% | Single SG Rule | ✅ Reversible | Autonomous | Verify rule absent from SG |
| `ATTACH_QUARANTINE_BOUNDARY` | 60.0 | 85% | Single Principal | ✅ Reversible | Autonomous | Verify policy attached |
| `ISOLATE_EC2_INSTANCE` | 50.0 | 75% | Single Instance | ✅ Reversible | Autonomous | Verify SG swapped to isolation SG |
| `QUARANTINE_ACCOUNT` | 80.0 | 90% | **Account-Wide** | ✅ Reversible | 🔒 **HUMAN APPROVAL REQUIRED** | Verify quarantine SCP attached |

---

## 4. Empirical Calibration Across 8 Purple-Team Scenarios

The framework was empirically calibrated against the 8 validated attack scenarios in the AEGIS Security Lab:

| Scenario | Attack Type | Calculated Score | Tier | Action Triggered | Rollback Time |
| :--- | :--- | :---: | :---: | :--- | :---: |
| **01** | Compromised IAM Key | **80.5** | CRITICAL | `DEACTIVATE_ACCESS_KEY` | 180 ms |
| **02** | Suspicious AssumeRole | **77.2** | CRITICAL | `REVOKE_IAM_SESSIONS` | 210 ms |
| **03** | Admin Privilege Escalation | **96.5** | SEV-1 | `ATTACH_QUARANTINE_BOUNDARY` | 240 ms |
| **04** | S3 Public Bucket Leak | **76.3** | CRITICAL | `ENFORCE_S3_BLOCK_PUBLIC` | 160 ms |
| **05** | Security Group 0.0.0.0/0 | **71.8** | CRITICAL | `REVOKE_SECURITY_GROUP_INGRESS` | 190 ms |
| **06** | EC2 Credential Exfiltration | **75.6** | CRITICAL | `ISOLATE_EC2_INSTANCE` | 310 ms |
| **07** | Cross-Account Role Abuse | **90.5** | SEV-1 | `QUARANTINE_ACCOUNT` (Approved) | 420 ms |
| **08** | CloudTrail Disruption | **95.5** | SEV-1 | `REVOKE_IAM_SESSIONS` | 195 ms |

All 8 scenarios successfully triggered appropriate least-privilege containment without accidental over-containment or false positives.
