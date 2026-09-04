# Security Risk Engine & Explainable Decision Model
## Project AEGIS - Phase 09 Architecture & Technical Specification

```
                   ┌─────────────────────────────────────────┐
                   │           AEGIS Context Inputs          │
                   └────────────────────┬────────────────────┘
                                        │
     ┌──────────────────┬───────────────┼───────────────┬──────────────────┐
     ▼                  ▼               ▼               ▼                  ▼
┌──────────┐     ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    ┌─────────────┐
│ Finding  │     │    Asset    │ │  Identity   │ │ Attack Graph│    │ SageMaker   │
│ Severity │     │ Criticality │ │  Privilege  │ │Blast Radius │    │ Anomaly     │
│ (25%)    │     │   (15%)     │ │   (15%)     │ │   (20%)     │    │   (15%)     │
└────┬─────┘     └──────┬──────┘ └──────┬──────┘ └──────┬──────┘    └──────┬──────┘
     │                  │               │               │                  │
     └──────────────────┴───────────────┼───────────────┴──────────────────┘
                                        │ Weighted Normalization (∑ = 1.0)
                                        ▼
                         ┌─────────────────────────────┐
                         │   Exposure Level (10%)      │
                         │   & Confidence Scaling      │
                         └──────────────┬──────────────┘
                                        │ Environmental Modifiers
                                        ▼
                         ┌─────────────────────────────┐
                         │    Final Score (0 - 100)    │
                         │    Explainable Decision     │
                         └─────────────────────────────┘
```

---

### 1. Mathematical Formulation

The AEGIS Risk Engine quantifies contextual security risk into a deterministic integer score \(R \in [0.0, 100.0]\).

$$\text{BaseScore} = \sum_{i=1}^{6} w_i \cdot N_i$$

$$\text{ScaledScore} = \text{BaseScore} \times \left(0.8 + 0.2 \cdot \text{Confidence}\right)$$

$$R = \min\left(100.0, \; \max\left(0.0, \; \text{round}(\text{ScaledScore} + \Delta_{\text{env}}, 1)\right)\right)$$

#### 1.1 Factor Weight Distribution
| Factor (\(i\)) | Weight (\(w_i\)) | Raw Range | Normalization Formula (\(N_i \in [0, 100]\)) |
| :--- | :--- | :--- | :--- |
| **Detection Severity** | `0.25` | `LOW`, `MED`, `HIGH`, `CRIT` | `LOW: 20`, `MEDIUM: 50`, `HIGH: 75`, `CRITICAL: 100` |
| **Asset Criticality** | `0.15` | `1.0` to `10.0` | \(\min(100.0, \; \text{Raw} \times 10.0)\) |
| **Identity Privilege** | `0.15` | 5 Privilege Tiers | `UNPRIV: 20`, `READ: 40`, `WRITE: 60`, `IAM: 90`, `ADMIN: 100` |
| **Graph Blast Radius** | `0.20` | `0.0` to `100.0` | \(\text{Raw Blast Score (Phase 08)}\) |
| **SageMaker Anomaly** | `0.15` | `0.0` to `1.0` | \(\text{Raw Score} \times 100.0\) |
| **Network Exposure** | `0.10` | 4 Exposure Tiers | `ISOLATED: 20`, `VPC: 40`, `RESTRICTED: 70`, `INTERNET: 100` |

#### 1.2 Contextual Modifiers (\(\Delta_{\text{env}}\))
- **Production Asset Bonus**: \(+5.0\) points if `is_production = true` and \(\text{ScaledScore} \ge 25.0\).
- **Cross-Account Traversal**: \(+5.0\) points if finding spans cross-account trusts and \(\text{ScaledScore} \ge 25.0\).
- **CVSS Critical Floor**: If `vulnerability_cvss >= 9.0`, enforces a minimum floor score of `75.0` (`CRITICAL`).

---

### 2. Risk Classification & Operational Response

| Range | Level | Operational Posture | Automated Action |
| :--- | :--- | :--- | :--- |
| **0 – 25** | `LOW` | Benign or low-impact deviation | Log telemetry, update local registry, no active containment. |
| **26 – 50** | `MEDIUM` | Policy drift or suspicious access | Publish War Room advisory, notify security operations via SNS. |
| **51 – 75** | `HIGH` | Verified privilege escalation | Trigger human approval workflow for targeted role containment. |
| **76 – 100** | `CRITICAL` | Confirmed lateral breach / credential theft | Autonomous Step Functions execution: isolate instance, revoke active sessions. |

---

### 3. Factor Attribution & Explainability

Every evaluation returns an array of `RiskFactorContribution` objects detailing:
1. `raw_value`: Unprocessed telemetry metric.
2. `normalized_value`: Scaled \(0.0 - 100.0\) factor metric.
3. `weight`: Multiplier applied.
4. `weighted_contribution`: Exact points contributed to the final score.
5. `narrative`: Plain-language justification for auditors.

#### Example Output:
```json
{
  "assessment_id": "risk-9b1c7a810f22",
  "finding_id": "finding-iam-priv-esc-001",
  "risk_score": 94.2,
  "risk_level": "CRITICAL",
  "recommended_action": "Execute autonomous Step Functions containment (quarantine security group, attach deny-all boundary).",
  "explanation": "Risk Score: 94.2/100 [CRITICAL]. Primary drivers: Detection Severity (25.0 pts), Graph Blast Radius (20.0 pts), Identity Privilege (15.0 pts). Confidence: 100%. Modifiers: +5.0 Production Environment Bonus; +5.0 Cross-Account Breach Penalty."
}
```

---

### 4. Explicit Anti-Overclaiming & Model Limitations

> [!IMPORTANT]
> **This is an AEGIS internal contextual scoring model, NOT an AWS or NIST standard.**
>
> 1. The scoring weights and linear combination are calibrated specifically for Project AEGIS's multi-account lab and enterprise simulation environment.
> 2. It does not replace CVSS, EPSS, or formal risk governance frameworks (e.g. NIST SP 800-30, FAIR).
> 3. Asset criticalities and exposure levels must be accurately populated in AWS resource tags or the AEGIS Graph compiler to ensure realistic score calculations.
