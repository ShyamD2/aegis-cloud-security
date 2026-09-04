# Blast-Radius Impact Model
## Project AEGIS - Deterministic Reachability & Risk Quantification

```
                        ┌──────────────────────────────┐
                        │   Compromised Principal      │
                        └──────────────┬───────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
     ┌──────────────────────┐                      ┌──────────────────────┐
     │  Direct Reachability │                      │ Indirect Reachability│
     │    (1-Hop Access)    │                      │  (Role Escalation)   │
     └──────────┬───────────┘                      └──────────┬───────────┘
                │                                             │
                └──────────────────────┬──────────────────────┘
                                       ▼
                     ┌────────────────────────────────────┐
                     │    Multi-Account Blast Score       │
                     │  S = min(100.0, ∑ Weighted Factors)│
                     └────────────────────────────────────┘
```

---

### 1. Mathematical Formulation

The AEGIS Blast Radius Model computes an explainable, deterministic impact score \(S \in [0.0, 100.0]\) measuring the potential damage radius from a compromised identity.

$$\text{RawScore} = w_{\text{dir}} N_{\text{dir}} + w_{\text{ind}} N_{\text{ind}} + w_{\text{role}} N_{\text{role}} + w_{\text{sens}} \sum_{r \in \mathcal{R}_{\text{sens}}} C(r) + \beta_{\text{cross}} N_{\text{extra\_acc}}$$

$$S = \min\left(100.0, \; \text{round}(\text{RawScore}, 2)\right)$$

#### Model Parameters & Calibrated Weights
| Parameter | Notation | Default Weight | Justification |
| :--- | :--- | :--- | :--- |
| Direct Resource Weight | \(w_{\text{dir}}\) | `3.0` | Immediate 1-hop exposure without assuming lateral roles. |
| Indirect Resource Weight | \(w_{\text{ind}}\) | `4.5` | Latent exposure accessible via privilege escalation or role-chaining. |
| Assumable Role Weight | \(w_{\text{role}}\) | `8.0` | Each assumable role grants an additional lateral mobility pivot. |
| Sensitive Resource Multiplier | \(w_{\text{sens}}\) | `5.0` | Multiplied by target asset criticality \(C(r) \in [1.0, 10.0]\). |
| Cross-Account Penalty | \(\beta_{\text{cross}}\) | `15.0` | Penalty per extra account compromised beyond the principal's home account. |

---

### 2. Factor Definitions

1. **Direct Reachability (\(N_{\text{dir}}\))**:
   Workload resources (S3 buckets, RDS clusters, Secrets, EC2 instances) to which the compromised principal possesses explicit data-plane permissions without executing `sts:AssumeRole`.
2. **Indirect Reachability (\(N_{\text{ind}}\))**:
   Workload resources reachable only after traversing one or more `ASSUME_ROLE` edges. Direct resources are subtracted from this set to eliminate double-counting.
3. **Assumable Roles (\(N_{\text{role}}\))**:
   IAM roles whose trust policies and permission boundaries allow the principal (or any upstream role in the chain) to invoke `sts:AssumeRole`.
4. **Sensitive Asset Criticality (\(\sum C(r)\))**:
   Assets flagged with `is_sensitive = true` (e.g. customer PII vaults, master database credentials, production databases). Assets with \(C(r) \ge 9.0\) heavily escalate the score.
5. **Cross-Account Expansion (\(N_{\text{extra\_acc}}\))**:
   Number of unique external AWS accounts reachable through cross-account trust relationships, breaking boundary containment.

---

### 3. Empirical Evaluation Examples

#### Scenario A: Compromised Contractor (`contractor-alice`)
- **Direct**: `arn:aws:s3:::dev-build-artifacts` (\(N_{\text{dir}} = 1\))
- **Assumable Roles**: `DevEngineer`, `CrossAccountProdReader`, `ProdDatabaseAdmin` (\(N_{\text{role}} = 3\))
- **Indirect**: `prod-customer-pii-vault`, `prod-db-master-creds`, `prod-core-aurora` (\(N_{\text{ind}} = 3\))
- **Sensitive Assets**: 3 assets with criticalities 9.5, 10.0, 10.0 (\(\sum C(r) = 29.5\))
- **Cross-Account**: 1 external account (`111111111111`, \(N_{\text{extra\_acc}} = 1\))
- **Raw Calculation**:
  $$\text{RawScore} = (1 \times 3.0) + (3 \times 4.5) + (3 \times 8.0) + (5.0 \times 29.5) + (1 \times 15.0) = 3.0 + 13.5 + 24.0 + 147.5 + 15.0 = 203.0$$
  $$\mathbf{Score = 100.0 / 100.0} \quad (\text{CRITICAL IMPACT})$$

#### Scenario B: Isolated Intern (`intern-bob`)
- **Direct**: `arn:aws:s3:::dev-build-artifacts` (\(N_{\text{dir}} = 1\))
- **Assumable Roles**: 0 (\(N_{\text{role}} = 0\))
- **Indirect**: 0 (\(N_{\text{ind}} = 0\))
- **Sensitive Assets**: 0 (\(\sum C(r) = 0\))
- **Cross-Account**: 0 (\(N_{\text{extra\_acc}} = 0\))
- **Raw Calculation**:
  $$\text{RawScore} = 1 \times 3.0 = 3.0$$
  $$\mathbf{Score = 3.0 / 100.0} \quad (\text{LOW IMPACT})$$

---

### 4. Containment Constraints & Architectural Assumptions

> [!NOTE]
> The blast radius calculation models *worst-case reachable authorization space*.
> It assumes:
> 1. Valid network routes exist between caller environments and resource VPC endpoints.
> 2. Organization SCPs that explicitly deny services (e.g. denying all actions outside approved regions) override role permissions and restrict the theoretical maximum blast radius.
