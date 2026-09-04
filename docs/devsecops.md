# Project AEGIS - DevSecOps Pipeline & Shift-Left Architecture
## Phase 15 Specification: Zero-Trust CI/CD, OIDC Federation & Automated Security Gates

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                           AEGIS DevSecOps Pipeline                          │
  │                                                                             │
  │  [Developer Commit]                                                         │
  │          │                                                                  │
  │          ▼                                                                  │
  │  [Pre-Commit / Push] ──► [TruffleHog: Zero Secrets]                        │
  │          │           ──► [Ruff / Mypy: Syntax & Type Safety]                │
  │          │                                                                  │
  │          ▼                                                                  │
  │  [GitHub Actions CI] ──► [Bandit: Python SAST Security Audit]               │
  │          │           ──► [Checkov: IaC & Terraform Benchmark Scanning]      │
  │          │           ──► [Trivy: Filesystem & Dependency CVE Analysis]      │
  │          │           ──► [Pytest: 95+ Unit & Adversarial Tests]             │
  │          │                                                                  │
  │          ▼                                                                  │
  │  [OIDC Auth Gate]   ──► [AWS STS: AssumeRoleWithWebIdentity]                │
  │          │               (ZERO Static AWS Keys, 1-Hour Ephemeral Token)     │
  │          │                                                                  │
  │          ▼                                                                  │
  │  [Deployment]       ──► [Least-Privilege Scoped Deployer Role]              │
  │                          (NO AdministratorAccess, Tag-Enforced Mutations)   │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

Project AEGIS enforces an uncompromising **Shift-Left DevSecOps** posture. Cloud defense infrastructure cannot be trusted if the pipeline that builds and deploys it is vulnerable to supply chain attacks, credential theft, or misconfigured permissions.

The AEGIS CI/CD pipeline guarantees:
1. **Zero Long-Lived Credentials**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are permanently banned from GitHub Secrets. All AWS authentication utilizes **GitHub Actions OpenID Connect (OIDC)** federated through AWS STS.
2. **Multi-Layer Static & Dynamic Security Gates**: Every commit and pull request must pass automated secret scanning, Python SAST, IaC security scanning, and dependency vulnerability audits before merge.
3. **Least-Privilege Scoped Deployment**: The CI/CD deployer role explicitly prohibits `AdministratorAccess` and is constrained strictly to AEGIS service namespaces and state resources.

---

## 2. Automated Security Scanning Matrix

| Stage | Tool | Engine | Target | Enforcement / Threshold |
| :--- | :--- | :--- | :--- | :--- |
| **Secret Detection** | **TruffleHog OSS** | Entropy & Regex Analysis | Entire git history & commit diffs | **Zero tolerance**: Any high-entropy string or known key pattern blocks pipeline. |
| **Python SAST** | **Bandit** (`pyproject.toml`) | AST Security Inspection | `services/`, `detection_engine/` | High/Medium severity vulnerabilities (injections, weak crypto, unsafe deserialization) fail build. |
| **Code Hygiene** | **Ruff & Mypy** | Fast Rust Linter & Type Checker | Full repository | Enforces Python 3.12+ type consistency, strict imports, and PEP compliance. |
| **IaC Security** | **Checkov** | Static Analysis Framework | `terraform/` (all modules) | Audits against CIS AWS Foundations Benchmark, Well-Architected Security Pillar. Outputs SARIF to GitHub Security tab. |
| **Vulnerability Analysis** | **Trivy** | CVE & Package Database | Dependencies & Filesystem | Scans for known CVEs in Python dependencies. Uploads SARIF report. |
| **Automated Testing** | **Pytest** | Test Engine + Coverage | `tests/unit/` (95+ tests) | Enforces 100% pass rate across detection, risk engine, forensics, and resilience suites. |

---

## 3. GitHub Actions AWS OIDC Federation (Zero Static Credentials)

### 3.1. Architectural Risk of Long-Lived Credentials
Traditional CI/CD pipelines store long-lived IAM User access keys in repository secrets (`AWS_ACCESS_KEY_ID`). If repository maintainers, GitHub Action dependencies, or runner environments are compromised, these credentials can be exfiltrated and used indefinitely without geographical or temporal boundaries.

### 3.2. AEGIS OIDC Architecture
AEGIS authenticates using **AWS IAM OpenID Connect (OIDC)** identity federation:
1. GitHub Actions spins up an ephemeral runner with a signed OIDC JSON Web Token (JWT).
2. The runner invokes `sts:AssumeRoleWithWebIdentity` against AWS STS.
3. AWS validates the JWT signature against `https://token.actions.githubusercontent.com`.
4. AWS validates that the token audience is `sts.amazonaws.com` and that the subject matches:
   ```hcl
   condition {
     test     = "StringEquals"
     variable = "token.actions.githubusercontent.com:aud"
     values   = ["sts.amazonaws.com"]
   }
   condition {
     test     = "StringLike"
     variable = "token.actions.githubusercontent.com:sub"
     values   = ["repo:Project-AEGIS/PROJECT-AEGIS:ref:refs/heads/main"]
   }
   ```
5. AWS returns short-lived (1-hour) temporary session credentials. No keys are ever written to disk or stored in GitHub.

---

## 4. Least-Privilege Deployer IAM Role (`aegis-prod-github-deployer-role`)

The deployment role created by `terraform/modules/oidc_deployer/` adheres strictly to the principle of least privilege:

```hcl
# Scoped strictly to AEGIS service namespaces
statement {
  sid    = "AEGISWorkloadDeployment"
  effect = "Allow"
  actions = [
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "states:CreateStateMachine",
    "states:UpdateStateMachine",
    "dynamodb:CreateTable",
    "dynamodb:UpdateTable",
    "sqs:CreateQueue",
    "kinesis:CreateStream",
    "events:PutRule",
    "events:PutTargets"
  ]
  resources = [
    "arn:aws:lambda:*:*:function:aegis-*",
    "arn:aws:states:*:*:stateMachine:aegis-*",
    "arn:aws:dynamodb:*:*:table/aegis-*",
    "arn:aws:sqs:*:*:aegis-*",
    "arn:aws:kinesis:*:*:stream/aegis-*",
    "arn:aws:events:*:*:rule/aegis-*"
  ]
}
```

### Security Invariants:
- **No Wildcard Resource Mutations**: Action statements cannot modify arbitrary AWS resources outside the `aegis-*` namespace.
- **No IAM User Creation**: The CI/CD role cannot create IAM users, access keys, or modify root settings.
- **No SCP Modification**: Service Control Policies are strictly managed out-of-band by AWS Organization root administrators.

---

## 5. Pipeline Workflows Reference

1. [`.github/workflows/ci.yml`](../.github/workflows/ci.yml): Python code quality, linting, formatting, type checking, unit tests, and Terraform validation.
2. [`.github/workflows/security.yml`](../.github/workflows/security.yml): TruffleHog secret scanning, Bandit Python SAST, Checkov IaC scanning, and Trivy CVE scanning.
3. [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml): OIDC-authenticated plan and apply pipelines with GitHub Environment approval gates.
