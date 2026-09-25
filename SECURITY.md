# Security Policy — Project AEGIS

Project AEGIS (*Autonomous Enterprise Guardian for Incident Security*) is committed to maintaining the highest security posture across all codified architectures, runtime detection pipelines, and autonomous remediation engines. We take security vulnerabilities seriously and appreciate the efforts of the security research community in responsibly disclosing vulnerabilities.

---

## 1. Supported Versions

Only the latest release on the primary development branch (`main`) receives active security updates and vulnerability patches.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main` (v1.x)    | :white_check_mark: |
| `< 1.0.0`        | :x:                |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or weakness within Project AEGIS, please **DO NOT open a public GitHub issue, pull request, or discussion**. Instead, please report it privately via one of the following channels:

1. **GitHub Private Security Advisory**: Use the **Report a vulnerability** tab under the repository's [Security Advisories](https://github.com/ShyamD2/aegis-cloud-security/security/advisories) section.
2. **Security Contact**: Email our core security team at `security@project-aegis.dev` (or the repository maintainer) with the subject line `[SECURITY ADVISORY] <Brief Summary>`.

### Required Information
To help us triage and resolve the issue quickly, please include:
- Description of the vulnerability and its potential impact.
- Affected components (e.g. Terraform module, Lambda handler, detection rule, SOAR Step Functions).
- Step-by-step reproduction instructions or proof-of-concept (PoC) code.
- Any suggested mitigations or remediation patches.

---

## 3. Vulnerability Response Timeline

Our security team adheres to the following coordinated vulnerability response timeline:

- **Initial Acknowledgement**: Within **24 hours** of submission.
- **Triage & Severity Assessment**: Within **72 hours**, using CVSS v3.1 scoring.
- **Fix Development & Testing**: Target within **7 to 14 business days** depending on severity.
- **Coordinated Public Disclosure**: Within **30 to 90 days** from initial notification, allowing users time to apply patches.

---

## 4. Safe Harbor & Research Guidelines

We consider security research conducted in good faith under this policy to be authorized. We will not pursue legal action against researchers who:
- Comply with all applicable laws and respect privacy.
- Avoid accessing, modifying, or destroying user data or production environments.
- Conduct testing exclusively against synthetic test harnesses or isolated personal AWS accounts.
- Provide us a reasonable amount of time to remediate the vulnerability before public disclosure.

---

## 5. Security Architecture Invariants

Project AEGIS is designed around the following core security principles:
1. **Zero Static Credentials**: All AWS authentication is conducted via short-lived AWS IAM OpenID Connect (OIDC) federation tokens.
2. **Least-Privilege Execution Boundaries**: Workload roles are strictly scoped; `AdministratorAccess` is explicitly barred.
3. **Immutable Evidence Integrity**: Forensic records are cryptographically sealed with SHA-256 and KMS asymmetric signatures into Amazon S3 Object Lock compliance vaults.
4. **Idempotency & Race Safety**: Distributed locks prevent duplicate or cascading autonomous remediation actions.
