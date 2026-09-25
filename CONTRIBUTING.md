# Contributing to Project AEGIS

Thank you for your interest in contributing to **Project AEGIS** (*Autonomous Enterprise Guardian for Incident Security*)! We welcome contributions from cloud security researchers, DevSecOps practitioners, and software engineers.

---

## 1. Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all participants with respect, empathy, and professionalism.

---

## 2. Getting Started & Local Development Setup

### Prerequisites
- **Python**: Version `3.12+` or `3.13`
- **Terraform**: Version `1.8+`
- **Git**

### Installation

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/<your-username>/aegis-cloud-security.git
   cd aegis-cloud-security
   ```

2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # Windows (PowerShell):
   .\.venv\Scripts\Activate.ps1
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. Install development dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements-dev.txt
   pip install -e .
   ```

---

## 3. Development Standards & Quality Gates

Every pull request must pass all continuous integration quality gates before merge.

### Python Code Quality
- **Formatting & Linting**: We enforce strict PEP 8 and modern Python practices via `ruff`:
  ```bash
  ruff format --check .
  ruff check .
  ```
- **Type Safety**: Strict typing via `mypy`:
  ```bash
  mypy services/ tests/
  ```
- **Automated Testing & Coverage**:
  ```bash
  pytest --cov=services --cov-report=term-missing tests/
  ```

### Terraform Standards
- Format all configuration files recursively:
  ```bash
  terraform fmt -check -recursive terraform/
  ```
- Validate Terraform modules without backend initialization:
  ```bash
  cd terraform/environments/dev && terraform init -backend=false && terraform validate
  ```
- Ensure all resources have standard tags: `ManagedBy = "Terraform"`, `Project = "aegis"`.

---

## 4. Pull Request Workflow

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feat/add-new-detection-rule
   # or
   git checkout -b fix/remediation-idempotency-lock
   ```
2. **Commit Changes**: Use clear, conventional commit messages:
   - `feat(detection): add rule AEGIS-DET-011 for Route 53 DNS exfiltration`
   - `fix(remediation): enforce dry-run check in EC2 isolator`
   - `docs(risk): clarify 6-factor weight calibration`
3. **Run Pre-Commit Checks**: Ensure `ruff`, `mypy`, and `pytest` all pass locally.
4. **Submit PR**: Open a pull request against `main` using the [Pull Request Template](.github/pull_request_template.md).

---

## 5. Security Invariants for Contributors

When writing code for Project AEGIS, you must adhere to these safety rules:
- **Never hardcode AWS credentials, account IDs, or secrets.**
- **Remediation actions must be safe, idempotent, and reversible** whenever possible.
- **Always provide pre-state and post-state verification** for automated mutations.
- **Ensure no telemetry drop or unhandled exceptions** degrade the real-time processing loop.
