# AEGIS Deployment & Engineering Setup
## Environment Prerequisites, Bootstrap Process & Local Development

### 1. Prerequisites & Tooling

To develop, validate, and deploy Project AEGIS, ensure the following tools are installed:

- **Terraform**: `v1.5.0+` (Tested on `v1.15.8+`) or OpenTofu `v1.6.0+`
- **Python**: `3.12+` (Tested on `3.13.0`)
- **AWS CLI**: `v2.15+` configured with administrative permissions in the Management Account or delegated security admin role.
- **Git**: `2.40+`
- **Node.js & npm**: `v20+` (Required for Phase 12 War Room Dashboard).

---

### 2. Repository Layout & Engineering Standards

```text
project-aegis/
├── terraform/
│   ├── bootstrap/            # S3 remote state bucket, DynamoDB lock table, KMS CMKs
│   ├── modules/              # Reusable least-privilege infrastructure components
│   └── environments/         # Root deployment configurations (dev, lab, prod)
├── services/                 # Common Python runtime libraries and event schemas
├── detection-engine/         # High-throughput detection rules
├── correlation-engine/       # Multi-event correlation logic
├── attack-path/              # Neptune graph builder and query engine
├── risk-engine/              # Contextual 0-100 risk calculation
├── remediation/              # Step Functions containment handlers
├── forensics/                # S3 Object Lock evidence collectors
├── dashboard/                # React / TypeScript SOC frontend
├── attack-lab/               # Controlled purple-team attack scenarios
├── tests/                    # Unit, integration, and security test harnesses
└── docs/                     # Architectural, threat model, and engineering guides
```

---

### 3. Bootstrap Phase (Terraform Remote State)

Before provisioning AEGIS microservices, the remote state foundation must be established:

```bash
# 1. Navigate to bootstrap directory
cd terraform/bootstrap

# 2. Copy and configure variables
cp terraform.tfvars.example terraform.tfvars
# Update bucket_prefix, aws_region, and tags

# 3. Initialize and deploy remote state backend
terraform init
terraform plan -out=bootstrap.tfplan
terraform apply bootstrap.tfplan
```

The bootstrap module creates:
- Customer-managed AWS KMS key for state encryption with key rotation enabled.
- Encrypted S3 bucket with versioning, S3 Public Access Block, and SSL enforcement policy.
- DynamoDB table with `LockID` string primary key for distributed state locking.

---

### 4. Local Development & Testing Workflow

```bash
# Set up Python virtual environment
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows PowerShell:
.\.venv\Scripts\activate

# Install all development dependencies
pip install -r requirements-dev.txt

# Run code linter and formatting checks
ruff check .
ruff format --check .

# Automatically fix lint issues and format code
ruff check --fix .
ruff format .

# Run test suite with coverage
pytest --cov=services --cov=detection_engine -v

# Validate Terraform configurations recursively
terraform fmt -check -recursive terraform/
cd terraform/bootstrap && terraform init -backend=false && terraform validate
```

---

### 5. Multi-Account Deployment Staging

AEGIS deployments follow a strict promotion model:
1. **Security Lab**: All new detection rules, ML models, and remediation handlers deploy first to the Security Lab account and execute against synthetic attack scenarios.
2. **Development / Staging**: Integration with simulated workload telemetry.
3. **Production**: Controlled deployment with automated remediation restricted to HIGH and CRITICAL severity rules with human-in-the-loop overrides.
