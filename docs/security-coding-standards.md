# AEGIS Security Coding Standards
## DevSecOps Guidelines for Python, Terraform & Cloud Engineering

### 1. General Principles

All code contributed to Project AEGIS must adhere to strict security hygiene:
1. **Never Hardcode Secrets**: No API keys, passwords, AWS access keys, or private certificates may be committed to version control. All secrets must be fetched via AWS Secrets Manager or environment variables at runtime.
2. **Least-Privilege by Default**: Every AWS API call must operate under an IAM role scoped to specific resource ARNs.
3. **Fail Securely (Fail-Closed)**: If a security validation, token verification, or input check fails, execution must abort immediately and log an alert. Never fail-open.
4. **Input Sanitization & Schema Enforcement**: All incoming events and external payloads must be validated against strict Pydantic schemas before processing.

---

### 2. Python Engineering Standards

- **Python Version**: 3.12+ (strictly typed using `mypy`).
- **Data Modeling**: All telemetry events, findings, and remediation payloads must inherit from Pydantic `BaseModel` with strict type annotations.
- **Error Handling**: Catch specific exceptions (`botocore.exceptions.ClientError`), never bare `except:`.
- **Logging**: Use structured JSON logging via Python `logging` module. Never log raw event bodies containing authorization headers, session tokens, or customer data.
- **Boto3 Client Creation**: Use a centralized client factory with standard timeout and retry configurations:

```python
import boto3
from botocore.config import Config

STANDARD_BOTO_CONFIG = Config(
    region_name="us-east-1",
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=10,
)


def get_boto3_client(service_name: str, session: boto3.Session | None = None) -> boto3.client:
    s = session or boto3.Session()
    return s.client(service_name, config=STANDARD_BOTO_CONFIG)
```

---

### 3. Terraform Engineering Standards

- **Provider Constraints**: Always pin AWS provider versions (e.g. `~> 5.0`).
- **Resource Tagging**: Every resource must inherit standard organizational tags (`Project`, `Environment`, `ManagedBy`, `SecurityClassification`).
- **Encryption**:
  - S3 buckets must enforce `aws_s3_bucket_server_side_encryption_configuration` using `aws:kms`.
  - S3 public access blocks (`aws_s3_bucket_public_access_block`) must set all 4 public access prevention flags to `true`.
  - EBS volumes must enforce encryption.
- **IAM Policies**:
  - Do not use `*` for both Action and Resource simultaneously.
  - Require conditions where appropriate (`aws:PrincipalOrgID`, `aws:SecureTransport`).
  - Cross-account roles must require `sts:ExternalId`.
