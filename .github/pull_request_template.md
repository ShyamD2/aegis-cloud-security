## Description
<!-- Provide a clear, concise summary of the changes and motivation. -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update
- [ ] Security hardening or policy refinement

## Security & Verification Checklist
- [ ] No hardcoded AWS credentials, secrets, or account IDs are included.
- [ ] Remediation actions follow least privilege and provide post-condition verification.
- [ ] All automated tests pass (`pytest tests/`).
- [ ] Python code adheres to formatting and lint standards (`ruff check .` & `ruff format --check .`).
- [ ] Strict type checking passes (`mypy services/ tests/`).
- [ ] Terraform formatting and validation pass (if applicable).
- [ ] Any modified performance or compliance claims are backed by reproducible evidence.

## Related Issues
<!-- Link related issues, e.g. Fixes #123 -->
