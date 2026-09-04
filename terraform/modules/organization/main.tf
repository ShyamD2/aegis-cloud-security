# AWS Organizations Root
resource "aws_organizations_organization" "org" {
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "inspector2.amazonaws.com",
    "sso.amazonaws.com",
  ]

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY"
  ]

  feature_set = var.feature_set
}

# Core Security Organizational Unit (OU)
resource "aws_organizations_organizational_unit" "core" {
  name      = "Core-Security"
  parent_id = aws_organizations_organization.org.roots[0].id
  tags      = var.tags
}

# Workloads Organizational Unit (OU)
resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = aws_organizations_organization.org.roots[0].id
  tags      = var.tags
}

# Security Lab Organizational Unit (OU)
resource "aws_organizations_organizational_unit" "security_lab" {
  name      = "Security-Lab"
  parent_id = aws_organizations_organization.org.roots[0].id
  tags      = var.tags
}

# Security Core Member Accounts (Optional creation for greenfield environments)
resource "aws_organizations_account" "security" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "aegis-security"
  email     = var.security_account_email
  parent_id = aws_organizations_organizational_unit.core.id
  tags      = var.tags
}

resource "aws_organizations_account" "log_archive" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "aegis-log-archive"
  email     = var.log_archive_account_email
  parent_id = aws_organizations_organizational_unit.core.id
  tags      = var.tags
}

resource "aws_organizations_account" "production" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "aegis-production"
  email     = var.production_account_email
  parent_id = aws_organizations_organizational_unit.workloads.id
  tags      = var.tags
}

resource "aws_organizations_account" "development" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "aegis-development"
  email     = var.development_account_email
  parent_id = aws_organizations_organizational_unit.workloads.id
  tags      = var.tags
}

resource "aws_organizations_account" "security_lab" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "aegis-security-lab"
  email     = var.security_lab_account_email
  parent_id = aws_organizations_organizational_unit.security_lab.id
  tags      = var.tags
}
