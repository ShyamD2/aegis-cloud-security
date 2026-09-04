terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project                = "AEGIS"
      Environment            = "org-core"
      ManagedBy              = "Terraform"
      SecurityClassification = "Confidential"
    }
  }
}

# 1. AWS Organization & OU Hierarchy Module
module "organization" {
  source = "../../modules/organization"

  aws_region             = var.aws_region
  create_member_accounts = var.create_member_accounts
}

# 2. Service Control Policies (SCPs) Module
module "scps" {
  source = "../../modules/scps"

  root_id         = module.organization.root_id
  core_ou_id      = module.organization.core_ou_id
  workloads_ou_id = module.organization.workloads_ou_id
  lab_ou_id       = module.organization.security_lab_ou_id
  allowed_regions = var.allowed_regions
}

# 3. Cross-Account IAM Trust & Containment Roles
module "iam_trust" {
  source = "../../modules/iam_trust"

  security_account_id = var.security_account_id
  external_id         = var.external_id
  role_prefix         = var.project_name
}

# 4. Central KMS Cryptographic Foundation
module "kms_foundation" {
  source = "../../modules/kms_foundation"

  project_name           = var.project_name
  security_account_id    = var.security_account_id
  log_archive_account_id = var.log_archive_account_id
}
