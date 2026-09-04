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
      Project     = "AEGIS"
      Environment = "forensics"
      ManagedBy   = "Terraform"
    }
  }
}

module "kms_foundation" {
  source = "../../modules/kms_foundation"

  project_name           = var.project_name
  security_account_id    = var.security_account_id
  log_archive_account_id = var.log_archive_account_id
}

module "forensics_vault" {
  source = "../../modules/forensics_vault"

  project_name      = var.project_name
  environment       = "lab"
  vault_bucket_name = "${var.project_name}-forensic-evidence-vault-lab-9988"
  kms_key_arn       = module.kms_foundation.pipeline_key_arn
  retention_days    = 90
}
