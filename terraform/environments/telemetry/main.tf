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
      Environment            = "telemetry"
      ManagedBy              = "Terraform"
      SecurityClassification = "Confidential"
    }
  }
}

# KMS Foundation Module (provides Central Logs Key)
module "kms_foundation" {
  source = "../../modules/kms_foundation"

  project_name           = var.project_name
  security_account_id    = var.security_account_id
  log_archive_account_id = var.log_archive_account_id
}

# Centralized Telemetry Module
module "telemetry" {
  source = "../../modules/telemetry"

  aws_region                = var.aws_region
  project_name              = var.project_name
  kms_key_arn               = module.kms_foundation.central_logs_key_arn
  enable_organization_trail = var.enable_organization_trail
}
