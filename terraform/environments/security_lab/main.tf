terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state backend configuration populated during deployment
  # backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AEGIS"
      Environment = "aegis-security-lab"
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  common_tags = {
    Project     = "AEGIS"
    Environment = "aegis-security-lab"
    ManagedBy   = "Terraform"
  }
}

# 1. KMS Encryption Foundation
module "kms" {
  source = "../../modules/kms_foundation"

  project_name           = var.project_name
  security_account_id    = local.account_id
  log_archive_account_id = local.account_id
  workload_account_ids   = [local.account_id]
  tags                   = local.common_tags
}

# 2. Immutable Digital Forensics Vault
module "forensics_vault" {
  source = "../../modules/forensics_vault"

  project_name      = var.project_name
  vault_bucket_name = "${var.project_name}-forensics-vault-${local.account_id}"
  kms_key_arn       = module.kms.forensic_key_arn
  retention_days    = 90
  tags              = local.common_tags
}

# 3. Real-Time Telemetry Streaming Pipeline
module "pipeline" {
  source = "../../modules/pipeline"

  project_name    = var.project_name
  kms_key_arn     = module.kms.pipeline_key_arn
  retention_hours = 24
  enable_kinesis  = false
  tags            = local.common_tags
}

# 4. Native AWS Detection & Finding EventBridge Bus
module "native_detection" {
  source = "../../modules/native_detection"

  project_name        = var.project_name
  enable_guardduty    = false
  enable_security_hub = false
  tags                = local.common_tags
}

# 5. Automated Incident Response & Containment (SOAR)
module "remediation" {
  source = "../../modules/remediation"

  project_name = var.project_name
  environment  = var.environment
  kms_key_arn  = module.kms.pipeline_key_arn
  tags         = local.common_tags
}

# 6. Autonomous Security Lab Continuous Testing Orchestrator
module "security_lab" {
  source = "../../modules/security_lab"

  project_name               = var.project_name
  environment                = var.environment
  aws_region                 = var.aws_region
  kms_key_arn                = module.kms.pipeline_key_arn
  event_bus_arn              = module.native_detection.findings_bus_arn
  forensic_vault_bucket_name = module.forensics_vault.vault_bucket_name
  scheduler_interval_minutes = var.scheduler_interval_minutes
  tags                       = local.common_tags
}

# 7. Security Operations War Room (API Gateway & Cognito)
module "war_room" {
  source = "../../modules/war_room"

  project_name      = var.project_name
  environment       = var.environment
  kms_key_arn       = module.kms.pipeline_key_arn
  enable_cloudfront = false
  tags              = local.common_tags
}
