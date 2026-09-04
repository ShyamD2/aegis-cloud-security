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
      Environment = "war-room"
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

module "war_room" {
  source = "../../modules/war_room"

  project_name = var.project_name
  environment  = "lab"
  kms_key_arn  = module.kms_foundation.pipeline_key_arn
}
