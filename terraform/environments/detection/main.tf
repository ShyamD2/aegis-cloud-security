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
      Environment = "detection"
      ManagedBy   = "Terraform"
    }
  }
}

module "native_detection" {
  source = "../../modules/native_detection"

  aws_region          = var.aws_region
  project_name        = var.project_name
  enable_guardduty    = var.enable_guardduty
  enable_security_hub = var.enable_security_hub
}
