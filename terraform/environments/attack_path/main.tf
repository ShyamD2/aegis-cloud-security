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
      Environment = "attack-path"
      ManagedBy   = "Terraform"
    }
  }
}

resource "aws_vpc" "aegis_sec_vpc" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "aegis-security-vpc"
  }
}

resource "aws_subnet" "neptune_sub_1" {
  vpc_id            = aws_vpc.aegis_sec_vpc.id
  cidr_block        = "10.100.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "aegis-neptune-subnet-1"
  }
}

resource "aws_subnet" "neptune_sub_2" {
  vpc_id            = aws_vpc.aegis_sec_vpc.id
  cidr_block        = "10.100.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "aegis-neptune-subnet-2"
  }
}

module "kms_foundation" {
  source = "../../modules/kms_foundation"

  project_name           = var.project_name
  security_account_id    = var.security_account_id
  log_archive_account_id = var.log_archive_account_id
}

module "neptune_graph" {
  source = "../../modules/neptune_graph"

  cluster_identifier  = "aegis-neptune"
  environment         = "lab"
  vpc_id              = aws_vpc.aegis_sec_vpc.id
  subnet_ids          = [aws_subnet.neptune_sub_1.id, aws_subnet.neptune_sub_2.id]
  kms_key_arn         = module.kms_foundation.pipeline_key_arn
  allowed_cidr_blocks = [aws_vpc.aegis_sec_vpc.cidr_block]
}
