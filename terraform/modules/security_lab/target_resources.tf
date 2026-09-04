# Project AEGIS - Isolated Security Lab Target Resources
# Strictly tagged for boundary enforcement: Environment = "aegis-security-lab".
# These dedicated resources are the ONLY assets targeted during autonomous simulations.

data "aws_caller_identity" "current" {}

locals {
  lab_target_tags = merge(var.tags, {
    Environment = "aegis-security-lab"
    Project     = "aegis"
    LabTarget   = "true"
  })
}

# 1. Isolated Lab IAM User (For Key Compromise & Privilege Escalation Scenarios)
resource "aws_iam_user" "lab_test_user" {
  name = "${var.project_name}-lab-test-user"
  path = "/aegis-lab/"

  tags = local.lab_target_tags
}

# 2. Isolated Lab IAM Role (For AssumeRole & Lateral Movement Scenarios)
resource "aws_iam_role" "lab_test_role" {
  name = "${var.project_name}-lab-test-role"
  path = "/aegis-lab/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })

  tags = local.lab_target_tags
}

# 3. Isolated Lab S3 Bucket (For S3 Security Drift Scenarios)
resource "aws_s3_bucket" "lab_test_bucket" {
  bucket_prefix = "${var.project_name}-lab-target-"
  force_destroy = true

  tags = local.lab_target_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab_test_bucket" {
  bucket = aws_s3_bucket.lab_test_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "lab_test_bucket" {
  bucket = aws_s3_bucket.lab_test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 4. Isolated Lab Security Group (For Ingress Opening Scenarios)
# In standalone/lab mode, this can be created without requiring a non-default VPC if vpc_id is supplied
resource "aws_security_group" "lab_test_sg" {
  name        = "${var.project_name}-lab-test-sg"
  description = "Isolated security group strictly for AEGIS Lab scenario testing"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["127.0.0.1/32"]
  }

  tags = local.lab_target_tags
}
