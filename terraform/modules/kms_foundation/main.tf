data "aws_caller_identity" "current" {}

# 1. Centralized Telemetry & Log Vault KMS CMK
resource "aws_kms_key" "central_logs_key" {
  description             = "KMS CMK for centralized CloudTrail, Flow Logs, and DNS logging"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = merge(var.tags, {
    Name = "${var.project_name}-central-logs-key"
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowSecurityIngestionDecryption"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "central_logs_key_alias" {
  name          = "alias/${var.project_name}-central-logs"
  target_key_id = aws_kms_key.central_logs_key.key_id
}

# 2. Security Pipeline KMS CMK (Kinesis, DynamoDB, EventBridge)
resource "aws_kms_key" "pipeline_key" {
  description             = "KMS CMK for AEGIS internal streaming and state database encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = merge(var.tags, {
    Name = "${var.project_name}-pipeline-key"
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSecurityAccountServices"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "pipeline_key_alias" {
  name          = "alias/${var.project_name}-pipeline"
  target_key_id = aws_kms_key.pipeline_key.key_id
}

# 3. Forensic Evidence KMS CMK (Protected with Anti-Tampering Key Policy)
resource "aws_kms_key" "forensic_key" {
  description             = "KMS CMK for S3 Object Lock immutable forensic evidence vault"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = merge(var.tags, {
    Name = "${var.project_name}-forensic-evidence-key"
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Get*",
          "kms:TagResource",
          "kms:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowForensicCollectorWrites"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "forensic_key_alias" {
  name          = "alias/${var.project_name}-forensic-evidence"
  target_key_id = aws_kms_key.forensic_key.key_id
}
