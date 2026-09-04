data "aws_caller_identity" "current" {}

# 1. Centralized Security Log Archive S3 Bucket
resource "aws_s3_bucket" "central_logs" {
  bucket_prefix = "${var.log_bucket_prefix}-${var.aws_region}-"
  force_destroy = false

  object_lock_enabled = true

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "central_logs_versioning" {
  bucket = aws_s3_bucket.central_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "central_logs_encryption" {
  bucket = aws_s3_bucket.central_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "central_logs_pab" {
  bucket = aws_s3_bucket.central_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "central_logs_lifecycle" {
  bucket = aws_s3_bucket.central_logs.id

  rule {
    id     = "aegis-telemetry-tiering-and-archive"
    status = "Enabled"

    filter {
      prefix = "AWSLogs/"
    }

    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "central_logs_policy" {
  bucket = aws_s3_bucket.central_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.central_logs.arn,
          "${aws_s3_bucket.central_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.central_logs.arn
      },
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.central_logs.arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AllowVpcFlowLogsDelivery"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl"
        ]
        Resource = [
          aws_s3_bucket.central_logs.arn,
          "${aws_s3_bucket.central_logs.arn}/AWSLogs/*"
        ]
      }
    ]
  })
}

# 2. Centralized CloudTrail Trail (Multi-Region, Organization-wide, Log File Validation)
resource "aws_cloudtrail" "aegis_trail" {
  name                          = "${var.project_name}-central-trail"
  s3_bucket_name                = aws_s3_bucket.central_logs.id
  s3_key_prefix                 = ""
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  is_organization_trail         = var.enable_organization_trail
  kms_key_id                    = var.kms_key_arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    dynamic "data_resource" {
      for_each = var.enable_data_events ? [1] : []
      content {
        type   = "AWS::S3::Object"
        values = ["arn:aws:s3:::aegis-*/*"]
      }
    }
  }

  tags = var.tags

  depends_on = [
    aws_s3_bucket_policy.central_logs_policy
  ]
}

# 3. Route 53 Resolver Query Logging Configuration
resource "aws_route53_resolver_query_log_config" "dns_query_log" {
  name            = "${var.project_name}-dns-query-logs"
  destination_arn = aws_s3_bucket.central_logs.arn
  tags            = var.tags
}
