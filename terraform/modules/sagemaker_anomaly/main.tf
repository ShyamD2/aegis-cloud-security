data "aws_caller_identity" "current" {}

# 1. S3 Bucket for SageMaker Model Artifacts
resource "aws_s3_bucket" "model_artifacts" {
  bucket_prefix = "${var.project_name}-sagemaker-artifacts-${var.aws_region}-"
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "model_encryption" {
  bucket = aws_s3_bucket.model_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "model_pab" {
  bucket = aws_s3_bucket.model_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 2. IAM Role for SageMaker Service Execution
resource "aws_iam_role" "sagemaker_role" {
  name = "${var.project_name}-sagemaker-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "sagemaker_scoped_policy" {
  name = "${var.project_name}-sagemaker-scoped-policy"
  role = aws_iam_role.sagemaker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ModelArtifactsRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.model_artifacts.arn,
          "${aws_s3_bucket.model_artifacts.arn}/*"
        ]
      },
      {
        Sid    = "KmsDecryptArtifacts"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/sagemaker/*"
      }
    ]
  })
}

# 3. SageMaker Model Definition
resource "aws_sagemaker_model" "anomaly_model" {
  name               = "${var.project_name}-behavioral-anomaly-model"
  execution_role_arn = aws_iam_role.sagemaker_role.arn

  primary_container {
    image          = "683313688378.dkr.ecr.${var.aws_region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"
    model_data_url = "s3://${aws_s3_bucket.model_artifacts.id}/models/model.tar.gz"
  }

  tags = var.tags
}

# 4. SageMaker Serverless Endpoint Configuration
resource "aws_sagemaker_endpoint_configuration" "serverless_config" {
  name = "${var.project_name}-serverless-anomaly-config"

  production_variants {
    variant_name = "AllTraffic"
    model_name   = aws_sagemaker_model.anomaly_model.name

    serverless_config {
      max_concurrency   = var.max_concurrency
      memory_size_in_mb = var.serverless_memory_in_mb
    }
  }

  tags = var.tags
}

# 5. SageMaker Serverless Inference Endpoint
resource "aws_sagemaker_endpoint" "anomaly_endpoint" {
  name                 = "${var.project_name}-anomaly-endpoint"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.serverless_config.name

  tags = var.tags
}
