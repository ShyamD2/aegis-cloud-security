# 1. Amazon Kinesis Data Stream (On-Demand Mode)
resource "aws_kinesis_stream" "security_events" {
  name             = "${var.project_name}-security-events-stream"
  retention_period = var.retention_hours

  stream_mode_details {
    stream_mode = "ON_DEMAND"
  }

  encryption_type = "KMS"
  kms_key_id      = var.kms_key_arn

  tags = var.tags
}

# 2. Amazon SQS Dead-Letter Queue (DLQ)
resource "aws_sqs_queue" "pipeline_dlq" {
  name                      = "${var.project_name}-pipeline-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = var.kms_key_arn

  tags = var.tags
}

# 3. CloudWatch Log Group for Pipeline Processing
resource "aws_cloudwatch_log_group" "pipeline_logs" {
  name              = "/aws/aegis/pipeline-processor"
  retention_in_days = 30
  kms_key_id        = var.kms_key_arn

  tags = var.tags
}

# 4. IAM Execution Role for Stream Processing Lambda
resource "aws_iam_role" "pipeline_lambda_role" {
  name = "${var.project_name}-pipeline-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "pipeline_lambda_policy" {
  name = "${var.project_name}-pipeline-lambda-policy"
  role = aws_iam_role.pipeline_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KinesisStreamRead"
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords",
          "kinesis:GetShardIterator",
          "kinesis:DescribeStream",
          "kinesis:ListShards"
        ]
        Resource = aws_kinesis_stream.security_events.arn
      },
      {
        Sid    = "DLQSend"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.pipeline_dlq.arn
      },
      {
        Sid    = "Logging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.pipeline_logs.arn}:*"
      }
    ]
  })
}
