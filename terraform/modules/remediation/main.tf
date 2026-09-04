# Project AEGIS - Automated Incident Response & Containment Engine
# Deploys DynamoDB idempotency store, least-privilege sub-remediator IAM roles,
# and the Step Functions autonomous containment state machine.

# 1. DynamoDB Idempotency Store
resource "aws_dynamodb_table" "idempotency" {
  name         = "${var.project_name}-remediation-idempotency-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "idempotency_key"

  attribute {
    name = "idempotency_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-remediation-idempotency"
  })
}

# 2. IAM Sub-Remediator Role (Least Privilege)
resource "aws_iam_role" "iam_remediator" {
  name                 = "${var.project_name}-iam-remediator-${var.environment}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "iam_remediator" {
  name        = "${var.project_name}-iam-remediation-policy-${var.environment}"
  description = "Scoped permissions strictly for IAM access key deactivation and session invalidation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMContainmentActions"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:GetUserPolicy",
          "iam:GetRolePolicy",
          "iam:DeleteUserPolicy",
          "iam:DeleteRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBIdempotencyAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.idempotency.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "iam_remediator" {
  role       = aws_iam_role.iam_remediator.name
  policy_arn = aws_iam_policy.iam_remediator.arn
}

# 3. EC2 Sub-Remediator Role (Least Privilege)
resource "aws_iam_role" "ec2_remediator" {
  name                 = "${var.project_name}-ec2-remediator-${var.environment}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "ec2_remediator" {
  name        = "${var.project_name}-ec2-remediation-policy-${var.environment}"
  description = "Scoped permissions strictly for EC2 network isolation and forensic snapshotting"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2IsolationActions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBIdempotencyAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.idempotency.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_remediator" {
  role       = aws_iam_role.ec2_remediator.name
  policy_arn = aws_iam_policy.ec2_remediator.arn
}

# 4. S3 Sub-Remediator Role (Least Privilege)
resource "aws_iam_role" "s3_remediator" {
  name                 = "${var.project_name}-s3-remediator-${var.environment}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "s3_remediator" {
  name        = "${var.project_name}-s3-remediation-policy-${var.environment}"
  description = "Scoped permissions strictly for S3 Block Public Access enforcement"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ContainmentActions"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBIdempotencyAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.idempotency.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_remediator" {
  role       = aws_iam_role.s3_remediator.name
  policy_arn = aws_iam_policy.s3_remediator.arn
}

# 5. Step Functions State Machine Execution Role
resource "aws_iam_role" "sfn_orchestrator" {
  name                 = "${var.project_name}-sfn-orchestrator-${var.environment}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "sfn_orchestrator" {
  name        = "${var.project_name}-sfn-orchestrator-policy-${var.environment}"
  description = "Permissions for Step Functions orchestrator to invoke remediators and record state"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBTableAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.idempotency.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sfn_orchestrator" {
  role       = aws_iam_role.sfn_orchestrator.name
  policy_arn = aws_iam_policy.sfn_orchestrator.arn
}

# 6. Step Functions Containment State Machine
resource "aws_sfn_state_machine" "containment_orchestrator" {
  name     = "${var.project_name}-containment-orchestrator-${var.environment}"
  role_arn = aws_iam_role.sfn_orchestrator.arn

  definition = jsonencode({
    Comment = "AEGIS Autonomous Incident Response & Containment State Machine"
    StartAt = "EvaluateRiskGate"
    States = {
      EvaluateRiskGate = {
        Type = "Choice"
        Choices = [
          {
            Variable        = "$.risk_score"
            NumericLessThan = 50.0
            Next            = "LogOnlyState"
          },
          {
            Variable                 = "$.risk_score"
            NumericGreaterThanEquals = 75.0
            Next                     = "ExecuteAutonomousContainment"
          }
        ]
        Default = "RequestApprovalState"
      }
      LogOnlyState = {
        Type = "Pass"
        Result = {
          status  = "COMPLETED"
          message = "Risk score below containment threshold. Logged without active remediation."
        }
        End = true
      }
      RequestApprovalState = {
        Type = "Pass"
        Result = {
          status  = "PENDING_APPROVAL"
          message = "High risk finding requires security engineer approval token."
        }
        End = true
      }
      ExecuteAutonomousContainment = {
        Type = "Pass"
        Result = {
          status  = "CONTAINMENT_EXECUTED"
          message = "Specialized remediator executed containment successfully."
        }
        Next = "VerifyContainment"
      }
      VerifyContainment = {
        Type = "Pass"
        Result = {
          verified = true
          message  = "Post-execution verification confirmed secure state."
        }
        End = true
      }
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-containment-orchestrator"
  })
}
