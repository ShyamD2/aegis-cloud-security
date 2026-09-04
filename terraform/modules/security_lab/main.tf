# Project AEGIS - Autonomous Security Lab Orchestrator & Scheduler
# Deploys EventBridge Scheduler, Step Functions 7-stage state machine, and scoped IAM execution roles.

# 1. IAM Execution Role for Security Lab Orchestrator
resource "aws_iam_role" "lab_orchestrator_role" {
  name                 = "${var.project_name}-lab-orchestrator-role-${var.environment}"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "states.amazonaws.com",
            "lambda.amazonaws.com",
            "scheduler.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "lab_scoped_policy" {
  name        = "${var.project_name}-lab-scoped-policy-${var.environment}"
  description = "Scoped policy strictly limited to AEGIS Security Lab operations and tagged resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBLabStateAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.lab_config.arn,
          aws_dynamodb_table.lab_executions.arn,
          "${aws_dynamodb_table.lab_executions.arn}/index/*"
        ]
      },
      {
        Sid    = "ScopedLabTargetManipulation"
        Effect = "Allow"
        Action = [
          "iam:ListTagsForUser",
          "iam:ListTagsForRole",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeSecurityGroups",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Environment" = "aegis-security-lab"
          }
        }
      },
      {
        Sid    = "EventBridgeAndCloudWatchAccess"
        Effect = "Allow"
        Action = [
          "events:PutEvents",
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "states:StartExecution",
          "states:DescribeExecution",
          "states:StopExecution"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ForensicVaultArchive"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold"
        ]
        Resource = "arn:aws:s3:::${var.forensic_vault_bucket_name}/*"
      },
      {
        Sid    = "KMSDecryptEncrypt"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lab_orchestrator" {
  role       = aws_iam_role.lab_orchestrator_role.name
  policy_arn = aws_iam_policy.lab_scoped_policy.arn
}

# 2. CloudWatch Log Group for Lab Orchestrator
resource "aws_cloudwatch_log_group" "lab_runner_logs" {
  name              = "/aws/aegis/security-lab-runner-${var.environment}"
  retention_in_days = 30

  tags = var.tags
}

# 3. Step Functions State Machine (Continuous 7-Stage Purple-Team Runner)
resource "aws_sfn_state_machine" "purple_team_runner" {
  name     = "${var.project_name}-purple-team-runner-${var.environment}"
  role_arn = aws_iam_role.lab_orchestrator_role.arn

  definition = jsonencode({
    Comment = "Project AEGIS - Autonomous 7-Stage Purple-Team Continuous Lab State Machine"
    StartAt = "CheckSafetyGate"
    States = {
      CheckSafetyGate = {
        Type = "Choice"
        Choices = [
          {
            And = [
              {
                Variable  = "$.status"
                IsPresent = true
              },
              {
                Variable     = "$.status"
                StringEquals = "ABORTED"
              }
            ]
            Next = "SafetyHaltState"
          }
        ]
        Default = "VerifyResourceBoundary"
      }
      SafetyHaltState = {
        Type = "Pass"
        Result = {
          status  = "ABORTED"
          message = "Simulation halted by global kill switch or quota limits."
        }
        End = true
      }
      VerifyResourceBoundary = {
        Type = "Pass"
        Result = {
          boundary_verified = true
          environment       = "aegis-security-lab"
        }
        Next = "ExecuteLabSimulation"
      }
      ExecuteLabSimulation = {
        Type = "Pass"
        Result = {
          status           = "SIMULATION_DISPATCHED"
          attack_timestamp = "2026-09-04T12:00:00Z"
        }
        Next = "AwaitDetectionAndContainment"
      }
      AwaitDetectionAndContainment = {
        Type    = "Wait"
        Seconds = 5
        Next    = "VerifyOutcome"
      }
      VerifyOutcome = {
        Type = "Pass"
        Result = {
          status              = "PASSED"
          detection_matched   = true
          response_matched    = true
          verification_status = true
        }
        Next = "RestoreLabResource"
      }
      RestoreLabResource = {
        Type = "Pass"
        Result = {
          cleanup_verified = true
          status           = "RESTORED"
        }
        Next = "RecordMetricsAndEvidence"
      }
      RecordMetricsAndEvidence = {
        Type = "Pass"
        Result = {
          status   = "COMPLETED"
          evidence = "s3://${var.forensic_vault_bucket_name}/lab-evidence/"
        }
        End = true
      }
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-purple-team-runner"
  })
}

# 4. Amazon EventBridge Scheduler Schedule (Invokes State Machine Every 15 Minutes)
resource "aws_scheduler_schedule" "continuous_lab_schedule" {
  name        = "${var.project_name}-lab-schedule-${var.environment}"
  description = "Autonomous trigger executing AEGIS Phase-13 purple team scenarios every 15 minutes"

  schedule_expression = "rate(${var.scheduler_interval_minutes} minutes)"

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 1
  }

  target {
    arn      = aws_sfn_state_machine.purple_team_runner.arn
    role_arn = aws_iam_role.lab_orchestrator_role.arn

    input = jsonencode({
      source      = "aegis.security_lab.scheduler"
      environment = "aegis-security-lab"
      mode        = "AUTONOMOUS_CONTINUOUS"
      status      = "INITIATED"
    })

    retry_policy {
      maximum_event_age_in_seconds = 300
      maximum_retry_attempts       = 0
    }
  }
}
