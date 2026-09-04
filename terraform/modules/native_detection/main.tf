# 1. Amazon GuardDuty Detector
resource "aws_guardduty_detector" "primary" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = var.tags
}

# 2. AWS Security Hub Account Subscription
resource "aws_securityhub_account" "primary" {
  count                     = var.enable_security_hub ? 1 : 0
  enable_default_standards  = true
  control_finding_generator = "SECURITY_CONTROL"
}

# 3. AEGIS Dedicated Central Finding EventBridge Bus
resource "aws_cloudwatch_event_bus" "aegis_findings" {
  name = "${var.project_name}-findings-bus"
  tags = var.tags
}

# 4. EventBridge Rule: Capture GuardDuty Findings and Route to AEGIS Finding Bus
resource "aws_cloudwatch_event_rule" "capture_guardduty" {
  name        = "${var.project_name}-capture-guardduty"
  description = "Capture GuardDuty findings and route into AEGIS central finding bus"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "guardduty_to_bus" {
  rule     = aws_cloudwatch_event_rule.capture_guardduty.name
  arn      = aws_cloudwatch_event_bus.aegis_findings.arn
  role_arn = aws_iam_role.eventbridge_bus_role.arn
}

# 5. EventBridge Rule: Capture Security Hub Findings
resource "aws_cloudwatch_event_rule" "capture_securityhub" {
  name        = "${var.project_name}-capture-securityhub"
  description = "Capture Security Hub findings and route into AEGIS central finding bus"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "securityhub_to_bus" {
  rule     = aws_cloudwatch_event_rule.capture_securityhub.name
  arn      = aws_cloudwatch_event_bus.aegis_findings.arn
  role_arn = aws_iam_role.eventbridge_bus_role.arn
}

# IAM Role permitting EventBridge to publish to the AEGIS Finding Bus
resource "aws_iam_role" "eventbridge_bus_role" {
  name = "${var.project_name}-eventbridge-bus-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "allow_put_events" {
  name = "${var.project_name}-allow-put-events"
  role = aws_iam_role.eventbridge_bus_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "events:PutEvents"
        Resource = aws_cloudwatch_event_bus.aegis_findings.arn
      }
    ]
  })
}
