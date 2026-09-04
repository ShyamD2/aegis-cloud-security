# SCP 1: Prevent Member Accounts From Leaving the Organization
resource "aws_organizations_policy" "deny_leaving_org" {
  name        = "aegis-deny-leaving-org"
  description = "Deny member accounts from leaving the AWS Organization"
  type        = "SERVICE_CONTROL_POLICY"
  tags        = var.tags

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLeavingOrg"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      }
    ]
  })
}

# SCP 2: Prevent Disabling Critical Security Controls
resource "aws_organizations_policy" "protect_security_controls" {
  name        = "aegis-protect-security-controls"
  description = "Deny disabling or deleting CloudTrail, GuardDuty, Security Hub, or Config"
  type        = "SERVICE_CONTROL_POLICY"
  tags        = var.tags

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDisablingSecurityControls"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:StopMonitoringMembers",
          "securityhub:DeleteMembers",
          "securityhub:DisableSecurityHub",
          "securityhub:DisassociateFromMasterAccount",
          "config:DeleteDeliveryChannel",
          "config:StopConfigurationRecorder"
        ]
        Resource = "*"
      }
    ]
  })
}

# SCP 3: Protect Centralized Log Archive & Forensic Buckets
resource "aws_organizations_policy" "protect_log_archive" {
  name        = "aegis-protect-log-archive"
  description = "Deny deleting or modifying central log archive S3 buckets and KMS keys"
  type        = "SERVICE_CONTROL_POLICY"
  tags        = var.tags

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyCentralLogDestruction"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:PutBucketPolicy"
        ]
        Resource = [
          "arn:aws:s3:::aegis-central-logs-*",
          "arn:aws:s3:::aegis-central-logs-*/*",
          "arn:aws:s3:::aegis-forensic-evidence-*",
          "arn:aws:s3:::aegis-forensic-evidence-*/*"
        ]
      },
      {
        Sid    = "DenyKmsKeyDestruction"
        Effect = "Deny"
        Action = [
          "kms:DisableKey",
          "kms:ScheduleKeyDeletion"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:ResourceTag/Project" = "AEGIS"
          }
        }
      }
    ]
  })
}

# SCP 4: Restrict Unauthorized AWS Regions
resource "aws_organizations_policy" "restrict_regions" {
  name        = "aegis-restrict-regions"
  description = "Deny infrastructure actions outside authorized AWS regions"
  type        = "SERVICE_CONTROL_POLICY"
  tags        = var.tags

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnapprovedRegions"
        Effect = "Deny"
        NotAction = [
          "a4b:*",
          "acm:*",
          "aws-marketplace-management:*",
          "aws-marketplace:*",
          "aws-portal:*",
          "budgets:*",
          "ce:*",
          "chime:*",
          "cloudfront:*",
          "config:*",
          "cur:*",
          "directconnect:*",
          "ec2:DescribeRegions",
          "ec2:DescribeTransitGateways",
          "ec2:DescribeVpnGateways",
          "fms:*",
          "globalaccelerator:*",
          "health:*",
          "iam:*",
          "importexport:*",
          "kms:*",
          "mobileanalytics:*",
          "networkmanager:*",
          "organizations:*",
          "pricing:*",
          "route53:*",
          "route53domains:*",
          "route53-recovery-cluster:*",
          "route53-recovery-control-config:*",
          "route53-recovery-readiness:*",
          "s3:GetAccountPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:ListAccessPoints",
          "s3:PutAccountPublicAccessBlock",
          "shield:*",
          "sts:*",
          "support:*",
          "trustedadvisor:*",
          "waf-regional:*",
          "waf:*",
          "wafv2:*",
          "wellarchitected:*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
          ArnNotLike = {
            "aws:PrincipalARN" = [
              "arn:aws:iam::*:role/AWSOrganizations*",
              "arn:aws:iam::*:role/aws-service-role/*"
            ]
          }
        }
      }
    ]
  })
}

# SCP 5: Emergency Account Quarantine (Attached dynamically per incident)
resource "aws_organizations_policy" "emergency_quarantine" {
  name        = "aegis-emergency-quarantine"
  description = "Emergency isolation guardrail denying non-remediation actions during account compromise"
  type        = "SERVICE_CONTROL_POLICY"
  tags        = var.tags

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllExceptRemediationAndInspection"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalARN" = [
              "arn:aws:iam::*:role/AegisSecurityEngineRole",
              "arn:aws:iam::*:role/AegisContainmentRole",
              "arn:aws:iam::*:role/AegisAuditRole",
              "arn:aws:iam::*:role/aws-service-role/*",
              "arn:aws:iam::*:role/*EmergencyBreakGlass*"
            ]
          }
        }
      }
    ]
  })
}

# Attachments to OUs
resource "aws_organizations_policy_attachment" "attach_deny_leaving_org" {
  policy_id = aws_organizations_policy.deny_leaving_org.id
  target_id = var.root_id
}

resource "aws_organizations_policy_attachment" "attach_protect_controls_workloads" {
  policy_id = aws_organizations_policy.protect_security_controls.id
  target_id = var.workloads_ou_id
}

resource "aws_organizations_policy_attachment" "attach_protect_controls_core" {
  policy_id = aws_organizations_policy.protect_security_controls.id
  target_id = var.core_ou_id
}

resource "aws_organizations_policy_attachment" "attach_protect_log_archive_workloads" {
  policy_id = aws_organizations_policy.protect_log_archive.id
  target_id = var.workloads_ou_id
}

resource "aws_organizations_policy_attachment" "attach_restrict_regions" {
  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = var.workloads_ou_id
}
