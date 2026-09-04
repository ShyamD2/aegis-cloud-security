# Permissions Boundary for AEGIS Remediation Roles
resource "aws_iam_policy" "remediation_boundary" {
  name        = "${var.role_prefix}-remediation-boundary"
  description = "Maximum permissions boundary for AEGIS containment roles in workload accounts"
  tags        = var.tags

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowedContainmentAPIs"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:Get*",
          "iam:List*",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "s3:GetBucket*",
          "s3:GetAccountPublicAccessBlock",
          "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyHighPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:CreateAccessKey",
          "iam:PassRole",
          "organizations:*",
          "cloudtrail:*",
          "kms:ScheduleKeyDeletion"
        ]
        Resource = "*"
      }
    ]
  })
}

# Cross-Account Audit Role (Deployable in Workload & Member Accounts)
resource "aws_iam_role" "aegis_audit_role" {
  name                 = "${var.role_prefix}-audit-role"
  description          = "Read-only security audit role assumed by AEGIS engine from the Security Account"
  max_session_duration = 3600
  tags                 = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecurityAccountAssume"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

# Attach AWS Managed SecurityAudit policy to Audit Role
resource "aws_iam_role_policy_attachment" "audit_role_security_audit" {
  role       = aws_iam_role.aegis_audit_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Cross-Account Containment Role (Deployable in Workload Accounts)
resource "aws_iam_role" "aegis_containment_role" {
  name                 = "${var.role_prefix}-containment-role"
  description          = "Constrained self-healing containment role assumed exclusively during verified incidents"
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.remediation_boundary.arn
  tags                 = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecurityEngineAssumeOnly"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

# Fine-Grained Least-Privilege Containment Inline Policy
resource "aws_iam_role_policy" "containment_policy" {
  name = "${var.role_prefix}-containment-policy"
  role = aws_iam_role.aegis_containment_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMContainmentActions"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2IsolationActions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateSnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ContainmentActions"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })
}
