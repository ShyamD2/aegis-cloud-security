# Project AEGIS - GitHub Actions OIDC Deployer Module
# Eliminates static long-lived AWS IAM credentials by federating GitHub Actions via OpenID Connect (OIDC).
# Enforces strictly scoped least privilege without unconstrained administrative roles.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# GitHub Actions OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f8d73ac64c"]

  tags = var.tags
}

# Trust Policy: Restricts role assumption strictly to specific branches of this repository
data "aws_iam_policy_document" "oidc_trust" {
  statement {
    sid     = "GitHubActionsOIDC"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for b in var.allowed_branches : "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${b}"]
    }
  }
}

resource "aws_iam_role" "github_actions_deployer" {
  name                 = "aegis-${var.environment}-github-deployer-role"
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust.json
  max_session_duration = 3600 # 1 hour max session

  tags = var.tags
}

# Least-Privilege Scoped Policy: No Full Admin Access, No Wildcard Mutations
data "aws_iam_policy_document" "deployer_least_privilege" {
  # 1. State backend access (S3 + DynamoDB lock table)
  statement {
    sid    = "TerraformStateBackend"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem"
    ]
    resources = [
      "arn:aws:s3:::aegis-tfstate-*",
      "arn:aws:s3:::aegis-tfstate-*/*",
      "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/aegis-tflocks"
    ]
  }

  # 2. Scoped resource deployment for AEGIS services
  statement {
    sid    = "AEGISWorkloadDeployment"
    effect = "Allow"
    actions = [
      "lambda:CreateFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:GetFunction",
      "lambda:DeleteFunction",
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "states:CreateStateMachine",
      "states:UpdateStateMachine",
      "states:DescribeStateMachine",
      "states:DeleteStateMachine",
      "dynamodb:CreateTable",
      "dynamodb:UpdateTable",
      "dynamodb:DescribeTable",
      "sqs:CreateQueue",
      "sqs:SetQueueAttributes",
      "sqs:GetQueueAttributes",
      "kinesis:CreateStream",
      "kinesis:DescribeStreamSummary",
      "events:PutRule",
      "events:PutTargets",
      "events:DescribeRule"
    ]
    resources = [
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:aegis-*",
      "arn:aws:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stateMachine:aegis-*",
      "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/aegis-*",
      "arn:aws:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:aegis-*",
      "arn:aws:kinesis:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stream/aegis-*",
      "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/aegis-*"
    ]
  }

  # 3. Read-only validation & logging
  statement {
    sid    = "InspectionAndLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "kms:DescribeKey",
      "kms:ListAliases"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "deployer_policy" {
  name        = "aegis-${var.environment}-github-deployer-policy"
  description = "Scoped least-privilege policy for Project AEGIS GitHub Actions CI/CD pipeline"
  policy      = data.aws_iam_policy_document.deployer_least_privilege.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "deployer_attach" {
  role       = aws_iam_role.github_actions_deployer.name
  policy_arn = aws_iam_policy.deployer_policy.arn
}
