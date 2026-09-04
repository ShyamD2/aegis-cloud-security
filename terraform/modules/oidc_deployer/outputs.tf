output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC identity provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "deployer_role_arn" {
  description = "ARN of the scoped GitHub Actions deployment role"
  value       = aws_iam_role.github_actions_deployer.arn
}

output "deployer_role_name" {
  description = "Name of the deployment role"
  value       = aws_iam_role.github_actions_deployer.name
}
