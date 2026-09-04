output "audit_role_arn" {
  description = "ARN of the cross-account security audit role"
  value       = aws_iam_role.aegis_audit_role.arn
}

output "audit_role_name" {
  description = "Name of the cross-account security audit role"
  value       = aws_iam_role.aegis_audit_role.name
}

output "containment_role_arn" {
  description = "ARN of the cross-account containment role"
  value       = aws_iam_role.aegis_containment_role.arn
}

output "containment_role_name" {
  description = "Name of the cross-account containment role"
  value       = aws_iam_role.aegis_containment_role.name
}

output "remediation_boundary_arn" {
  description = "ARN of the remediation permissions boundary policy"
  value       = aws_iam_policy.remediation_boundary.arn
}
