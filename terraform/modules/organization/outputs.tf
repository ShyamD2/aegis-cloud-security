output "organization_id" {
  description = "Identifier of the AWS Organization"
  value       = aws_organizations_organization.org.id
}

output "organization_arn" {
  description = "ARN of the AWS Organization"
  value       = aws_organizations_organization.org.arn
}

output "root_id" {
  description = "Identifier of the Organization Root"
  value       = aws_organizations_organization.org.roots[0].id
}

output "core_ou_id" {
  description = "Identifier of the Core Security OU"
  value       = aws_organizations_organizational_unit.core.id
}

output "workloads_ou_id" {
  description = "Identifier of the Workloads OU"
  value       = aws_organizations_organizational_unit.workloads.id
}

output "security_lab_ou_id" {
  description = "Identifier of the Security Lab OU"
  value       = aws_organizations_organizational_unit.security_lab.id
}
