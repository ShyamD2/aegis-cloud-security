output "deny_leaving_org_policy_id" {
  description = "ID of deny leaving org policy"
  value       = aws_organizations_policy.deny_leaving_org.id
}

output "protect_security_controls_policy_id" {
  description = "ID of protect security controls policy"
  value       = aws_organizations_policy.protect_security_controls.id
}

output "protect_log_archive_policy_id" {
  description = "ID of protect log archive policy"
  value       = aws_organizations_policy.protect_log_archive.id
}

output "restrict_regions_policy_id" {
  description = "ID of region restriction policy"
  value       = aws_organizations_policy.restrict_regions.id
}

output "emergency_quarantine_policy_id" {
  description = "ID of emergency quarantine policy"
  value       = aws_organizations_policy.emergency_quarantine.id
}
