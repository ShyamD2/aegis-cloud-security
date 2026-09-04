output "organization_id" {
  description = "AWS Organization ID"
  value       = module.organization.organization_id
}

output "core_ou_id" {
  description = "Core Security OU ID"
  value       = module.organization.core_ou_id
}

output "workloads_ou_id" {
  description = "Workloads OU ID"
  value       = module.organization.workloads_ou_id
}

output "security_lab_ou_id" {
  description = "Security Lab OU ID"
  value       = module.organization.security_lab_ou_id
}

output "audit_role_arn" {
  description = "Cross-account audit role ARN"
  value       = module.iam_trust.audit_role_arn
}

output "containment_role_arn" {
  description = "Cross-account containment role ARN"
  value       = module.iam_trust.containment_role_arn
}

output "central_logs_key_arn" {
  description = "Centralized logging KMS key ARN"
  value       = module.kms_foundation.central_logs_key_arn
}

output "pipeline_key_arn" {
  description = "Security pipeline KMS key ARN"
  value       = module.kms_foundation.pipeline_key_arn
}

output "forensic_key_arn" {
  description = "Forensic evidence KMS key ARN"
  value       = module.kms_foundation.forensic_key_arn
}
