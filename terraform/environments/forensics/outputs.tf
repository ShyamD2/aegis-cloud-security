output "vault_bucket_arn" {
  description = "Forensic evidence S3 bucket ARN"
  value       = module.forensics_vault.vault_bucket_arn
}

output "glue_database_name" {
  description = "Glue database name"
  value       = module.forensics_vault.glue_database_name
}

output "athena_workgroup_name" {
  description = "Athena workgroup name"
  value       = module.forensics_vault.athena_workgroup_name
}
