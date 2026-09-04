output "vault_bucket_name" {
  description = "Forensic evidence S3 bucket name"
  value       = aws_s3_bucket.vault.bucket
}

output "vault_bucket_arn" {
  description = "Forensic evidence S3 bucket ARN"
  value       = aws_s3_bucket.vault.arn
}

output "glue_database_name" {
  description = "Glue database cataloging forensic evidence"
  value       = aws_glue_catalog_database.forensics.name
}

output "athena_workgroup_name" {
  description = "Athena workgroup for forensic queries"
  value       = aws_athena_workgroup.forensics.name
}
