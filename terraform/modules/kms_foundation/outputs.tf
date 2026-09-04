output "central_logs_key_arn" {
  description = "ARN of the KMS CMK for centralized logs"
  value       = aws_kms_key.central_logs_key.arn
}

output "central_logs_key_alias" {
  description = "Alias name of the KMS CMK for centralized logs"
  value       = aws_kms_alias.central_logs_key_alias.name
}

output "pipeline_key_arn" {
  description = "ARN of the KMS CMK for security pipeline state and streaming"
  value       = aws_kms_key.pipeline_key.arn
}

output "pipeline_key_alias" {
  description = "Alias name of the KMS CMK for security pipeline"
  value       = aws_kms_alias.pipeline_key_alias.name
}

output "forensic_key_arn" {
  description = "ARN of the KMS CMK for forensic evidence storage"
  value       = aws_kms_key.forensic_key.arn
}

output "forensic_key_alias" {
  description = "Alias name of the KMS CMK for forensic evidence storage"
  value       = aws_kms_alias.forensic_key_alias.name
}
