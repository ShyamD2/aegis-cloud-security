output "state_bucket_name" {
  description = "Name of the S3 bucket created for Terraform remote state"
  value       = aws_s3_bucket.state_bucket.id
}

output "state_bucket_arn" {
  description = "ARN of the S3 bucket created for Terraform remote state"
  value       = aws_s3_bucket.state_bucket.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS CMK encrypting the state bucket and lock table"
  value       = aws_kms_key.state_key.arn
}

output "dynamodb_lock_table_name" {
  description = "Name of the DynamoDB table used for state locking"
  value       = aws_dynamodb_table.state_locks.name
}

output "dynamodb_lock_table_arn" {
  description = "ARN of the DynamoDB table used for state locking"
  value       = aws_dynamodb_table.state_locks.arn
}
