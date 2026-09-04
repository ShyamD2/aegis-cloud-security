output "idempotency_table_name" {
  description = "Name of the DynamoDB remediation idempotency table"
  value       = aws_dynamodb_table.idempotency.name
}

output "idempotency_table_arn" {
  description = "ARN of the DynamoDB remediation idempotency table"
  value       = aws_dynamodb_table.idempotency.arn
}

output "iam_remediator_role_arn" {
  description = "ARN of scoped IAM role for IAM remediator"
  value       = aws_iam_role.iam_remediator.arn
}

output "ec2_remediator_role_arn" {
  description = "ARN of scoped IAM role for EC2 remediator"
  value       = aws_iam_role.ec2_remediator.arn
}

output "s3_remediator_role_arn" {
  description = "ARN of scoped IAM role for S3 remediator"
  value       = aws_iam_role.s3_remediator.arn
}

output "state_machine_arn" {
  description = "ARN of the Step Functions containment state machine"
  value       = aws_sfn_state_machine.containment_orchestrator.arn
}
