output "idempotency_table_arn" {
  description = "DynamoDB remediation table ARN"
  value       = module.remediation.idempotency_table_arn
}

output "state_machine_arn" {
  description = "Step Functions containment state machine ARN"
  value       = module.remediation.state_machine_arn
}
