output "forensics_vault_bucket" {
  description = "S3 Object Lock forensics vault bucket name"
  value       = module.forensics_vault.vault_bucket_name
}

output "event_stream_arn" {
  description = "Kinesis security events stream ARN"
  value       = module.pipeline.kinesis_stream_arn
}

output "findings_bus_arn" {
  description = "EventBridge central findings bus ARN"
  value       = module.native_detection.findings_bus_arn
}

output "containment_state_machine_arn" {
  description = "Step Functions automated containment orchestrator ARN"
  value       = module.remediation.state_machine_arn
}

output "security_lab_runner_arn" {
  description = "Step Functions continuous purple-team runner ARN"
  value       = module.security_lab.purple_team_runner_sfn_arn
}

output "security_lab_scheduler_arn" {
  description = "EventBridge Scheduler schedule ARN"
  value       = module.security_lab.scheduler_schedule_arn
}

output "security_lab_config_table" {
  description = "DynamoDB table name for security lab kill-switch and configuration"
  value       = module.security_lab.lab_config_table_name
}

output "security_lab_executions_table" {
  description = "DynamoDB table name for continuous test executions"
  value       = module.security_lab.lab_executions_table_name
}

output "war_room_api_endpoint" {
  description = "API Gateway HTTP endpoint for the War Room"
  value       = module.war_room.api_endpoint
}
