output "lab_config_table_name" {
  description = "DynamoDB table name for security lab configuration and kill-switch"
  value       = aws_dynamodb_table.lab_config.name
}

output "lab_executions_table_name" {
  description = "DynamoDB table name for security lab historical executions and latency"
  value       = aws_dynamodb_table.lab_executions.name
}

output "purple_team_runner_sfn_arn" {
  description = "ARN of the Step Functions purple team scenario runner"
  value       = aws_sfn_state_machine.purple_team_runner.arn
}

output "scheduler_schedule_arn" {
  description = "ARN of the EventBridge Scheduler schedule"
  value       = aws_scheduler_schedule.continuous_lab_schedule.arn
}

output "lab_test_user_arn" {
  description = "ARN of the isolated lab test IAM user"
  value       = aws_iam_user.lab_test_user.arn
}

output "lab_test_bucket_name" {
  description = "Name of the isolated lab test S3 bucket"
  value       = aws_s3_bucket.lab_test_bucket.id
}
