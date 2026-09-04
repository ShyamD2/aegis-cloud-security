output "central_logs_bucket_id" {
  description = "Centralized logging S3 bucket ID"
  value       = module.telemetry.central_logs_bucket_id
}

output "central_logs_bucket_arn" {
  description = "Centralized logging S3 bucket ARN"
  value       = module.telemetry.central_logs_bucket_arn
}

output "cloudtrail_arn" {
  description = "Centralized CloudTrail ARN"
  value       = module.telemetry.cloudtrail_arn
}

output "dns_query_log_config_arn" {
  description = "Route 53 Resolver query logging configuration ARN"
  value       = module.telemetry.dns_query_log_config_arn
}
