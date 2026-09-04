output "central_logs_bucket_id" {
  description = "Name of the centralized security log archive S3 bucket"
  value       = aws_s3_bucket.central_logs.id
}

output "central_logs_bucket_arn" {
  description = "ARN of the centralized security log archive S3 bucket"
  value       = aws_s3_bucket.central_logs.arn
}

output "cloudtrail_arn" {
  description = "ARN of the centralized CloudTrail trail"
  value       = aws_cloudtrail.aegis_trail.arn
}

output "dns_query_log_config_arn" {
  description = "ARN of the Route 53 Resolver query log config"
  value       = aws_route53_resolver_query_log_config.dns_query_log.arn
}
