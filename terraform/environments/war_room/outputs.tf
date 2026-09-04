output "api_endpoint" {
  description = "War Room API endpoint"
  value       = module.war_room.api_endpoint
}

output "cloudfront_domain_name" {
  description = "War Room CloudFront domain"
  value       = module.war_room.cloudfront_domain_name
}

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = module.war_room.cognito_user_pool_id
}
