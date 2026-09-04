output "cognito_user_pool_id" {
  description = "Cognito user pool ID"
  value       = aws_cognito_user_pool.war_room.id
}

output "cognito_client_id" {
  description = "Cognito SPA client ID"
  value       = aws_cognito_user_pool_client.war_room.id
}

output "api_endpoint" {
  description = "API Gateway HTTP endpoint"
  value       = aws_apigatewayv2_api.war_room.api_endpoint
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.dashboard[0].domain_name : null
}
