# Project AEGIS - Security Operations War Room Infrastructure
# Deploys Amazon Cognito with MFA, API Gateway with JWT authorizer,
# and encrypted S3 bucket with CloudFront distribution for SPA hosting.

# 1. Amazon Cognito User Pool with MFA
resource "aws_cognito_user_pool" "war_room" {
  name              = "${var.project_name}-war-room-pool-${var.environment}"
  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length    = 14
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  tags = var.tags
}

resource "aws_cognito_user_pool_client" "war_room" {
  name            = "${var.project_name}-war-room-spa-client"
  user_pool_id    = aws_cognito_user_pool.war_room.id
  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
}

# 2. Amazon API Gateway HTTP API
resource "aws_apigatewayv2_api" "war_room" {
  name          = "${var.project_name}-war-room-api-${var.environment}"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["Authorization", "Content-Type"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_origins = ["https://localhost:3000"]
    max_age       = 3600
  }

  tags = var.tags
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.war_room.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "cognito-authorizer"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.war_room.id]
    issuer   = "https://${aws_cognito_user_pool.war_room.endpoint}"
  }
}

# 3. Static Hosting S3 Bucket
resource "aws_s3_bucket" "dashboard_assets" {
  bucket_prefix = "${var.project_name}-war-assets-${var.environment}-"

  tags = merge(var.tags, {
    Name = "${var.project_name}-war-room-assets"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dashboard_assets" {
  bucket = aws_s3_bucket.dashboard_assets.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "dashboard_assets" {
  bucket = aws_s3_bucket.dashboard_assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "dashboard" {
  count                             = var.enable_cloudfront ? 1 : 0
  name                              = "${var.project_name}-oac-${var.environment}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront CDN Distribution
resource "aws_cloudfront_distribution" "dashboard" {
  count               = var.enable_cloudfront ? 1 : 0
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.dashboard_assets.bucket_regional_domain_name
    origin_id                = "S3Origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.dashboard[0].id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3Origin"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = var.tags
}
