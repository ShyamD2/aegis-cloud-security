config {
  module = true
  force  = false
}

plugin "aws" {
  enabled = true
  version = "0.30.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "aws_s3_bucket_server_side_encryption_configuration" {
  enabled = true
}

rule "aws_s3_bucket_public_access_block" {
  enabled = true
}
