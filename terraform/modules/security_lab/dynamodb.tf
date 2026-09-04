# Project AEGIS - Security Lab DynamoDB State & Configuration Tables
# Implements atomic idempotency, execution logging, and global kill switch state.

# 1. Security Lab Configuration & Kill-Switch Table
resource "aws_dynamodb_table" "lab_config" {
  name         = "${var.project_name}-lab-config-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "config_key"

  attribute {
    name = "config_key"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-lab-config"
  })
}

# 2. Security Lab Execution History & Empirical Latency Table
resource "aws_dynamodb_table" "lab_executions" {
  name         = "${var.project_name}-lab-executions-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "execution_id"

  attribute {
    name = "execution_id"
    type = "S"
  }

  attribute {
    name = "scenario_id"
    type = "S"
  }

  global_secondary_index {
    name            = "ScenarioIndex"
    hash_key        = "scenario_id"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-lab-executions"
  })
}
