variable "project_name" {
  description = "Project name prefix for resources"
  type        = string
  default     = "aegis"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "security-lab"
}

variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for encryption at rest"
  type        = string
}

variable "event_bus_arn" {
  description = "AEGIS Findings EventBridge Bus ARN"
  type        = string
}

variable "forensic_vault_bucket_name" {
  description = "Name of the S3 immutable forensic vault bucket"
  type        = string
}

variable "scheduler_interval_minutes" {
  description = "Interval in minutes between autonomous test scenarios"
  type        = number
  default     = 15
}

variable "global_kill_switch_enabled" {
  description = "Whether the safety kill switch is primed"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Resource tags applied to all security lab infrastructure"
  type        = map(string)
  default = {
    Project     = "AEGIS"
    Environment = "aegis-security-lab"
    ManagedBy   = "Terraform"
  }
}
