variable "aws_region" {
  type        = string
  description = "AWS region for centralized telemetry infrastructure"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for AEGIS telemetry resources"
  default     = "aegis"
}

variable "log_bucket_prefix" {
  type        = string
  description = "S3 bucket name prefix for centralized log archive"
  default     = "aegis-central-logs"
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of the KMS CMK encrypting centralized telemetry"
}

variable "organization_id" {
  type        = string
  description = "AWS Organization ID for multi-account CloudTrail validation"
  default     = ""
}

variable "enable_organization_trail" {
  type        = bool
  description = "Whether to deploy the trail as an AWS Organizations trail (set false in single-account lab)"
  default     = false
}

variable "enable_data_events" {
  type        = bool
  description = "Whether to enable CloudTrail data events for S3 and Lambda"
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project                = "AEGIS"
    Component              = "Telemetry"
    ManagedBy              = "Terraform"
    SecurityClassification = "Confidential"
  }
}
