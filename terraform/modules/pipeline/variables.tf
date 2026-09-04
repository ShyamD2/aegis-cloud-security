variable "aws_region" {
  type        = string
  description = "AWS region for pipeline resources"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for pipeline components"
  default     = "aegis"
}

variable "retention_hours" {
  type        = number
  description = "Retention period for Kinesis data stream in hours"
  default     = 24
}

variable "kms_key_arn" {
  type        = string
  description = "KMS CMK for stream and queue encryption"
}

variable "enable_kinesis" {
  type        = bool
  description = "Enable Amazon Kinesis stream (requires active Kinesis subscription)"
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project   = "AEGIS"
    Component = "Pipeline"
    ManagedBy = "Terraform"
  }
}
