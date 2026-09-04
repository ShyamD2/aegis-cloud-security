variable "aws_region" {
  type        = string
  description = "AWS region for centralized telemetry"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for resources"
  default     = "aegis"
}

variable "log_archive_account_id" {
  type        = string
  description = "12-digit AWS Account ID for Log Archive account"
  default     = "444455556666"
}

variable "security_account_id" {
  type        = string
  description = "12-digit AWS Account ID for Security account"
  default     = "111122223333"
}

variable "enable_organization_trail" {
  type        = bool
  description = "Whether to enable multi-account AWS Organization trail"
  default     = false
}
