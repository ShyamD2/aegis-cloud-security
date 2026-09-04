variable "aws_region" {
  type        = string
  description = "AWS region for anomaly environment"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for resources"
  default     = "aegis"
}

variable "security_account_id" {
  type        = string
  description = "AWS Account ID for Security account"
  default     = "111122223333"
}

variable "log_archive_account_id" {
  type        = string
  description = "AWS Account ID for Log Archive account"
  default     = "444455556666"
}
