variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project name identifier"
  default     = "aegis"
}

variable "security_account_id" {
  type        = string
  description = "Security tooling account ID"
  default     = "222222222222"
}

variable "log_archive_account_id" {
  type        = string
  description = "Central log archive account ID"
  default     = "444444444444"
}
