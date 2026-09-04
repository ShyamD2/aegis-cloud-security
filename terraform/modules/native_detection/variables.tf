variable "aws_region" {
  type        = string
  description = "AWS region for native detection sensors"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for resources"
  default     = "aegis"
}

variable "enable_guardduty" {
  type        = bool
  description = "Enable Amazon GuardDuty detector"
  default     = true
}

variable "enable_security_hub" {
  type        = bool
  description = "Enable AWS Security Hub standard subscriptions"
  default     = true
}

variable "enable_config" {
  type        = bool
  description = "Enable AWS Config configuration recorder"
  default     = false
}

variable "enable_inspector" {
  type        = bool
  description = "Enable Amazon Inspector v2"
  default     = false
}

variable "config_log_bucket" {
  type        = string
  description = "S3 bucket name for AWS Config delivery channel"
  default     = ""
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project   = "AEGIS"
    Component = "NativeDetection"
    ManagedBy = "Terraform"
  }
}
