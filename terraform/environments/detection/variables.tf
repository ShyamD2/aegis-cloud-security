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
  description = "Enable GuardDuty detector"
  default     = true
}

variable "enable_security_hub" {
  type        = bool
  description = "Enable Security Hub subscriptions"
  default     = true
}
