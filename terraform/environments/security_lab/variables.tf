variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all AEGIS resources"
  type        = string
  default     = "aegis"
}

variable "environment" {
  description = "Target deployment tier"
  type        = string
  default     = "security-lab"
}

variable "deployment_mode" {
  description = "Operating mode: DEMO (pure serverless, <$0.50/day) vs FULL (includes Neptune + SageMaker endpoints)"
  type        = string
  default     = "DEMO"
  validation {
    condition     = contains(["DEMO", "FULL"], var.deployment_mode)
    error_message = "deployment_mode must be either 'DEMO' or 'FULL'."
  }
}

variable "scheduler_interval_minutes" {
  description = "Interval in minutes between autonomous purple team scenario runs"
  type        = number
  default     = 15
}
