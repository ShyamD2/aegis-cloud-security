variable "project_name" {
  type        = string
  description = "Project name identifier"
  default     = "aegis"
}

variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "lab"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Customer Managed Key ARN for dashboard bucket encryption"
}

variable "enable_cloudfront" {
  type        = bool
  description = "Whether to create CloudFront CDN distribution (requires verified AWS account)"
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Resource tags applied to War Room infrastructure"
  default = {
    Project   = "PROJECT-AEGIS"
    Component = "SecurityWarRoom"
    ManagedBy = "Terraform"
  }
}
