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
  description = "KMS Key ARN for DynamoDB encryption"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags applied to remediation infrastructure"
  default = {
    Project   = "PROJECT-AEGIS"
    Component = "RemediationEngine"
    ManagedBy = "Terraform"
  }
}
