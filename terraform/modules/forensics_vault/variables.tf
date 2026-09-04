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

variable "vault_bucket_name" {
  type        = string
  description = "Name of the dedicated S3 forensic evidence vault bucket"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Customer Managed Key ARN for S3 Object Lock encryption"
}

variable "retention_days" {
  type        = number
  description = "S3 Object Lock default retention period in days"
  default     = 90
}

variable "tags" {
  type        = map(string)
  description = "Resource tags applied to forensic infrastructure"
  default = {
    Project   = "PROJECT-AEGIS"
    Component = "ForensicsVault"
    ManagedBy = "Terraform"
  }
}
