variable "project_name" {
  type        = string
  description = "Naming prefix for KMS keys"
  default     = "aegis"
}

variable "log_archive_account_id" {
  type        = string
  description = "AWS Account ID for Log Archive account"
}

variable "security_account_id" {
  type        = string
  description = "AWS Account ID for Security account"
}

variable "workload_account_ids" {
  type        = list(string)
  description = "List of workload AWS Account IDs permitted to encrypt/generate data keys for telemetry"
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project   = "AEGIS"
    ManagedBy = "Terraform"
  }
}
