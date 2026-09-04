variable "security_account_id" {
  type        = string
  description = "AWS 12-digit Account ID of the centralized Security Account"
}

variable "external_id" {
  type        = string
  description = "Cryptographic external ID for confused-deputy protection on cross-account AssumeRole"
  default     = "aegis-trust-9f82d1c4e7"
}

variable "role_prefix" {
  type        = string
  description = "Naming prefix for AEGIS IAM roles"
  default     = "aegis"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project   = "AEGIS"
    ManagedBy = "Terraform"
  }
}
