variable "aws_region" {
  type        = string
  description = "Primary AWS region for organization and security management"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for AEGIS infrastructure"
  default     = "aegis"
}

variable "security_account_id" {
  type        = string
  description = "12-digit AWS Account ID for the Security Account"
  default     = "111122223333"
}

variable "log_archive_account_id" {
  type        = string
  description = "12-digit AWS Account ID for the Log Archive Account"
  default     = "444455556666"
}

variable "external_id" {
  type        = string
  description = "Cryptographic external ID for cross-account STS trust"
  default     = "aegis-trust-9f82d1c4e7"
}

variable "allowed_regions" {
  type        = list(string)
  description = "List of approved AWS regions permitted by SCP guardrails"
  default     = ["us-east-1", "us-west-2"]
}

variable "create_member_accounts" {
  type        = bool
  description = "Whether to provision new member accounts via AWS Organizations"
  default     = false
}
