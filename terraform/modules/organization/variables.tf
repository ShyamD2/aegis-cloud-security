variable "aws_region" {
  type        = string
  description = "AWS region for organization management"
  default     = "us-east-1"
}

variable "feature_set" {
  type        = string
  description = "AWS Organizations feature set (ALL or CONSOLIDATED_BILLING)"
  default     = "ALL"
}

variable "security_account_email" {
  type        = string
  description = "Email address for the Security Account"
  default     = "security@aegis.cloud.corp"
}

variable "log_archive_account_email" {
  type        = string
  description = "Email address for the Log Archive Account"
  default     = "log-archive@aegis.cloud.corp"
}

variable "production_account_email" {
  type        = string
  description = "Email address for the Production Account"
  default     = "production@aegis.cloud.corp"
}

variable "development_account_email" {
  type        = string
  description = "Email address for the Development Account"
  default     = "development@aegis.cloud.corp"
}

variable "security_lab_account_email" {
  type        = string
  description = "Email address for the Security Attack Lab Account"
  default     = "security-lab@aegis.cloud.corp"
}

variable "create_member_accounts" {
  type        = bool
  description = "Whether to provision member accounts in AWS Organizations (set false in existing multi-account setups)"
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Resource tags for organization components"
  default = {
    Project   = "AEGIS"
    ManagedBy = "Terraform"
  }
}
