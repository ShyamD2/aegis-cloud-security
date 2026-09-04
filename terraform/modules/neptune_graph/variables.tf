variable "cluster_identifier" {
  type        = string
  description = "Identifier prefix for the Amazon Neptune cluster"
  default     = "aegis-security-graph"
}

variable "environment" {
  type        = string
  description = "Deployment environment name (e.g. lab, prod)"
  default     = "lab"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where the Neptune cluster will be deployed"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs (minimum 2 across separate AZs) for Neptune subnet group"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Customer Managed Key ARN for Neptune storage encryption"
}

variable "allowed_cidr_blocks" {
  type        = list(string)
  description = "List of CIDR blocks permitted to query Neptune on port 8182"
  default     = ["10.0.0.0/16"]
}

variable "tags" {
  type        = map(string)
  description = "Resource tags applied to Neptune infrastructure"
  default = {
    Project   = "PROJECT-AEGIS"
    Component = "AttackPathEngine"
    ManagedBy = "Terraform"
  }
}
