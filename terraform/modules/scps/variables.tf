variable "root_id" {
  type        = string
  description = "Organization root ID for global SCP attachments"
}

variable "core_ou_id" {
  type        = string
  description = "Identifier of the Core Security OU"
}

variable "workloads_ou_id" {
  type        = string
  description = "Identifier of the Workloads OU"
}

variable "lab_ou_id" {
  type        = string
  description = "Identifier of the Security Lab OU"
}

variable "allowed_regions" {
  type        = list(string)
  description = "Approved AWS regions for workload deployment"
  default     = ["us-east-1", "us-west-2"]
}

variable "tags" {
  type        = map(string)
  description = "Resource tags for SCP policies"
  default = {
    Project   = "AEGIS"
    ManagedBy = "Terraform"
  }
}
