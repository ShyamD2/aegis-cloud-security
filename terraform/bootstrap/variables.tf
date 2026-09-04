variable "aws_region" {
  type        = string
  description = "AWS region for AEGIS state backend infrastructure"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project name tag and naming prefix"
  default     = "aegis"
}

variable "environment" {
  type        = string
  description = "Deployment environment (e.g. bootstrap, dev, prod)"
  default     = "bootstrap"
}

variable "state_bucket_prefix" {
  type        = string
  description = "Prefix for the remote state S3 bucket"
  default     = "aegis-tf-state"
}

variable "tags" {
  type        = map(string)
  description = "Standard resource tags for AEGIS infrastructure"
  default = {
    Project                = "AEGIS"
    ManagedBy              = "Terraform"
    SecurityClassification = "Confidential"
  }
}
