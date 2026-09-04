variable "aws_region" {
  type        = string
  description = "AWS region for SageMaker anomaly inference"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Naming prefix for SageMaker resources"
  default     = "aegis"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS CMK for model artifact encryption"
}

variable "serverless_memory_in_mb" {
  type        = number
  description = "Memory allocation for SageMaker Serverless Inference (1024, 2048, 4096, 6144 MB)"
  default     = 2048
}

variable "max_concurrency" {
  type        = number
  description = "Max concurrent invocations for Serverless Inference"
  default     = 5
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project   = "AEGIS"
    Component = "SageMakerAnomaly"
    ManagedBy = "Terraform"
  }
}
