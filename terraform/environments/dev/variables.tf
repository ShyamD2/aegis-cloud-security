variable "aws_region" {
  type        = string
  description = "AWS region for development resources"
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project naming prefix"
  default     = "aegis"
}
