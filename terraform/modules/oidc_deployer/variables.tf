variable "github_org" {
  type        = string
  description = "GitHub Organization or username owning the Project AEGIS repository"
  default     = "Project-AEGIS"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name"
  default     = "PROJECT-AEGIS"
}

variable "allowed_branches" {
  type        = list(string)
  description = "Allowed branches permitted to assume deployment role"
  default     = ["main", "master"]
}

variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "prod"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default = {
    Project     = "AEGIS"
    Component   = "DevSecOps"
    ManagedBy   = "Terraform"
    Environment = "prod"
  }
}
