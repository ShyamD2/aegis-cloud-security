output "endpoint_name" {
  description = "Name of the SageMaker anomaly inference endpoint"
  value       = aws_sagemaker_endpoint.anomaly_endpoint.name
}

output "endpoint_arn" {
  description = "ARN of the SageMaker anomaly inference endpoint"
  value       = aws_sagemaker_endpoint.anomaly_endpoint.arn
}

output "model_artifacts_bucket" {
  description = "Name of S3 bucket housing SageMaker model artifacts"
  value       = aws_s3_bucket.model_artifacts.id
}
