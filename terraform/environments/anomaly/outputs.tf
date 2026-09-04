output "anomaly_endpoint_arn" {
  description = "SageMaker anomaly endpoint ARN"
  value       = module.sagemaker_anomaly.endpoint_arn
}

output "anomaly_endpoint_name" {
  description = "SageMaker anomaly endpoint name"
  value       = module.sagemaker_anomaly.endpoint_name
}
