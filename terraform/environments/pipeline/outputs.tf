output "kinesis_stream_arn" {
  description = "Kinesis data stream ARN"
  value       = module.pipeline.kinesis_stream_arn
}

output "dlq_url" {
  description = "Pipeline SQS DLQ URL"
  value       = module.pipeline.dlq_url
}
