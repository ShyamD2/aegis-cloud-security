output "kinesis_stream_name" {
  description = "Name of the Kinesis data stream"
  value       = var.enable_kinesis ? aws_kinesis_stream.security_events[0].name : null
}

output "kinesis_stream_arn" {
  description = "ARN of the Kinesis data stream"
  value       = var.enable_kinesis ? aws_kinesis_stream.security_events[0].arn : null
}

output "dlq_url" {
  description = "URL of the SQS Dead-Letter Queue"
  value       = aws_sqs_queue.pipeline_dlq.url
}

output "dlq_arn" {
  description = "ARN of the SQS Dead-Letter Queue"
  value       = aws_sqs_queue.pipeline_dlq.arn
}
