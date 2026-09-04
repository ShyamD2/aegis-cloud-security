output "findings_bus_name" {
  description = "Name of the AEGIS central findings EventBridge bus"
  value       = aws_cloudwatch_event_bus.aegis_findings.name
}

output "findings_bus_arn" {
  description = "ARN of the AEGIS central findings EventBridge bus"
  value       = aws_cloudwatch_event_bus.aegis_findings.arn
}

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = try(aws_guardduty_detector.primary[0].id, null)
}
