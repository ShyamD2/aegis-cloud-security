output "findings_bus_name" {
  description = "AEGIS findings EventBridge bus name"
  value       = module.native_detection.findings_bus_name
}

output "findings_bus_arn" {
  description = "AEGIS findings EventBridge bus ARN"
  value       = module.native_detection.findings_bus_arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = module.native_detection.guardduty_detector_id
}
