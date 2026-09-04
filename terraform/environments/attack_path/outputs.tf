output "neptune_cluster_endpoint" {
  description = "Neptune cluster read/write openCypher HTTPS endpoint"
  value       = module.neptune_graph.cluster_endpoint
}

output "neptune_cluster_arn" {
  description = "Neptune cluster ARN"
  value       = module.neptune_graph.cluster_arn
}

output "neptune_security_group_id" {
  description = "Security group ID attached to Neptune cluster"
  value       = module.neptune_graph.security_group_id
}
