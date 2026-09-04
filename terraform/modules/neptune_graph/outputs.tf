output "cluster_id" {
  description = "Neptune cluster identifier"
  value       = aws_neptune_cluster.this.id
}

output "cluster_endpoint" {
  description = "Neptune cluster read/write HTTPS endpoint"
  value       = aws_neptune_cluster.this.endpoint
}

output "cluster_reader_endpoint" {
  description = "Neptune cluster read-only HTTPS endpoint"
  value       = aws_neptune_cluster.this.reader_endpoint
}

output "cluster_arn" {
  description = "Neptune cluster ARN"
  value       = aws_neptune_cluster.this.arn
}

output "security_group_id" {
  description = "Security group protecting Neptune openCypher/Gremlin ports"
  value       = aws_security_group.neptune.id
}
