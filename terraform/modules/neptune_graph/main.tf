# Project AEGIS - Amazon Neptune Attack Path & Blast Radius Engine
# Provisions an encrypted, IAM-authenticated Serverless Neptune cluster with CloudWatch audit exports.

resource "aws_security_group" "neptune" {
  name        = "${var.cluster_identifier}-${var.environment}-sg"
  description = "Security group for AEGIS Neptune attack-path graph cluster"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow openCypher/Gremlin queries on port 8182 from AEGIS internal subnets"
    from_port   = 8182
    to_port     = 8182
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    description = "Allow outbound to KMS and AWS service endpoints"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_identifier}-${var.environment}-sg"
  })
}

resource "aws_neptune_subnet_group" "this" {
  name       = "${var.cluster_identifier}-${var.environment}-subnets"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.cluster_identifier}-${var.environment}-subnet-group"
  })
}

resource "aws_neptune_cluster" "this" {
  cluster_identifier                  = "${var.cluster_identifier}-${var.environment}"
  engine                              = "neptune"
  neptune_subnet_group_name           = aws_neptune_subnet_group.this.name
  vpc_security_group_ids              = [aws_security_group.neptune.id]
  kms_key_arn                         = var.kms_key_arn
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  enable_cloudwatch_logs_exports      = ["audit"]
  skip_final_snapshot                 = true
  deletion_protection                 = false

  serverless_v2_scaling_configuration {
    min_capacity = 1.0
    max_capacity = 2.5
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_identifier}-${var.environment}"
  })
}

resource "aws_neptune_cluster_instance" "this" {
  cluster_identifier = aws_neptune_cluster.this.id
  identifier         = "${var.cluster_identifier}-${var.environment}-instance-1"
  instance_class     = "db.serverless"
  apply_immediately  = true

  tags = merge(var.tags, {
    Name = "${var.cluster_identifier}-${var.environment}-instance-1"
  })
}
