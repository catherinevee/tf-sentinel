# Example infrastructure showing compliant configurations
provider "aws" {
  region = "us-east-1"
}

# VPC Configuration with proper tagging and encryption
resource "aws_vpc" "compliant_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name           = "prod-app-vpc"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
    DataClassification = "internal"
  }
}

# Encrypted S3 bucket with proper access controls
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "prod-app-secure-data"

  tags = {
    Name              = "prod-app-secure-data"
    Environment       = "prod"
    Owner             = "data-team"
    CostCenter        = "12345"
    Project           = "core-infrastructure"
    DataClassification = "confidential"
    RetentionPeriod   = "365"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.encryption_key.arn
    }
  }
}

# KMS key for encryption
resource "aws_kms_key" "encryption_key" {
  description             = "KMS key for bucket encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name           = "prod-app-encryption-key"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# RDS instance with proper security configurations
resource "aws_db_instance" "compliant_db" {
  identifier           = "prod-app-db"
  engine              = "postgres"
  engine_version      = "13.7"
  instance_class      = "db.r6g.large"
  allocated_storage   = 100
  storage_encrypted   = true
  multi_az           = true
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name

  tags = {
    Name              = "prod-app-db"
    Environment       = "prod"
    Owner             = "dba-team"
    CostCenter        = "12345"
    Project           = "core-infrastructure"
    DataClassification = "confidential"
  }
}

# Security group with proper ingress/egress rules
resource "aws_security_group" "db_sg" {
  name        = "prod-app-db-sg"
  description = "Security group for production database"
  vpc_id      = aws_vpc.compliant_vpc.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  tags = {
    Name           = "prod-app-db-sg"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Auto Scaling Group with proper configurations
resource "aws_autoscaling_group" "compliant_asg" {
  name                = "prod-app-asg"
  min_size            = 2
  max_size            = 6
  desired_capacity    = 2
  health_check_type   = "ELB"
  vpc_zone_identifier = aws_subnet.private[*].id

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Environment"
    value               = "prod"
    propagate_at_launch = true
  }

  tag {
    key                 = "Owner"
    value               = "platform-team"
    propagate_at_launch = true
  }
}

# CloudWatch monitoring with proper retention
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/prod/app/logs"
  retention_in_days = 90

  tags = {
    Name           = "prod-app-logs"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# IAM role with proper permissions boundary
resource "aws_iam_role" "app_role" {
  name                 = "prod-app-role"
  assume_role_policy   = data.aws_iam_policy_document.assume_role.json
  permissions_boundary = "arn:aws:iam::ACCOUNT_ID:policy/ProductionBoundary"

  tags = {
    Name           = "prod-app-role"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Compliant IAM policy
data "aws_iam_policy_document" "app_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.compliant_bucket.arn}/*"
    ]
  }
}
