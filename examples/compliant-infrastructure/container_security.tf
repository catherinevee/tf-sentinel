# Example of Container Security Configuration
provider "aws" {
  region = "us-east-1"
}

# ECS Cluster with security configurations
resource "aws_ecs_cluster" "secure_cluster" {
  name = "secure-production-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name           = "secure-production-cluster"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
    SecurityZone   = "restricted"
  }
}

# Cluster capacity providers
resource "aws_ecs_cluster_capacity_providers" "secure_cluster" {
  cluster_name = aws_ecs_cluster.secure_cluster.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight           = 1
    base            = 1
  }
}

# Task execution role with least privilege
resource "aws_iam_role" "ecs_execution_role" {
  name = "ecs-secure-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# Task execution role policy
resource "aws_iam_role_policy" "ecs_execution_role_policy" {
  name = "ecs-secure-execution-policy"
  role = aws_iam_role.ecs_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# Task definition with security configurations
resource "aws_ecs_task_definition" "secure_task" {
  family                   = "secure-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                     = 256
  memory                  = 512
  execution_role_arn      = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([
    {
      name  = "secure-app"
      image = "my-secure-app:latest"
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/secure-app"
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # Security configurations
      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          drop = ["ALL"]
          add  = ["NET_BIND_SERVICE"]
        }
      }

      # Read-only root filesystem
      readonlyRootFilesystem = true

      # Environment variables from secure parameters
      secrets = [
        {
          name      = "DATABASE_PASSWORD"
          valueFrom = "arn:aws:ssm:us-east-1:123456789012:parameter/prod/db/password"
        }
      ]
    }
  ])

  # Enable EFS for persistent storage
  volume {
    name = "secure-storage"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.secure_storage.id
      root_directory = "/"
      transit_encryption = "ENABLED"
      authorization_config {
        iam = "ENABLED"
      }
    }
  }

  tags = {
    Name           = "secure-app-task"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
    SecurityZone   = "restricted"
  }
}

# EFS File System for secure storage
resource "aws_efs_file_system" "secure_storage" {
  creation_token = "secure-storage"
  encrypted      = true
  
  kms_key_id     = aws_kms_key.efs_key.arn

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name           = "secure-storage"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
    SecurityZone   = "restricted"
  }
}

# KMS key for EFS encryption
resource "aws_kms_key" "efs_key" {
  description             = "KMS key for EFS encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name           = "efs-encryption-key"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

data "aws_caller_identity" "current" {}
