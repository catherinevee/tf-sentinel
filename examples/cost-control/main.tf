# Example infrastructure demonstrating cost control best practices
provider "aws" {
  region = "us-east-1"
}

# EC2 Instance with cost-optimized configuration
resource "aws_instance" "cost_optimized_instance" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.medium"  # Cost-effective instance type

  # Use Spot instances for non-production workloads
  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price = "0.0416" # Maximum hourly price (example)
    }
  }

  # Enable detailed monitoring only when needed
  monitoring = false

  # Automatic shutdown schedule using AWS EventBridge
  lifecycle {
    ignore_changes = [tags["LastStartTime"]]
  }

  tags = {
    Name           = "dev-app-server"
    Environment    = "dev"
    Owner          = "dev-team"
    CostCenter     = "12345"
    Project        = "dev-infrastructure"
    AutoShutdown   = "true"
    ShutdownTime   = "0000"
    StartupTime    = "0800"
  }
}

# Auto Scaling Group with cost optimization
resource "aws_autoscaling_group" "cost_optimized_asg" {
  name                = "dev-app-asg"
  min_size            = 1
  max_size            = 4
  desired_capacity    = 1
  
  # Use mixed instance types for cost optimization
  mixed_instances_policy {
    instances_distribution {
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 20
      spot_allocation_strategy                 = "capacity-optimized"
    }

    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.app.id
        version           = "$Latest"
      }

      override {
        instance_type = "t3.medium"
      }
      override {
        instance_type = "t3a.medium"
      }
      override {
        instance_type = "t2.medium"
      }
    }
  }

  tag {
    key                 = "Environment"
    value               = "dev"
    propagate_at_launch = true
  }
}

# S3 Bucket with lifecycle rules for cost optimization
resource "aws_s3_bucket" "cost_optimized_bucket" {
  bucket = "dev-app-data"

  tags = {
    Name           = "dev-app-data"
    Environment    = "dev"
    Owner          = "dev-team"
    CostCenter     = "12345"
    Project        = "dev-infrastructure"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bucket_lifecycle" {
  bucket = aws_s3_bucket.cost_optimized_bucket.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    expiration {
      days = 90
    }
  }
}

# RDS instance with cost optimization
resource "aws_db_instance" "cost_optimized_db" {
  identifier           = "dev-app-db"
  engine              = "postgres"
  engine_version      = "13.7"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  storage_encrypted   = true
  
  # Enable storage autoscaling with reasonable limits
  max_allocated_storage = 100
  
  # Disable unnecessary features in non-production
  multi_az             = false
  publicly_accessible  = false
  
  # Optimize backup settings
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  # Enable performance insights only when needed
  performance_insights_enabled = false

  tags = {
    Name           = "dev-app-db"
    Environment    = "dev"
    Owner          = "dev-team"
    CostCenter     = "12345"
    Project        = "dev-infrastructure"
  }
}

# EBS Volume with cost-effective configuration
resource "aws_ebs_volume" "cost_optimized_volume" {
  availability_zone = "us-east-1a"
  size             = 20
  type             = "gp3"  # More cost-effective than gp2
  iops             = 3000   # Default for gp3

  tags = {
    Name           = "dev-app-volume"
    Environment    = "dev"
    Owner          = "dev-team"
    CostCenter     = "12345"
    Project        = "dev-infrastructure"
  }
}
