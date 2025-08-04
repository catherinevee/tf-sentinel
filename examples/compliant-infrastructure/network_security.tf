# Example of Network Security with WAF and Shield
provider "aws" {
  region = "us-east-1"
}

# AWS WAF Web ACL
resource "aws_wafv2_web_acl" "secure_acl" {
  name        = "secure-web-acl"
  description = "Secure Web ACL with strict rules"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # IP rate limiting rule
  rule {
    name     = "IPRateLimit"
    priority = 1

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "IPRateLimitMetric"
      sampled_requests_enabled  = true
    }
  }

  # SQL injection prevention
  rule {
    name     = "SQLInjectionRule"
    priority = 2

    override_action {
      none {}
    }

    statement {
      sql_injection_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "SQLInjectionMetric"
      sampled_requests_enabled  = true
    }
  }

  # Cross-site scripting prevention
  rule {
    name     = "XSSRule"
    priority = 3

    override_action {
      none {}
    }

    statement {
      xss_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "XSSMetric"
      sampled_requests_enabled  = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "SecureWebACLMetric"
    sampled_requests_enabled  = true
  }

  tags = {
    Name           = "secure-web-acl"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# AWS Shield Advanced
resource "aws_shield_protection" "secure_alb" {
  name         = "secure-alb-protection"
  resource_arn = aws_lb.secure_alb.arn

  tags = {
    Name           = "secure-alb-protection"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Application Load Balancer with security configurations
resource "aws_lb" "secure_alb" {
  name               = "secure-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets           = ["subnet-12345678", "subnet-87654321"]

  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb-logs"
    enabled = true
  }

  tags = {
    Name           = "secure-alb"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Security Group for ALB
resource "aws_security_group" "alb_sg" {
  name        = "secure-alb-sg"
  description = "Security group for secure ALB"
  vpc_id      = aws_vpc.secure_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name           = "secure-alb-sg"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# S3 bucket for ALB logs
resource "aws_s3_bucket" "alb_logs" {
  bucket = "secure-alb-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name           = "secure-alb-logs"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Enable encryption for ALB logs bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access to ALB logs bucket
resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# VPC configuration
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name           = "secure-vpc"
    Environment    = "prod"
    Owner          = "platform-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Allow ALB to write logs to S3
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
