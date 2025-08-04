# Example of Auto Scaling and EC2 Fleet for cost optimization
provider "aws" {
  region = "us-east-1"
}

# EC2 Fleet configuration for mixed instance types
resource "aws_ec2_fleet" "cost_optimized_fleet" {
  type = "maintain"
  
  target_capacity_specification {
    default_target_capacity_type = "spot"
    total_target_capacity       = 10
    on_demand_target_capacity  = 2
  }

  launch_template_config {
    launch_template_specification {
      launch_template_id = aws_launch_template.app_template.id
      version           = "$Latest"
    }

    override {
      instance_type     = "t3.medium"
      weighted_capacity = 1
    }
    override {
      instance_type     = "t3a.medium"
      weighted_capacity = 1
    }
    override {
      instance_type     = "t2.medium"
      weighted_capacity = 1
    }
  }

  spot_options {
    allocation_strategy = "diversified"
    instance_pools_to_use_count = 3
    maintenance_strategies {
      capacity_rebalance = true
    }
  }

  tags = {
    Name        = "cost-optimized-fleet"
    Environment = "staging"
    Purpose     = "web-services"
  }
}

# Launch template for EC2 instances
resource "aws_launch_template" "app_template" {
  name_prefix   = "app-template"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.medium"

  monitoring {
    enabled = false
  }

  credit_specification {
    cpu_credits = "unlimited"
  }

  placement {
    spread_domain = "host"
  }

  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price = "0.0416"
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "app-server"
      Environment = "staging"
      Purpose     = "web-services"
    }
  }
}

# Auto Scaling Group with predictive scaling
resource "aws_autoscaling_group" "predictive_scaling" {
  name                = "predictive-scaling-group"
  min_size            = 2
  max_size            = 10
  health_check_type   = "ELB"
  target_group_arns   = [aws_lb_target_group.app.arn]
  vpc_zone_identifier = ["subnet-12345678", "subnet-87654321"]

  launch_template {
    id      = aws_launch_template.app_template.id
    version = "$Latest"
  }

  predictive_scaling_configuration {
    metric_specification {
      target_value = 75
      customized_scaling_metric_specification {
        metric_data_queries {
          id          = "load_sum"
          expression  = "SUM(SEARCH('{AWS/EC2,AutoScalingGroupName} MetricName=\"CPUUtilization\"', 'Sum', 300))"
        }
      }
      customized_load_metric_specification {
        metric_data_queries {
          id         = "capacity_sum"
          expression = "SUM(SEARCH('{AWS/AutoScaling,AutoScalingGroupName} MetricName=\"GroupInServiceInstances\"', 'Average', 300))"
        }
      }
    }
  }

  tag {
    key                 = "Environment"
    value              = "staging"
    propagate_at_launch = true
  }
}

# Target group for load balancer
resource "aws_lb_target_group" "app" {
  name     = "app-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-12345678"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    path               = "/health"
    timeout            = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name        = "app-target-group"
    Environment = "staging"
  }
}
