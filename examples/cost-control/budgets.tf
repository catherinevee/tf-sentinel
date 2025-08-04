# Example of AWS Budgets and Cost Explorer setup
provider "aws" {
  region = "us-east-1"
}

# AWS Budget with multiple thresholds and notifications
resource "aws_budgets_budget" "cost_management" {
  name              = "monthly-cost-budget"
  budget_type       = "COST"
  limit_amount      = "1000"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2025-01-01_00:00"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_email_addresses = ["team@example.com"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = ["team@example.com"]
  }

  cost_filters = {
    TagKeyValue = "Environment$Dev"
  }
}

# Cost and Usage Report Configuration
resource "aws_cur_report_definition" "cost_report" {
  report_name                = "daily-cost-report"
  time_unit                  = "DAILY"
  format                     = "textORcsv"
  compression                = "GZIP"
  additional_schema_elements = ["RESOURCES"]
  s3_bucket                 = aws_s3_bucket.cost_reports.id
  s3_region                 = "us-east-1"
  additional_artifacts       = ["ATHENA"]
  report_versioning         = "OVERWRITE_REPORT"
}

# S3 Bucket for cost reports
resource "aws_s3_bucket" "cost_reports" {
  bucket = "org-cost-reports-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "cost-reports"
    Environment = "management"
    Purpose     = "cost-analysis"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cost_reports_lifecycle" {
  bucket = aws_s3_bucket.cost_reports.id

  rule {
    id     = "cost-reports-lifecycle"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# IAM Role for Cost Explorer access
resource "aws_iam_role" "cost_explorer" {
  name = "CostExplorerReadOnly"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ce.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cost_explorer" {
  role       = aws_iam_role.cost_explorer.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCostExplorerReadOnlyAccess"
}

data "aws_caller_identity" "current" {}
