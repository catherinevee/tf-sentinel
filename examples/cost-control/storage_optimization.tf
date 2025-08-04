# Example of S3 Storage Optimization
provider "aws" {
  region = "us-east-1"
}

# S3 Bucket with intelligent tiering
resource "aws_s3_bucket" "storage_optimized" {
  bucket = "storage-optimized-data"

  tags = {
    Name        = "storage-optimized-data"
    Environment = "prod"
    Purpose     = "data-storage"
  }
}

# Enable intelligent tiering
resource "aws_s3_bucket_intelligent_tiering_configuration" "storage_optimization" {
  bucket = aws_s3_bucket.storage_optimized.id
  name   = "EntireBucket"

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }

  status = "Enabled"
}

# Lifecycle rules for different storage classes
resource "aws_s3_bucket_lifecycle_configuration" "storage_lifecycle" {
  bucket = aws_s3_bucket.storage_optimized.id

  rule {
    id     = "log_lifecycle"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

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

  rule {
    id     = "document_lifecycle"
    status = "Enabled"

    filter {
      prefix = "documents/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    transition {
      days          = 180
      storage_class = "DEEP_ARCHIVE"
    }
  }
}

# Metrics configuration for cost monitoring
resource "aws_s3_bucket_metrics_configuration" "storage_metrics" {
  bucket = aws_s3_bucket.storage_optimized.id
  name   = "StorageMetrics"

  filter {
    prefix = "documents/"
    tags = {
      priority = "high"
    }
  }
}

# Analytics configuration for storage optimization
resource "aws_s3_bucket_analytics_configuration" "storage_analytics" {
  bucket = aws_s3_bucket.storage_optimized.id
  name   = "StorageAnalytics"

  storage_class_analysis {
    data_export {
      destination {
        s3_bucket_destination {
          bucket_arn = aws_s3_bucket.analytics_destination.arn
          prefix     = "analytics"
          format     = "CSV"
        }
      }
    }
  }
}

# Analytics destination bucket
resource "aws_s3_bucket" "analytics_destination" {
  bucket = "storage-analytics-destination"

  tags = {
    Name        = "storage-analytics"
    Environment = "prod"
    Purpose     = "analytics"
  }
}

# Inventory configuration for cost analysis
resource "aws_s3_bucket_inventory" "storage_inventory" {
  bucket = aws_s3_bucket.storage_optimized.id
  name   = "StorageInventory"

  included_object_versions = "All"

  schedule {
    frequency = "Weekly"
  }

  destination {
    bucket {
      bucket_arn = aws_s3_bucket.analytics_destination.arn
      format     = "CSV"
      prefix     = "inventory"
    }
  }

  optional_fields = [
    "Size",
    "LastModifiedDate",
    "StorageClass",
    "ETag",
    "IsMultipartUploaded",
    "ReplicationStatus"
  ]
}
