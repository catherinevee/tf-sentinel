# Example OPA policy for data protection
package terraform.data_protection

import input.plan as tfplan

# Data protection requirements by environment
data_requirements = {
    "prod": {
        "require_encryption": true,
        "allowed_kms_keys": ["aws/rds", "aws/ebs", "aws/s3"],
        "require_backup": true,
        "minimum_backup_retention": 30,
        "require_point_in_time_recovery": true,
        "require_versioning": true,
        "require_deletion_protection": true,
        "require_access_logging": true,
        "require_cmk": true,
        "require_replication": true,
        "allowed_storage_classes": ["STANDARD_IA", "GLACIER"],
        "require_secure_transport": true,
        "require_object_lock": true,
        "require_tags": ["DataClassification", "RetentionPeriod"],
        "allowed_data_classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
        "default_retention_period": 365
    },
    "staging": {
        "require_encryption": true,
        "allowed_kms_keys": ["aws/rds", "aws/ebs", "aws/s3"],
        "require_backup": true,
        "minimum_backup_retention": 14,
        "require_point_in_time_recovery": false,
        "require_versioning": true,
        "require_deletion_protection": false,
        "require_access_logging": true,
        "require_cmk": false,
        "require_replication": false,
        "allowed_storage_classes": ["STANDARD", "STANDARD_IA"],
        "require_secure_transport": true,
        "require_object_lock": false,
        "require_tags": ["DataClassification"],
        "allowed_data_classifications": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"],
        "default_retention_period": 90
    },
    "dev": {
        "require_encryption": true,
        "allowed_kms_keys": ["aws/rds", "aws/ebs", "aws/s3"],
        "require_backup": false,
        "minimum_backup_retention": 7,
        "require_point_in_time_recovery": false,
        "require_versioning": false,
        "require_deletion_protection": false,
        "require_access_logging": false,
        "require_cmk": false,
        "require_replication": false,
        "allowed_storage_classes": ["STANDARD"],
        "require_secure_transport": true,
        "require_object_lock": false,
        "require_tags": ["DataClassification"],
        "allowed_data_classifications": ["PUBLIC", "INTERNAL"],
        "default_retention_period": 30
    }
}

# Deny unencrypted resources
deny_unencrypted_resources[msg] {
    resource = tfplan.resource_changes[_]
    env = resource.change.after.tags.Environment
    data_requirements[env].require_encryption
    
    is_encryptable(resource.type)
    not is_encrypted(resource)
    
    msg = sprintf(
        "Resource %v must be encrypted in %v environment",
        [resource.address, env]
    )
}

# Helper to identify encryptable resources
is_encryptable(type) {
    encryptable_types := {
        "aws_s3_bucket",
        "aws_ebs_volume",
        "aws_rds_cluster",
        "aws_db_instance",
        "aws_dynamodb_table"
    }
    encryptable_types[type]
}

# Helper to check encryption
is_encrypted(resource) {
    resource.change.after.encrypted
} {
    resource.change.after.server_side_encryption_configuration
}

# Deny missing backups
deny_missing_backup[msg] {
    resource = tfplan.resource_changes[_]
    env = resource.change.after.tags.Environment
    
    data_requirements[env].require_backup
    is_backupable(resource.type)
    not has_backup_configuration(resource)
    
    msg = sprintf(
        "Resource %v must have backup configured in %v environment",
        [resource.address, env]
    )
}

# Helper to identify backupable resources
is_backupable(type) {
    backupable_types := {
        "aws_rds_cluster",
        "aws_db_instance",
        "aws_dynamodb_table",
        "aws_efs_file_system"
    }
    backupable_types[type]
}

# Helper to check backup configuration
has_backup_configuration(resource) {
    resource.change.after.backup_retention_period >= data_requirements[resource.change.after.tags.Environment].minimum_backup_retention
} {
    resource.change.after.backup.window
}

# Deny missing point-in-time recovery
deny_missing_pitr[msg] {
    table = tfplan.resource_changes[_]
    table.type == "aws_dynamodb_table"
    env = table.change.after.tags.Environment
    
    data_requirements[env].require_point_in_time_recovery
    not table.change.after.point_in_time_recovery
    
    msg = sprintf(
        "DynamoDB table must have point-in-time recovery enabled in %v environment",
        [env]
    )
}

# Deny missing versioning
deny_missing_versioning[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    data_requirements[env].require_versioning
    not has_versioning(bucket.change.after.id)
    
    msg = sprintf(
        "S3 bucket must have versioning enabled in %v environment",
        [env]
    )
}

# Helper to check versioning
has_versioning(bucket_id) {
    versioning = tfplan.resource_changes[_]
    versioning.type == "aws_s3_bucket_versioning"
    versioning.change.after.bucket == bucket_id
    versioning.change.after.versioning_configuration[0].status == "Enabled"
}

# Deny missing access logging
deny_missing_logging[msg] {
    resource = tfplan.resource_changes[_]
    env = resource.change.after.tags.Environment
    
    data_requirements[env].require_access_logging
    is_loggable(resource.type)
    not has_logging(resource)
    
    msg = sprintf(
        "Resource %v must have access logging enabled in %v environment",
        [resource.address, env]
    )
}

# Helper to identify loggable resources
is_loggable(type) {
    loggable_types := {
        "aws_s3_bucket",
        "aws_rds_cluster",
        "aws_db_instance",
        "aws_elasticache_cluster"
    }
    loggable_types[type]
}

# Helper to check logging
has_logging(resource) {
    resource.change.after.logging
} {
    logging = tfplan.resource_changes[_]
    logging.type == "aws_s3_bucket_logging"
    logging.change.after.bucket == resource.change.after.id
}

# Deny invalid storage classes
deny_invalid_storage_class[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    storage_class = bucket.change.after.lifecycle_rule[_].transition[_].storage_class
    not array_contains(data_requirements[env].allowed_storage_classes, storage_class)
    
    msg = sprintf(
        "Storage class %v is not allowed in %v environment",
        [storage_class, env]
    )
}

# Deny missing object lock
deny_missing_object_lock[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    data_requirements[env].require_object_lock
    not bucket.change.after.object_lock_configuration
    
    msg = sprintf(
        "S3 bucket must have object lock enabled in %v environment",
        [env]
    )
}

# Deny invalid data classifications
deny_invalid_classification[msg] {
    resource = tfplan.resource_changes[_]
    env = resource.change.after.tags.Environment
    
    classification = resource.change.after.tags.DataClassification
    not array_contains(data_requirements[env].allowed_data_classifications, classification)
    
    msg = sprintf(
        "Data classification %v is not allowed in %v environment",
        [classification, env]
    )
}

# Helper function for array operations
array_contains(arr, elem) {
    arr[_] == elem
}

# Main deny rule combining all data protection policies
deny[msg] {
    msg = deny_unencrypted_resources[_]
} {
    msg = deny_missing_backup[_]
} {
    msg = deny_missing_pitr[_]
} {
    msg = deny_missing_versioning[_]
} {
    msg = deny_missing_logging[_]
} {
    msg = deny_invalid_storage_class[_]
} {
    msg = deny_missing_object_lock[_]
} {
    msg = deny_invalid_classification[_]
}
