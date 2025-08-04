# Example OPA policy for AWS storage cost optimization
package terraform.storage_optimization

import input.plan as tfplan

# Storage optimization requirements by environment
storage_requirements = {
    "prod": {
        "require_lifecycle_rules": true,
        "max_glacier_transition_days": 90,
        "max_retention_days": 365,
        "require_compression": true,
        "max_snapshot_retention": 30,
        "require_cost_allocation": true,
        "max_provisioned_iops": 1000,
        "allowed_storage_classes": ["STANDARD", "STANDARD_IA", "GLACIER"],
        "require_intelligent_tiering": true
    },
    "staging": {
        "require_lifecycle_rules": true,
        "max_glacier_transition_days": 60,
        "max_retention_days": 180,
        "require_compression": true,
        "max_snapshot_retention": 14,
        "require_cost_allocation": true,
        "max_provisioned_iops": 500,
        "allowed_storage_classes": ["STANDARD", "STANDARD_IA"],
        "require_intelligent_tiering": false
    },
    "dev": {
        "require_lifecycle_rules": false,
        "max_glacier_transition_days": 30,
        "max_retention_days": 90,
        "require_compression": false,
        "max_snapshot_retention": 7,
        "require_cost_allocation": false,
        "max_provisioned_iops": 100,
        "allowed_storage_classes": ["STANDARD"],
        "require_intelligent_tiering": false
    }
}

# Deny missing S3 lifecycle rules
deny_missing_lifecycle_rules[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    storage_requirements[env].require_lifecycle_rules
    not has_lifecycle_rules(bucket.change.after)
    
    msg = sprintf(
        "S3 bucket must have lifecycle rules in %v environment",
        [env]
    )
}

# Helper to check lifecycle rules
has_lifecycle_rules(bucket) {
    bucket.lifecycle_rule[_]
}

# Deny invalid Glacier transition days
deny_invalid_glacier_transition[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    rule = bucket.change.after.lifecycle_rule[_]
    transition = rule.transition[_]
    transition.storage_class == "GLACIER"
    
    transition.days < storage_requirements[env].max_glacier_transition_days
    
    msg = sprintf(
        "Glacier transition must occur after %v days in %v environment",
        [storage_requirements[env].max_glacier_transition_days, env]
    )
}

# Deny excessive retention periods
deny_long_retention[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    rule = bucket.change.after.lifecycle_rule[_]
    rule.expiration.days > storage_requirements[env].max_retention_days
    
    msg = sprintf(
        "S3 object retention cannot exceed %v days in %v environment",
        [storage_requirements[env].max_retention_days, env]
    )
}

# Deny missing compression
deny_missing_compression[msg] {
    volume = tfplan.resource_changes[_]
    volume.type == "aws_ebs_volume"
    env = volume.change.after.tags.Environment
    
    storage_requirements[env].require_compression
    not volume.change.after.encrypted
    
    msg = sprintf(
        "EBS volumes must be encrypted (compressed) in %v environment",
        [env]
    )
}

# Deny excessive snapshot retention
deny_long_snapshot_retention[msg] {
    snapshot = tfplan.resource_changes[_]
    snapshot.type == "aws_dlm_lifecycle_policy"
    env = snapshot.change.after.tags.Environment
    
    policy = snapshot.change.after.policy_details[_]
    policy.retain_rule.count > storage_requirements[env].max_snapshot_retention
    
    msg = sprintf(
        "Snapshot retention cannot exceed %v in %v environment",
        [storage_requirements[env].max_snapshot_retention, env]
    )
}

# Deny missing cost allocation tags
deny_missing_cost_tags[msg] {
    resource = tfplan.resource_changes[_]
    types = ["aws_s3_bucket", "aws_ebs_volume", "aws_efs_file_system"]
    resource.type == types[_]
    env = resource.change.after.tags.Environment
    
    storage_requirements[env].require_cost_allocation
    not has_cost_tags(resource.change.after.tags)
    
    msg = sprintf(
        "Storage resources must have cost allocation tags in %v environment",
        [env]
    )
}

# Helper to check cost tags
has_cost_tags(tags) {
    tags.CostCenter
    tags.Project
}

# Deny excessive provisioned IOPS
deny_high_iops[msg] {
    volume = tfplan.resource_changes[_]
    volume.type == "aws_ebs_volume"
    env = volume.change.after.tags.Environment
    
    volume.change.after.iops > storage_requirements[env].max_provisioned_iops
    
    msg = sprintf(
        "Provisioned IOPS cannot exceed %v in %v environment",
        [storage_requirements[env].max_provisioned_iops, env]
    )
}

# Deny invalid storage classes
deny_invalid_storage_class[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    storage_class = bucket.change.after.storage_class
    not storage_class_allowed(storage_class, env)
    
    msg = sprintf(
        "Storage class %v is not allowed in %v environment. Allowed classes: %v",
        [storage_class, env, storage_requirements[env].allowed_storage_classes]
    )
}

# Helper to check allowed storage classes
storage_class_allowed(class, env) {
    storage_requirements[env].allowed_storage_classes[_] == class
}

# Deny missing intelligent tiering
deny_missing_intelligent_tiering[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    storage_requirements[env].require_intelligent_tiering
    not has_intelligent_tiering(bucket.change.after)
    
    msg = sprintf(
        "S3 bucket must use intelligent tiering in %v environment",
        [env]
    )
}

# Helper to check intelligent tiering
has_intelligent_tiering(bucket) {
    bucket.lifecycle_rule[_].transition[_].storage_class == "INTELLIGENT_TIERING"
}

# Main deny rule combining all storage optimization policies
deny[msg] {
    msg = deny_missing_lifecycle_rules[_]
} {
    msg = deny_invalid_glacier_transition[_]
} {
    msg = deny_long_retention[_]
} {
    msg = deny_missing_compression[_]
} {
    msg = deny_long_snapshot_retention[_]
} {
    msg = deny_missing_cost_tags[_]
} {
    msg = deny_high_iops[_]
} {
    msg = deny_invalid_storage_class[_]
} {
    msg = deny_missing_intelligent_tiering[_]
}
