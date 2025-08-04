# Example OPA policy for disaster recovery
package terraform.dr

import input.plan as tfplan

# DR requirements by environment
dr_requirements = {
    "prod": {
        "multi_az": true,
        "backup_retention": 30,
        "cross_region_replication": true,
        "point_in_time_recovery": true,
        "min_replicas": 2
    },
    "staging": {
        "multi_az": true,
        "backup_retention": 14,
        "cross_region_replication": false,
        "point_in_time_recovery": true,
        "min_replicas": 1
    },
    "dev": {
        "multi_az": false,
        "backup_retention": 7,
        "cross_region_replication": false,
        "point_in_time_recovery": false,
        "min_replicas": 1
    }
}

# Required recovery point objective (RPO) in hours
required_rpo = {
    "prod": 1,
    "staging": 24,
    "dev": 48
}

# Required recovery time objective (RTO) in hours
required_rto = {
    "prod": 2,
    "staging": 4,
    "dev": 24
}

# Deny RDS instances without proper DR configuration
deny_rds_dr_config[msg] {
    db = tfplan.resource_changes[_]
    db.type == "aws_db_instance"
    env = db.change.after.tags.Environment
    requirements = dr_requirements[env]
    
    requirements.multi_az
    not db.change.after.multi_az
    msg = sprintf(
        "RDS instance must be Multi-AZ in %v environment",
        [env]
    )
}

# Deny insufficient backup retention
deny_insufficient_backup[msg] {
    db = tfplan.resource_changes[_]
    db.type == "aws_db_instance"
    env = db.change.after.tags.Environment
    
    db.change.after.backup_retention_period < dr_requirements[env].backup_retention
    msg = sprintf(
        "Backup retention period must be at least %v days in %v environment",
        [dr_requirements[env].backup_retention, env]
    )
}

# Enforce cross-region replication for S3
deny_missing_replication[msg] {
    bucket = tfplan.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    env = bucket.change.after.tags.Environment
    
    dr_requirements[env].cross_region_replication
    not has_replication_configuration(bucket.change.after.id)
    msg = sprintf(
        "S3 bucket must have cross-region replication enabled in %v environment",
        [env]
    )
}

# Helper function to check replication
has_replication_configuration(bucket_id) {
    replication = tfplan.resource_changes[_]
    replication.type == "aws_s3_bucket_replication_configuration"
    replication.change.after.bucket == bucket_id
}

# Enforce point-in-time recovery for DynamoDB
deny_missing_pitr[msg] {
    table = tfplan.resource_changes[_]
    table.type == "aws_dynamodb_table"
    env = table.change.after.tags.Environment
    
    dr_requirements[env].point_in_time_recovery
    not table.change.after.point_in_time_recovery
    msg = sprintf(
        "DynamoDB table must have point-in-time recovery enabled in %v environment",
        [env]
    )
}

# Enforce minimum number of replicas
deny_insufficient_replicas[msg] {
    resource = tfplan.resource_changes[_]
    env = resource.change.after.tags.Environment
    min_replicas = dr_requirements[env].min_replicas
    
    count_replicas(resource) < min_replicas
    msg = sprintf(
        "Resource must have at least %v replicas in %v environment",
        [min_replicas, env]
    )
}

# Helper function to count replicas
count_replicas(resource) = count {
    resource.type == "aws_elasticache_replication_group"
    count = resource.change.after.number_cache_clusters
} {
    resource.type == "aws_rds_cluster"
    count = resource.change.after.number_instances
} {
    resource.type == "aws_elasticsearch_domain"
    count = resource.change.after.cluster_config[0].instance_count
}

# Enforce RPO compliance
deny_rpo_violation[msg] {
    backup = tfplan.resource_changes[_]
    env = backup.change.after.tags.Environment
    
    calculated_rpo = calculate_rpo(backup)
    calculated_rpo > required_rpo[env]
    msg = sprintf(
        "Backup configuration does not meet RPO requirement of %v hours for %v environment",
        [required_rpo[env], env]
    )
}

# Helper function to calculate RPO
calculate_rpo(backup) = rpo {
    backup.type == "aws_backup_plan"
    rpo = backup.change.after.rule[0].schedule_expression
}

# Main deny rule combining all DR policies
deny[msg] {
    msg = deny_rds_dr_config[_]
} {
    msg = deny_insufficient_backup[_]
} {
    msg = deny_missing_replication[_]
} {
    msg = deny_missing_pitr[_]
} {
    msg = deny_insufficient_replicas[_]
} {
    msg = deny_rpo_violation[_]
}
