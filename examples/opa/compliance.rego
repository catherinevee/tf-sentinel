# Example OPA policy for compliance
package terraform.compliance

import input.plan as tfplan

# Required tags for compliance
required_tags = {
    "all": ["Environment", "Owner", "CostCenter", "Project"],
    "prod": ["DataClassification", "ComplianceLevel", "DR"]
}

# Required backup settings by environment
backup_requirements = {
    "prod": {
        "retention_days": 30,
        "frequency": "daily"
    },
    "staging": {
        "retention_days": 14,
        "frequency": "daily"
    },
    "dev": {
        "retention_days": 7,
        "frequency": "weekly"
    }
}

# Required monitoring settings
monitoring_requirements = {
    "prod": {
        "detailed_monitoring": true,
        "log_retention_days": 365,
        "alerts_enabled": true
    },
    "staging": {
        "detailed_monitoring": true,
        "log_retention_days": 90,
        "alerts_enabled": true
    },
    "dev": {
        "detailed_monitoring": false,
        "log_retention_days": 30,
        "alerts_enabled": false
    }
}

# Enforce required tags
deny_missing_tags[msg] {
    resource = tfplan.resource_changes[_]
    env = resource.change.after.tags.Environment
    missing = missing_tags(resource.change.after.tags, env)
    count(missing) > 0
    msg = sprintf(
        "Resource missing required tags: %v",
        [missing]
    )
}

# Helper function to check missing tags
missing_tags(existing, env) = missing {
    required = required_tags.all
    env == "prod"
    full_required = array.concat(required, required_tags.prod)
    missing = [tag | tag = full_required[_]; not existing[tag]]
}

# Enforce backup requirements
deny_insufficient_backup[msg] {
    backup = tfplan.resource_changes[_]
    backup.type == "aws_backup_plan"
    env = backup.change.after.tags.Environment
    backup.change.after.rule[_].retention_in_days < backup_requirements[env].retention_days
    msg = sprintf(
        "Backup retention period does not meet minimum requirement of %v days for %v environment",
        [backup_requirements[env].retention_days, env]
    )
}

# Enforce monitoring requirements
deny_insufficient_monitoring[msg] {
    instance = tfplan.resource_changes[_]
    instance.type == "aws_instance"
    env = instance.change.after.tags.Environment
    monitoring_requirements[env].detailed_monitoring
    not instance.change.after.monitoring
    msg = sprintf(
        "Detailed monitoring must be enabled for instances in %v environment",
        [env]
    )
}

# Enforce log retention
deny_insufficient_log_retention[msg] {
    log_group = tfplan.resource_changes[_]
    log_group.type == "aws_cloudwatch_log_group"
    env = log_group.change.after.tags.Environment
    log_group.change.after.retention_in_days < monitoring_requirements[env].log_retention_days
    msg = sprintf(
        "Log retention period does not meet minimum requirement of %v days for %v environment",
        [monitoring_requirements[env].log_retention_days, env]
    )
}

# Main rule that combines all compliance deny conditions
deny[msg] {
    msg = deny_missing_tags[_]
} {
    msg = deny_insufficient_backup[_]
} {
    msg = deny_insufficient_monitoring[_]
} {
    msg = deny_insufficient_log_retention[_]
}
