# Example OPA policy for KMS security
package terraform.kms_security

import input.plan as tfplan

# KMS security requirements by environment
kms_requirements = {
    "prod": {
        "key_rotation": true,
        "minimum_deletion_window": 30,
        "require_tags": true,
        "require_description": true,
        "require_key_policy": true,
        "require_cmk": true,
        "allowed_key_users": ["arn:aws:iam::*:role/prod-*"],
        "allowed_key_admins": ["arn:aws:iam::*:role/security-*"],
        "denied_operations": [
            "kms:ScheduleKeyDeletion",
            "kms:DeleteImportedKeyMaterial"
        ],
        "require_cloudwatch": true,
        "require_multi_region": true
    },
    "staging": {
        "key_rotation": true,
        "minimum_deletion_window": 15,
        "require_tags": true,
        "require_description": true,
        "require_key_policy": true,
        "require_cmk": false,
        "allowed_key_users": ["arn:aws:iam::*:role/*"],
        "allowed_key_admins": ["arn:aws:iam::*:role/security-*"],
        "denied_operations": ["kms:ScheduleKeyDeletion"],
        "require_cloudwatch": true,
        "require_multi_region": false
    },
    "dev": {
        "key_rotation": false,
        "minimum_deletion_window": 7,
        "require_tags": false,
        "require_description": false,
        "require_key_policy": false,
        "require_cmk": false,
        "allowed_key_users": ["*"],
        "allowed_key_admins": ["arn:aws:iam::*:role/*"],
        "denied_operations": [],
        "require_cloudwatch": false,
        "require_multi_region": false
    }
}

# Required tags for KMS keys
required_kms_tags = {
    "prod": [
        "Name",
        "Environment",
        "Owner",
        "Project",
        "DataClassification",
        "Compliance"
    ]
}

# Deny disabled key rotation
deny_disabled_rotation[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    env = key.change.after.tags.Environment
    
    kms_requirements[env].key_rotation
    not key.change.after.enable_key_rotation
    
    msg = sprintf(
        "KMS key rotation must be enabled in %v environment",
        [env]
    )
}

# Deny insufficient deletion window
deny_short_deletion_window[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    env = key.change.after.tags.Environment
    
    key.change.after.deletion_window_in_days < kms_requirements[env].minimum_deletion_window
    msg = sprintf(
        "KMS key deletion window must be at least %v days in %v environment",
        [kms_requirements[env].minimum_deletion_window, env]
    )
}

# Deny missing tags
deny_missing_tags[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    env = key.change.after.tags.Environment
    
    kms_requirements[env].require_tags
    required_tag = required_kms_tags[env][_]
    not key.change.after.tags[required_tag]
    
    msg = sprintf(
        "KMS key missing required tag %v in %v environment",
        [required_tag, env]
    )
}

# Deny missing description
deny_missing_description[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    env = key.change.after.tags.Environment
    
    kms_requirements[env].require_description
    not key.change.after.description
    
    msg = sprintf(
        "KMS key must have a description in %v environment",
        [env]
    )
}

# Deny unauthorized key users
deny_unauthorized_users[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_kms_key_policy"
    env = policy.change.after.tags.Environment
    
    statement = policy.change.after.policy.Statement[_]
    statement.Effect == "Allow"
    principal = statement.Principal.AWS
    
    not is_allowed_user(principal, env)
    msg = sprintf(
        "Unauthorized principal %v for KMS key in %v environment",
        [principal, env]
    )
}

# Helper to check allowed users
is_allowed_user(principal, env) {
    allowed = kms_requirements[env].allowed_key_users[_]
    glob.match(allowed, [], principal)
}

# Deny prohibited operations
deny_prohibited_operations[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_kms_key_policy"
    env = policy.change.after.tags.Environment
    
    statement = policy.change.after.policy.Statement[_]
    action = statement.Action
    denied = kms_requirements[env].denied_operations[_]
    
    glob.match(denied, [], action)
    msg = sprintf(
        "Operation %v is not allowed in %v environment",
        [action, env]
    )
}

# Deny missing CloudWatch monitoring
deny_missing_monitoring[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    env = key.change.after.tags.Environment
    
    kms_requirements[env].require_cloudwatch
    not has_cloudwatch_logging(key.change.after.id)
    
    msg = sprintf(
        "KMS key must have CloudWatch logging enabled in %v environment",
        [env]
    )
}

# Helper to check CloudWatch logging
has_cloudwatch_logging(key_id) {
    log = tfplan.resource_changes[_]
    log.type == "aws_cloudwatch_log_group"
    startswith(log.change.after.name, concat("/aws/kms/", [key_id]))
}

# Deny missing multi-region configuration
deny_missing_multi_region[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    env = key.change.after.tags.Environment
    
    kms_requirements[env].require_multi_region
    not key.change.after.multi_region
    
    msg = sprintf(
        "KMS key must be multi-region enabled in %v environment",
        [env]
    )
}

# Deny key aliases without prefix
deny_invalid_alias[msg] {
    alias = tfplan.resource_changes[_]
    alias.type == "aws_kms_alias"
    env = alias.change.after.tags.Environment
    
    not startswith(alias.change.after.name, concat("alias/", [env, "-"]))
    msg = sprintf(
        "KMS key alias must start with alias/%v- in %v environment",
        [env, env]
    )
}

# Main deny rule combining all KMS security policies
deny[msg] {
    msg = deny_disabled_rotation[_]
} {
    msg = deny_short_deletion_window[_]
} {
    msg = deny_missing_tags[_]
} {
    msg = deny_missing_description[_]
} {
    msg = deny_unauthorized_users[_]
} {
    msg = deny_prohibited_operations[_]
} {
    msg = deny_missing_monitoring[_]
} {
    msg = deny_missing_multi_region[_]
} {
    msg = deny_invalid_alias[_]
}
