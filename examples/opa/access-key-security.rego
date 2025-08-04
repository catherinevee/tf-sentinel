# Example OPA policy for IAM Access Key security
package terraform.access_key_security

import input.plan as tfplan
import input.state as tfstate

# Access key requirements by environment
access_key_requirements = {
    "prod": {
        "max_access_keys_per_user": 1,
        "require_key_rotation": true,
        "max_key_age_days": 90,
        "require_pgp_key": true,
        "denied_users": [
            "root",
            "admin",
            "administrator"
        ],
        "require_user_tags": [
            "Department",
            "Project",
            "Environment"
        ]
    },
    "staging": {
        "max_access_keys_per_user": 2,
        "require_key_rotation": true,
        "max_key_age_days": 180,
        "require_pgp_key": true,
        "denied_users": [
            "root",
            "admin"
        ],
        "require_user_tags": [
            "Department",
            "Environment"
        ]
    },
    "dev": {
        "max_access_keys_per_user": 2,
        "require_key_rotation": false,
        "max_key_age_days": 365,
        "require_pgp_key": false,
        "denied_users": [
            "root"
        ],
        "require_user_tags": [
            "Environment"
        ]
    }
}

# Deny excessive access keys
deny_excessive_access_keys[msg] {
    access_key = tfplan.resource_changes[_]
    access_key.type == "aws_iam_access_key"
    env = access_key.change.after.tags.Environment
    
    existing_keys := [key | key = tfstate.resources[_]
                          ; key.type == "aws_iam_access_key"
                          ; key.instances[_].attributes.user == access_key.change.after.user]
    
    count(existing_keys) >= access_key_requirements[env].max_access_keys_per_user
    
    msg = sprintf(
        "User cannot have more than %v access keys in %v environment",
        [access_key_requirements[env].max_access_keys_per_user, env]
    )
}

# Deny missing PGP key
deny_missing_pgp_key[msg] {
    access_key = tfplan.resource_changes[_]
    access_key.type == "aws_iam_access_key"
    env = access_key.change.after.tags.Environment
    
    access_key_requirements[env].require_pgp_key
    not access_key.change.after.pgp_key
    
    msg = sprintf(
        "Access keys must be encrypted with a PGP key in %v environment",
        [env]
    )
}

# Deny access keys for denied users
deny_denied_users[msg] {
    access_key = tfplan.resource_changes[_]
    access_key.type == "aws_iam_access_key"
    env = access_key.change.after.tags.Environment
    
    denied_user = access_key_requirements[env].denied_users[_]
    contains(lower(access_key.change.after.user), denied_user)
    
    msg = sprintf(
        "Access keys are not allowed for user containing '%v' in %v environment",
        [denied_user, env]
    )
}

# Deny missing required user tags
deny_missing_user_tags[msg] {
    user = tfplan.resource_changes[_]
    user.type == "aws_iam_user"
    env = user.change.after.tags.Environment
    
    required_tag = access_key_requirements[env].require_user_tags[_]
    not user.change.after.tags[required_tag]
    
    msg = sprintf(
        "User must have the required tag '%v' in %v environment",
        [required_tag, env]
    )
}

# Deny expired access keys
deny_expired_access_keys[msg] {
    access_key = tfstate.resources[_]
    access_key.type == "aws_iam_access_key"
    env = access_key.instances[_].attributes.tags.Environment
    
    create_date := time.parse_rfc3339_ns(access_key.instances[_].attributes.create_date)
    current_time := time.now_ns()
    
    age_days := (current_time - create_date) / (24 * 60 * 60 * 1000000000)
    age_days > access_key_requirements[env].max_key_age_days
    
    msg = sprintf(
        "Access key for user %v has exceeded maximum age of %v days in %v environment",
        [access_key.instances[_].attributes.user, access_key_requirements[env].max_key_age_days, env]
    )
}

# Deny inactive access keys
deny_inactive_access_keys[msg] {
    access_key = tfstate.resources[_]
    access_key.type == "aws_iam_access_key"
    access_key.instances[_].attributes.status == "Inactive"
    
    msg = sprintf(
        "Inactive access key detected for user %v. Please remove inactive keys.",
        [access_key.instances[_].attributes.user]
    )
}

# Main deny rule combining all access key security policies
deny[msg] {
    msg = deny_excessive_access_keys[_]
} {
    msg = deny_missing_pgp_key[_]
} {
    msg = deny_denied_users[_]
} {
    msg = deny_missing_user_tags[_]
} {
    msg = deny_expired_access_keys[_]
} {
    msg = deny_inactive_access_keys[_]
}
