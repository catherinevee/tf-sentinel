# Example OPA policy for IAM security
package terraform.iam_security

import input.plan as tfplan

# IAM security requirements by environment
iam_requirements = {
    "prod": {
        "require_permission_boundaries": true,
        "max_policy_size": 6144,
        "require_mfa": true,
        "max_session_duration": 43200,
        "require_conditions": true,
        "denied_actions": [
            "iam:*",
            "organizations:*",
            "account:*",
            "*:*Admin",
            "*:*administrator*"
        ],
        "required_condition_keys": [
            "aws:MultiFactorAuthPresent",
            "aws:PrincipalOrgID",
            "aws:SourceIp"
        ]
    },
    "staging": {
        "require_permission_boundaries": true,
        "max_policy_size": 10240,
        "require_mfa": true,
        "max_session_duration": 43200,
        "require_conditions": false,
        "denied_actions": [
            "iam:*",
            "organizations:*",
            "account:*"
        ],
        "required_condition_keys": [
            "aws:MultiFactorAuthPresent"
        ]
    },
    "dev": {
        "require_permission_boundaries": false,
        "max_policy_size": 10240,
        "require_mfa": false,
        "max_session_duration": 86400,
        "require_conditions": false,
        "denied_actions": [
            "organizations:*",
            "account:*"
        ],
        "required_condition_keys": []
    }
}

# Password policy requirements
password_requirements = {
    "prod": {
        "minimum_length": 14,
        "require_symbols": true,
        "require_numbers": true,
        "require_uppercase": true,
        "require_lowercase": true,
        "allow_users_to_change": true,
        "max_age": 90,
        "password_reuse_prevention": 24,
        "require_lowercase": true
    }
}

# Deny missing permission boundaries
deny_missing_permission_boundary[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    iam_requirements[env].require_permission_boundaries
    not role.change.after.permissions_boundary
    
    msg = sprintf(
        "IAM role must have a permissions boundary in %v environment",
        [env]
    )
}

# Deny oversized policies
deny_oversized_policy[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_policy"
    env = policy.change.after.tags.Environment
    
    policy_size := count(policy.change.after.policy)
    policy_size > iam_requirements[env].max_policy_size
    
    msg = sprintf(
        "IAM policy size exceeds maximum of %v bytes in %v environment",
        [iam_requirements[env].max_policy_size, env]
    )
}

# Deny weak password policies
deny_weak_password_policy[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_account_password_policy"
    env = "prod"
    requirements = password_requirements[env]
    
    policy.change.after.minimum_password_length < requirements.minimum_length
    msg = sprintf(
        "Password minimum length must be at least %v characters",
        [requirements.minimum_length]
    )
}

# Deny missing MFA requirement
deny_missing_mfa[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    iam_requirements[env].require_mfa
    policy = role.change.after.assume_role_policy
    
    not has_mfa_condition(policy)
    msg = "Role assumption must require MFA"
}

# Helper to check MFA condition
has_mfa_condition(policy) {
    policy.Statement[_].Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "true"
}

# Deny excessive session duration
deny_excessive_session[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    role.change.after.max_session_duration > iam_requirements[env].max_session_duration
    msg = sprintf(
        "Role session duration cannot exceed %v seconds in %v environment",
        [iam_requirements[env].max_session_duration, env]
    )
}

# Deny missing required conditions
deny_missing_conditions[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_policy"
    env = policy.change.after.tags.Environment
    
    iam_requirements[env].require_conditions
    statement = policy.change.after.policy.Statement[_]
    
    required_key = iam_requirements[env].required_condition_keys[_]
    not has_condition_key(statement, required_key)
    
    msg = sprintf(
        "IAM policy must include condition key %v in %v environment",
        [required_key, env]
    )
}

# Helper to check condition keys
has_condition_key(statement, key) {
    statement.Condition[_][key]
}

# Deny prohibited actions
deny_prohibited_actions[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_policy"
    env = policy.change.after.tags.Environment
    
    action = policy.change.after.policy.Statement[_].Action
    denied = iam_requirements[env].denied_actions[_]
    
    glob.match(denied, [], action)
    msg = sprintf(
        "Action %v is not allowed in %v environment",
        [action, env]
    )
}

# Deny inline policies
deny_inline_policies[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    role.change.after.inline_policy
    msg = sprintf(
        "Inline policies are not allowed in %v environment. Use managed policies instead.",
        [env]
    )
}

# Deny full access policies
deny_full_access[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_policy"
    
    statement = policy.change.after.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    statement.Resource == "*"
    
    msg = "Full access (*) policies are not allowed"
}

# Main deny rule combining all IAM security policies
deny[msg] {
    msg = deny_missing_permission_boundary[_]
} {
    msg = deny_oversized_policy[_]
} {
    msg = deny_weak_password_policy[_]
} {
    msg = deny_missing_mfa[_]
} {
    msg = deny_excessive_session[_]
} {
    msg = deny_missing_conditions[_]
} {
    msg = deny_prohibited_actions[_]
} {
    msg = deny_inline_policies[_]
} {
    msg = deny_full_access[_]
}
