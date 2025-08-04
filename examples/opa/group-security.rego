# Example OPA policy for IAM Group security
package terraform.group_security

import input.plan as tfplan

# Group security requirements by environment
group_requirements = {
    "prod": {
        "required_groups": [
            "Admins",
            "SecurityAuditors",
            "Developers",
            "DataEngineers"
        ],
        "max_users_per_group": 20,
        "require_group_policy": true,
        "required_policy_arns": [
            "arn:aws:iam::aws:policy/SecurityAudit",
            "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
        ],
        "denied_policy_patterns": [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess"
        ]
    },
    "staging": {
        "required_groups": [
            "StagingAdmins",
            "StagingDevelopers"
        ],
        "max_users_per_group": 30,
        "require_group_policy": false,
        "required_policy_arns": [],
        "denied_policy_patterns": [
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ]
    },
    "dev": {
        "required_groups": [
            "DevAdmins",
            "DevDevelopers"
        ],
        "max_users_per_group": 50,
        "require_group_policy": false,
        "required_policy_arns": [],
        "denied_policy_patterns": []
    }
}

# Deny non-compliant group names
deny_invalid_group_name[msg] {
    group = tfplan.resource_changes[_]
    group.type == "aws_iam_group"
    env = group.change.after.tags.Environment
    
    required = group_requirements[env].required_groups[_]
    not startswith(group.change.after.name, required)
    
    msg = sprintf(
        "Group name must start with one of the required prefixes in %v environment",
        [env]
    )
}

# Deny excessive group membership
deny_excessive_group_members[msg] {
    group_membership = tfplan.resource_changes[_]
    group_membership.type == "aws_iam_group_membership"
    env = group_membership.change.after.tags.Environment
    
    count(group_membership.change.after.users) > group_requirements[env].max_users_per_group
    
    msg = sprintf(
        "Group cannot have more than %v users in %v environment",
        [group_requirements[env].max_users_per_group, env]
    )
}

# Deny missing required policies
deny_missing_required_policies[msg] {
    policy_attachment = tfplan.resource_changes[_]
    policy_attachment.type == "aws_iam_group_policy_attachment"
    env = policy_attachment.change.after.tags.Environment
    
    required_arn = group_requirements[env].required_policy_arns[_]
    not policy_attachment.change.after.policy_arn == required_arn
    
    msg = sprintf(
        "Required policy %v must be attached to groups in %v environment",
        [required_arn, env]
    )
}

# Deny denied policies
deny_denied_policies[msg] {
    policy_attachment = tfplan.resource_changes[_]
    policy_attachment.type == "aws_iam_group_policy_attachment"
    env = policy_attachment.change.after.tags.Environment
    
    denied_pattern = group_requirements[env].denied_policy_patterns[_]
    startswith(policy_attachment.change.after.policy_arn, denied_pattern)
    
    msg = sprintf(
        "Policy pattern %v is not allowed in %v environment",
        [denied_pattern, env]
    )
}

# Deny missing group policies when required
deny_missing_group_policy[msg] {
    group = tfplan.resource_changes[_]
    group.type == "aws_iam_group"
    env = group.change.after.tags.Environment
    
    group_requirements[env].require_group_policy
    not has_group_policy(group.change.after.name)
    
    msg = sprintf(
        "Groups must have an attached policy in %v environment",
        [env]
    )
}

# Helper to check if group has policy
has_group_policy(group_name) {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_group_policy"
    policy.change.after.group == group_name
}

# Deny direct user assignments (require group membership)
deny_direct_user_policy[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_user_policy_attachment"
    env = policy.change.after.tags.Environment
    
    msg = sprintf(
        "Direct user policy attachments are not allowed in %v environment. Use group policies instead.",
        [env]
    )
}

# Main deny rule combining all group security policies
deny[msg] {
    msg = deny_invalid_group_name[_]
} {
    msg = deny_excessive_group_members[_]
} {
    msg = deny_missing_required_policies[_]
} {
    msg = deny_denied_policies[_]
} {
    msg = deny_missing_group_policy[_]
} {
    msg = deny_direct_user_policy[_]
}
