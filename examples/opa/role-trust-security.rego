# Example OPA policy for role trust relationships
package terraform.role_trust_security

import input.plan as tfplan

# Trust relationship requirements by environment
trust_requirements = {
    "prod": {
        "allowed_aws_services": [
            "lambda.amazonaws.com",
            "ecs-tasks.amazonaws.com",
            "ec2.amazonaws.com"
        ],
        "allowed_aws_accounts": [
            "123456789012",  # prod account
            "210987654321"   # security account
        ],
        "require_external_id": true,
        "max_external_id_length": 36,
        "require_source_account": true,
        "require_source_arn": true
    },
    "staging": {
        "allowed_aws_services": [
            "lambda.amazonaws.com",
            "ecs-tasks.amazonaws.com",
            "ec2.amazonaws.com",
            "codebuild.amazonaws.com"
        ],
        "allowed_aws_accounts": [
            "123456789012",  # prod account
            "210987654321",  # security account
            "456789012345"   # staging account
        ],
        "require_external_id": true,
        "max_external_id_length": 36,
        "require_source_account": false,
        "require_source_arn": true
    },
    "dev": {
        "allowed_aws_services": [
            "lambda.amazonaws.com",
            "ecs-tasks.amazonaws.com",
            "ec2.amazonaws.com",
            "codebuild.amazonaws.com",
            "cloudformation.amazonaws.com"
        ],
        "allowed_aws_accounts": [
            "123456789012",  # prod account
            "210987654321",  # security account
            "456789012345",  # staging account
            "789012345678"   # dev account
        ],
        "require_external_id": false,
        "max_external_id_length": 36,
        "require_source_account": false,
        "require_source_arn": false
    }
}

# Deny unauthorized AWS service principals
deny_unauthorized_service[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    statement = role.change.after.assume_role_policy.Statement[_]
    service_principal = statement.Principal.Service

    not service_principal_allowed(service_principal, env)
    
    msg = sprintf(
        "AWS service principal %v is not allowed in %v environment",
        [service_principal, env]
    )
}

# Helper to check allowed service principals
service_principal_allowed(principal, env) {
    allowed = trust_requirements[env].allowed_aws_services[_]
    principal == allowed
}

# Deny unauthorized AWS account principals
deny_unauthorized_account[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    statement = role.change.after.assume_role_policy.Statement[_]
    account_principal = statement.Principal.AWS

    not account_principal_allowed(account_principal, env)
    
    msg = sprintf(
        "AWS account principal %v is not allowed in %v environment",
        [account_principal, env]
    )
}

# Helper to check allowed account principals
account_principal_allowed(principal, env) {
    allowed = trust_requirements[env].allowed_aws_accounts[_]
    contains(principal, allowed)
}

# Deny missing external ID
deny_missing_external_id[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    trust_requirements[env].require_external_id
    statement = role.change.after.assume_role_policy.Statement[_]
    
    not statement.Condition.StringEquals["sts:ExternalId"]
    
    msg = sprintf(
        "External ID is required for cross-account access in %v environment",
        [env]
    )
}

# Deny weak external IDs
deny_weak_external_id[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    statement = role.change.after.assume_role_policy.Statement[_]
    external_id = statement.Condition.StringEquals["sts:ExternalId"]
    
    count(external_id) < 32
    
    msg = sprintf(
        "External ID must be at least 32 characters in %v environment",
        [env]
    )
}

# Deny missing source account condition
deny_missing_source_account[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    trust_requirements[env].require_source_account
    statement = role.change.after.assume_role_policy.Statement[_]
    
    not statement.Condition.StringEquals["aws:SourceAccount"]
    
    msg = sprintf(
        "Source account condition is required in %v environment",
        [env]
    )
}

# Deny missing source ARN condition
deny_missing_source_arn[msg] {
    role = tfplan.resource_changes[_]
    role.type == "aws_iam_role"
    env = role.change.after.tags.Environment
    
    trust_requirements[env].require_source_arn
    statement = role.change.after.assume_role_policy.Statement[_]
    
    not statement.Condition.ArnLike["aws:SourceArn"]
    not statement.Condition.StringLike["aws:SourceArn"]
    
    msg = sprintf(
        "Source ARN condition is required in %v environment",
        [env]
    )
}

# Main deny rule combining all trust relationship security policies
deny[msg] {
    msg = deny_unauthorized_service[_]
} {
    msg = deny_unauthorized_account[_]
} {
    msg = deny_missing_external_id[_]
} {
    msg = deny_weak_external_id[_]
} {
    msg = deny_missing_source_account[_]
} {
    msg = deny_missing_source_arn[_]
}
