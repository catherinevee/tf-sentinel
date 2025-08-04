# Example OPA policy for security compliance
package terraform.security

import input.plan as tfplan

# Allowed VPC CIDR ranges
allowed_vpc_cidrs = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

# Required security controls
required_security_controls = {
    "encryption": true,
    "monitoring": true,
    "backup": true,
    "access_logs": true
}

# Approved AMIs by environment
approved_amis = {
    "prod": ["ami-123456", "ami-789012"],
    "dev": ["ami-345678"]
}

# Deny resources with public access
deny_public_access[msg] {
    resource = tfplan.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    msg = sprintf(
        "Public access is not allowed for bucket: %v",
        [resource.change.after.bucket]
    )
}

# Enforce encryption
deny_unencrypted_resources[msg] {
    resource = tfplan.resource_changes[_]
    resource.type == "aws_ebs_volume"
    not resource.change.after.encrypted
    msg = sprintf(
        "Encryption must be enabled for EBS volume: %v",
        [resource.address]
    )
}

# Enforce secure VPC configurations
deny_insecure_vpc[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    not vpc_cidr_allowed(vpc.change.after.cidr_block)
    msg = sprintf(
        "VPC CIDR %v is not in allowed ranges: %v",
        [vpc.change.after.cidr_block, allowed_vpc_cidrs]
    )
}

# Helper function to check VPC CIDR
vpc_cidr_allowed(cidr) {
    allowed_vpc_cidrs[_] == cidr
}

# Enforce security group rules
deny_insecure_sg_rules[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group_rule"
    sg.change.after.cidr_blocks[_] == "0.0.0.0/0"
    sg.change.after.to_port == 22
    msg = "SSH access from 0.0.0.0/0 is not allowed"
}

# Enforce IAM password policy
deny_weak_password_policy[msg] {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_iam_account_password_policy"
    policy.change.after.minimum_password_length < 14
    msg = "Password length must be at least 14 characters"
}

# Enforce KMS key rotation
deny_disabled_key_rotation[msg] {
    key = tfplan.resource_changes[_]
    key.type == "aws_kms_key"
    not key.change.after.enable_key_rotation
    msg = sprintf(
        "Key rotation must be enabled for KMS key: %v",
        [key.address]
    )
}

# Main rule that combines all security deny conditions
deny[msg] {
    msg = deny_public_access[_]
} {
    msg = deny_unencrypted_resources[_]
} {
    msg = deny_insecure_vpc[_]
} {
    msg = deny_insecure_sg_rules[_]
} {
    msg = deny_weak_password_policy[_]
} {
    msg = deny_disabled_key_rotation[_]
}
