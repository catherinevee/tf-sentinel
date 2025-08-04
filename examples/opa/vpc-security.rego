# Example OPA policy for VPC security configuration
package terraform.vpc_security

import input.plan as tfplan

# VPC security requirements by environment
vpc_requirements = {
    "prod": {
        "allowed_vpc_cidrs": ["10.0.0.0/8", "172.16.0.0/12"],
        "min_subnet_mask": 24,
        "max_subnet_mask": 16,
        "require_flow_logs": true,
        "require_vpc_endpoints": [
            "s3",
            "dynamodb",
            "kms",
            "secretsmanager",
            "ssm"
        ],
        "required_nacl_rules": [
            {
                "rule_no": 100,
                "protocol": "tcp",
                "action": "deny",
                "from_port": 22,
                "to_port": 22,
                "cidr_block": "0.0.0.0/0"
            },
            {
                "rule_no": 200,
                "protocol": "tcp",
                "action": "deny",
                "from_port": 3389,
                "to_port": 3389,
                "cidr_block": "0.0.0.0/0"
            }
        ],
        "require_nat_gateway": true,
        "require_vpn_gateway": true,
        "require_private_subnets": true
    },
    "staging": {
        "allowed_vpc_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "min_subnet_mask": 24,
        "max_subnet_mask": 16,
        "require_flow_logs": true,
        "require_vpc_endpoints": [
            "s3",
            "dynamodb"
        ],
        "required_nacl_rules": [
            {
                "rule_no": 100,
                "protocol": "tcp",
                "action": "deny",
                "from_port": 22,
                "to_port": 22,
                "cidr_block": "0.0.0.0/0"
            }
        ],
        "require_nat_gateway": true,
        "require_vpn_gateway": false,
        "require_private_subnets": true
    },
    "dev": {
        "allowed_vpc_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "min_subnet_mask": 28,
        "max_subnet_mask": 16,
        "require_flow_logs": false,
        "require_vpc_endpoints": [],
        "required_nacl_rules": [],
        "require_nat_gateway": false,
        "require_vpn_gateway": false,
        "require_private_subnets": false
    }
}

# Deny invalid VPC CIDR blocks
deny_invalid_vpc_cidr[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    not cidr_in_allowed_range(vpc.change.after.cidr_block, env)
    
    msg = sprintf(
        "VPC CIDR %v is not in allowed ranges for %v environment",
        [vpc.change.after.cidr_block, env]
    )
}

# Helper to check allowed CIDR ranges
cidr_in_allowed_range(cidr, env) {
    allowed = vpc_requirements[env].allowed_vpc_cidrs[_]
    net.cidr_contains(allowed, cidr)
}

# Deny invalid subnet masks
deny_invalid_subnet_mask[msg] {
    subnet = tfplan.resource_changes[_]
    subnet.type == "aws_subnet"
    env = subnet.change.after.tags.Environment
    
    cidr := subnet.change.after.cidr_block
    mask := split(cidr, "/")[1]
    
    mask_int := to_number(mask)
    mask_int > vpc_requirements[env].min_subnet_mask
    
    msg = sprintf(
        "Subnet mask /%v is smaller than minimum /%v in %v environment",
        [mask, vpc_requirements[env].min_subnet_mask, env]
    )
}

# Deny missing flow logs
deny_missing_flow_logs[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    vpc_requirements[env].require_flow_logs
    not has_flow_logs(vpc.change.after.id)
    
    msg = sprintf(
        "VPC flow logs are required in %v environment",
        [env]
    )
}

# Helper to check flow logs
has_flow_logs(vpc_id) {
    flow_log = tfplan.resource_changes[_]
    flow_log.type == "aws_flow_log"
    flow_log.change.after.vpc_id == vpc_id
}

# Deny missing required VPC endpoints
deny_missing_vpc_endpoints[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    required_endpoint = vpc_requirements[env].require_vpc_endpoints[_]
    not has_vpc_endpoint(vpc.change.after.id, required_endpoint)
    
    msg = sprintf(
        "VPC endpoint for %v service is required in %v environment",
        [required_endpoint, env]
    )
}

# Helper to check VPC endpoints
has_vpc_endpoint(vpc_id, service) {
    endpoint = tfplan.resource_changes[_]
    endpoint.type == "aws_vpc_endpoint"
    endpoint.change.after.vpc_id == vpc_id
    endpoint.change.after.service_name == sprintf("com.amazonaws.%s.%s", [data.aws_region.current.name, service])
}

# Deny missing required NACL rules
deny_missing_nacl_rules[msg] {
    nacl = tfplan.resource_changes[_]
    nacl.type == "aws_network_acl_rule"
    env = nacl.change.after.tags.Environment
    
    required_rule = vpc_requirements[env].required_nacl_rules[_]
    not has_nacl_rule(nacl, required_rule)
    
    msg = sprintf(
        "Required NACL rule %v is missing in %v environment",
        [required_rule.rule_no, env]
    )
}

# Helper to check NACL rules
has_nacl_rule(nacl, required_rule) {
    nacl.change.after.rule_no == required_rule.rule_no
    nacl.change.after.protocol == required_rule.protocol
    nacl.change.after.rule_action == required_rule.action
    nacl.change.after.from_port == required_rule.from_port
    nacl.change.after.to_port == required_rule.to_port
    nacl.change.after.cidr_block == required_rule.cidr_block
}

# Deny missing NAT Gateway in private subnets
deny_missing_nat_gateway[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    vpc_requirements[env].require_nat_gateway
    not has_nat_gateway(vpc.change.after.id)
    
    msg = sprintf(
        "NAT Gateway is required for private subnets in %v environment",
        [env]
    )
}

# Helper to check NAT Gateway
has_nat_gateway(vpc_id) {
    nat = tfplan.resource_changes[_]
    nat.type == "aws_nat_gateway"
    subnet = tfplan.resource_changes[_]
    subnet.type == "aws_subnet"
    subnet.change.after.vpc_id == vpc_id
    nat.change.after.subnet_id == subnet.change.after.id
}

# Deny missing private subnets
deny_missing_private_subnets[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    vpc_requirements[env].require_private_subnets
    not has_private_subnets(vpc.change.after.id)
    
    msg = sprintf(
        "Private subnets are required in %v environment",
        [env]
    )
}

# Helper to check private subnets
has_private_subnets(vpc_id) {
    subnet = tfplan.resource_changes[_]
    subnet.type == "aws_subnet"
    subnet.change.after.vpc_id == vpc_id
    not subnet.change.after.map_public_ip_on_launch
}

# Main deny rule combining all VPC security policies
deny[msg] {
    msg = deny_invalid_vpc_cidr[_]
} {
    msg = deny_invalid_subnet_mask[_]
} {
    msg = deny_missing_flow_logs[_]
} {
    msg = deny_missing_vpc_endpoints[_]
} {
    msg = deny_missing_nacl_rules[_]
} {
    msg = deny_missing_nat_gateway[_]
} {
    msg = deny_missing_private_subnets[_]
}

# Data source for current AWS region
data "aws_region" "current" {}
