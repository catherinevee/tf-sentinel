# Example OPA policy for networking controls
package terraform.networking

import input.plan as tfplan

# Allowed VPC configurations
allowed_vpc_configs = {
    "prod": {
        "allowed_cidrs": ["10.0.0.0/8", "172.16.0.0/12"],
        "required_features": ["enable_dns_support", "enable_dns_hostnames"],
        "flow_logs_required": true
    },
    "dev": {
        "allowed_cidrs": ["192.168.0.0/16"],
        "required_features": ["enable_dns_support"],
        "flow_logs_required": false
    }
}

# Allowed port ranges by environment
allowed_ports = {
    "prod": {
        "web": [80, 443],
        "api": [8080, 8443],
        "db": [5432, 3306]
    },
    "dev": {
        "web": [80, 443, 8000, 8080],
        "api": [8080, 8443, 9000],
        "db": [5432, 3306, 27017]
    }
}

# Subnet configuration requirements
subnet_requirements = {
    "prod": {
        "min_public_subnets": 2,
        "min_private_subnets": 3,
        "availability_zones": ["a", "b", "c"]
    },
    "dev": {
        "min_public_subnets": 1,
        "min_private_subnets": 1,
        "availability_zones": ["a", "b"]
    }
}

# VPC peering rules
allowed_peering_environments = {
    "prod": ["prod", "staging"],
    "staging": ["prod", "staging", "dev"],
    "dev": ["staging", "dev"]
}

# Deny non-compliant VPC configurations
deny_vpc_config[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    config = allowed_vpc_configs[env]
    
    not array_contains(config.allowed_cidrs, vpc.change.after.cidr_block)
    msg = sprintf(
        "VPC CIDR %v is not allowed in %v environment. Allowed CIDRs: %v",
        [vpc.change.after.cidr_block, env, config.allowed_cidrs]
    )
}

# Deny missing VPC features
deny_missing_vpc_features[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    feature = allowed_vpc_configs[env].required_features[_]
    not vpc.change.after[feature]
    msg = sprintf(
        "Required VPC feature %v is not enabled for %v environment",
        [feature, env]
    )
}

# Enforce VPC flow logs
deny_missing_flow_logs[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    allowed_vpc_configs[env].flow_logs_required
    
    not has_flow_logs(vpc.change.after.id)
    msg = sprintf(
        "VPC flow logs are required in %v environment",
        [env]
    )
}

# Helper function to check flow logs
has_flow_logs(vpc_id) {
    flow_log = tfplan.resource_changes[_]
    flow_log.type == "aws_flow_log"
    flow_log.change.after.vpc_id == vpc_id
}

# Deny invalid security group rules
deny_invalid_ports[msg] {
    sg_rule = tfplan.resource_changes[_]
    sg_rule.type == "aws_security_group_rule"
    env = sg_rule.change.after.tags.Environment
    port_type = get_port_type(sg_rule.change.after.to_port)
    
    not port_allowed(env, port_type, sg_rule.change.after.to_port)
    msg = sprintf(
        "Port %v is not allowed for %v in %v environment",
        [sg_rule.change.after.to_port, port_type, env]
    )
}

# Helper function to determine port type
get_port_type(port) = type {
    port >= 80
    port <= 443
    type := "web"
} {
    port >= 8000
    port <= 9000
    type := "api"
} {
    port >= 3306
    port <= 5432
    type := "db"
}

# Helper function to check allowed ports
port_allowed(env, type, port) {
    allowed_ports[env][type][_] == port
}

# Deny invalid VPC peering
deny_invalid_peering[msg] {
    peering = tfplan.resource_changes[_]
    peering.type == "aws_vpc_peering_connection"
    
    requester_env = get_vpc_environment(peering.change.after.vpc_id)
    accepter_env = get_vpc_environment(peering.change.after.peer_vpc_id)
    
    not array_contains(allowed_peering_environments[requester_env], accepter_env)
    msg = sprintf(
        "VPC peering between %v and %v environments is not allowed",
        [requester_env, accepter_env]
    )
}

# Helper function to get VPC environment
get_vpc_environment(vpc_id) = env {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    vpc.change.after.id == vpc_id
    env = vpc.change.after.tags.Environment
}

# Helper function for array contains
array_contains(arr, elem) {
    arr[_] == elem
}

# Main deny rule combining all networking policies
deny[msg] {
    msg = deny_vpc_config[_]
} {
    msg = deny_missing_vpc_features[_]
} {
    msg = deny_missing_flow_logs[_]
} {
    msg = deny_invalid_ports[_]
} {
    msg = deny_invalid_peering[_]
}
