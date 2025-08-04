# Example OPA policy for network security
package terraform.network_security

import input.plan as tfplan

# Network security requirements by environment
network_requirements = {
    "prod": {
        "allowed_vpc_cidrs": ["10.0.0.0/8", "172.16.0.0/12"],
        "required_nacl_rules": true,
        "require_flow_logs": true,
        "require_vpn": true,
        "require_transit_gateway": true,
        "require_vpc_endpoints": true,
        "require_network_firewall": true,
        "allowed_ports": {
            "inbound": [80, 443, 22],
            "outbound": [80, 443]
        },
        "deny_public_ips": true,
        "require_nat_gateway": true,
        "min_az_count": 3,
        "require_private_subnets": true
    },
    "staging": {
        "allowed_vpc_cidrs": ["192.168.0.0/16"],
        "required_nacl_rules": true,
        "require_flow_logs": true,
        "require_vpn": false,
        "require_transit_gateway": false,
        "require_vpc_endpoints": true,
        "require_network_firewall": false,
        "allowed_ports": {
            "inbound": [80, 443, 22, 3306, 5432],
            "outbound": [80, 443, 3306, 5432]
        },
        "deny_public_ips": false,
        "require_nat_gateway": true,
        "min_az_count": 2,
        "require_private_subnets": true
    },
    "dev": {
        "allowed_vpc_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "required_nacl_rules": false,
        "require_flow_logs": false,
        "require_vpn": false,
        "require_transit_gateway": false,
        "require_vpc_endpoints": false,
        "require_network_firewall": false,
        "allowed_ports": {
            "inbound": ["all"],
            "outbound": ["all"]
        },
        "deny_public_ips": false,
        "require_nat_gateway": false,
        "min_az_count": 1,
        "require_private_subnets": false
    }
}

# Required VPC endpoints by environment
required_vpc_endpoints = {
    "prod": [
        "s3",
        "dynamodb",
        "kms",
        "secretsmanager",
        "logs",
        "monitoring"
    ],
    "staging": [
        "s3",
        "dynamodb"
    ]
}

# Deny unauthorized VPC CIDR ranges
deny_unauthorized_vpc[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    not cidr_in_allowed_range(vpc.change.after.cidr_block, env)
    msg = sprintf(
        "VPC CIDR %v is not in allowed ranges for %v environment",
        [vpc.change.after.cidr_block, env]
    )
}

# Helper to check CIDR ranges
cidr_in_allowed_range(cidr, env) {
    allowed = network_requirements[env].allowed_vpc_cidrs[_]
    net.cidr_contains(allowed, cidr)
}

# Deny missing NACL rules
deny_missing_nacl[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    network_requirements[env].required_nacl_rules
    not has_nacl_rules(vpc.change.after.id)
    
    msg = sprintf(
        "VPC must have NACL rules configured in %v environment",
        [env]
    )
}

# Helper to check NACL rules
has_nacl_rules(vpc_id) {
    nacl = tfplan.resource_changes[_]
    nacl.type == "aws_network_acl_rule"
    nacl.change.after.vpc_id == vpc_id
}

# Deny missing flow logs
deny_missing_flow_logs[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    network_requirements[env].require_flow_logs
    not has_flow_logs(vpc.change.after.id)
    
    msg = sprintf(
        "VPC must have flow logs enabled in %v environment",
        [env]
    )
}

# Helper to check flow logs
has_flow_logs(vpc_id) {
    flow_log = tfplan.resource_changes[_]
    flow_log.type == "aws_flow_log"
    flow_log.change.after.vpc_id == vpc_id
}

# Deny missing VPC endpoints
deny_missing_vpc_endpoints[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    network_requirements[env].require_vpc_endpoints
    endpoint_service = required_vpc_endpoints[env][_]
    not has_vpc_endpoint(vpc.change.after.id, endpoint_service)
    
    msg = sprintf(
        "VPC must have endpoint for service %v in %v environment",
        [endpoint_service, env]
    )
}

# Helper to check VPC endpoints
has_vpc_endpoint(vpc_id, service) {
    endpoint = tfplan.resource_changes[_]
    endpoint.type == "aws_vpc_endpoint"
    endpoint.change.after.vpc_id == vpc_id
    endpoint.change.after.service_name == concat("com.amazonaws.", [service])
}

# Deny unauthorized ports
deny_unauthorized_ports[msg] {
    sg_rule = tfplan.resource_changes[_]
    sg_rule.type == "aws_security_group_rule"
    env = sg_rule.change.after.tags.Environment
    
    not is_port_allowed(sg_rule.change.after.to_port, sg_rule.change.after.type, env)
    msg = sprintf(
        "Port %v is not allowed for %v traffic in %v environment",
        [sg_rule.change.after.to_port, sg_rule.change.after.type, env]
    )
}

# Helper to check allowed ports
is_port_allowed(port, type, env) {
    network_requirements[env].allowed_ports[type][_] == port
} {
    network_requirements[env].allowed_ports[type][_] == "all"
}

# Deny public IP assignments
deny_public_ips[msg] {
    subnet = tfplan.resource_changes[_]
    subnet.type == "aws_subnet"
    env = subnet.change.after.tags.Environment
    
    network_requirements[env].deny_public_ips
    subnet.change.after.map_public_ip_on_launch
    
    msg = sprintf(
        "Public IP assignment is not allowed in %v environment",
        [env]
    )
}

# Enforce NAT Gateway requirement
deny_missing_nat[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    network_requirements[env].require_nat_gateway
    not has_nat_gateway(vpc.change.after.id)
    
    msg = sprintf(
        "VPC must have NAT Gateway in %v environment",
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

# Enforce minimum AZ count
deny_insufficient_azs[msg] {
    vpc = tfplan.resource_changes[_]
    vpc.type == "aws_vpc"
    env = vpc.change.after.tags.Environment
    
    count_azs(vpc.change.after.id) < network_requirements[env].min_az_count
    msg = sprintf(
        "VPC must span at least %v availability zones in %v environment",
        [network_requirements[env].min_az_count, env]
    )
}

# Helper to count AZs
count_azs(vpc_id) = count {
    subnets = [subnet |
        subnet = tfplan.resource_changes[_]
        subnet.type == "aws_subnet"
        subnet.change.after.vpc_id == vpc_id
    ]
    azs = {subnet.change.after.availability_zone | subnet in subnets}
    count = count(azs)
}

# Main deny rule combining all network security policies
deny[msg] {
    msg = deny_unauthorized_vpc[_]
} {
    msg = deny_missing_nacl[_]
} {
    msg = deny_missing_flow_logs[_]
} {
    msg = deny_missing_vpc_endpoints[_]
} {
    msg = deny_unauthorized_ports[_]
} {
    msg = deny_public_ips[_]
} {
    msg = deny_missing_nat[_]
} {
    msg = deny_insufficient_azs[_]
}
