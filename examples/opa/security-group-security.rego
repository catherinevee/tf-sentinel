# Example OPA policy for security group configurations
package terraform.security_group_security

import input.plan as tfplan

# Security group requirements by environment
sg_requirements = {
    "prod": {
        "max_rules_per_group": 50,
        "require_description": true,
        "denied_ports": [22, 3389, 23, 21, 20],
        "denied_protocols": ["all"],
        "denied_cidr_blocks": ["0.0.0.0/0"],
        "required_tags": ["Name", "Environment", "Service", "Owner"],
        "require_egress_restriction": true,
        "allowed_source_prefix_lists": [
            "pl-123456", # internal services
            "pl-789012"  # partner networks
        ],
        "require_source_tracking": true
    },
    "staging": {
        "max_rules_per_group": 100,
        "require_description": true,
        "denied_ports": [3389],
        "denied_protocols": ["all"],
        "denied_cidr_blocks": [],
        "required_tags": ["Name", "Environment"],
        "require_egress_restriction": false,
        "allowed_source_prefix_lists": [
            "pl-123456" # internal services
        ],
        "require_source_tracking": false
    },
    "dev": {
        "max_rules_per_group": 200,
        "require_description": false,
        "denied_ports": [],
        "denied_protocols": [],
        "denied_cidr_blocks": [],
        "required_tags": ["Name"],
        "require_egress_restriction": false,
        "allowed_source_prefix_lists": [],
        "require_source_tracking": false
    }
}

# Deny excessive security group rules
deny_excessive_rules[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    rules_count := count(sg.change.after.ingress) + count(sg.change.after.egress)
    rules_count > sg_requirements[env].max_rules_per_group
    
    msg = sprintf(
        "Security group exceeds maximum of %v rules in %v environment",
        [sg_requirements[env].max_rules_per_group, env]
    )
}

# Deny missing rule descriptions
deny_missing_description[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    sg_requirements[env].require_description
    rule = sg.change.after.ingress[_]
    not rule.description
    
    msg = sprintf(
        "Security group rules must have descriptions in %v environment",
        [env]
    )
}

# Deny denied ports
deny_denied_ports[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    rule = sg.change.after.ingress[_]
    port = sg_requirements[env].denied_ports[_]
    rule.from_port <= port
    rule.to_port >= port
    
    msg = sprintf(
        "Port %v is not allowed in security groups in %v environment",
        [port, env]
    )
}

# Deny denied protocols
deny_denied_protocols[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    rule = sg.change.after.ingress[_]
    denied_protocol = sg_requirements[env].denied_protocols[_]
    rule.protocol == denied_protocol
    
    msg = sprintf(
        "Protocol %v is not allowed in security groups in %v environment",
        [denied_protocol, env]
    )
}

# Deny open CIDR blocks
deny_open_cidrs[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    rule = sg.change.after.ingress[_]
    cidr = sg_requirements[env].denied_cidr_blocks[_]
    rule.cidr_blocks[_] == cidr
    
    msg = sprintf(
        "CIDR block %v is not allowed in security groups in %v environment",
        [cidr, env]
    )
}

# Deny missing required tags
deny_missing_tags[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    required_tag = sg_requirements[env].required_tags[_]
    not sg.change.after.tags[required_tag]
    
    msg = sprintf(
        "Security group must have tag %v in %v environment",
        [required_tag, env]
    )
}

# Deny unrestricted egress
deny_unrestricted_egress[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    sg_requirements[env].require_egress_restriction
    rule = sg.change.after.egress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port == 0
    rule.to_port == 0
    rule.protocol == "-1"
    
    msg = sprintf(
        "Unrestricted egress (0.0.0.0/0) is not allowed in %v environment",
        [env]
    )
}

# Deny invalid source prefix lists
deny_invalid_prefix_lists[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    rule = sg.change.after.ingress[_]
    prefix_list_id = rule.prefix_list_ids[_]
    
    not prefix_list_allowed(prefix_list_id, env)
    
    msg = sprintf(
        "Prefix list %v is not in allowed list for %v environment",
        [prefix_list_id, env]
    )
}

# Helper to check allowed prefix lists
prefix_list_allowed(prefix_list_id, env) {
    allowed = sg_requirements[env].allowed_source_prefix_lists[_]
    prefix_list_id == allowed
}

# Deny missing source tracking tags
deny_missing_source_tracking[msg] {
    sg = tfplan.resource_changes[_]
    sg.type == "aws_security_group"
    env = sg.change.after.tags.Environment
    
    sg_requirements[env].require_source_tracking
    not sg.change.after.tags["Source"]
    not sg.change.after.tags["RequestId"]
    
    msg = sprintf(
        "Security group must have source tracking tags in %v environment",
        [env]
    )
}

# Main deny rule combining all security group policies
deny[msg] {
    msg = deny_excessive_rules[_]
} {
    msg = deny_missing_description[_]
} {
    msg = deny_denied_ports[_]
} {
    msg = deny_denied_protocols[_]
} {
    msg = deny_open_cidrs[_]
} {
    msg = deny_missing_tags[_]
} {
    msg = deny_unrestricted_egress[_]
} {
    msg = deny_invalid_prefix_lists[_]
} {
    msg = deny_missing_source_tracking[_]
}
