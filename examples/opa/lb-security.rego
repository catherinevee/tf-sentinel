# Example OPA policy for load balancer security configuration
package terraform.lb_security

import input.plan as tfplan

# Load balancer security requirements by environment
lb_requirements = {
    "prod": {
        "allowed_listeners": ["HTTPS", "TLS"],
        "min_tls_version": "TLS_1_2",
        "require_access_logs": true,
        "require_deletion_protection": true,
        "require_http_to_https_redirect": true,
        "require_ssl_policy": "ELBSecurityPolicy-TLS-1-2-2017-01",
        "require_waf": true,
        "required_tags": [
            "Name",
            "Environment",
            "Service",
            "Owner",
            "CostCenter"
        ],
        "allowed_target_types": [
            "ip",
            "instance",
            "lambda"
        ],
        "health_check_requirements": {
            "min_healthy_threshold": 2,
            "max_healthy_threshold": 5,
            "min_interval": 15,
            "max_interval": 300,
            "min_timeout": 5,
            "max_timeout": 120
        }
    },
    "staging": {
        "allowed_listeners": ["HTTP", "HTTPS"],
        "min_tls_version": "TLS_1_2",
        "require_access_logs": true,
        "require_deletion_protection": false,
        "require_http_to_https_redirect": true,
        "require_ssl_policy": "ELBSecurityPolicy-TLS-1-2-2017-01",
        "require_waf": false,
        "required_tags": [
            "Name",
            "Environment",
            "Service"
        ],
        "allowed_target_types": [
            "ip",
            "instance",
            "lambda"
        ],
        "health_check_requirements": {
            "min_healthy_threshold": 2,
            "max_healthy_threshold": 10,
            "min_interval": 10,
            "max_interval": 300,
            "min_timeout": 5,
            "max_timeout": 60
        }
    },
    "dev": {
        "allowed_listeners": ["HTTP", "HTTPS"],
        "min_tls_version": "TLS_1_2",
        "require_access_logs": false,
        "require_deletion_protection": false,
        "require_http_to_https_redirect": false,
        "require_ssl_policy": "ELBSecurityPolicy-2016-08",
        "require_waf": false,
        "required_tags": [
            "Name",
            "Environment"
        ],
        "allowed_target_types": [
            "ip",
            "instance",
            "lambda"
        ],
        "health_check_requirements": {
            "min_healthy_threshold": 2,
            "max_healthy_threshold": 10,
            "min_interval": 5,
            "max_interval": 300,
            "min_timeout": 2,
            "max_timeout": 60
        }
    }
}

# Deny non-HTTPS listeners
deny_non_https_listeners[msg] {
    lb = tfplan.resource_changes[_]
    lb.type == "aws_lb_listener"
    env = lb.change.after.tags.Environment
    
    allowed = lb_requirements[env].allowed_listeners[_]
    not protocol_allowed(lb.change.after.protocol, allowed)
    
    msg = sprintf(
        "Protocol %v is not allowed for listeners in %v environment",
        [lb.change.after.protocol, env]
    )
}

# Helper to check allowed protocols
protocol_allowed(protocol, allowed) {
    upper(protocol) == allowed
}

# Deny weak TLS versions
deny_weak_tls[msg] {
    listener = tfplan.resource_changes[_]
    listener.type == "aws_lb_listener"
    env = listener.change.after.tags.Environment
    
    listener.change.after.protocol == "HTTPS"
    not ssl_policy_compliant(listener.change.after.ssl_policy, env)
    
    msg = sprintf(
        "SSL policy %v does not meet minimum requirements for %v environment",
        [listener.change.after.ssl_policy, env]
    )
}

# Helper to check SSL policy compliance
ssl_policy_compliant(policy, env) {
    policy == lb_requirements[env].require_ssl_policy
}

# Deny missing access logs
deny_missing_access_logs[msg] {
    lb = tfplan.resource_changes[_]
    lb.type == "aws_lb"
    env = lb.change.after.tags.Environment
    
    lb_requirements[env].require_access_logs
    not has_access_logs(lb)
    
    msg = sprintf(
        "Load balancer must have access logs enabled in %v environment",
        [env]
    )
}

# Helper to check access logs
has_access_logs(lb) {
    lb.change.after.access_logs[_].enabled == true
}

# Deny disabled deletion protection
deny_disabled_deletion_protection[msg] {
    lb = tfplan.resource_changes[_]
    lb.type == "aws_lb"
    env = lb.change.after.tags.Environment
    
    lb_requirements[env].require_deletion_protection
    not lb.change.after.enable_deletion_protection
    
    msg = sprintf(
        "Load balancer must have deletion protection enabled in %v environment",
        [env]
    )
}

# Deny missing HTTP to HTTPS redirect
deny_missing_https_redirect[msg] {
    listener = tfplan.resource_changes[_]
    listener.type == "aws_lb_listener"
    env = listener.change.after.tags.Environment
    
    lb_requirements[env].require_http_to_https_redirect
    listener.change.after.protocol == "HTTP"
    not has_https_redirect(listener)
    
    msg = sprintf(
        "HTTP listener must redirect to HTTPS in %v environment",
        [env]
    )
}

# Helper to check HTTPS redirect
has_https_redirect(listener) {
    action = listener.change.after.default_action[_]
    action.type == "redirect"
    action.redirect[_].protocol == "HTTPS"
}

# Deny missing WAF association
deny_missing_waf[msg] {
    lb = tfplan.resource_changes[_]
    lb.type == "aws_lb"
    env = lb.change.after.tags.Environment
    
    lb_requirements[env].require_waf
    not has_waf_association(lb.change.after.arn)
    
    msg = sprintf(
        "Load balancer must have WAF enabled in %v environment",
        [env]
    )
}

# Helper to check WAF association
has_waf_association(lb_arn) {
    waf = tfplan.resource_changes[_]
    waf.type == "aws_wafregional_web_acl_association"
    waf.change.after.resource_arn == lb_arn
}

# Deny invalid target types
deny_invalid_target_type[msg] {
    target_group = tfplan.resource_changes[_]
    target_group.type == "aws_lb_target_group"
    env = target_group.change.after.tags.Environment
    
    not target_type_allowed(target_group.change.after.target_type, env)
    
    msg = sprintf(
        "Target type %v is not allowed in %v environment",
        [target_group.change.after.target_type, env]
    )
}

# Helper to check allowed target types
target_type_allowed(target_type, env) {
    allowed = lb_requirements[env].allowed_target_types[_]
    target_type == allowed
}

# Deny invalid health check settings
deny_invalid_health_check[msg] {
    target_group = tfplan.resource_changes[_]
    target_group.type == "aws_lb_target_group"
    env = target_group.change.after.tags.Environment
    reqs = lb_requirements[env].health_check_requirements
    
    health_check = target_group.change.after.health_check[_]
    
    invalid_threshold := health_check.healthy_threshold < reqs.min_healthy_threshold or
                        health_check.healthy_threshold > reqs.max_healthy_threshold
    
    invalid_interval := health_check.interval < reqs.min_interval or
                       health_check.interval > reqs.max_interval
    
    invalid_timeout := health_check.timeout < reqs.min_timeout or
                      health_check.timeout > reqs.max_timeout
    
    any([invalid_threshold, invalid_interval, invalid_timeout])
    
    msg = sprintf(
        "Health check configuration does not meet requirements for %v environment",
        [env]
    )
}

# Main deny rule combining all load balancer security policies
deny[msg] {
    msg = deny_non_https_listeners[_]
} {
    msg = deny_weak_tls[_]
} {
    msg = deny_missing_access_logs[_]
} {
    msg = deny_disabled_deletion_protection[_]
} {
    msg = deny_missing_https_redirect[_]
} {
    msg = deny_missing_waf[_]
} {
    msg = deny_invalid_target_type[_]
} {
    msg = deny_invalid_health_check[_]
}
