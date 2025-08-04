# Example OPA policy for API security
package terraform.api_security

import input.plan as tfplan

# API Gateway security requirements by environment
api_requirements = {
    "prod": {
        "minimum_tls_version": "TLS_1_2",
        "require_authentication": true,
        "require_authorization": true,
        "require_waf": true,
        "require_vpc_endpoints": true,
        "require_access_logs": true,
        "require_api_key": true,
        "throttling_required": true,
        "default_throttle_rate": 1000,
        "default_throttle_burst": 500,
        "require_cognito": true,
        "allowed_cors_origins": ["https://*.company.com"],
        "request_validation_required": true
    },
    "staging": {
        "minimum_tls_version": "TLS_1_2",
        "require_authentication": true,
        "require_authorization": true,
        "require_waf": true,
        "require_vpc_endpoints": false,
        "require_access_logs": true,
        "require_api_key": false,
        "throttling_required": true,
        "default_throttle_rate": 2000,
        "default_throttle_burst": 1000,
        "require_cognito": false,
        "allowed_cors_origins": ["https://*.company.com", "https://*.company-staging.com"],
        "request_validation_required": true
    },
    "dev": {
        "minimum_tls_version": "TLS_1_2",
        "require_authentication": false,
        "require_authorization": false,
        "require_waf": false,
        "require_vpc_endpoints": false,
        "require_access_logs": false,
        "require_api_key": false,
        "throttling_required": false,
        "default_throttle_rate": 5000,
        "default_throttle_burst": 2000,
        "require_cognito": false,
        "allowed_cors_origins": ["*"],
        "request_validation_required": false
    }
}

# Required WAF rules
required_waf_rules = {
    "prod": [
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesATPRuleSet",
        "AWSManagedRulesSQLiRuleSet"
    ],
    "staging": [
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesSQLiRuleSet"
    ]
}

# Enforce TLS version
deny_insecure_tls[msg] {
    api = tfplan.resource_changes[_]
    api.type == "aws_api_gateway_domain_name"
    env = api.change.after.tags.Environment
    
    not api.change.after.security_policy == api_requirements[env].minimum_tls_version
    msg = sprintf(
        "API Gateway must use %v or higher in %v environment",
        [api_requirements[env].minimum_tls_version, env]
    )
}

# Enforce authentication
deny_missing_auth[msg] {
    api = tfplan.resource_changes[_]
    api.type == "aws_api_gateway_method"
    env = api.change.after.tags.Environment
    
    api_requirements[env].require_authentication
    api.change.after.authorization == "NONE"
    
    msg = sprintf(
        "API Gateway methods must require authentication in %v environment",
        [env]
    )
}

# Enforce WAF
deny_missing_waf[msg] {
    api = tfplan.resource_changes[_]
    api.type == "aws_api_gateway_stage"
    env = api.change.after.tags.Environment
    
    api_requirements[env].require_waf
    not has_waf_association(api.change.after.arn)
    
    msg = sprintf(
        "API Gateway stage must have WAF enabled in %v environment",
        [env]
    )
}

# Helper to check WAF association
has_waf_association(stage_arn) {
    waf = tfplan.resource_changes[_]
    waf.type == "aws_wafv2_web_acl_association"
    waf.change.after.resource_arn == stage_arn
}

# Enforce required WAF rules
deny_missing_waf_rules[msg] {
    waf = tfplan.resource_changes[_]
    waf.type == "aws_wafv2_web_acl"
    env = waf.change.after.tags.Environment
    
    required_rule = required_waf_rules[env][_]
    not has_rule(waf.change.after.rule, required_rule)
    
    msg = sprintf(
        "WAF configuration must include rule %v in %v environment",
        [required_rule, env]
    )
}

# Helper to check WAF rules
has_rule(rules, required_rule) {
    rules[_].name == required_rule
}

# Enforce VPC endpoints
deny_missing_vpc_endpoint[msg] {
    api = tfplan.resource_changes[_]
    api.type == "aws_api_gateway_rest_api"
    env = api.change.after.tags.Environment
    
    api_requirements[env].require_vpc_endpoints
    not api.change.after.endpoint_configuration[0].types[_] == "PRIVATE"
    
    msg = sprintf(
        "API Gateway must use VPC endpoints in %v environment",
        [env]
    )
}

# Enforce access logging
deny_missing_access_logs[msg] {
    stage = tfplan.resource_changes[_]
    stage.type == "aws_api_gateway_stage"
    env = stage.change.after.tags.Environment
    
    api_requirements[env].require_access_logs
    not stage.change.after.access_log_settings
    
    msg = sprintf(
        "API Gateway stage must have access logging enabled in %v environment",
        [env]
    )
}

# Enforce API key requirement
deny_missing_api_key[msg] {
    method = tfplan.resource_changes[_]
    method.type == "aws_api_gateway_method"
    env = method.change.after.tags.Environment
    
    api_requirements[env].require_api_key
    not method.change.after.api_key_required
    
    msg = sprintf(
        "API Gateway methods must require API keys in %v environment",
        [env]
    )
}

# Enforce throttling
deny_missing_throttling[msg] {
    stage = tfplan.resource_changes[_]
    stage.type == "aws_api_gateway_stage"
    env = stage.change.after.tags.Environment
    
    api_requirements[env].throttling_required
    not stage.change.after.throttling_burst_limit
    not stage.change.after.throttling_rate_limit
    
    msg = sprintf(
        "API Gateway stage must have throttling configured in %v environment",
        [env]
    )
}

# Enforce CORS configuration
deny_invalid_cors[msg] {
    resource = tfplan.resource_changes[_]
    resource.type == "aws_api_gateway_resource"
    env = resource.change.after.tags.Environment
    
    cors_origin = resource.change.after.cors_configuration[0].allow_origins[_]
    not is_allowed_origin(cors_origin, env)
    
    msg = sprintf(
        "Invalid CORS origin %v in %v environment",
        [cors_origin, env]
    )
}

# Helper to check allowed CORS origins
is_allowed_origin(origin, env) {
    allowed = api_requirements[env].allowed_cors_origins[_]
    allowed == "*"
} {
    allowed = api_requirements[env].allowed_cors_origins[_]
    glob.match(allowed, [], origin)
}

# Enforce request validation
deny_missing_validation[msg] {
    api = tfplan.resource_changes[_]
    api.type == "aws_api_gateway_rest_api"
    env = api.change.after.tags.Environment
    
    api_requirements[env].request_validation_required
    not has_validator(api.change.after.id)
    
    msg = sprintf(
        "API Gateway must have request validation enabled in %v environment",
        [env]
    )
}

# Helper to check request validator
has_validator(api_id) {
    validator = tfplan.resource_changes[_]
    validator.type == "aws_api_gateway_request_validator"
    validator.change.after.rest_api_id == api_id
}

# Main deny rule combining all API security policies
deny[msg] {
    msg = deny_insecure_tls[_]
} {
    msg = deny_missing_auth[_]
} {
    msg = deny_missing_waf[_]
} {
    msg = deny_missing_waf_rules[_]
} {
    msg = deny_missing_vpc_endpoint[_]
} {
    msg = deny_missing_access_logs[_]
} {
    msg = deny_missing_api_key[_]
} {
    msg = deny_missing_throttling[_]
} {
    msg = deny_invalid_cors[_]
} {
    msg = deny_missing_validation[_]
}
