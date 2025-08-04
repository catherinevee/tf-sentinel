# Example OPA policy for certificate and TLS security
package terraform.certificate_security

import input.plan as tfplan

# Certificate security requirements by environment
cert_requirements = {
    "prod": {
        "min_key_bits": 4096,
        "allowed_key_algorithms": ["RSA", "ECDSA"],
        "min_days_before_expiry": 90,
        "require_domain_validation": true,
        "allowed_domain_types": ["AMAZON_ISSUED"],
        "require_transparency_logging": true,
        "allowed_renewal_methods": ["DNS"],
        "require_subject_alternative_names": true,
        "allowed_san_types": ["DNS", "IP"],
        "require_wildcard_protection": true,
        "allowed_tls_versions": ["TLS_1_2", "TLS_1_3"],
        "denied_tls_versions": ["TLS_1_0", "TLS_1_1", "SSL_3_0"],
        "require_certificate_rotation": true,
        "rotation_window_days": 30
    },
    "staging": {
        "min_key_bits": 2048,
        "allowed_key_algorithms": ["RSA", "ECDSA"],
        "min_days_before_expiry": 30,
        "require_domain_validation": true,
        "allowed_domain_types": ["AMAZON_ISSUED", "IMPORTED"],
        "require_transparency_logging": false,
        "allowed_renewal_methods": ["DNS", "EMAIL"],
        "require_subject_alternative_names": false,
        "allowed_san_types": ["DNS", "IP", "EMAIL"],
        "require_wildcard_protection": false,
        "allowed_tls_versions": ["TLS_1_2", "TLS_1_3"],
        "denied_tls_versions": ["TLS_1_0", "TLS_1_1"],
        "require_certificate_rotation": false,
        "rotation_window_days": 14
    },
    "dev": {
        "min_key_bits": 2048,
        "allowed_key_algorithms": ["RSA", "ECDSA"],
        "min_days_before_expiry": 7,
        "require_domain_validation": false,
        "allowed_domain_types": ["AMAZON_ISSUED", "IMPORTED", "PRIVATE"],
        "require_transparency_logging": false,
        "allowed_renewal_methods": ["DNS", "EMAIL"],
        "require_subject_alternative_names": false,
        "allowed_san_types": ["DNS", "IP", "EMAIL"],
        "require_wildcard_protection": false,
        "allowed_tls_versions": ["TLS_1_2", "TLS_1_3"],
        "denied_tls_versions": [],
        "require_certificate_rotation": false,
        "rotation_window_days": 7
    }
}

# Deny weak certificate configurations
deny_weak_certificate[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    cert.change.after.key_algorithm != cert_requirements[env].allowed_key_algorithms[_]
    msg = sprintf(
        "Certificate must use an approved key algorithm (%v) in %v environment",
        [cert_requirements[env].allowed_key_algorithms, env]
    )
}

# Deny certificates near expiration
deny_expiring_certificate[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    days_until_expiry := (cert.change.after.not_after - time.now_ns()) / (24 * 60 * 60 * 1000000000)
    days_until_expiry < cert_requirements[env].min_days_before_expiry
    
    msg = sprintf(
        "Certificate must have at least %v days before expiry in %v environment",
        [cert_requirements[env].min_days_before_expiry, env]
    )
}

# Enforce domain validation
deny_missing_validation[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    cert_requirements[env].require_domain_validation
    not cert.change.after.domain_validation_options
    
    msg = sprintf(
        "Domain validation is required for certificates in %v environment",
        [env]
    )
}

# Enforce certificate transparency logging
deny_missing_transparency[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    cert_requirements[env].require_transparency_logging
    not cert.change.after.certificate_transparency_logging_preference == "ENABLED"
    
    msg = sprintf(
        "Certificate transparency logging must be enabled in %v environment",
        [env]
    )
}

# Enforce SAN requirements
deny_invalid_san[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    cert_requirements[env].require_subject_alternative_names
    san_type = get_san_type(cert.change.after.subject_alternative_names[_])
    not array_contains(cert_requirements[env].allowed_san_types, san_type)
    
    msg = sprintf(
        "Invalid SAN type %v in %v environment",
        [san_type, env]
    )
}

# Helper to determine SAN type
get_san_type(san) = type {
    contains(san, "@")
    type := "EMAIL"
} {
    regex.match(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`, san)
    type := "IP"
} {
    type := "DNS"
}

# Deny invalid TLS versions
deny_invalid_tls[msg] {
    listener = tfplan.resource_changes[_]
    listener.type == "aws_lb_listener"
    env = listener.change.after.tags.Environment
    
    array_contains(cert_requirements[env].denied_tls_versions, listener.change.after.ssl_policy)
    msg = sprintf(
        "TLS version %v is not allowed in %v environment",
        [listener.change.after.ssl_policy, env]
    )
}

# Enforce certificate rotation
deny_missing_rotation[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    cert_requirements[env].require_certificate_rotation
    not has_rotation_rule(cert.change.after.arn, env)
    
    msg = sprintf(
        "Certificate must have an automatic rotation rule in %v environment",
        [env]
    )
}

# Helper to check rotation rules
has_rotation_rule(cert_arn, env) {
    rule = tfplan.resource_changes[_]
    rule.type == "aws_acm_certificate_rotation"
    rule.change.after.certificate_arn == cert_arn
    rule.change.after.rotation_window <= cert_requirements[env].rotation_window_days
}

# Deny wildcard certificates when protected
deny_wildcard_certificates[msg] {
    cert = tfplan.resource_changes[_]
    cert.type == "aws_acm_certificate"
    env = cert.change.after.tags.Environment
    
    cert_requirements[env].require_wildcard_protection
    contains(cert.change.after.domain_name, "*")
    
    msg = sprintf(
        "Wildcard certificates are not allowed in %v environment",
        [env]
    )
}

# Helper function for array operations
array_contains(arr, elem) {
    arr[_] == elem
}

# Main deny rule combining all certificate security policies
deny[msg] {
    msg = deny_weak_certificate[_]
} {
    msg = deny_expiring_certificate[_]
} {
    msg = deny_missing_validation[_]
} {
    msg = deny_missing_transparency[_]
} {
    msg = deny_invalid_san[_]
} {
    msg = deny_invalid_tls[_]
} {
    msg = deny_missing_rotation[_]
} {
    msg = deny_wildcard_certificates[_]
}
