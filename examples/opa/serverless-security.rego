# Example OPA policy for serverless security
package terraform.serverless_security

import input.plan as tfplan

# Serverless security requirements by environment
lambda_requirements = {
    "prod": {
        "runtime_versions": {
            "python": ["3.9", "3.10", "3.11"],
            "nodejs": ["18.x", "20.x"],
            "java": ["17"]
        },
        "vpc_required": true,
        "reserved_concurrency_required": true,
        "max_timeout": 900,
        "min_memory": 512,
        "require_x_ray": true,
        "require_dead_letter_queue": true
    },
    "staging": {
        "runtime_versions": {
            "python": ["3.9", "3.10", "3.11"],
            "nodejs": ["18.x", "20.x"],
            "java": ["17"]
        },
        "vpc_required": true,
        "reserved_concurrency_required": false,
        "max_timeout": 900,
        "min_memory": 256,
        "require_x_ray": true,
        "require_dead_letter_queue": false
    },
    "dev": {
        "runtime_versions": {
            "python": ["3.8", "3.9", "3.10", "3.11"],
            "nodejs": ["16.x", "18.x", "20.x"],
            "java": ["11", "17"]
        },
        "vpc_required": false,
        "reserved_concurrency_required": false,
        "max_timeout": 900,
        "min_memory": 128,
        "require_x_ray": false,
        "require_dead_letter_queue": false
    }
}

# Required environment variables
required_env_vars = {
    "prod": ["LOG_LEVEL", "POWERTOOLS_SERVICE_NAME", "POWERTOOLS_METRICS_NAMESPACE"],
    "staging": ["LOG_LEVEL", "POWERTOOLS_SERVICE_NAME"],
    "dev": ["LOG_LEVEL"]
}

# Deny outdated runtimes
deny_outdated_runtime[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    runtime_family = get_runtime_family(func.change.after.runtime)
    not is_allowed_runtime(func.change.after.runtime, env, runtime_family)
    
    msg = sprintf(
        "Lambda function runtime %v is not allowed in %v environment. Allowed versions: %v",
        [func.change.after.runtime, env, lambda_requirements[env].runtime_versions[runtime_family]]
    )
}

# Helper to get runtime family
get_runtime_family(runtime) = family {
    startswith(runtime, "python")
    family := "python"
} {
    startswith(runtime, "nodejs")
    family := "nodejs"
} {
    startswith(runtime, "java")
    family := "java"
}

# Helper to check allowed runtime versions
is_allowed_runtime(runtime, env, family) {
    version = split(runtime, family)[1]
    lambda_requirements[env].runtime_versions[family][_] == version
}

# Enforce VPC configuration
deny_missing_vpc[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    lambda_requirements[env].vpc_required
    not func.change.after.vpc_config
    
    msg = sprintf(
        "Lambda function must be deployed in a VPC in %v environment",
        [env]
    )
}

# Enforce concurrency limits
deny_missing_concurrency[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    lambda_requirements[env].reserved_concurrency_required
    not func.change.after.reserved_concurrent_executions
    
    msg = sprintf(
        "Lambda function must have reserved concurrency set in %v environment",
        [env]
    )
}

# Enforce timeout limits
deny_excessive_timeout[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    func.change.after.timeout > lambda_requirements[env].max_timeout
    msg = sprintf(
        "Lambda function timeout cannot exceed %v seconds in %v environment",
        [lambda_requirements[env].max_timeout, env]
    )
}

# Enforce minimum memory
deny_insufficient_memory[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    func.change.after.memory_size < lambda_requirements[env].min_memory
    msg = sprintf(
        "Lambda function memory must be at least %vMB in %v environment",
        [lambda_requirements[env].min_memory, env]
    )
}

# Enforce X-Ray tracing
deny_missing_tracing[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    lambda_requirements[env].require_x_ray
    not func.change.after.tracing_config[0].mode == "Active"
    
    msg = sprintf(
        "Lambda function must have X-Ray tracing enabled in %v environment",
        [env]
    )
}

# Enforce Dead Letter Queue
deny_missing_dlq[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    lambda_requirements[env].require_dead_letter_queue
    not func.change.after.dead_letter_config
    
    msg = sprintf(
        "Lambda function must have a Dead Letter Queue configured in %v environment",
        [env]
    )
}

# Enforce required environment variables
deny_missing_env_vars[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    required_var = required_env_vars[env][_]
    not func.change.after.environment[0].variables[required_var]
    
    msg = sprintf(
        "Lambda function missing required environment variable %v in %v environment",
        [required_var, env]
    )
}

# Enforce secure environment variables
deny_insecure_env_vars[msg] {
    func = tfplan.resource_changes[_]
    func.type == "aws_lambda_function"
    env = func.change.after.tags.Environment
    
    contains(lower(key), "secret")
    contains(lower(key), "password")
    contains(lower(key), "key")
    
    msg = sprintf(
        "Sensitive information should not be stored in environment variables: %v",
        [key]
    )
}

# Main deny rule combining all serverless security policies
deny[msg] {
    msg = deny_outdated_runtime[_]
} {
    msg = deny_missing_vpc[_]
} {
    msg = deny_missing_concurrency[_]
} {
    msg = deny_excessive_timeout[_]
} {
    msg = deny_insufficient_memory[_]
} {
    msg = deny_missing_tracing[_]
} {
    msg = deny_missing_dlq[_]
} {
    msg = deny_missing_env_vars[_]
} {
    msg = deny_insecure_env_vars[_]
}
