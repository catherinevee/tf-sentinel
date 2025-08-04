# Example OPA policy for container security
package terraform.container_security

import input.plan as tfplan

# Container security requirements by environment
container_requirements = {
    "prod": {
        "allowed_registries": ["aws.ecr.us-east-1.amazonaws.com", "aws.ecr.us-west-2.amazonaws.com"],
        "scan_on_push": true,
        "immutable_tags": true,
        "require_signed_images": true,
        "max_image_age_days": 30,
        "required_capabilities": ["FARGATE"],
        "denied_capabilities": ["privileged", "NET_ADMIN", "SYS_ADMIN"]
    },
    "staging": {
        "allowed_registries": ["aws.ecr.us-east-1.amazonaws.com"],
        "scan_on_push": true,
        "immutable_tags": false,
        "require_signed_images": false,
        "max_image_age_days": 90,
        "required_capabilities": ["FARGATE"],
        "denied_capabilities": ["privileged"]
    },
    "dev": {
        "allowed_registries": ["*"],
        "scan_on_push": false,
        "immutable_tags": false,
        "require_signed_images": false,
        "max_image_age_days": 180,
        "required_capabilities": [],
        "denied_capabilities": ["privileged"]
    }
}

# Security group requirements for containers
container_sg_requirements = {
    "prod": {
        "allowed_ports": [443, 8443],
        "allowed_protocols": ["tcp"],
        "require_sg_rules": true
    }
}

# Deny unauthorized container registries
deny_unauthorized_registry[msg] {
    task = tfplan.resource_changes[_]
    task.type == "aws_ecs_task_definition"
    env = task.change.after.tags.Environment
    
    container = task.change.after.container_definitions[_]
    not is_allowed_registry(container.image, env)
    
    msg = sprintf(
        "Container image %v is not from an allowed registry for %v environment",
        [container.image, env]
    )
}

# Helper to check allowed registries
is_allowed_registry(image, env) {
    requirements = container_requirements[env]
    registry = split("/", image)[0]
    requirements.allowed_registries[_] == registry
} {
    requirements = container_requirements[env]
    requirements.allowed_registries[_] == "*"
}

# Deny missing image scanning
deny_missing_scan[msg] {
    repo = tfplan.resource_changes[_]
    repo.type == "aws_ecr_repository"
    env = repo.change.after.tags.Environment
    
    container_requirements[env].scan_on_push
    not repo.change.after.image_scanning_configuration[0].scan_on_push
    
    msg = sprintf(
        "ECR repository must have scan on push enabled in %v environment",
        [env]
    )
}

# Deny mutable image tags
deny_mutable_tags[msg] {
    repo = tfplan.resource_changes[_]
    repo.type == "aws_ecr_repository"
    env = repo.change.after.tags.Environment
    
    container_requirements[env].immutable_tags
    not repo.change.after.image_tag_mutability == "IMMUTABLE"
    
    msg = sprintf(
        "ECR repository must have immutable tags in %v environment",
        [env]
    )
}

# Deny unauthorized container capabilities
deny_container_capabilities[msg] {
    task = tfplan.resource_changes[_]
    task.type == "aws_ecs_task_definition"
    env = task.change.after.tags.Environment
    requirements = container_requirements[env]
    
    container = task.change.after.container_definitions[_]
    cap = container.linux_parameters.capabilities.add[_]
    array_contains(requirements.denied_capabilities, cap)
    
    msg = sprintf(
        "Container capability %v is not allowed in %v environment",
        [cap, env]
    )
}

# Enforce required container capabilities
deny_missing_capabilities[msg] {
    task = tfplan.resource_changes[_]
    task.type == "aws_ecs_task_definition"
    env = task.change.after.tags.Environment
    requirements = container_requirements[env]
    
    required_cap = requirements.required_capabilities[_]
    not array_contains(task.change.after.requires_capabilities, required_cap)
    
    msg = sprintf(
        "ECS task definition must have %v capability in %v environment",
        [required_cap, env]
    )
}

# Deny insecure container configurations
deny_insecure_container_config[msg] {
    task = tfplan.resource_changes[_]
    task.type == "aws_ecs_task_definition"
    container = task.change.after.container_definitions[_]
    
    container.privileged
    msg = sprintf(
        "Container %v must not run in privileged mode",
        [container.name]
    )
}

# Enforce secure container networking
deny_insecure_networking[msg] {
    service = tfplan.resource_changes[_]
    service.type == "aws_ecs_service"
    env = service.change.after.tags.Environment
    
    not service.change.after.network_configuration[0].assign_public_ip
    msg = sprintf(
        "ECS service in %v environment must not have public IP addresses assigned",
        [env]
    )
}

# Enforce container logging
deny_missing_logging[msg] {
    task = tfplan.resource_changes[_]
    task.type == "aws_ecs_task_definition"
    container = task.change.after.container_definitions[_]
    
    not container.logConfiguration
    msg = sprintf(
        "Container %v must have logging configured",
        [container.name]
    )
}

# Enforce secure task execution role
deny_insecure_task_role[msg] {
    task = tfplan.resource_changes[_]
    task.type == "aws_ecs_task_definition"
    env = task.change.after.tags.Environment
    
    not task.change.after.task_role_arn
    msg = sprintf(
        "ECS task definition must have a task role in %v environment",
        [env]
    )
}

# Helper function for array operations
array_contains(arr, elem) {
    arr[_] == elem
}

# Main deny rule combining all container security policies
deny[msg] {
    msg = deny_unauthorized_registry[_]
} {
    msg = deny_missing_scan[_]
} {
    msg = deny_mutable_tags[_]
} {
    msg = deny_container_capabilities[_]
} {
    msg = deny_missing_capabilities[_]
} {
    msg = deny_insecure_container_config[_]
} {
    msg = deny_insecure_networking[_]
} {
    msg = deny_missing_logging[_]
} {
    msg = deny_insecure_task_role[_]
}
