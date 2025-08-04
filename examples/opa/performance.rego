# Example OPA policy for performance and scalability
package terraform.performance

import input.plan as tfplan

# Performance requirements by environment
performance_requirements = {
    "prod": {
        "min_instance_count": 2,
        "max_instance_count": 10,
        "min_cpu": 2,
        "min_memory": 4,
        "autoscaling_required": true,
        "load_balancer_required": true
    },
    "staging": {
        "min_instance_count": 1,
        "max_instance_count": 5,
        "min_cpu": 1,
        "min_memory": 2,
        "autoscaling_required": true,
        "load_balancer_required": true
    },
    "dev": {
        "min_instance_count": 1,
        "max_instance_count": 3,
        "min_cpu": 1,
        "min_memory": 1,
        "autoscaling_required": false,
        "load_balancer_required": false
    }
}

# Instance type specifications
instance_specs = {
    "t3.micro": {
        "cpu": 1,
        "memory": 1
    },
    "t3.small": {
        "cpu": 1,
        "memory": 2
    },
    "t3.medium": {
        "cpu": 2,
        "memory": 4
    },
    "t3.large": {
        "cpu": 2,
        "memory": 8
    }
}

# Database performance requirements
db_performance_requirements = {
    "prod": {
        "min_storage": 100,
        "max_connections": 1000,
        "iops_per_gb": 3,
        "performance_insights": true
    },
    "staging": {
        "min_storage": 50,
        "max_connections": 500,
        "iops_per_gb": 3,
        "performance_insights": true
    },
    "dev": {
        "min_storage": 20,
        "max_connections": 100,
        "iops_per_gb": 0,
        "performance_insights": false
    }
}

# Deny insufficient compute resources
deny_insufficient_compute[msg] {
    instance = tfplan.resource_changes[_]
    instance.type == "aws_instance"
    env = instance.change.after.tags.Environment
    requirements = performance_requirements[env]
    
    specs = instance_specs[instance.change.after.instance_type]
    specs.cpu < requirements.min_cpu
    msg = sprintf(
        "Instance type %v does not meet minimum CPU requirement of %v cores for %v environment",
        [instance.change.after.instance_type, requirements.min_cpu, env]
    )
}

# Deny missing auto scaling
deny_missing_autoscaling[msg] {
    asg = tfplan.resource_changes[_]
    asg.type == "aws_autoscaling_group"
    env = asg.change.after.tags[_].value
    requirements = performance_requirements[env]
    
    requirements.autoscaling_required
    not has_proper_scaling_policies(asg.change.after.name)
    msg = sprintf(
        "Auto Scaling Group must have proper scaling policies in %v environment",
        [env]
    )
}

# Helper function to check scaling policies
has_proper_scaling_policies(asg_name) {
    policy = tfplan.resource_changes[_]
    policy.type == "aws_autoscaling_policy"
    policy.change.after.autoscaling_group_name == asg_name
}

# Deny insufficient database performance configuration
deny_insufficient_db_performance[msg] {
    db = tfplan.resource_changes[_]
    db.type == "aws_db_instance"
    env = db.change.after.tags.Environment
    requirements = db_performance_requirements[env]
    
    db.change.after.allocated_storage < requirements.min_storage
    msg = sprintf(
        "Database storage must be at least %vGB in %v environment",
        [requirements.min_storage, env]
    )
}

# Enforce performance insights
deny_missing_performance_insights[msg] {
    db = tfplan.resource_changes[_]
    db.type == "aws_db_instance"
    env = db.change.after.tags.Environment
    requirements = db_performance_requirements[env]
    
    requirements.performance_insights
    not db.change.after.performance_insights_enabled
    msg = sprintf(
        "Performance Insights must be enabled for databases in %v environment",
        [env]
    )
}

# Enforce proper connection limits
deny_improper_connection_limits[msg] {
    db = tfplan.resource_changes[_]
    db.type == "aws_db_instance"
    env = db.change.after.tags.Environment
    requirements = db_performance_requirements[env]
    
    db.change.after.max_connections > requirements.max_connections
    msg = sprintf(
        "Database max connections cannot exceed %v in %v environment",
        [requirements.max_connections, env]
    )
}

# Enforce proper IOPS configuration
deny_insufficient_iops[msg] {
    volume = tfplan.resource_changes[_]
    volume.type == "aws_ebs_volume"
    env = volume.change.after.tags.Environment
    requirements = db_performance_requirements[env]
    
    required_iops = volume.change.after.size * requirements.iops_per_gb
    volume.change.after.iops < required_iops
    msg = sprintf(
        "EBS volume must have at least %v IOPS in %v environment",
        [required_iops, env]
    )
}

# Main deny rule combining all performance policies
deny[msg] {
    msg = deny_insufficient_compute[_]
} {
    msg = deny_missing_autoscaling[_]
} {
    msg = deny_insufficient_db_performance[_]
} {
    msg = deny_missing_performance_insights[_]
} {
    msg = deny_improper_connection_limits[_]
} {
    msg = deny_insufficient_iops[_]
}
