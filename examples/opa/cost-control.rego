# Example OPA policy for cost control
package terraform.cost

import input.plan as tfplan

# Default maximum instance sizes
allowed_instance_types = {
    "dev": ["t2.micro", "t2.small", "t3.micro", "t3.small"],
    "staging": ["t2.medium", "t3.medium", "t3a.medium"],
    "prod": ["t3.large", "t3a.large", "m5.large"]
}

# Maximum allowed storage sizes
max_storage_gb = {
    "dev": 100,
    "staging": 500,
    "prod": 1000
}

# Maximum allowed costs per resource type
max_monthly_cost = {
    "dev": 1000,
    "staging": 5000,
    "prod": 10000
}

# Deny EC2 instances that are too large for the environment
deny_large_instances[msg] {
    instance = tfplan.resource_changes[_]
    instance.type == "aws_instance"
    instance.change.after.tags.Environment == env
    not allowed_instance_type(instance.change.after.instance_type, env)
    msg = sprintf(
        "Instance type %v is not allowed in %v environment. Allowed types: %v",
        [instance.change.after.instance_type, env, allowed_instance_types[env]]
    )
}

# Helper function to check allowed instance types
allowed_instance_type(type, env) {
    allowed_instance_types[env][_] == type
}

# Deny EBS volumes that are too large
deny_large_volumes[msg] {
    volume = tfplan.resource_changes[_]
    volume.type == "aws_ebs_volume"
    env = volume.change.after.tags.Environment
    volume.change.after.size > max_storage_gb[env]
    msg = sprintf(
        "EBS volume size %vGB exceeds maximum allowed size %vGB for %v environment",
        [volume.change.after.size, max_storage_gb[env], env]
    )
}

# Require cost-effective storage types
deny_expensive_storage[msg] {
    volume = tfplan.resource_changes[_]
    volume.type == "aws_ebs_volume"
    env = volume.change.after.tags.Environment
    volume.change.after.type == "io1"
    env != "prod"
    msg = sprintf(
        "Provisioned IOPS volumes (io1) are not allowed in %v environment",
        [env]
    )
}

# Enforce proper resource tagging for cost allocation
deny_missing_cost_tags[msg] {
    resource = tfplan.resource_changes[_]
    required_tags = ["CostCenter", "Project", "Environment", "Owner"]
    tag = required_tags[_]
    not resource.change.after.tags[tag]
    msg = sprintf(
        "Resource is missing required cost allocation tag: %v",
        [tag]
    )
}

# Check for cost-effective RDS configurations
deny_expensive_db_config[msg] {
    db = tfplan.resource_changes[_]
    db.type == "aws_db_instance"
    env = db.change.after.tags.Environment
    env != "prod"
    db.change.after.multi_az == true
    msg = "Multi-AZ deployment is not allowed in non-production environments"
}

# Enforce auto-scaling group size limits
deny_large_asg[msg] {
    asg = tfplan.resource_changes[_]
    asg.type == "aws_autoscaling_group"
    env = asg.change.after.tag[_][tags].Environment
    env == "dev"
    asg.change.after.max_size > 4
    msg = "Auto Scaling Groups in dev environment cannot have max_size > 4"
}

# Main rule that combines all deny conditions
deny[msg] {
    msg = deny_large_instances[_]
} {
    msg = deny_large_volumes[_]
} {
    msg = deny_expensive_storage[_]
} {
    msg = deny_missing_cost_tags[_]
} {
    msg = deny_expensive_db_config[_]
} {
    msg = deny_large_asg[_]
}
