# Examples for AWS-Specific Sentinel Policies

This directory contains examples showing how to run and test Sentinel policies designed for AWS environments.

## Running AWS-Specific Sentinel Tests

# 1. Initialize sentinel test environment
sentinel test security-policy.sentinel

# 2. Run specific test
sentinel test security-policy.sentinel -run=verify_encryption_enabled

# 3. Test against actual Terraform plan
sentinel apply -policy=security-policy.sentinel -policyfile=/path/to/terraform.tfplan.json

# 4. Test against mock data
sentinel test security-policy_test.sentinel

# 5. Run in advisory mode (warns but doesn't block)
sentinel apply -policy=security-policy.sentinel -level=advisory

# 6. Run in soft-mandatory mode (can be overridden)
sentinel apply -policy=security-policy.sentinel -level=soft-mandatory

# 7. Run in hard-mandatory mode (cannot be overridden)
sentinel apply -policy=security-policy.sentinel -level=hard-mandatory
