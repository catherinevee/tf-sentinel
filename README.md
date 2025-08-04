# tf-sentinel

This repository contains Sentinel and Open Policy Agent (OPA) policies for enforcing security, compliance, and operational best practices in Terraform workflows.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Sentinel Integration](#sentinel-integration)
- [OPA Integration](#opa-integration)
- [Policy Structure](#policy-structure)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)

## Prerequisites

### For Sentinel:
- Terraform Enterprise or Terraform Cloud account
- Sentinel CLI (for local testing)
- Terraform CLI

### For OPA:
- OPA CLI
- conftest (optional, for easier testing)

## Sentinel Integration

1. **Configure Sentinel in Terraform Enterprise/Cloud**:
   ```hcl
   policy_set "security_policies" {
     name = "Security Policies"
     path = "./sentinel"
     enforcement_level = "hard-mandatory"
   }
   ```

2. **Add Sentinel Files to Your Repository**:
   - Place `.sentinel` files in your designated policy directory
   - Configure `sentinel.hcl` with policy settings:
   ```hcl
   policy "enforce_encryption" {
     enforcement_level = "hard-mandatory"
   }
   ```

3. **Local Testing**:
   ```bash
   sentinel test
   sentinel apply <policy-name>
   ```

## OPA Integration

1. **Add OPA Files to Your Repository**:
   - Place `.rego` files in your designated policy directory
   - Structure policies using packages:
   ```rego
   package terraform.policies
   ```

2. **Using with Terraform**:
   ```bash
   # Generate Terraform plan in JSON format
   terraform plan -out=tfplan
   terraform show -json tfplan > plan.json

   # Evaluate with OPA
   opa eval --data policy.rego --input plan.json "data.terraform.policies"
   ```

3. **Using with conftest**:
   ```bash
   conftest test plan.json
   ```

## Policy Structure

### Sentinel Policies
```hcl
import "tfplan/v2" as tfplan

# Policy rule
<policy_name> = rule {
    all tfplan.resources.<resource_type> as _, resource {
        # Policy conditions
    }
}
```

### OPA Policies
```rego
package terraform.policies

# Policy rule
deny[msg] {
    resource := input.resource_changes[_]
    # Policy conditions
    msg := sprintf("Policy violation: %v", [resource.address])
}
```

## Usage

### Workflow Integration

1. **CI/CD Pipeline**:
   ```yaml
   terraform_plan:
     steps:
       - terraform plan -out=tfplan
       - terraform show -json tfplan > plan.json
       - conftest test plan.json
   ```

2. **Pre-commit Hooks**:
   ```yaml
   repos:
     - repo: local
       hooks:
         - id: policy-check
           name: Policy Check
           entry: conftest test
           language: system
           files: \.tf$
   ```

### Common Policy Patterns

1. **Resource Tagging**:
   ```rego
   deny[msg] {
       resource := input.resource_changes[_]
       required_tags := ["Environment", "Owner", "CostCenter"]
       tag := required_tags[_]
       not resource.change.after.tags[tag]
       msg := sprintf("Resource %v missing required tag: %v", [resource.address, tag])
   }
   ```

2. **Security Controls**:
   ```rego
   deny[msg] {
       sg := input.resource_changes[_]
       sg.type == "aws_security_group"
       rule := sg.change.after.ingress[_]
       rule.cidr_blocks[_] == "0.0.0.0/0"
       rule.to_port == 22
       msg := "SSH port 22 cannot be open to 0.0.0.0/0"
   }
   ```

## Testing

### Testing Sentinel Policies
```bash
# Run all tests
sentinel test

# Test specific policy
sentinel test <policy-name>.sentinel
```

### Testing OPA Policies
```bash
# Using OPA CLI
opa test . -v

# Using conftest
conftest verify
```

### Mock Data
The repository includes mock data for testing in:
- `examples/tests/mocks/` - Mock Terraform plans
- `examples/tests/fixtures/` - Test fixtures

## Contributing

1. Fork the repository
2. Create your feature branch
3. Write or update tests
4. Add or modify policies
5. Submit a pull request

### Policy Guidelines
- Write clear policy names and descriptions
- Include comprehensive tests
- Document any assumptions or prerequisites
- Follow existing policy structure
- Include both positive and negative test cases