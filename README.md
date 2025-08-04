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

### For Terragrunt:
- Terragrunt CLI
- Terraform CLI
- jq (for JSON processing)

## Terragrunt Integration

1. **Directory Structure**:
   ```
   .
   ├── terragrunt.hcl
   ├── env
   │   ├── prod
   │   │   └── terragrunt.hcl
   │   └── dev
   │       └── terragrunt.hcl
   └── policies
       ├── sentinel
       │   └── sentinel.hcl
       └── opa
           └── policy.rego
   ```

2. **Terragrunt Configuration**:
   ```hcl
   # terragrunt.hcl
   terraform {
     before_hook "policy_check" {
       commands = ["plan", "apply"]
       execute  = [
         "bash", "-c",
         <<-EOF
           terragrunt show -json \
           | opa eval --format pretty \
             --data policies/opa \
             --input - \
             "data.terraform.deny"
         EOF
       ]
     }
   }
   ```

3. **Running Policy Checks**:
   ```bash
   # Run Terragrunt with policy checks
   terragrunt plan
   
   # Run specific environment
   cd env/prod
   terragrunt plan
   ```

4. **Policy Output Processing**:
   ```bash
   # Get policy violations for specific environment
   terragrunt show -json | jq -r '.resource_changes[] | select(.change.actions[] | contains("create"))'
   ```

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

1. **GitHub Actions Workflow**:

   ```yaml
   name: 'Terraform Plan and Policy Check'
   
   on:
     pull_request:
       branches: [ main ]
     push:
       branches: [ main ]
   
   jobs:
     terraform:
       name: 'Terraform and Policy Check'
       runs-on: ubuntu-latest
       
       env:
         AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
         AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
         TERRAFORM_CLOUD_TOKEN: ${{ secrets.TF_CLOUD_TOKEN }}
   
       steps:
         # Checkout the repository
         - name: Checkout
           uses: actions/checkout@v2
   
         # Install Terraform
         - name: Setup Terraform
           uses: hashicorp/setup-terraform@v1
           with:
             terraform_version: 1.0.0
             cli_config_credentials_token: ${{ secrets.TF_CLOUD_TOKEN }}
   
         # Install Sentinel
         - name: Setup Sentinel
           run: |
             wget https://releases.hashicorp.com/sentinel/0.18.4/sentinel_0.18.4_linux_amd64.zip
             unzip sentinel_0.18.4_linux_amd64.zip
             sudo mv sentinel /usr/local/bin/
   
         # Install OPA
         - name: Setup OPA
           run: |
             curl -L -o opa https://openpolicyagent.org/downloads/v0.42.0/opa_linux_amd64
             chmod 755 opa
             sudo mv opa /usr/local/bin/
   
         # Terraform Format Check
         - name: Terraform Format
           run: terraform fmt -check
   
         # Terraform Init
         - name: Terraform Init
           run: terraform init
   
         # Terraform Validate
         - name: Terraform Validate
           run: terraform validate
   
         # Terraform Plan
         - name: Terraform Plan
           run: |
             terraform plan -out=tfplan
             terraform show -json tfplan > plan.json
   
         # Sentinel Policy Check
         - name: Sentinel Policy Check
           run: |
             cd policies/sentinel
             sentinel test
             for f in *.sentinel; do
               sentinel apply "$f"
             done
   
         # OPA Policy Check
         - name: OPA Policy Check
           run: |
             cd policies/opa
             opa eval --data . --input ../../plan.json --format pretty "data.terraform.deny"
   
         # Comment Policy Results on PR
         - name: Comment Policy Results
           if: github.event_name == 'pull_request'
           uses: actions/github-script@v4
           with:
             github-token: ${{ secrets.GITHUB_TOKEN }}
             script: |
               const fs = require('fs');
               const sentinelResults = fs.readFileSync('sentinel-results.txt', 'utf8');
               const opaResults = fs.readFileSync('opa-results.txt', 'utf8');
               
               const body = `### Policy Check Results
               
               #### Sentinel Policies
               \`\`\`
               ${sentinelResults}
               \`\`\`
               
               #### OPA Policies
               \`\`\`
               ${opaResults}
               \`\`\``;
               
               github.issues.createComment({
                 issue_number: context.issue.number,
                 owner: context.repo.owner,
                 repo: context.repo.repo,
                 body: body
               });

   ```

2. **Terraform Enterprise/Cloud Integration**:

   ```yaml
   name: 'Terraform Enterprise Policy Check'
   
   on:
     pull_request:
       branches: [ main ]
   
   jobs:
     terraform:
       name: 'Terraform Enterprise Policy Check'
       runs-on: ubuntu-latest
       
       env:
         TF_TOKEN_app_terraform_io: ${{ secrets.TF_CLOUD_TOKEN }}
         
       steps:
         - name: Checkout
           uses: actions/checkout@v2
           
         - name: Setup Terraform
           uses: hashicorp/setup-terraform@v1
           with:
             cli_config_credentials_token: ${{ secrets.TF_CLOUD_TOKEN }}
             
         - name: Terraform Init
           run: terraform init
           
         - name: Terraform Plan
           run: terraform plan
           # Terraform Cloud/Enterprise will automatically run policy checks
           # Results will be reported back to the GitHub PR
   ```

3. **Pre-commit Hooks**:
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