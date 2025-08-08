# tf-sentinel

This repository contains Sentinel and Open Policy Agent (OPA) policies for enforcing security, compliance, and operational best practices in **AWS-specific** Terraform workflows. The policies are designed specifically for AWS resources and services, providing comprehensive governance for AWS cloud environments.

## Table of Contents
- [AWS Focus](#aws-focus)
- [Prerequisites](#prerequisites)
- [Sentinel Integration](#sentinel-integration)
- [OPA Integration](#opa-integration)
- [Policy Structure](#policy-structure)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)

## AWS Focus

This repository is specifically designed for **AWS environments** and includes policies for:

- **AWS Security Services**: S3, RDS, EBS, Secrets Manager, KMS, IAM, Security Groups, NACLs
- **AWS Compute Services**: EC2, Lambda, ECS, EKS, Auto Scaling Groups
- **AWS Storage Services**: S3, EBS, EFS, FSx
- **AWS Database Services**: RDS, DynamoDB, Redshift, ElastiCache
- **AWS Network Services**: VPC, Subnets, Route Tables, NAT Gateways, Load Balancers
- **AWS Monitoring & Logging**: CloudWatch, CloudTrail, VPC Flow Logs
- **AWS Cost Management**: Resource tagging, instance sizing, reserved instances

All policies are written with AWS resource types, attributes, and best practices in mind. They enforce AWS Well-Architected Framework principles including security, reliability, performance efficiency, cost optimization, and operational excellence.

## Prerequisites

### For Sentinel:
- Terraform Enterprise or Terraform Cloud account
- Sentinel CLI (for local testing)
- Terraform CLI
- AWS CLI configured with appropriate credentials
- AWS account with necessary permissions

### For OPA:
- OPA CLI
- conftest (optional, for easier testing)
- AWS CLI configured with appropriate credentials
- AWS account with necessary permissions

### For Terragrunt:
- Terragrunt CLI
- Terraform CLI
- jq (for JSON processing)
- AWS CLI configured with appropriate credentials
- AWS account with necessary permissions

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

### Sentinel Policies for AWS
```hcl
import "tfplan/v2" as tfplan

# Example: Enforce encryption on AWS S3 buckets
aws_s3_encryption_required = rule {
    all tfplan.resources.aws_s3_bucket as _, bucket {
        bucket.applied.server_side_encryption_configuration is not null
    }
}

# Example: Ensure AWS EC2 instances are not publicly accessible
aws_ec2_no_public_ip = rule {
    all tfplan.resources.aws_instance as _, instance {
        instance.applied.associate_public_ip_address is false
    }
}
```

### OPA Policies for AWS
```rego
package terraform.aws.policies

# Example: Deny AWS resources without proper encryption
deny[msg] {
    resource := input.resource_changes[_]
    aws_encrypted_resources := ["aws_s3_bucket", "aws_rds_instance", "aws_ebs_volume"]
    resource.type == aws_encrypted_resources[_]
    not is_encrypted(resource)
    msg := sprintf("AWS Policy violation: %v must have encryption enabled", [resource.address])
}

# Helper function to check encryption for different AWS resource types
is_encrypted(resource) {
    resource.type == "aws_s3_bucket"
    resource.change.after.server_side_encryption_configuration != null
}

is_encrypted(resource) {
    resource.type == "aws_rds_instance"
    resource.change.after.storage_encrypted == true
}

is_encrypted(resource) {
    resource.type == "aws_ebs_volume"
    resource.change.after.encrypted == true
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

### Common AWS Policy Patterns

1. **AWS Resource Tagging**:
   ```rego
   deny[msg] {
       resource := input.resource_changes[_]
       # Check AWS resources that support tagging
       aws_resources := ["aws_instance", "aws_s3_bucket", "aws_rds_instance", "aws_vpc"]
       resource.type == aws_resources[_]
       required_tags := ["Environment", "Owner", "CostCenter", "Project"]
       tag := required_tags[_]
       not resource.change.after.tags[tag]
       msg := sprintf("AWS Resource %v missing required tag: %v", [resource.address, tag])
   }
   ```

2. **AWS Security Group Controls**:
   ```rego
   deny[msg] {
       sg := input.resource_changes[_]
       sg.type == "aws_security_group"
       rule := sg.change.after.ingress[_]
       rule.cidr_blocks[_] == "0.0.0.0/0"
       rule.to_port == 22
       msg := sprintf("AWS Security Group %v: SSH port 22 cannot be open to 0.0.0.0/0", [sg.address])
   }
   ```

3. **AWS S3 Bucket Security**:
   ```rego
   deny[msg] {
       bucket := input.resource_changes[_]
       bucket.type == "aws_s3_bucket"
       bucket.change.after.acl == "public-read"
       msg := sprintf("AWS S3 Bucket %v cannot have public-read ACL", [bucket.address])
   }
   ```

4. **AWS RDS Encryption**:
   ```rego
   deny[msg] {
       rds := input.resource_changes[_]
       rds.type == "aws_db_instance"
       not rds.change.after.storage_encrypted
       msg := sprintf("AWS RDS instance %v must have storage encryption enabled", [rds.address])
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

### Policy Guidelines for AWS
- **AWS-Specific Focus**: All policies must target AWS resources and services
- Write clear policy names and descriptions that specify AWS resource types
- Include comprehensive tests using AWS mock data
- Document any AWS-specific assumptions or prerequisites
- Follow existing policy structure for AWS resources
- Include both positive and negative test cases with AWS scenarios
- Reference AWS Well-Architected Framework principles where applicable
- Use AWS resource naming conventions (e.g., `aws_s3_bucket`, `aws_ec2_instance`)
- Consider AWS regional differences and availability zones in policies