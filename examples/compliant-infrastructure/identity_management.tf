# Example of Identity and Access Management with SSO
provider "aws" {
  region = "us-east-1"
}

# AWS IAM Identity Center (SSO)
resource "aws_identitystore_user" "admin_user" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]

  display_name = "Admin User"
  user_name    = "admin.user@example.com"

  name {
    given_name  = "Admin"
    family_name = "User"
  }
}

# Permission Set for Administrators
resource "aws_ssoadmin_permission_set" "admin" {
  name             = "AdministratorAccess"
  description      = "Administrator access permission set"
  instance_arn     = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
  session_duration = "PT8H"

  tags = {
    Name           = "administrator-access"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Attach AWS managed policy to permission set
resource "aws_ssoadmin_managed_policy_attachment" "admin_policy" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Permission Set for Developers
resource "aws_ssoadmin_permission_set" "developer" {
  name             = "DeveloperAccess"
  description      = "Developer access permission set"
  instance_arn     = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
  session_duration = "PT8H"

  tags = {
    Name           = "developer-access"
    Environment    = "prod"
    Owner          = "security-team"
    CostCenter     = "12345"
    Project        = "core-infrastructure"
  }
}

# Custom policy for developers
resource "aws_ssoadmin_permission_set_inline_policy" "developer_policy" {
  inline_policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "elasticloadbalancing:Describe*",
          "autoscaling:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*"
        ]
        Resource = "*"
      }
    ]
  })
  instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
}

# Group for Administrators
resource "aws_identitystore_group" "administrators" {
  display_name      = "Administrators"
  description       = "Administrator group"
  identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
}

# Group for Developers
resource "aws_identitystore_group" "developers" {
  display_name      = "Developers"
  description       = "Developer group"
  identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
}

# Assign user to group
resource "aws_identitystore_group_membership" "admin_user_group" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.sso.identity_store_ids)[0]
  group_id         = aws_identitystore_group.administrators.group_id
  member_id        = aws_identitystore_user.admin_user.user_id
}

# Account assignment for administrators
resource "aws_ssoadmin_account_assignment" "admin_assignment" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.admin.arn

  principal_id   = aws_identitystore_group.administrators.group_id
  principal_type = "GROUP"

  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# Account assignment for developers
resource "aws_ssoadmin_account_assignment" "developer_assignment" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.sso.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn

  principal_id   = aws_identitystore_group.developers.group_id
  principal_type = "GROUP"

  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# Data sources
data "aws_ssoadmin_instances" "sso" {}
data "aws_caller_identity" "current" {}
