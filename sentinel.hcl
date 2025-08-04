# HashiCorp Sentinel Configuration
# This file specifies the policy sets and their enforcement levels

policy "encryption-policy" {
    source = "./policies/security/encryption-policy.sentinel"
    enforcement_level = "hard-mandatory"
}

policy "network-policy" {
    source = "./policies/security/network-policy.sentinel"
    enforcement_level = "hard-mandatory"
}

policy "cost-policy" {
    source = "./policies/cost/cost-policy.sentinel"
    enforcement_level = "soft-mandatory"
}

policy "compliance-policy" {
    source = "./policies/compliance/compliance-policy.sentinel"
    enforcement_level = "hard-mandatory"
}
