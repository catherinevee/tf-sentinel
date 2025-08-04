# Test case for non-compliant encryption
mock "tfplan/v2" {
  module {
    source = "./mocks/encryption/fail-missing-encryption.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}
