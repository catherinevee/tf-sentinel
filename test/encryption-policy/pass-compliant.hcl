# Test cases for encryption policy
mock "tfplan/v2" {
  module {
    source = "./mocks/encryption/pass-compliant.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
