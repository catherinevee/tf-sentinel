# Test case: Compliant resources with proper encryption
# Expected result: PASS
# Description: All AWS resources have proper encryption configured

mock "tfplan/v2" {
  module {
    source = "./mock-compliant-encryption.sentinel"
  }
}

mock "tfrun" {
  module {
    source = "./mock-tfrun.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
