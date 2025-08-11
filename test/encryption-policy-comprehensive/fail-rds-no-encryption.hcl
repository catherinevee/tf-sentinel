# Test case: RDS instance without encryption
# Expected result: FAIL
# Description: RDS instance with storage_encrypted = false

mock "tfplan/v2" {
  module {
    source = "./mock-rds-no-encryption.sentinel"
  }
}

mock "tfrun" {
  module {
    source = "./mock-tfrun.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}
