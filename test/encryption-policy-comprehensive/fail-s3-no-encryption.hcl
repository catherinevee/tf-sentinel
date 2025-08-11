# Test case: S3 bucket without encryption
# Expected result: FAIL
# Description: S3 bucket missing server-side encryption configuration

mock "tfplan/v2" {
  module {
    source = "./mock-s3-no-encryption.sentinel"
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
