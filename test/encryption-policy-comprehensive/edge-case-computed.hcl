# Test case: Computed resource values
# Expected result: PASS (with warnings)
# Description: Resources with computed values should apply conservative validation

mock "tfplan/v2" {
  module {
    source = "./mock-computed-values.sentinel"
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
