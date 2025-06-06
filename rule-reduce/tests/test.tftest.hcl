run "cidr_merge_test" {
  variables {
    rule_sets = {
      // Set 0
      set-0 = {
        singleton_encapsulation = {
          protocol = {

          }
        }
        rules = [
          {
            ranges = {
              ports = {
                from_inclusive = 10
                to_inclusive   = 20
              }
              foo = {
                from_inclusive = 122
                to_inclusive   = 133
              }
            }
            singletons = {
              protocol = "tcp"
            }
            metadata = "something!"
          },
          {
            ranges = {
              foo = {
                from_inclusive = 5
                to_inclusive   = 600
              }
            }
            singletons = {
              protocol = "tcp"
            }
            metadata = [{
              another = thing
            }]
          },
        ]
      }
    }
  }

  # assert {
  #   condition = output.merged_rule_sets = {
  #     set-0 = {

  #     }
  #   }
  # }

}
