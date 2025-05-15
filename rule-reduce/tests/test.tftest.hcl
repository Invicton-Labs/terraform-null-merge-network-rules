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
            }
            singletons = {
              protocol = "tcp"
            }
            metadata = []
          },
          # {
          #   ranges = {
          #     ports = {
          #       from_inclusive = 10
          #       to_inclusive   = 30
          #     }
          #   }
          #   singletons = {
          #     protocol = ["abc"]
          #   }
          #   metadata = []
          # },
        ]
      }
    }
  }

}
