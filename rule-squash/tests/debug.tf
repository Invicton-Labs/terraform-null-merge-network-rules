module "merge_rules" {
  source = "../"
  rule_sets = {
    // Set 0
    set-0 = {
      discrete_encapsulation = {
        protocol = {
          "*" = ["tcps"]
        }
      }
      discrete_equivalents = {
        protocol = {
          6 = ["tcp"]
          7 = ["udp"]
        }
        protocol2 = {
          6 = [7]
          8 = ["udp"]
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
          discretes = {
            protocol = "tcp"
          }
          metadata = {
            id  = 1
            foo = "bar"
          }
        },
        {
          ranges = {
            ports = {
              from_inclusive = 12
              to_inclusive   = 13
            }
          }
          discretes = {
            protocol = "tcp"
          }
          metadata = {
            id  = 2
            foo = "bar"
            baz = false
          }
        },
        {
          ranges = {
            ports = {
              from_inclusive = 8
              to_inclusive   = null
            }
          }
          discretes = {
            protocol = "tcp"
          }
          metadata = {
            id  = 6
            foo = "bar"
            baz = 23
          }
        },
        {
          ranges = {
            ports = {
              from_inclusive = 18
              to_inclusive   = 40
            }
          }
          discretes = {
            protocol = "tcp"
          }
          metadata = {
            id  = 3
            foo = "bar"
            baz = 23
          }
        },
        {
          ranges = {
            ports = {
              from_inclusive = 42
              to_inclusive   = 50
            }
          }
          discretes = {
            protocol = "tcp"
          }
          metadata = {
            id  = 4
            foo = "bar"
            baz = 23
          }
        },
      ]
    }
  }
}

output "debug" {
  value = module.merge_rules.debug
}
