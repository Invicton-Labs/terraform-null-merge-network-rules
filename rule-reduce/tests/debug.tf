module "merge-ports" {
  source = "../"
  rule_sets = {
    // Set 0
    set-0 = {
      singleton_encapsulation = {
        protocol = {
          "*" = ["tcps"]
        }
      }
      singleton_equivalents = {
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
          singletons = {
            protocol = "tcp"
          }
          metadata = ["1"]
        },
        {
          ranges = {
            ports = {
              from_inclusive = 12
              to_inclusive   = 13
            }
          }
          singletons = {
            protocol = "tcp"
          }
          metadata = ["2"]
        },
      ]
    }
  }
}

output "merge-ports" {
  value = module.merge-ports
}
