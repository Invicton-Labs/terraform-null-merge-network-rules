module "merge-ports" {
  source = "../"
  rule_sets = {
    // Set 0
    set-0 = {
      singleton_encapsulation = {
        protocol = {
          "tcp" = ["tcps"]
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
