module "squash" {
  source = "../"
  rule_sets = {
    set-1 = {
      discrete_encapsulation = {}
      discrete_equivalents   = {}
      rules = [
        {
          cidr_ipv4 = "10.1.0.0/16"
          ranges = {
            ports = {
              from_inclusive = 10
              to_inclusive   = 100
            }
          }
          metadata = {
            id = 1
          }
        },
        {
          cidr_ipv4 = "10.2.0.0/16"
          ranges = {
            ports = {
              from_inclusive = 10
              to_inclusive   = 100
            }
          }
          metadata = {
            id = 2
          }
        },
        {
          cidr_ipv4 = "10.3.0.0/16"
          ranges = {
            ports = {
              from_inclusive = 10
              to_inclusive   = 100
            }
          }
          metadata = {
            id = 3
          }
        },
        {
          cidr_ipv4 = "10.4.0.0/15"
          ranges = {
            ports = {
              from_inclusive = 20
              to_inclusive   = 101
            }
          }
          metadata = {
            id = 4
          }
        },
      ]
    }
  }
}

output "module" {
  value = module.squash
}
