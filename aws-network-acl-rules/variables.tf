variable "rule_sets" {
  nullable = false
  type = map(list(object({
    egress     = bool
    allow      = bool
    protocol   = any
    cidr_block = string
    from_port  = optional(number, null)
    to_port    = optional(number, null)
    icmp_type  = optional(string, null)
    icmp_code  = optional(number, null)
    metadata   = optional(map(any))
  })))

  // TODO: validate that all protocols are strings or numbers and not null
  // TODO: validate that the allow is not null
  // TODO: validate that the CIDR block is valid and not null
}

locals {
  // Discrete encapsulations and equivalencies are found here:
  // https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html
  discrete_encapsulation = {
    protocol = {
      -1 = null
    }
    icmp_type = {
      -1 = null
    }
    icmp_code = {
      -1 = null
    }
  }

  discrete_equivalents = {
    protocol = merge({
      -1 = null
    }, local.iana_protocol_equivalencies)
  }
}

module "squash_ipv4" {
  source = "../ipv4"
  rule_sets = {
    set-1 = {
      discrete_encapsulation = {

      }
      discrete_equivalents = {}
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
