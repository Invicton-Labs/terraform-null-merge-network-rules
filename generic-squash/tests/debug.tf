module "merge_rules" {
  source = "../"
  rule_sets = {
    // Set 0
    # set-0 = {
    #   discrete_encapsulation = {
    #     protocol = {
    #       "*" = ["tcps"]
    #     }
    #   }
    #   discrete_equivalents = {
    #     protocol = {
    #       6 = ["tcp"]
    #       7 = ["udp"]
    #     }
    #     protocol2 = {
    #       6 = [7]
    #       8 = ["udp"]
    #     }
    #   }
    #   rules = [
    #     {
    #       ranges = {
    #         ports = {
    #           from_inclusive = 10
    #           to_inclusive   = 20
    #         }
    #       }
    #       discretes = {
    #         protocol = "tcp"
    #       }
    #       metadata = {
    #         id  = 1
    #         foo = "bar"
    #       }
    #     },
    #     {
    #       ranges = {
    #         ports = {
    #           from_inclusive = 12
    #           to_inclusive   = 13
    #         }
    #       }
    #       discretes = {
    #         protocol = "tcp"
    #       }
    #       metadata = {
    #         id  = 2
    #         foo = "bar"
    #         baz = false
    #       }
    #     },
    #     {
    #       ranges = {
    #         ports = {
    #           from_inclusive = 8
    #           to_inclusive   = null
    #         }
    #       }
    #       discretes = {
    #         protocol = "tcp"
    #       }
    #       metadata = {
    #         id  = 6
    #         foo = "bar"
    #         baz = 23
    #       }
    #     },
    #     {
    #       ranges = {
    #         ports = {
    #           from_inclusive = 18
    #           to_inclusive   = 40
    #         }
    #       }
    #       discretes = {
    #         protocol = "tcp"
    #       }
    #       metadata = {
    #         id  = 3
    #         foo = "bar"
    #         baz = 23
    #       }
    #     },
    #     {
    #       ranges = {
    #         ports = {
    #           from_inclusive = 42
    #           to_inclusive   = 50
    #         }
    #       }
    #       discretes = {
    #         protocol = "tcp"
    #       }
    #       metadata = {
    #         id  = 4
    #         foo = "bar"
    #         baz = 23
    #       }
    #     },
    #   ]
    # }

    set-1 = {
      discrete_encapsulation = {
        egress   = []
        allow    = []
        protocol = []
        icmp_type = [
          {
            primary      = -1
            encapsulated = null
          }
        ]
        icmp_code = [
          {
            primary      = -1
            encapsulated = null
          }
        ]
      }
      discrete_equivalents = {
        egress = []
        allow  = []
        protocol = [
          {
            primary      = 1
            alternatives = ["icmp"]
          }
        ]
        icmp_type = [
          {
            primary      = -1
            alternatives = ["all"]
          }
        ]
        icmp_code = [
          {
            primary      = -1
            alternatives = ["all"]
          }
        ]
      }
      base2_align_range_keys = [
        "ipv4"
      ]
      rules = [
        {
          ranges = {
            ipv4 = {
              from_inclusive = 0
              to_inclusive   = 4294967295
            }
          }
          discretes = {
            egress    = false
            allow     = true
            protocol  = "icmp"
            icmp_type = null
            icmp_code = null
          }
          metadata = {
            id = 1
          }
        },
        {
          ranges = {
            ipv4 = {
              from_inclusive = 0
              to_inclusive   = 4294967295
            }
            test = {
              from_inclusive = 1
              to_inclusive = 2
            }
          }
          discretes = {
            egress    = false
            allow     = true
            protocol  = "1"
            icmp_type = 8
            icmp_code = 0
          }
          metadata = {
            id = 2
          }
        },
      ]
    }
  }
}

output "module" {
  value = module.merge_rules
}
