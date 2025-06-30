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
      discrete_encapsulation = {}
      discrete_equivalents   = {}
      base2_align_ranges = [
        "ipv4"
      ]
      rules = [
        {
          ranges = {
            ipv4 = {
              from_inclusive = 167837696
              to_inclusive   = 167903231
            }
          }
          metadata = {
            id = 1
          }
        },
        {
          ranges = {
            ipv4 = {
              from_inclusive = 167903232
              to_inclusive   = 167968767
            }
          }
          metadata = {
            id = 2
          }
        },
        {
          ranges = {
            ipv4 = {
              from_inclusive = 167968768
              to_inclusive   = 168034303
            }
          }
          metadata = {
            id = 3
          }
        },
      ]
    }
  }
}

output "module" {
  value = module.merge_rules
}
