module "squash" {
  source = "../"
  egress = true
  rule_sets = [

    // The first rule set denies access to highly sensitive internal subnets
    {
      rule_action = "deny"
      rules = [
        {
          protocol   = "tcp"
          cidr_block = "10.0.2.0/24"
          from_port  = 22
          to_port    = 22
          metadata = {
            id = 1
          }
        },
        {
          protocol   = "tcp"
          cidr_block = "10.0.3.0/24"
          from_port  = 22
          to_port    = 22
          metadata = {
            id = 2
          }
        }
      ]
    },

    // The second rule set allows access to internal networks
    {
      rule_action = "allow"
      rules = [
        {
          protocol   = "tcp"
          cidr_block = "10.0.0.0/16"
          from_port  = 22
          to_port    = 22
          metadata = {
            id = 3
          }
        },
        {
          protocol   = "tcp"
          cidr_block = "10.1.0.0/16"
          from_port  = 22
          to_port    = 22
          metadata = {
            id = 4
          }
        }
      ]
    },

    // The third rule set blocks all public egress
    {
      rule_action = "deny"
      rules = [
        {
          protocol   = -1
          cidr_block = "0.0.0.0/0"
          metadata = {
            id = 5
          }
        },
      ]
    },
  ]
}

output "module" {
  value = module.squash
}
