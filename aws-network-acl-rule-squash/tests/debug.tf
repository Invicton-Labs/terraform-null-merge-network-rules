// This file is just for debugging, so we can output specific debug
// values to figure out what is going on in the insides.
module "squash" {
  source = "../"
  rule_sets = {
    set-0 = [
      {
        egress     = false
        allow      = true
        protocol   = "icmp"
        cidr_block = "10.0.0.0/16"
        icmp_type  = -1
        icmp_code  = -1
        metadata = {
          id = 1
        }
      },
      {
        egress     = false
        allow      = true
        protocol   = "icmp"
        cidr_block = "10.1.0.0/16"
        icmp_type  = -1
        icmp_code  = -1
        metadata = {
          id = 2
        }
      },
      {
        egress     = false
        allow      = true
        protocol   = 1
        cidr_block = "10.2.0.0/16"
        icmp_type  = -1
        icmp_code  = -1
        metadata = {
          id = 3
        }
      },
      {
        egress     = false
        allow      = true
        protocol   = 1
        cidr_block = "10.3.0.0/16"
        icmp_type  = -1
        icmp_code  = -1
        metadata = {
          id = 4
        }
      },
    ]
  }
}

output "module" {
  value = module.squash
}
