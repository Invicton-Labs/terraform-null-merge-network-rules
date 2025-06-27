module "squash" {
  source = "../"
  rule_sets = {
    set-0 = [
        {
            egress     = false
            allow      = true
            protocol   = "tcp"
            cidr_block = "10.1.0.0/16"
            from_port  = 10
            to_port    = null
            metadata = {
            id = 1
            }
        },
        {
            egress     = false
            allow      = true
            protocol   = "tcp"
            cidr_block = "10.2.0.0/16"
            from_port  = 12
            to_port    = null
            metadata = {
            id = 2
            }
        },
        {
            egress     = false
            allow      = true
            protocol   = "tcp"
            cidr_block = "10.3.0.0/16"
            from_port  = 12
            to_port    = null
            metadata = {
            id = 3
            }
        },
        {
            egress     = false
            allow      = true
            protocol   = "tcp"
            cidr_block = "10.3.128.0/17"
            from_port  = 16
            to_port    = null
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
