run "simple" {
  command = plan
  module {
    source = "../"
  }
  variables {
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
  assert {
    // We have to compare with jsonencode, because there is some odd typing issues
    // that cause a direct object comparison to fail with "different types"
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
            egress     = false
            allow      = true
            protocol   = 6
            cidr_block = "10.1.0.0/16"
            from_port  = 10
            to_port    = null
            icmp_code = null
            icmp_type = null
            metadata = [
                {
                    id = 1
                }
            ]
        },
        {
            egress     = false
            allow      = true
            protocol   = 6
            cidr_block = "10.2.0.0/15"
            from_port  = 12
            to_port    = null
            icmp_code = null
            icmp_type = null
            metadata = [
                {
                    id = 2
                },
                {
                    id = 3
                },
                {
                    id = 4
                },
            ]
        },
      ]
    })
    error_message = "Unexpected output: ${jsonencode(output.squashed_rule_sets)}"
  }
}