run "simple" {
  command = plan
  module {
    source = "./"
  }
  variables {
    egress = true
    rule_sets = [

      // The first rule set denies access to highly sensitive internal subnets.
      // These two will get squashed to rule #1, since the CIDRs are contiguous
      // and the protocols and ports are the same.
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

      // The second rule set allows access to internal networks.
      // These two will get squashed to rule #2, since the CIDRs are contiguous
      // and the protocols and ports are the same.
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

      // The third rule set blocks all public egress. 
      // No squashing here since there's only one rule,
      // and it will be rule #3.
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
  assert {
    // We have to compare with jsonencode, because the result has "dynamic" type
    // fields, while the expected value has fixed type fields.
    condition = jsonencode(output.squashed_rules) == jsonencode([
      {
        rule_number = 1
        egress      = true
        rule_action = "deny"
        protocol    = 6
        cidr_block  = "10.0.2.0/23"
        from_port   = 22
        to_port     = 22
        icmp_code   = null
        icmp_type   = null
        // This contains the two rules in the first rule set
        contains_rules = [
          0,
          1,
        ]
        metadata = [
          {
            id = 1
          },
          {
            id = 2
          },
        ]
      },
      {
        rule_number = 2
        egress      = true
        rule_action = "allow"
        protocol    = 6
        cidr_block  = "10.0.0.0/15"
        from_port   = 22
        to_port     = 22
        icmp_code   = null
        icmp_type   = null
        // This contains the two rules in the first rule set
        contains_rules = [
          0,
          1,
        ]
        metadata = [
          {
            id = 3
          },
          {
            id = 4
          },
        ]
      },
      {
        rule_number = 3
        egress      = true
        rule_action = "deny"
        protocol    = -1
        cidr_block  = "0.0.0.0/0"
        from_port   = null
        to_port     = null
        icmp_code   = null
        icmp_type   = null
        // This contains the two rules in the first rule set
        contains_rules = [
          0,
        ]
        metadata = [
          {
            id = 5
          },
        ]
      },
    ])
    error_message = "Unexpected output: ${jsonencode(output.squashed_rules)}"
  }
}
