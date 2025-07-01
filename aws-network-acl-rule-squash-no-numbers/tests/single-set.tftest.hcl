run "simple" {
  command = plan
  module {
    source = "./"
  }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.1.0.0/16"
          from_port   = 10
          to_port     = null
          metadata = {
            id = 1
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.2.0.0/16"
          from_port   = 12
          to_port     = null
          metadata = {
            id = 2
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.3.0.0/16"
          from_port   = 12
          to_port     = null
          metadata = {
            id = 3
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.3.128.0/17"
          from_port   = 16
          to_port     = null
          metadata = {
            id = 4
          }
        },
      ]
    }
  }
  assert {
    // We have to compare with jsonencode, because the result has "dynamic" type
    // fields, while the expected value has fixed type fields.
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.1.0.0/16"
          from_port   = 10
          to_port     = null
          icmp_code   = null
          icmp_type   = null
          contains_rules = [
            0
          ]
          metadata = [
            {
              id = 1
            }
          ]
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.2.0.0/15"
          from_port   = 12
          to_port     = null
          icmp_code   = null
          icmp_type   = null
          contains_rules = [
            1,
            2,
            3,
          ]
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

run "port_merge" {
  command = plan
  module {
    source = "./"
  }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.1.0.0/16"
          from_port   = 10
          to_port     = 20
          metadata = {
            id = 1
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.1.0.0/16"
          from_port   = 21
          to_port     = 30
          metadata = {
            id = 2
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.1.0.0/16"
          from_port   = 15
          to_port     = 28
          metadata = {
            id = 3
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = null
          to_port     = null
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
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.1.0.0/16"
          from_port   = 10
          to_port     = 30
          icmp_code   = null
          icmp_type   = null
          contains_rules = [
            0,
            1,
            2
          ]
          metadata = [
            {
              id = 1
            },
            {
              id = 2
            },
            {
              id = 3
            }
          ]
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.0.0.0/16"
          from_port   = null
          to_port     = null
          icmp_code   = null
          icmp_type   = null
          contains_rules = [
            3
          ]
          metadata = [
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


run "icmp_merge" {
  command = plan
  module {
    source = "./"
  }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "icmp"
          cidr_block  = "10.0.0.0/16"
          icmp_type   = -1
          icmp_code   = -1
          metadata = {
            id = 1
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "icmp"
          cidr_block  = "10.1.0.0/16"
          icmp_type   = -1
          icmp_code   = -1
          metadata = {
            id = 2
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 1
          cidr_block  = "10.2.0.0/16"
          icmp_type   = -1
          icmp_code   = -1
          metadata = {
            id = 3
          }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 1
          cidr_block  = "10.3.0.0/16"
          icmp_type   = -1
          icmp_code   = -1
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
          egress      = false
          rule_action = "allow"
          protocol    = 1
          cidr_block  = "10.0.0.0/14"
          from_port   = null
          to_port     = null
          icmp_code   = -1
          icmp_type   = -1
          contains_rules = [
            0,
            1,
            2,
            3,
          ]
          metadata = [
            {
              id = 1
            },
            {
              id = 2
            },
            {
              id = 3
            },
            {
              id = 4
            }
          ]
        },
      ]
    })
    error_message = "Unexpected output: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 1. Protocol name ⇒ number normalisation & duplicate collapse
###############################################################################
run "protocol_normalisation" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp" # name form
          cidr_block  = "10.0.0.0/16"
          from_port   = 80
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6 # numeric form
          cidr_block  = "10.0.0.0/16"
          from_port   = 80
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 80
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0, 1]
          metadata       = [{ id = 1 }, { id = 2 }]
        },
      ]
    })
    error_message = "protocol_normalisation failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 2. Protocol mismatch ⇒ do NOT merge
###############################################################################
run "protocol_mismatch" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 53
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "udp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 53
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 53
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 1 }]
        },
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 17
          cidr_block     = "10.0.0.0/16"
          from_port      = 53
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [1]
          metadata       = [{ id = 2 }]
        },
      ]
    })
    error_message = "protocol_mismatch failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 3. Contiguous CIDRs ⇒ super-net merge
###############################################################################
run "cidr_contiguous_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 22
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.1.0.0/16" # immediately adjacent
          from_port   = 22
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/15" # merged /15
          from_port      = 22
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0, 1]
          metadata       = [{ id = 1 }, { id = 2 }]
        },
      ]
    })
    error_message = "cidr_contiguous_merge failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 4. Non-contiguous CIDRs ⇒ keep separate
###############################################################################
run "cidr_gap_no_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.0.0.0/16"
          from_port   = 22
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.2.0.0/16" # 10.1.0.0/16 gap prevents super-net
          from_port   = 22
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 22
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 1 }]
        },
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.2.0.0/16"
          from_port      = 22
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [1]
          metadata       = [{ id = 2 }]
        },
      ]
    })
    error_message = "cidr_gap_no_merge failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 5. Adjacent port ranges ⇒ merge
###############################################################################
run "port_adjacent_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.0.0.0/16"
          from_port   = 100
          to_port     = 199
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 200
          to_port     = 300
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 100
          to_port        = 300 # merged 100-300
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0, 1]
          metadata       = [{ id = 1 }, { id = 2 }]
        },
      ]
    })
    error_message = "port_adjacent_merge failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 6. Port-gap ⇒ keep separate
###############################################################################
run "port_gap_no_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.0.0.0/16"
          from_port   = 100
          to_port     = 199
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 201 # 200 is the gap
          to_port     = 300
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 100
          to_port        = 199
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 1 }]
        },
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 201
          to_port        = 300
          icmp_code      = null
          icmp_type      = null
          contains_rules = [1]
          metadata       = [{ id = 2 }]
        },
      ]
    })
    error_message = "port_gap_no_merge failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 7. Egress TRUE vs FALSE ⇒ separate
###############################################################################
run "egress_partition" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "0.0.0.0/0"
          from_port   = 443
          to_port     = 443
          metadata    = { id = 1 }
        },
        {
          egress      = true # <-- different direction
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "0.0.0.0/0"
          from_port   = 443
          to_port     = 443
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "0.0.0.0/0"
          from_port      = 443
          to_port        = 443
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 1 }]
        },
        {
          egress         = true
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "0.0.0.0/0"
          from_port      = 443
          to_port        = 443
          icmp_code      = null
          icmp_type      = null
          contains_rules = [1]
          metadata       = [{ id = 2 }]
        },
      ]
    })
    error_message = "egress_partition failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 8. Allow vs Deny ⇒ separate
###############################################################################
run "allow_vs_deny" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.0.0.0/16"
          from_port   = 22
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "deny" # <-- DENY
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 22
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 22
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 1 }]
        },
        {
          egress         = false
          rule_action    = "deny"
          protocol       = 6
          cidr_block     = "10.0.0.0/16"
          from_port      = 22
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [1]
          metadata       = [{ id = 2 }]
        },
      ]
    })
    error_message = "allow_vs_deny failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 9. ICMP merging: identical type/code merge; different type/code no merge
###############################################################################
run "icmp_type_code" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      set-0 = [
        # Echo request
        {
          egress      = false
          rule_action = "allow"
          protocol    = "icmp"
          cidr_block  = "0.0.0.0/0"
          icmp_type   = 8
          icmp_code   = 0
          from_port   = null
          to_port     = null
          metadata    = { id = 1 }
        },
        # Same rule, numeric protocol
        {
          egress      = false
          rule_action = "allow"
          protocol    = 1
          cidr_block  = "0.0.0.0/0"
          icmp_type   = 8
          icmp_code   = 0
          from_port   = null
          to_port     = null
          metadata    = { id = 2 }
        },
        # Destination-unreachable/host-unreachable
        {
          egress      = false
          rule_action = "allow"
          protocol    = 1
          cidr_block  = "0.0.0.0/0"
          icmp_type   = 3
          icmp_code   = 1
          from_port   = null
          to_port     = null
          metadata    = { id = 3 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      set-0 = [
        # merged echo-request rule
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 1
          cidr_block     = "0.0.0.0/0"
          icmp_type      = 8
          icmp_code      = 0
          from_port      = null
          to_port        = null
          contains_rules = [0, 1]
          metadata       = [{ id = 1 }, { id = 2 }]
        },
        # separate destination-unreachable rule
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 1
          cidr_block     = "0.0.0.0/0"
          icmp_type      = 3
          icmp_code      = 1
          from_port      = null
          to_port        = null
          contains_rules = [2]
          metadata       = [{ id = 3 }]
        },
      ]
    })
    error_message = "icmp_type_code failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}
