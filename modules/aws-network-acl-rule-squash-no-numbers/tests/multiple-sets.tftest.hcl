###############################################################################
# 1. Two sets: one needs merging, the other does not
###############################################################################
run "two_sets_independent" {
  command = plan
  module { source = "./" }

  variables {
    rule_sets = {
      # ── set-0: should collapse from 2 → 1 rule ────────────────────────────────
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

      # ── set-1: already minimal; should stay as-is ─────────────────────────────
      set-1 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "192.168.0.0/24"
          from_port   = 22
          to_port     = null
          metadata    = { id = 3 }
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

      set-1 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "192.168.0.0/24"
          from_port      = 22
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 3 }]
        },
      ]
    })
    error_message = "two_sets_independent failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 2. Identical rules in two different sets MUST NOT be coalesced together
###############################################################################
run "identical_rules_separate_sets" {
  command = plan
  module { source = "./" }

  variables {
    rule_sets = {
      set-0 = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.10.0.0/16"
          from_port   = 443
          to_port     = 443
          metadata    = { id = 1 }
        },
      ]

      set-1 = [
        # Exact same rule, but a **different set** – must remain separate
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.10.0.0/16"
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
          cidr_block     = "10.10.0.0/16"
          from_port      = 443
          to_port        = 443
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 1 }]
        },
      ]

      set-1 = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "10.10.0.0/16"
          from_port      = 443
          to_port        = 443
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0]
          metadata       = [{ id = 2 }]
        },
      ]
    })
    error_message = "identical_rules_separate_sets failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 3. Three sets, each exercising different merge logic simultaneously
###############################################################################
run "three_sets_mixed_logic" {
  command = plan
  module { source = "./" }

  variables {
    rule_sets = {
      # ── set-A: CIDR super-net merge ───────────────────────────────────────────
      A = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "udp"
          cidr_block  = "172.16.0.0/16"
          from_port   = 53
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 17
          cidr_block  = "172.17.0.0/16"
          from_port   = 53
          to_port     = null
          metadata    = { id = 2 }
        },
      ]

      # ── set-B: port-range coalesce ────────────────────────────────────────────
      B = [
        {
          egress      = true
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "0.0.0.0/0"
          from_port   = 1000
          to_port     = 1999
          metadata    = { id = 3 }
        },
        {
          egress      = true
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "0.0.0.0/0"
          from_port   = 2000
          to_port     = 2000
          metadata    = { id = 4 }
        },
      ]

      # ── set-C: single ICMP rule (nothing to merge) ───────────────────────────
      C = [
        {
          egress      = false
          rule_action = "deny"
          protocol    = "icmp"
          cidr_block  = "0.0.0.0/0"
          icmp_type   = 3
          icmp_code   = 0
          from_port   = null
          to_port     = null
          metadata    = { id = 5 }
        },
      ]
    }
  }

  assert {
    condition = jsonencode(output.squashed_rule_sets) == jsonencode({
      # Merged /15 for UDP 53
      A = [
        {
          egress         = false
          rule_action    = "allow"
          protocol       = 17
          cidr_block     = "172.16.0.0/15"
          from_port      = 53
          to_port        = null
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0, 1]
          metadata       = [{ id = 1 }, { id = 2 }]
        },
      ]

      # Merged 1000-2000 TCP range
      B = [
        {
          egress         = true
          rule_action    = "allow"
          protocol       = 6
          cidr_block     = "0.0.0.0/0"
          from_port      = 1000
          to_port        = 2000
          icmp_code      = null
          icmp_type      = null
          contains_rules = [0, 1]
          metadata       = [{ id = 3 }, { id = 4 }]
        },
      ]

      # Unchanged ICMP deny rule
      C = [
        {
          egress         = false
          rule_action    = "deny"
          protocol       = 1
          cidr_block     = "0.0.0.0/0"
          icmp_type      = 3
          icmp_code      = 0
          from_port      = null
          to_port        = null
          contains_rules = [0]
          metadata       = [{ id = 5 }]
        },
      ]
    })
    error_message = "three_sets_mixed_logic failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}
