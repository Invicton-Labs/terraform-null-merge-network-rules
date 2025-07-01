###############################################################################
# 01 ‑ Empty rule_sets map ‑> empty output                                     #
###############################################################################
run "empty_rule_sets" {
  command = plan
  module { source = "./" }
  variables { rule_sets = {} }

  assert {
    condition     = length(keys(output.squashed_rule_sets)) == 0
    error_message = "Expected empty map, got ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 02 ‑ Empty list inside a set ‑> present but empty                             #
###############################################################################
run "empty_rule_list" {
  command = plan
  module { source = "./" }
  variables { rule_sets = { "set-0" = [] } }

  assert {
    condition     = jsonencode(output.squashed_rule_sets) == jsonencode({ "set-0" = [] })
    error_message = "Unexpected non‑empty list: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 03 ‑ Ten identical rules collapse to one (metadata & contains_rules length)  #
###############################################################################
run "large_duplicate_collapse" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [for i in range(10) : {
        egress      = false
        rule_action = "allow"
        protocol    = "tcp"
        cidr_block  = "10.0.0.0/16"
        from_port   = 80
        to_port     = null
        metadata    = { id = i }
      }]
    }
  }

  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1 && length(output.squashed_rule_sets["set-0"][0].contains_rules) == 10
    error_message = "Duplicate rules did not collapse: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 04 ‑ Four contiguous port ranges merge to 1000‑4999                           #
###############################################################################
run "port_range_contiguous" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        for r in [1000, 2000, 3000, 4000] : {
          egress      = true
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "0.0.0.0/0"
          from_port   = r
          to_port     = r + 999
          metadata    = { base = r }
        }
      ]
    }
  }

  assert {
    condition     = output.squashed_rule_sets["set-0"][0].from_port == 1000 && output.squashed_rule_sets["set-0"][0].to_port == 4999
    error_message = "Port ranges not merged as expected: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 05 ‑ Two /24s merge into /23                                                  #
###############################################################################
run "cidr_supernet_23" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = "udp"
          cidr_block  = "192.168.0.0/24"
          from_port   = 53
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = 17
          cidr_block  = "192.168.1.0/24"
          from_port   = 53
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition     = output.squashed_rule_sets["set-0"][0].cidr_block == "192.168.0.0/23"
    error_message = "CIDRs not super‑netted: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 06 ‑ Non‑contiguous /24s stay separate                                        #
###############################################################################
run "cidr_gap_no_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "192.168.0.0/24"
          from_port   = 22
          to_port     = null
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "192.168.2.0/24" # gap at .1.0/24
          from_port   = 22
          to_port     = null
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "Unexpected merge across CIDR gap: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 07 ‑ Port gap prevents merge                                                  #
###############################################################################
run "port_gap_no_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        {
          egress      = false
          rule_action = "allow"
          protocol    = 6
          cidr_block  = "10.0.0.0/16"
          from_port   = 1000
          to_port     = 1500
          metadata    = { id = 1 }
        },
        {
          egress      = false
          rule_action = "allow"
          protocol    = "tcp"
          cidr_block  = "10.0.0.0/16"
          from_port   = 1502
          to_port     = 2000
          metadata    = { id = 2 }
        },
      ]
    }
  }

  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "Port ranges with gap were merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 08 ‑ UDP vs TCP not merged                                                    #
###############################################################################
run "udp_vs_tcp" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 53, to_port = 53, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = "udp", cidr_block = "10.0.0.0/16", from_port = 53, to_port = 53, metadata = { id = 2 } },
      ]
    }
  }

  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "Different protocols were incorrectly merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 09 ‑ Ingress vs Egress stays separate                                         #
###############################################################################
run "direction_partition" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "0.0.0.0/0", from_port = 443, to_port = 443, metadata = { id = 1 } },
        { egress = true, rule_action = "allow", protocol = "tcp", cidr_block = "0.0.0.0/0", from_port = 443, to_port = 443, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "Ingress/Egress rules merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 10 ‑ Allow vs Deny separate                                                  #
###############################################################################
run "allow_deny_separate" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "10.0.0.0/16", from_port = 22, to_port = null, metadata = { id = 1 } },
        { egress = false, rule_action = "deny", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 22, to_port = null, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "Allow/Deny incorrectly merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 11 ‑ ICMP any vs specific not merged                                          #
###############################################################################
run "icmp_any_vs_specific" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "icmp", cidr_block = "0.0.0.0/0", icmp_type = null, icmp_code = null, from_port = null, to_port = null, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = 1, cidr_block = "0.0.0.0/0", icmp_type = 8, icmp_code = 0, from_port = null, to_port = null, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "ICMP any merged with specific: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 12 ‑ ICMP same type different code not merged                                 #
###############################################################################
run "icmp_type_diff_code" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = 1, cidr_block = "0.0.0.0/0", icmp_type = 3, icmp_code = 0, from_port = null, to_port = null, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = "icmp", cidr_block = "0.0.0.0/0", icmp_type = 3, icmp_code = 1, from_port = null, to_port = null, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 2
    error_message = "ICMP diff code merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 13 ‑ Two independent sets identical rule                                     #
###############################################################################
run "two_sets_identical_rule" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      A = [{ egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.10.0.0/16", from_port = 443, to_port = 443, metadata = { id = 1 } }],
      B = [{ egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.10.0.0/16", from_port = 443, to_port = 443, metadata = { id = 2 } }],
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["A"]) == 1 && length(output.squashed_rule_sets["B"]) == 1
    error_message = "Cross‑set merge occurred: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 14 ‑ Small vs big set collapse lengths                                        #
###############################################################################
run "set_size_variation" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      small = [{ egress = false, rule_action = "allow", protocol = 6, cidr_block = "192.0.2.0/24", from_port = 22, to_port = null, metadata = { id = 1 } }],
      big   = [for i in range(5) : { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "192.0.2.0/24", from_port = 22, to_port = null, metadata = { id = i } }],
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["small"]) == 1 && length(output.squashed_rule_sets["big"]) == 1
    error_message = "Unexpected lengths: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 15 ‑ Metadata aggregation count                                               #
###############################################################################
run "metadata_aggregation" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 443, to_port = 443, metadata = { tag = "one" } },
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "10.0.0.0/16", from_port = 443, to_port = 443, metadata = { tag = "two" } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"][0].metadata) == 2
    error_message = "Metadata not preserved: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 16 ‑ contains_rules indexing                                                  #
###############################################################################
run "contains_rules_indexes" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [for i in range(3) : { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 80, to_port = null, metadata = { i = i } }]
    }
  }
  assert {
    condition     = output.squashed_rule_sets["set-0"][0].contains_rules == [0, 1, 2]
    error_message = "contains_rules wrong: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 17 ‑ Protocol case insensitivity                                              #
###############################################################################
run "protocol_case" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "TCP", cidr_block = "10.0.0.0/16", from_port = 25, to_port = 25, metadata = { case = "upper" } },
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 25, to_port = 25, metadata = { case = "lower" } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1
    error_message = "Protocol case caused split: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 18 ‑ From/To null vs zero merges                                              #
###############################################################################
run "null_vs_zero_port" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "10.0.0.0/16", from_port = null, to_port = null, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 0, to_port = 0, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1
    error_message = "Null vs zero treated differently: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 19 ‑ to_port null vs equal merges                                             #
###############################################################################
run "null_vs_equal_to_port" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 8080, to_port = null, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "10.0.0.0/16", from_port = 8080, to_port = 8080, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1
    error_message = "Null vs equal to_port split: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 20 ‑ Ten sets with duplicates each collapse independently                     #
###############################################################################
run "ten_sets_independent" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = { for idx in range(10) : "set-${idx}" => [
      for dup in range(3) : {
        egress      = false
        rule_action = "allow"
        protocol    = "tcp"
        cidr_block  = "172.${idx}.0.0/16"
        from_port   = 22
        to_port     = null
        metadata    = { dup = dup }
      }
    ] }
  }
  assert {
    condition     = length(keys(output.squashed_rule_sets)) == 10 && alltrue([for k, v in output.squashed_rule_sets : length(v) == 1])
    error_message = "Ten‑set isolation failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 21 ‑ Wide port range supersedes narrow one, collapses to superset             #
###############################################################################
run "wide_port_superset" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = true, rule_action = "allow", protocol = 6, cidr_block = "0.0.0.0/0", from_port = 0, to_port = 65535, metadata = { id = "wide" } },
        { egress = true, rule_action = "allow", protocol = "tcp", cidr_block = "0.0.0.0/0", from_port = 22, to_port = 22, metadata = { id = "narrow" } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1 && output.squashed_rule_sets["set-0"][0].from_port == 0 && output.squashed_rule_sets["set-0"][0].to_port == 65535
    error_message = "Wide/narrow not collapsed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 22 ‑ Super‑net 0.0.0.0/0 absorbs 0.0.0.0/1                                    #
###############################################################################
run "cidr_superset_zero" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "0.0.0.0/0", from_port = 80, to_port = 80, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "0.0.0.0/1", from_port = 80, to_port = 80, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1 && output.squashed_rule_sets["set-0"][0].cidr_block == "0.0.0.0/0"
    error_message = "CIDR superset failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 23 ‑ Overlapping port ranges collapse                                         #
###############################################################################
run "port_overlap" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = true, rule_action = "allow", protocol = 6, cidr_block = "10.0.0.0/16", from_port = 10, to_port = 20, metadata = { id = 1 } },
        { egress = true, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 15, to_port = 25, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = output.squashed_rule_sets["set-0"][0].from_port == 10 && output.squashed_rule_sets["set-0"][0].to_port == 25
    error_message = "Overlap not merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 24 ‑ Overlapping CIDR (subset) collapses                                      #
###############################################################################
run "cidr_subset" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = 6, cidr_block = "192.168.0.0/24", from_port = 80, to_port = 80, metadata = { id = 1 } },
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "192.168.0.128/25", from_port = 80, to_port = 80, metadata = { id = 2 } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 1 && output.squashed_rule_sets["set-0"][0].cidr_block == "192.168.0.0/24"
    error_message = "Subset CIDR not collapsed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 25 ‑ Three distinct protocols → three rules                                   #
###############################################################################
run "three_protocols" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [
        { egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.0.0.0/16", from_port = 22, to_port = 22, metadata = { id = "tcp" } },
        { egress = false, rule_action = "allow", protocol = "udp", cidr_block = "10.0.0.0/16", from_port = 22, to_port = 22, metadata = { id = "udp" } },
        { egress = false, rule_action = "allow", protocol = "icmp", cidr_block = "10.0.0.0/16", icmp_type = 8, icmp_code = 0, from_port = null, to_port = null, metadata = { id = "icmp" } },
      ]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 3
    error_message = "Protocols incorrectly merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 26 ‑ Non‑merging random ports produce 10 outputs                              #
###############################################################################
run "random_ports_no_merge" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      "set-0" = [for p in [22, 80, 123, 161, 389, 443, 465, 587, 993, 3389] : {
        egress = false, rule_action = "allow", protocol = "tcp", cidr_block = "10.1.0.0/16", from_port = p, to_port = p, metadata = { p = p }
      }]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["set-0"]) == 10
    error_message = "Random single ports collapsed: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 27 ‑ Mixed direction & action across sets                                     #
###############################################################################
run "mixed_direction_action_sets" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      IN_ALLOW = [{ egress = false, rule_action = "allow", protocol = 6, cidr_block = "0.0.0.0/0", from_port = 8080, to_port = 8080, metadata = { id = 1 } }],
      OUT_DENY = [{ egress = true, rule_action = "deny", protocol = "tcp", cidr_block = "0.0.0.0/0", from_port = 8080, to_port = 8080, metadata = { id = 2 } }],
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["IN_ALLOW"]) == 1 && length(output.squashed_rule_sets["OUT_DENY"]) == 1
    error_message = "Direction/action mis‑grouped: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 28 ‑ Duplicate ICMP echo across three sets independent                        #
###############################################################################
run "icmp_echo_three_sets" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      S1 = [{ egress = false, rule_action = "allow", protocol = "icmp", cidr_block = "0.0.0.0/0", icmp_type = 8, icmp_code = 0, from_port = null, to_port = null, metadata = { s = 1 } }],
      S2 = [{ egress = false, rule_action = "allow", protocol = "icmp", cidr_block = "0.0.0.0/0", icmp_type = 8, icmp_code = 0, from_port = null, to_port = null, metadata = { s = 2 } }],
      S3 = [{ egress = false, rule_action = "allow", protocol = 1, cidr_block = "0.0.0.0/0", icmp_type = 8, icmp_code = 0, from_port = null, to_port = null, metadata = { s = 3 } }],
    }
  }
  assert {
    condition     = alltrue([for k, v in output.squashed_rule_sets : length(v) == 1]) && length(keys(output.squashed_rule_sets)) == 3
    error_message = "ICMP sets merged: ${jsonencode(output.squashed_rule_sets)}"
  }
}

###############################################################################
# 29 ‑ Huge list (100 rules) collapse to one                                    #
###############################################################################
run "hundred_rules_collapse" {
  command = plan
  module { source = "./" }
  variables {
    rule_sets = {
      huge = [for i in range(100) : {
        egress      = false
        rule_action = "allow"
        protocol    = "tcp"
        cidr_block  = "198.51.100.0/24"
        from_port   = 8080
        to_port     = 8080
        metadata    = { i = i }
      }]
    }
  }
  assert {
    condition     = length(output.squashed_rule_sets["huge"]) == 1 && length(output.squashed_rule_sets["huge"][0].contains_rules) == 100
    error_message = "100‑rule collapse failed: ${jsonencode(output.squashed_rule_sets)}"
  }
}
