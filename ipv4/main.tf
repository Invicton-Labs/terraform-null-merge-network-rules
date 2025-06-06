locals {
  // Use a UUID for the range key that represents the CIDR block,
  // so we don't accidentally overwrite a range key the user provided
  cidr_range_key = uuid()

  // Conver the CIDRs to IP ranges in decimal format
  with_cidr_ranges = {
    for group_key, group in var.rule_sets :
    group_key => merge(group, {
      rules = [
        for rule in group.rules :
        // If there's no CIDR block, just use the base rule
        rule.cidr_ipv4 == null ? rule : merge(rule, {
          // But if there IS a CIDR block, add it as a range
          ranges = merge(rule.ranges, {
            (local.cidr_range_key) = {
              // This looks complicated, but that's just because there are a lot of nested functions for splitting strings.
              // We're just splitting the CIDR block by octets and bit shifting them.

              // Lower bound is the first IP address in the block
              from_inclusive = pow(2, 24) * tonumber(split(".", cidrhost(rule.cidr_ipv4, 0))[0]) + pow(2, 16) * tonumber(split(".", cidrhost(rule.cidr_ipv4, 0))[1]) + pow(2, 8) * tonumber(split(".", cidrhost(rule.cidr_ipv4, 0))[2]) + tonumber(split(".", cidrhost(rule.cidr_ipv4, 0))[3])

              // Upper bound is the last IP address in the block
              to_inclusive = pow(2, 24) * tonumber(split(".", cidrhost(rule.cidr_ipv4, pow(2, 32 - tonumber(split("/", rule.cidr_ipv4)[1])) - 1))[0]) + pow(2, 16) * tonumber(split(".", cidrhost(rule.cidr_ipv4, pow(2, 32 - tonumber(split("/", rule.cidr_ipv4)[1])) - 1))[1]) + pow(2, 8) * tonumber(split(".", cidrhost(rule.cidr_ipv4, pow(2, 32 - tonumber(split("/", rule.cidr_ipv4)[1])) - 1))[2]) + tonumber(split(".", cidrhost(rule.cidr_ipv4, pow(2, 32 - tonumber(split("/", rule.cidr_ipv4)[1])) - 1))[3])
            }
          })
        })
      ]
    })
  }
}

// Now that we've converted the CIDR to a decimal range,
// squash the rules as we normally would.
module "rule_squash" {
  source    = "../rule-squash"
  rule_sets = local.with_cidr_ranges
}

locals {
  // Convert back from decimal ranges to CIDRs
  with_cidr_prefix = {
    for group_key, group in module.rule_squash.squashed_rule_sets :
    group_key => merge(group, {
      rules = flatten([
        for rule in group.rules :
        // If this squashed rule doesn't have the CIDR range key, just use the squashed rule as-is
        lookup(rule.ranges[local.local.cidr_range_key], null) == null ? rule : (
          // Otherwise, we have to split the result into the minimum number of valid CIDRs
          [
            // TODO
          ]
        )
      ])
    })
  }
}
