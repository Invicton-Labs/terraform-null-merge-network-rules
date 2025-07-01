locals {
  // Use a UUID for the range key that represents the CIDR block,
  // so we don't accidentally overwrite a range key the user provided
  cidr_range_key = "f72898f3-1f01-4d7d-96d9-6e151249bc84"

  // Conver the CIDRs to IP ranges in decimal format
  with_cidr_ranges = {
    for group_key, group in var.rule_sets :
    group_key => merge(group, {
      // Flag that the CIDR range key should be base2 aligned
      base2_align_range_keys = [
        local.cidr_range_key,
      ]
      discrete_encapsulation = merge(group.discrete_encapsulation, {
        (local.cidr_range_key) = []
      })
      discrete_equivalents = merge(group.discrete_equivalents, {
        (local.cidr_range_key) = []
      })
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
  source    = "../generic-squash"
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
        merge(concat([rule], lookup(rule.ranges, local.cidr_range_key, null) == null ? [] : [{
          ranges = {
            for range_key, range_value in rule.ranges :
            range_key => range_value
            // Strip out the range key that was used as the placeholder for IPv4
            if range_key != local.cidr_range_key
          }
          // Convert the starting IP back to a specific IP, then add the prefix based on the size of the ranges
          cidr_ipv4 = "${cidrhost("0.0.0.0/0", rule.ranges[local.cidr_range_key].from_inclusive)}/${32 - log(rule.ranges[local.cidr_range_key].to_inclusive - rule.ranges[local.cidr_range_key].from_inclusive + 1, 2)}"
        }])...)
      ])
    })
  }
}
