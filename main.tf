locals {
  // Use a UUID for the temporary range key, so it
  // never conflicts with a provided key.
  cidr_ipv4_ranges_key = "78c9ea65-4aa8-4b4e-93ca-6bcbef6eaf25"

  // This adds the first and last IP addresses (in octet format) to each CIDR
  rules_with_cidr_first_last = {
    for key, group in var.rule_sets :
    key => merge(group, {
      rules = [
        for rule in group.rules :
        merge(rule, rule.cidr_ipv4 == null ? {} : {
          cidr_ipv4_data = {
            first_ip = cidrhost(rule.cidr_ipv4, 0)
            last_ip  = cidrhost(rule.cidr_ipv4, pow(2, 32 - tonumber(split("/", rule.cidr_ipv4)[1])) - 1)
          }
        })
      ]
    })
  }

  rules_with_cidr_as_range = {
    for key, group in local.rules_with_cidr_first_last :
    key => merge(group, {
      rules = [
        for rule in group.rules :
        merge(rule, rule.cidr_ipv4 == null ? {} : {
          ranges = merge(rule.ranges, {
            local.cidr_ipv4_ranges_key = {
              from_inclusive = pow(2, 24) * tonumber(split(".", rule.cidr_ipv4_data.first_ip)[0]) + pow(2, 16) * tonumber(split(".", rule.cidr_ipv4_data.first_ip)[1]) + pow(2, 8) * tonumber(split(".", rule.cidr_ipv4_data.first_ip)[2]) + tonumber(split(".", rule.cidr_ipv4_data.first_ip)[3])
              to_inclusive   = pow(2, 24) * tonumber(split(".", rule.cidr_ipv4_data.last_ip)[0]) + pow(2, 16) * tonumber(split(".", rule.cidr_ipv4_data.last_ip)[1]) + pow(2, 8) * tonumber(split(".", rule.cidr_ipv4_data.last_ip)[2]) + tonumber(split(".", rule.cidr_ipv4_data.last_ip)[3])
            }
          })
        })
      ]
    })
  }
}

module "rule_reduce" {
  source    = "./rule-reduce"
  rule_sets = local.rules_with_cidr_as_range
}

locals {
  // TODO: reconstruct CIDR
  reduced_rules = {
    for key, group in module.rule_reduce.merged_rule_sets :
    key => {
      rules = [
        for rule in group.rules :
        {
          ranges = {
            for range_key, range_value in rule.ranges :
            range_key => range_value
            if range_key != local.cidr_ipv4_ranges_key
          }
          singletons = rule.singletons
          metadata = rule.metadata
          cidr_ipv4 = 
        }
      ]
    }
  }
}
