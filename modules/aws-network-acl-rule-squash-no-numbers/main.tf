
locals {
  // Discrete encapsulations and equivalencies are found here:
  // https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html
  discrete_encapsulation = {
    protocol    = local.protocol_encapsulations
    icmp_type   = local.icmp_type_encapsulations
    icmp_code   = local.icmp_code_encapsulations
    egress      = []
    rule_action = []
  }

  discrete_equivalents = {
    // AWS uses IANA protocol numbers
    protocol    = local.iana_protocol_equivalencies
    icmp_type   = []
    icmp_code   = []
    egress      = []
    rule_action = []
  }
}

module "squash_ipv4" {
  source = "../ipv4-squash"
  rule_sets = {
    for group_key, group in var.rule_sets :
    group_key => {
      discrete_encapsulation = local.discrete_encapsulation
      discrete_equivalents   = local.discrete_equivalents
      rules = [
        for rule in group :
        {
          cidr_ipv4 = rule.cidr_block
          discretes = {
            egress      = rule.egress
            rule_action = rule.rule_action
            // Uppercase the protocol so it matches the IANA equivalencies.
            protocol  = upper(tostring(rule.protocol))
            icmp_type = rule.icmp_type
            icmp_code = rule.icmp_code
          }
          ranges = {
            ports = {
              from_inclusive = rule.from_port
              to_inclusive   = rule.to_port
            }
          }
          metadata = rule.metadata
        }
      ]
    }
  }
}

locals {
  squashed = {
    for group_key, group in module.squash_ipv4.squashed_rule_sets :
    group_key => [
      for rule in group.rules :
      {
        egress      = rule.discretes.egress
        rule_action = rule.discretes.rule_action
        // This may have been converted to a string during the equivalency phase
        protocol   = tonumber(rule.discretes.protocol)
        cidr_block = rule.cidr_ipv4
        from_port  = rule.ranges.ports.from_inclusive
        to_port    = rule.ranges.ports.to_inclusive
        // This may have been converted to a string during the equivalency phase
        icmp_type = tonumber(rule.discretes.icmp_type)
        // This may have been converted to a string during the equivalency phase
        icmp_code      = tonumber(rule.discretes.icmp_code)
        metadata       = rule.metadata
        contains_rules = rule.contains_rules
      }
    ]
  }
}
