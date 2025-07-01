locals {
  // Since the squash module uses a map, we need to get the keys and sort
  // them so we can convert it back to a list of rule sets.
  sorted_rule_set_keys = sort(keys(module.squash.squashed_rule_sets))
  squashed_as_list = [
    for group_key in local.sorted_rule_set_keys :
    module.squash.squashed_rule_sets[group_key]
  ]
  // Sweeten the output with extra fields, like rule numbers
  final_rules = flatten([
    for group_idx, group in local.squashed_as_list :
    [
      for rule_idx, rule in group :
      {
        egress = var.egress
        // Ensure there are no collisions in rule numbers.
        // Always start the numbering from the total count of previous
        // rules, plus 1 for 1-based rule number indexing.
        rule_number = 1 + sum(concat([0], [
          for prev_group_idx in range(0, group_idx) :
          length(local.squashed_as_list[prev_group_idx])
        ])) + rule_idx
        rule_action    = rule.rule_action
        protocol       = rule.protocol
        cidr_block     = rule.cidr_block
        from_port      = rule.from_port
        to_port        = rule.to_port
        icmp_type      = rule.icmp_type
        icmp_code      = rule.icmp_code
        metadata       = rule.metadata
        contains_rules = rule.contains_rules
      }
    ]
  ])
}
