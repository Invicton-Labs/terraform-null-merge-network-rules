
locals {
  // Replace any singleton values with their primary equivalency
  equivilencies = {
    for key, group in var.rule_sets :
    key => merge(group, {
      rules = {
        for rule_idx, rule in group.rules :
        rule_idx => merge(rule, {
          singletons = {
            for sk, sv in rule.singletons :
            // Create a list of all equivalent values, and
            // add the current value at the end, then take the first index.
            // This will ensure that if there's an equivalency, it gets used, but
            // if not then the current value is used.
            sk => concat([
              for sek, sev in group.singleton_equivalents[sk] :
              sek
              if contains(sev, sv)
            ], [sv])[0]
          }
        })
      }
    })
  }

  with_encapsulations = {
    for key, group in local.equivilencies :
    key => merge(group, {
      rules = {
        for rule_idx, rule in group.rules :
        rule_idx => merge(rule, {
          contains = {
            for compare_idx, compare in group.rules :
            compare_idx => compare
            if compare_idx == rule_idx ? false : 0 == length(concat(
              [
                // This will be a list of all range rules that are violated
                for range_key, range_value in rule.ranges :
                true
                // It violates this range rule if it has a start port below the compare from port, or a to port above the compare to port
                if(
                  // First test the lower bound
                  // If the rule doesn't have one, that's not a violation
                  // Otherwise, if the compare doesn't have one, that's definitely a violation
                  // Otherwise, if the rule has a higher lower bound, that's a violation
                  range_value.from_inclusive == null ? false : compare.ranges[range_key].from_inclusive == null ? true : range_value.from_inclusive > compare.ranges[range_key].from_inclusive
                  ) ? true : (
                  // Now test the upper bound
                  // If the rule doesn't have one, that's not a violation
                  // Otherwise, if the compare doesn't have one, that's definitely a violation
                  // Otherwise, if the rule has a lower upper bound, that's a violation
                  range_value.to_inclusive == null ? false : compare.ranges[range_key].to_inclusive == null ? true : range_value.to_inclusive < compare.ranges[range_key].to_inclusive
                )
              ],
              [
                // This will be a list of all singleton rules that are violated
                for singleton_key, singleton_value in rule.singletons :
                true
                // If the value is equal, it matches so that's fine
                // If it's not equal, we have to check if this rule's value encapsulates the compare rule's singleton value
                if singleton_value == compare.singletons[singleton_key] ? false : !contains(lookup(group.singleton_encapsulation[singleton_key], rule.singletons[singleton_key], []), compare.singletons[singleton_key])
              ]
            ))
          }
        })
      }
    })
  }

  // Do a forward pass to remove any rules that are encapsulated in a later rule.
  // We do this in two steps (forward, then reverse) so two equal rules don't
  // remove each other.
  forward_pass_merge = {
    for key, group in local.with_encapsulations :
    key => merge(group, {
      rules = {
        for rule_idx, rule in group.rules :
        rule_idx => rule
        if 0 == length([
          for compare_idx in keys(group.rules) :
          true
          if compare_idx > rule_idx && contains(keys(group.rules[compare_idx].contains), rule_idx)
        ])
      }
    })
  }

  // Do a reverse pass to remove any rules that are encapsulated in a previous rule.
  reverse_pass_merge = {
    for key, group in local.forward_pass_merge :
    key => merge(group, {
      rules = {
        for rule_idx, rule in group.rules :
        rule_idx => rule
        if 0 == length([
          for compare_idx in keys(group.rules) :
          true
          if compare_idx < rule_idx && contains(keys(group.rules[compare_idx].contains), rule_idx)
        ])
      }
    })
  }

  // Now clean it up for the final output format
  merged_rule_sets = {
    for key, group in local.reverse_pass_merge :
    key => merge(group, {
      rules = [
        for rule in values(group.rules) :
        merge(rule, {
          contains = values(rule.contains)
        })
      ]
    })
  }

  // TODO: merge rules where ranges are all contiguous
}
