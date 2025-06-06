locals {
  neg_inf     = -999999999999999999999999999999
  pos_inf     = 999999999999999999999999999999
  digit_count = 30
  // STEPS:
  //  1. Sort ascending by "from" value
  //  2. For each rule, check if it's contiguous with the next one
  //  3. Then loop through and count how many rules forward it remains contiguous
  //  4. Then loop through and forward merge

  range_0_with_sort_keys = length(local.range_keys) <= 0 ? {} : {
    for group_key, group in local.reverse_pass_encapsulate :
    group_key => merge(group, {
      rules = [
        for rule_idx, rule in group.rules :
        merge(rule, {
          sort_key = contains(keys(rule.ranges), local.range_keys[group_key][0]) ? "${format("%0${local.digit_count}d", rule.ranges[local.range_keys[group_key][0]].from_inclusive == null ? local.neg_inf : rule.ranges[local.range_keys[group_key][0]].from_inclusive)}-${format("%0${local.digit_count}d", rule.ranges[local.range_keys[group_key][0]].to_inclusive == null ? local.pos_inf : rule.ranges[local.range_keys[group_key][0]].to_inclusive)}-${rule_idx}" : "nokey-${rule_idx}"
        })
      ]
    })
  }

  range_0_sort_keys = length(local.range_keys) <= 0 ? {} : {
    for group_key, group in local.range_0_with_sort_keys :
    group_key => sort([
      for rule in group.rules :
      rule.sort_key
    ])
  }

  range_0_sorted = length(local.range_keys) <= 0 ? {} : {
    for group_key, group in local.range_0_with_sort_keys :
    group_key => merge(group, {
      rules = [
        for sort_key in local.range_0_sort_keys[group_key] :
        [
          for rule in group.rules :
          rule
          if rule.sort_key == sort_key
        ][0]
      ]
    })
  }

  // Determine if a rule is contiguous with the next one
  range_0_next_contiguous = {
    for group_key, group in local.range_0_sorted :
    group_key => merge(group, {
      rules = [
        for rule_idx, rule in group.rules :
        merge(rule, {
          // It's contiguous with the next rule if:
          // - It's not the last rule
          // - The next rule has a "from" that is overlaping with or adjacent to the "to" value of this rule
          // - For every range other than the one being considered, the next rule's value is exactly equal
          // - For every discrete key, the next rule's value is exactly equal
          contiguous_with_next = (
            // Check if it's the last rule.
            // If this index is equal to the last index value, bail out with "false" because it's
            // the last rule and therefore cannot be contiguous with the next rule.
            rule_idx == length(group.rules) - 1 ? false : (
              // Check if the range we're considering is actually contiguous
              // It's contiguous with the next rule if:
              // - Both rules have the key, AND
              //    - This rule's "to" value is greater than or equal to one less than the next rule's "from" value (forward contiguity)

              // This rule doesn't contain the range key we're checking? That means it can't be contiguous.
              !contains(keys(rule.ranges), local.range_keys[group_key][0]) ? false : (
                // The next rule doesn't contain the range key we're checking? That means it can't be contiguous.
                !contains(keys(group.rules[rule_idx + 1].ranges), local.range_keys[group_key][0]) ? false : (
                  // Check forward contiguity (next rule has higher values)
                  // If this rule's value we're comparing has a null "to", that means we can't compare on the upper (forward) side.
                  // This case should be filtered out in the encapsulation merging.
                  rule.ranges[local.range_keys[group_key][0]].to_inclusive == null ? false : (
                    // If the next rule's value we're comparing has a null "from", that means we can't compare on the upper (forward) side.
                    // This case should be filtered out in the encapsulation merging.
                    group.rules[rule_idx + 1].ranges[local.range_keys[group_key][0]].from_inclusive == null ? false : (
                      // We have two real values to compare, so compare them.
                      // They are forward contiguous if this rule's "to" value is at least adjacent (one less) to the next rule's "from" value
                      rule.ranges[local.range_keys[group_key][0]].to_inclusive < group.rules[rule_idx + 1].ranges[local.range_keys[group_key][0]].from_inclusive - 1 ? false : (
                        // We get here if the first few checks passed (not the last rule, has the key, next rule is forward or reverse contiguous),
                        // so now we ensure no other ranges or discretes are violated.

                        // Check every range other than the one being considered for contiguity
                        // If any are more restrictive, then it is not contiguous
                        0 < length(
                          [
                            for range_key in local.range_keys[group_key] :
                            true
                            if(
                              // Only make this check if it's a range key other than the one we're considering for contiguity
                              // TODO: update this index in the template
                              range_key != local.range_keys[group_key][0] ? (
                                // This first check ensures that either neither of them have the key, or they both have the key
                                (contains(keys(rule.ranges), range_key) != contains(keys(group.rules[rule_idx + 1].ranges), range_key)) ? true : (
                                  // If this rule doesn't have the key, then due to the first check the next rule can't have the key, so this passes (false for violation)
                                  !contains(keys(rule.ranges), range_key) ? false : (
                                    // This check returns true (is a violation) if both rules have the key but the from value is different
                                    rule.ranges[range_key].from_inclusive != group.rules[rule_idx + 1].ranges[range_key].from_inclusive ? true : (
                                      // This check returns true (is a violation) if both rules have the key but the to value is different
                                      rule.ranges[range_key].to_inclusive != group.rules[rule_idx + 1].ranges[range_key].to_inclusive
                                    )
                                  )
                                )
                              ) : false // false (not a violation) if it's the range key we're considering for contiguity
                            )
                          ],
                        ) ? false :
                        // Check every discrete. If any are more restrictive, then it's not contiguous.
                        0 == length(
                          [
                            for discrete_key in local.discrete_keys[group_key] :
                            true
                            if(
                              // It's a violation if:
                              // - This rule has a key and the next rule doesn't OR
                              // - The next rule has a key and htis rule doesn't
                              // - This rule's value is different than the next rule's value

                              // This first check ensures that either neither of them have the key, or they both have the key
                              (contains(keys(rule.discretes), discrete_key) != contains(keys(group.rules[rule_idx + 1].discretes), discrete_key)) ? true : (
                                // If this rule doesn't have the key, then due to the first check the next rule can't have the key, so this passes (false for violation)
                                !contains(keys(rule.discretes), discrete_key) ? false : (
                                  // This check returns true (is a violation) if both rules have the key but have different values
                                  rule.discretes[discrete_key] != group.rules[rule_idx + 1].discretes[discrete_key]
                                )
                              )
                            )
                          ]
                        )
                      )
                    )
                  )
                )
              )
            )
          )
          }
        )
      ]
    })
  }

  range_0_contiguous_forward_count = length(local.range_keys) <= 0 ? {} : {
    for group_key, group in local.range_0_next_contiguous :
    group_key => merge(group, {
      rules = [
        for rule_idx, rule in group.rules :
        merge(rule, {
          contiguous_forward_count = length([
            for compare_rule_idx in range(rule_idx, length(group.rules) - 1) :
            null
            if group.rules[compare_rule_idx].contiguous_with_next
          ])
        })
      ]
    })
  }

  range_0_squashed = length(local.range_keys) <= 0 ? {} : {
    for group_key, group in local.range_0_contiguous_forward_count :
    group_key => merge(group, {
      rules = [
        for rule_idx, rule in group.rules :
        {
          discrets = rule.discretes
          ranges = {
            for range_key, range_value in rule.ranges :
            // If it's the range key we're comparing, update it to
            // use the "to" value of the last contiguous rule in this sequence.
            range_key => range_key == local.range_keys[group_key][0] ? merge(range_value, {
              to_inclusive = group.rules[rule_idx + rule.contiguous_forward_count].ranges[range_key].to_inclusive
            }) : range_value
          }
          // Merge the metadata from all of the rules that we just squashed
          metadata = flatten(
            [
              for squashed_idx in range(rule_idx, rule_idx + rule.contiguous_forward_count + 1) :
              group.rules[squashed_idx].metadata
            ]
          )
        }
        // Only include the rule if it's the first rule OR 
        // the previous rule was not contiguous with this one.
        // This removes rules that got squashed into a previous one.
        if rule_idx == 0 ? true : !group.rules[rule_idx - 1].contiguous_with_next
      ]
    })
  }

  final_squashed = local.range_0_squashed
}
