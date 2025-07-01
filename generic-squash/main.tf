// Why so many ternaries, instead of || / &&?
// Because terneries do lazy evaluation, while and/or do not.
// This notably speeds up the process for huge rule sets.

locals {
  // Get a list of all discrete and range keys found within each rule set.
  // We use this to standardize the rules for merging.
  // Get the complete set of range keys we're dealing with for each rule list.
  range_keys = {
    for group_key, group in var.rule_sets :
    group_key => distinct(flatten([
      for rule in group.rules :
      keys(rule.ranges)
    ]))
  }

  // This adds any missing discrete and range keys to any rule that doesn't have them,
  // so that all rules have the same keys to ensure consistency in merging.
  standardized_rule_sets = {
    for group_key, group in var.rule_sets :
    group_key => merge(group, {
      rules = [
        for rule_idx, rule in group.rules :
        merge(rule, {
          // Add any range keys that are missing, with ranges that are equivalent
          // to not existing (no restriction).
          ranges = merge(rule.ranges, {
            for k in setsubtract(local.range_keys[group_key], keys(rule.ranges)) :
            k => {
              from_inclusive = null
              to_inclusive   = null
            }
          })
          // Replace any discrete values with their primary equivalency
          discretes = {
            for dk, dv in rule.discretes :
            // Create a list of all equivalent values, and
            // add the current value at the end, then take the first index.
            // This will ensure that if there's an equivalency, it gets used, but
            // if not then the current value is used.
            dk => concat([
              for de_pair in group.discrete_equivalents[dk] :
              de_pair.primary
              // This is an alternative to the "contains" function, except that
              // it works to find "null", which the "contains" function can't do.
              if length([
                for alternative in de_pair.alternatives :
                null
                if alternative == dv
              ]) > 0
            ], [dv])[0]
          }
          metadata = {
            original = rule.metadata
            temp = {
              original_rule_idx = rule_idx
            }
          }
        })
      ]
      }
    )
  }

  discrete_encapsulation_primaries = {
    for group_key, group in local.standardized_rule_sets :
    group_key => {
      for discrete_key, discrete_encapsulation in group.discrete_encapsulation :
      discrete_key => [
        for pair in discrete_encapsulation :
        pair.primary
      ]
    }
  }
  discrete_encapsulation_encapsulated_values = {
    for group_key, group in local.standardized_rule_sets :
    group_key => {
      for discrete_key, discrete_encapsulation in group.discrete_encapsulation :
      discrete_key => [
        for pair in discrete_encapsulation :
        pair.encapsulated
      ]
    }
  }

  // This adds to each rule a listing of all of the rules it encapuslates (rules that can be merged into it)
  with_encapsulations = {
    for group_key, group in local.standardized_rule_sets :
    group_key => merge(group, {
      rules = {
        for encapsulator_idx, encapsulator in group.rules :
        encapsulator_idx => merge(encapsulator, {
          encapsulates = {
            // Loop through all other rules in the same rule list
            for encapsulated_idx, encapsulated in group.rules :
            encapsulated_idx => encapsulated
            // Exclude comparision of a rule to itself
            if encapsulated_idx == encapsulator_idx ? false : (
              // Check if there are any ranges in the encapsulator that do not encapsulate the encapsulated (violations)
              length(
                [
                  // Loop through all ranges in the rule that would be the encapsulator
                  // This loop tracks violations, so true = bad
                  for range_key, encapsulator_range_value in encapsulator.ranges :
                  true
                  // It violates this range rule if it has a start port below the encapsulated from port, or a to port above the encapsulated to port
                  if(
                    // If both the from and the to values are null, then it's like this range doesn't exist (no limits), so ignore it
                    (encapsulator_range_value.from_inclusive == null && encapsulator_range_value.to_inclusive == null) ? false :
                    // If the encapsulated rule doesn't have this range key, it can't be encapsulated
                    !contains(keys(encapsulated.ranges), range_key) ? true : (
                      // First test the lower bound
                      // If the encapsulator doesn't have one, that's not a violation since that means infinity
                      // Otherwise, if the encapsulated doesn't have one, that's definitely a violation
                      // Otherwise, if the encapsulator has a higher lower bound, that's a violation
                      encapsulator_range_value.from_inclusive == null ? false : encapsulated.ranges[range_key].from_inclusive == null ? true : encapsulator_range_value.from_inclusive > encapsulated.ranges[range_key].from_inclusive
                      ) ? true : (
                      // Now test the upper bound
                      // If the encapsulator doesn't have one, that's not a violation since that means infinity
                      // Otherwise, if the encapsulated doesn't have one, that's definitely a violation
                      // Otherwise, if the encapsulator has a lower upper bound, that's a violation
                      encapsulator_range_value.to_inclusive == null ? false : encapsulated.ranges[range_key].to_inclusive == null ? true : encapsulator_range_value.to_inclusive < encapsulated.ranges[range_key].to_inclusive
                    )
                  )
                ]
                ) > 0 ? false : (
                // Check if there are any discrete rules that are violated
                length(
                  [
                    // Since the variable validation rules require all rules to have the same discrete keys,
                    // we only have to loop through the keys in the encapsulator, as those keys are guaranteed
                    // to be present in the encapsulated.
                    for discrete_key in keys(encapsulator.discretes) :
                    true
                    if(
                      // If the key is equal, that's fine, no violation
                      encapsulator.discretes[discrete_key] == encapsulated.discretes[discrete_key] ? false : (
                        // Otherwise, check if the value of the encapsulator encapsulates the value of the encapsulated

                        // See if the the encapsulator's discrete value is in the discrete_encapsulation values and covers all (null) other values
                        try(local.discrete_encapsulation_encapsulated_values[index(local.discrete_encapsulation_primaries[group_key][discrete_key], encapsulator.discretes[discrete_key])], []) == null ? false : (
                          // It doesn't so now try if it covers this specific discrete value in the encapsulated rule
                          // This is an alternative to the "contains" function, except that
                          // it works to find "null", which the "contains" function can't do.
                          length([
                            for check_value in try(local.discrete_encapsulation_encapsulated_values[index(local.discrete_encapsulation_primaries[group_key][discrete_key], encapsulator.discretes[discrete_key])], []) :
                            null
                            if check_value == encapsulated.discretes[discrete_key]
                          ]) == 0
                        )
                      )
                    )
                  ]
                ) > 0 ? false : true
              )
            )
          }
        })
      }
    })
  }

  // Do a forward pass to remove any rules that are encapsulated in a later rule.
  // We do this in two steps (forward, then reverse) so two equal rules don't
  // remove each other.
  forward_pass_encapsulate = {
    for key, group in local.with_encapsulations :
    key => merge(group, {
      rules = {
        for rule_idx, rule in group.rules :
        rule_idx => rule
        // Only include the rule if it's not encapsulated by a subsequent rule
        if 0 == length([
          for compare_idx in keys(group.rules) :
          true
          if compare_idx > rule_idx ? lookup(group.rules[compare_idx].encapsulates, rule_idx, null) != null : false
        ])
      }
    })
  }

  // Do a reverse pass to remove any rules that are encapsulated in a previous rule.
  reverse_pass_encapsulate = {
    for key, group in local.forward_pass_encapsulate :
    key => merge(group, {
      // Use a list instead of a map because this is the final encapsulation
      // merge, so we must re-index them.
      rules = [
        for rule_idx, rule in group.rules :
        {
          // We re-construct the rules to remove the "encapsulates"
          // key, so the next steps aren't as massive in memory.
          for field_key, field_value in merge(rule, {
            // Update this rule's metadata to include metadata from all encapsulated rules
            metadata = flatten([
              [
                rule.metadata
              ],
              [
                for encapsulated in rule.encapsulates :
                encapsulated.metadata
              ]
            ])
          }) :
          field_key => field_value
          // Strip out this field we no longer need
          if field_key != "encapsulates"
        }
        // Only include the rule if it's not encapsulated by a previous rule
        if 0 == length([
          for compare_idx in keys(group.rules) :
          true
          if compare_idx < rule_idx ? lookup(group.rules[compare_idx].encapsulates, rule_idx, null) != null : false
        ])
      ]
    })
  }

  // Get the complete set of discrete keys we're dealing with for each rule list.
  discrete_keys = {
    for group_key, group in local.reverse_pass_encapsulate :
    group_key => distinct(flatten([
      for rule in group.rules :
      keys(rule.discretes)
    ]))
  }

  // Convert back to the original metadata form, since we don't need
  // the temp values anymore.
  sorted_metadata = {
    for group_key, group in local.final_contiguous_squashed :
    group_key => merge(group, {
      rules = [
        for rule in group.rules :
        merge(rule, {
          metadata = [
            for original_rule_idx in sort([
              for meta in rule.metadata :
              // "sort" does a lexigraphical sort, so we need
              // leading zeros on everything so all values are the
              // same length.
              format("%020d", meta.temp.original_rule_idx)
            ]) :
            [
              for meta in rule.metadata :
              meta.original
              if meta.temp.original_rule_idx == tonumber(original_rule_idx)
            ][0]
          ]
          contains_rules = [
            // For some unknown reason, the "sort" function
            // converts all values to strings, so we have to
            // convert them back to numbers.
            for idx in sort([
              for meta in rule.metadata :
              // "sort" does a lexigraphical sort, so we need
              // leading zeros on everything so all values are the
              // same length.
              format("%020d", meta.temp.original_rule_idx)
            ]) :
            tonumber(idx)
          ]
        })
      ]
    })
  }

  // Sort the rules by the index of their first contained metadata,
  // which was already sorted by merged rule order
  sorted_squashed = {
    for group_key, group in local.sorted_metadata :
    group_key => merge(group, {
      rules = [
        for first_rule_idx in sort([
          for rule in group.rules :
          // "sort" does a lexigraphical sort, so we need
          // leading zeros on everything so all values are the
          // same length.
          format("%020d", rule.contains_rules[0])
        ]) :
        [
          for rule in group.rules :
          rule
          if rule.contains_rules[0] == tonumber(first_rule_idx)
        ][0]
      ]
    })
  }

}
