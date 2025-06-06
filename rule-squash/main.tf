// Why so many ternaries, instead of || / &&?
// Because terneries do lazy evaluation, while and/or do not.
// This notably speeds up the process for huge rule sets.

locals {
  // Do a first pass to clean up equivalencies and ranges that are meaningless
  equivalencies = {
    for key, group in var.rule_sets :
    key => merge(group, {
      rules = {
        for rule_idx, rule in group.rules :
        rule_idx => merge(rule, {
          // Replace any discrete values with their primary equivalency
          discretes = {
            for dk, dv in rule.discretes :
            // Create a list of all equivalent values, and
            // add the current value at the end, then take the first index.
            // This will ensure that if there's an equivalency, it gets used, but
            // if not then the current value is used.
            dk => concat([
              for dek, dev in group.discrete_equivalents[dk] :
              dek
              if contains(dev, dv)
            ], [dv])[0]
          }
          // Remove any ranges where both values are null, as that makes it an
          // infinite range and thereby not a range limit at all.
          ranges = {
            for rk, rv in rule.ranges :
            rk => rv
            // Only include the range if at least one of the bounds is non-null
            if rv.to_inclusive != null ? true : rv.from_inclusive != null
          }
        })
      }
    })
  }

  // This adds to each rule a listing of all of the rules it encapuslates (rules that can be merged into it)
  with_encapsulations = {
    for key, group in local.equivalencies :
    key => merge(group, {
      rules = {
        for encapsulator_idx, encapsulator in group.rules :
        encapsulator_idx => merge(encapsulator, {
          encapsulates = {
            // Loop through all other rules in the same rule list
            for encapsulated_idx, encapsulated in group.rules :
            encapsulated_idx => encapsulated
            // Exclude comparision of a rule to itself
            if encapsulated_idx == encapsulator_idx ? false : (
              // Check if there are any ranges in the encapsulator that do not encapsulate the encapsulator (violations)
              length(
                [
                  // Loop through all ranges in the rule that would be the encapsulator
                  // This loop tracks violations, so true = bad
                  for range_key, encapsulator_range_value in encapsulator.ranges :
                  true
                  // It violates this range rule if it has a start port below the encapsulated from port, or a to port above the encapsulated to port
                  if(
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
                ]) > 0 ? false : (
                // Check if there are any ranges in the encapsulated rule that aren't in the has a range key that doesn't exist in the encapsulator.
                // If there are any of these, the encapsulator cannot encapsulate the encapsulated.
                length(
                  [
                    for range_key in keys(encapsulated.ranges) :
                    true
                    if lookup(encapsulator.ranges, range_key, null) == null
                  ]
                  ) > 0 ? false : (
                  // Check if there are any discrete rules that are violated
                  length(
                    [
                      for discrete_key, encapsulator_discrete_value in encapsulator.discretes :
                      true
                      // If the value is equal, it matches so that's fine
                      // If it's not equal, we have to check if this rule's value encapsulates the encapsulated rule's discrete value
                      if encapsulator_discrete_value == encapsulated.discretes[discrete_key] ? false : !contains(lookup(group.discrete_encapsulation[discrete_key], encapsulator.discretes[discrete_key], []), encapsulated.discretes[discrete_key])
                    ]) > 0 ? false : (
                    // Check if the encapsulated rule has any discrete keys that don't exist in the encapsulator.
                    // If there are any of these, the encapsulator cannot encapsulate the encapsulated.
                    length(
                      [
                        for discrete_key in keys(encapsulated.discretes) :
                        true
                        if lookup(encapsulator.discretes, discrete_key, null) == null
                      ]
                    ) == 0
                  )
                )
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


  // Get the complete set of range keys we're dealing with for each rule list.
  range_keys = {
    for key, group in local.reverse_pass_encapsulate :
    key => distinct(flatten([
      for rule in group.rules :
      keys(rule.ranges)
    ]))
  }

  // Get the complete set of discrete keys we're dealing with for each rule list.
  discrete_keys = {
    for key, group in local.reverse_pass_encapsulate :
    key => distinct(flatten([
      for rule in group.rules :
      keys(rule.discretes)
    ]))
  }

  // TODO: test nested encapsulation metadata and rules
  // TODO: don't include non-rules fields in rule sets for intermediate steps
}
