variable "rule_sets" {
  description = "A map of lists of IPv4 CIDRs and associated protocols/ports. All CIDRs within each sublist will be merged to the minimum set of CIDRs that cover exactly the same IP ranges and same protocols/ports. The sublists are handled independently; the module is structured this way to support processing multiple independent lists of CIDRs with a single instance of the module."
  nullable    = false
  type = map(
    object(
      {
        singleton_encapsulation = optional(map(map(list(any))), {})
        singleton_equivalents   = optional(map(map(list(any))), {})
        rules = optional(list(object({
          ranges = optional(map(object({
            from_inclusive = number
            to_inclusive   = number
          })), {})
          singletons = optional(map(any), {})
          metadata   = optional(any)
        })), [])
      }
    )
  )

  // TODO:
  // - Check for loops in the singleton encapsulation?
  // - Useful output for each validation

  // Ensure that no singleton equivalent type keys are in the associated values for the same singleton type
  validation {
    condition = 0 == length(flatten([
      for key, group in var.rule_sets :
      [
        for sev in values(group.singleton_equivalents) :
        null
        // If any of the keys are found in any of the values, that's a problem
        if length(setintersection(keys(sev), flatten([values(sev)]))) > 0
      ]
    ]))
    error_message = "For each set, none of the keys in any `singleton_equivalents` map may be present in the values for that same map. The input does not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      "${key} - ${join(", ", [
        for sek, sev in group.singleton_equivalents :
        "${sek} (${join(", ", distinct(setintersection(keys(sev), flatten([values(sev)]))))})"
        if length(setintersection(keys(sev), flatten([values(sev)]))) > 0
      ])}"
      if length(flatten([
        for sev in values(group.singleton_equivalents) :
        null
        if length(setintersection(keys(sev), flatten([values(sev)]))) > 0
      ])) > 0
    ])}"
  }

  // Ensure that there are no singleton equivalent duplicates
  validation {
    condition = 0 == length(flatten([
      for key, group in var.rule_sets :
      [
        for sev in values(group.singleton_equivalents) :
        null
        // It's invalid if the length of the distinct set is different than the length of the complete set,
        // since that means that the complete set has duplicates.
        if length(distinct(flatten([values(sev)]))) != length(flatten([values(sev)]))
      ]
    ]))
    error_message = "For each set, the values in the `singleton_equivalents` map must not have any duplicates. The input does not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      "${key} - ${join(", ", [
        for sek, sev in group.singleton_equivalents :
        "${sek} (${join(", ", distinct([
          for v in flatten([values(sev)]) :
          v
          // Count how many instances of this value there are. If there's more than 1, it's a duplicate.
          if length([for v2 in flatten([values(sev)]) : v2 if v2 == v]) > 1
        ]))})"
        if length(distinct(flatten([values(sev)]))) != length(flatten([values(sev)]))
      ])}"
      if length(flatten([
        for sev in values(group.singleton_equivalents) :
        null
        if length(distinct(flatten([values(sev)]))) != length(flatten([values(sev)]))
      ])) > 0
    ])}"
  }

  // Ensure that the singleton encapsulation values are all valid
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each singleton encapsulation type
        for singleton_name, singleton_encapsulations in group.singleton_encapsulation :
        true
        if length([
          // Check each encapsulation
          for singleton_equalities in singleton_encapsulations :
          true
          if length([
            for equality in singleton_equalities :
            true
            if can(keys(equality)) || can(anytrue(equality))
          ]) > 0
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For each singleton encapsulation, the value must be a string, number, or boolean."
  }

  // Ensure that the singleton equivalents values are all valid
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each singleton encapsulation type
        for singleton_name, singleton_equivalents in group.singleton_equivalents :
        true
        if length([
          // Check each encapsulation
          for singleton_equivalent in singleton_equivalents :
          true
          if length([
            for equivalent in singleton_equivalent :
            true
            if can(keys(equivalent)) || can(anytrue(equivalent))
          ]) > 0
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For each singleton equivalent, the value must be a string, number, or boolean."
  }

  // Ensure that the singleton values are all valid
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each rule
        for rule in group.rules :
        true
        if length([
          // Check each singleton in the rule
          for sk, sv in rule.singletons :
          true
          if can(keys(sv)) || can(tolist(sv))
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For each singleton, the value must be a string, number, or boolean."
  }

  // Ensure that every singleton key is in the singleton_encapsulation keys
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each rule
        for rule in group.rules :
        true
        if length([
          // Check each singleton in the rule
          for sk, sv in rule.singletons :
          true
          if !contains(keys(group.singleton_encapsulation), sk)
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For a given set, the key of every singleton must be in the `singleton_encapsulation` map. This is to help ensure there are no accidental key typos."
  }

  // Ensure that every singleton key is in the singleton_equivalents keys
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each rule
        for rule in group.rules :
        true
        if length([
          // Check each singleton in the rule
          for sk, sv in rule.singletons :
          true
          if !contains(keys(group.singleton_equivalents), sk)
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For a given set, the key of every singleton must be in the `singleton_equivalents` map. This is to help ensure there are no accidental key typos."
  }

  // Ensure that all items have the same range keys
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length(group.rules) == 0 ? false : length([
        // Check each rule other than the first one
        for idx in range(1, length(group.rules)) :
        true
        // It's a problem if they have different numbers of keys, or if the length of the intersection doesn't match both of their lengths
        if length(setsubtract(keys(group.rules[idx].ranges), keys(group.rules[0].ranges))) != 0 ? length(setsubtract(keys(group.rules[0].ranges), keys(group.rules[idx].ranges))) != 0 : false
      ]) > 0
    ]) == 0
    error_message = "For all rules in a given set, the keys in the `ranges` field of each rule must be consistent. The following set(s) do not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      key
      if length(group.rules) == 0 ? false : length([
        for idx in range(1, length(group.rules)) :
        true
        // It's a problem if they have different numbers of keys, or if the length of the intersection doesn't match both of their lengths
        if length(setsubtract(keys(group.rules[idx].ranges), keys(group.rules[0].ranges))) != 0 ? length(setsubtract(keys(group.rules[0].ranges), keys(group.rules[idx].ranges))) != 0 : false
      ]) > 0
    ])}"
  }

  // Ensure that for each range, the "to" must be greater than or equal to the "from"
  validation {
    condition = 0 == length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length(flatten([
        for rule in group.rules :
        [
          for range_key, range_value in rule.ranges :
          true
          if(
            // If both are null, that's not a violation
            (range_value.from_inclusive == null && range_value.to_inclusive == null) ? false : (
              (
                // If one is null and the other is not, that's a violation
                (range_value.from_inclusive == null && range_value.to_inclusive != null) ||
                (range_value.from_inclusive != null && range_value.to_inclusive == null)
                ) ? true : (
                // They're both non-null, so if the to value is below the from value, that's a violation
                range_value.to_inclusive < range_value.from_inclusive
              )
            )
          )
        ]
      ])) > 0
    ])
    error_message = "For all ranges, either both the `from_inclusive` and `to_inclusive` values must be null, or both of them must be non-null with the `to_inclusive` value greater than or equal to the `from_inclusive` value."
  }

  // Ensure that all items have the same singleton keys
  validation {
    condition = length([
      for key, group in var.rule_sets :
      key
      if length(group.rules) == 0 ? false : length([
        for idx in range(1, length(group.rules)) :
        true
        // It's a problem if they have different numbers of keys, or if the length of the intersection doesn't match both of their lengths
        if length(setsubtract(keys(group.rules[idx].singletons), keys(group.rules[0].singletons))) != 0 ? length(setsubtract(keys(group.rules[0].singletons), keys(group.rules[idx].singletons))) != 0 : false
      ]) > 0
    ]) == 0
    error_message = "For all rules in a given set, the keys in the `singletons` field of each rule must be consistent. The following set(s) do not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      key
      if length(group.rules) == 0 ? false : length([
        for idx in range(1, length(group.rules)) :
        true
        // It's a problem if they have different numbers of keys, or if the length of the intersection doesn't match both of their lengths
        if length(setsubtract(keys(group.rules[idx].singletons), keys(group.rules[0].singletons))) != 0 ? length(setsubtract(keys(group.rules[0].singletons), keys(group.rules[idx].singletons))) != 0 : false
      ]) > 0
    ])}"
  }

  // TODO: ensure there are no cycles in the singleton encapsulations
}
