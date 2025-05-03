variable "rule_sets" {
  description = "A map of lists of IPv4 CIDRs and associated protocols/ports. All CIDRs within each sublist will be merged to the minimum set of CIDRs that cover exactly the same IP ranges and same protocols/ports. The sublists are handled independently; the module is structured this way to support processing multiple independent lists of CIDRs with a single instance of the module."
  nullable    = false
  type = map(
    object(
      {
        singleton_encapsulation = optional(map(map(list(any))), {})
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
