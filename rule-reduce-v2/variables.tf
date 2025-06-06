variable "rule_sets" {
  description = <<EOF
A map of rule lists. Each rule list is handled independently; the map-based input is simply to allow multiple rule lists to be reduced in a single module.

Each rule list has:
- `discrete_encapsulation`: a map (key = discrete key) of maps (key = discrete value) of lists of discrete values that encapsulate other descrete values. This indicates a one-way encapsulation (the key encapsulates all values), but does not imply the reverse is true. For example, if the discrete key is for "protocol", the value "all" might encapsulate ["udp", "tcp", "icmp"]. This would be represented as:

discrete_encapsulation = {
    protocol = {
        all = ["udp", "tcp", "icmp"]
    }
}

- `discrete_equivalents`: a map (key = discrete key) of maps (key = discrete value) of lists where the key is equivalent to all values. This indicates a bi-directional equivalency. In reduced rules, all discrete values found in the map values will be replaced with the key for that map. For example, in AWS network rules, protocol "6" is equivalent to "tcp". This would be represented as:

discrete_equivalents = {
    protocol = {
        6 = ["tcp"]
    }
}

- `rules`: a list of the actual rules to be reduced. Each rule has:
    - `ranges`: a map of range objects, where the key is the range type (e.g. "ports") and the value is an object with a `from_inclusive` and `to_inclusive`. `null` values for `from_inclusive` or `to_inclusive` represent negative and positive infinity, respectively.
    - `discretes`: a map of discrete values for the rule, where the key is the descrete type (e.g. "protocol") and the value is the descrete value (e.g. "tcp").
    - `metadata`: anything that your heart desires. When rules are merged/reduced, the final rules will contain the metadata of all rules that were reduced into that final rule. This is particularly helpful if you want to be able to generate text descriptions of what the final rules do, and this allows them to include descriptions or names of all of the rules that were reduced into it.
EOF
  nullable    = false
  type = map(
    object(
      {
        discrete_encapsulation = optional(map(map(list(any))), {})
        discrete_equivalents   = optional(map(map(list(any))), {})
        rules = optional(list(object({
          ranges = optional(map(object({
            from_inclusive = number
            to_inclusive   = number
          })), {})
          discretes = optional(map(any), {})
          metadata  = optional(map(any))
        })), [])
      }
    )
  )

  // TODO:
  // - Check for loops in the discrete encapsulation?
  // - Useful output for each validation


  // Ensure that no discrete equivalent type keys are in the associated values for the same discrete type
  validation {
    condition = 0 == length(flatten([
      for key, group in var.rule_sets :
      [
        for sev in values(group.discrete_equivalents) :
        null
        // If any of the keys are found in any of the values, that's a problem
        if length(setintersection(keys(sev), flatten([values(sev)]))) > 0
      ]
    ]))
    error_message = "For each set, none of the keys in any `discrete_equivalents` map may be present in the values for that same map. The input does not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      "${key} - ${join(", ", [
        for sek, sev in group.discrete_equivalents :
        "${sek} (${join(", ", distinct(setintersection(keys(sev), flatten([values(sev)]))))})"
        if length(setintersection(keys(sev), flatten([values(sev)]))) > 0
      ])}"
      if length(flatten([
        for sev in values(group.discrete_equivalents) :
        null
        if length(setintersection(keys(sev), flatten([values(sev)]))) > 0
      ])) > 0
    ])}"
  }

  // Ensure that there are no discrete equivalent duplicates
  validation {
    condition = 0 == length(flatten([
      for key, group in var.rule_sets :
      [
        for sev in values(group.discrete_equivalents) :
        null
        // It's invalid if the length of the distinct set is different than the length of the complete set,
        // since that means that the complete set has duplicates.
        if length(distinct(flatten([values(sev)]))) != length(flatten([values(sev)]))
      ]
    ]))
    error_message = "For each set, the values in the `discrete_equivalents` map must not have any duplicates. The input does not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      "${key} - ${join(", ", [
        for sek, sev in group.discrete_equivalents :
        "${sek} (${join(", ", distinct([
          for v in flatten([values(sev)]) :
          v
          // Count how many instances of this value there are. If there's more than 1, it's a duplicate.
          if length([for v2 in flatten([values(sev)]) : v2 if v2 == v]) > 1
        ]))})"
        if length(distinct(flatten([values(sev)]))) != length(flatten([values(sev)]))
      ])}"
      if length(flatten([
        for sev in values(group.discrete_equivalents) :
        null
        if length(distinct(flatten([values(sev)]))) != length(flatten([values(sev)]))
      ])) > 0
    ])}"
  }

  // Ensure that the discrete encapsulation values are all valid
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each discrete encapsulation type
        for discrete_name, discrete_encapsulations in group.discrete_encapsulation :
        true
        if length([
          // Check each encapsulation
          for discrete_equalities in discrete_encapsulations :
          true
          if length([
            for equality in discrete_equalities :
            true
            if can(keys(equality)) || can(anytrue(equality))
          ]) > 0
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For each discrete encapsulation, the value must be a string, number, or boolean."
  }

  // Ensure that the discrete equivalents values are all valid
  validation {
    condition = length([
      // Check each set
      for key, group in var.rule_sets :
      key
      if length([
        // Check each discrete encapsulation type
        for discrete_name, discrete_equivalents in group.discrete_equivalents :
        true
        if length([
          // Check each encapsulation
          for discrete_equivalent in discrete_equivalents :
          true
          if length([
            for equivalent in discrete_equivalent :
            true
            if can(keys(equivalent)) || can(anytrue(equivalent))
          ]) > 0
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For each discrete equivalent, the value must be a string, number, or boolean."
  }

  // Ensure that the discrete values are all valid
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
          // Check each discrete in the rule
          for sk, sv in rule.discretes :
          true
          if can(keys(sv)) || can(tolist(sv))
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For each discrete, the value must be a string, number, or boolean."
  }

  // Ensure that every discrete key is in the discrete_encapsulation keys
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
          // Check each discrete in the rule
          for sk, sv in rule.discretes :
          true
          if !contains(keys(group.discrete_encapsulation), sk)
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For a given set, the key of every discrete must be in the `discrete_encapsulation` map. This is to help ensure there are no accidental key typos."
  }

  // Ensure that every discrete key is in the discrete_equivalents keys
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
          // Check each discrete in the rule
          for sk, sv in rule.discretes :
          true
          if !contains(keys(group.discrete_equivalents), sk)
        ]) > 0
      ]) > 0
    ]) == 0
    error_message = "For a given set, the key of every discrete must be in the `discrete_equivalents` map. This is to help ensure there are no accidental key typos."
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

  // Ensure that all items have the same discrete keys
  validation {
    condition = length([
      for key, group in var.rule_sets :
      key
      if length(group.rules) == 0 ? false : length([
        for idx in range(1, length(group.rules)) :
        true
        // It's a problem if they have different numbers of keys, or if the length of the intersection doesn't match both of their lengths
        if length(setsubtract(keys(group.rules[idx].discretes), keys(group.rules[0].discretes))) != 0 ? length(setsubtract(keys(group.rules[0].discretes), keys(group.rules[idx].discretes))) != 0 : false
      ]) > 0
    ]) == 0
    error_message = "For all rules in a given set, the keys in the `discretes` field of each rule must be consistent. The following set(s) do not meet this requirement: ${join(", ", [
      for key, group in var.rule_sets :
      key
      if length(group.rules) == 0 ? false : length([
        for idx in range(1, length(group.rules)) :
        true
        // It's a problem if they have different numbers of keys, or if the length of the intersection doesn't match both of their lengths
        if length(setsubtract(keys(group.rules[idx].discretes), keys(group.rules[0].discretes))) != 0 ? length(setsubtract(keys(group.rules[0].discretes), keys(group.rules[idx].discretes))) != 0 : false
      ]) > 0
    ])}"
  }

  // TODO: ensure there are no cycles in the discrete encapsulations
}
