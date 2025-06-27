variable "rule_sets" {
  description = <<EOF
A map of rule lists. Each rule list is handled independently; the map-based input is simply to allow multiple rule lists to be reduced in a single module.

Each rule list has:
- `discrete_encapsulation`: a map (key = discrete key) of lists of objects (`primary` = encapsulating value, `encapsulated` = list of encapsulated vlaues). If `null` is provided instead of a list, this indicates that all values are encapsulated. This indicates a one-way encapsulation (the key encapsulates all values), but does not imply the reverse is true. For example, if the discrete key is for "protocol", the value "all" might encapsulate ["udp", "tcp", "icmp"]. This would be represented as:

discrete_encapsulation = {
    protocol = [
        {
            primary = "all"
            encapsulated = ["udp", "tcp", "icmp"]
        }
    ]
}

- `discrete_equivalents`: a map (key = discrete key) of lists of objects (`primary` = preferred value, `alternatives` = list of equivalent values). This indicates a bi-directional equivalency. In reduced rules, all discrete values found in the alternative values will be replaced with the primary value for that key. For example, in AWS network rules, protocol 6 is equivalent to "tcp". This would be represented as:

discrete_equivalents = {
    protocol = [
        {
            primary = 6
            alternatives = ["tcp"]
        }
    ]
}

- `base2_align_range_keys`: a list of range keys, where those ranges can only be merged along base2 boundaries (e.g. IPv4 CIDR blocks). For ranges that have range keys in this list, this will prevent contiguous rules from being merged if the resulting range doesn't have a size that is a power of 2 OR if the `from` value of the merged range doesn't align with that power of 2.

- `rules`: a list of the actual rules to be reduced. Each rule has:
    - `discretes`: a map of discrete values for the rule, where the key is the descrete type (e.g. "protocol") and the value is the descrete value (e.g. "tcp").
    - `ranges`: a map of range objects, where the key is the range type (e.g. "ports") and the value is an object with a `from_inclusive` and `to_inclusive`. `null` values for `from_inclusive` or `to_inclusive` represent negative and positive infinity, respectively.
    - `metadata`: anything that your heart desires. When rules are merged/reduced, the final rules will contain the metadata of all rules that were reduced into that final rule. This is particularly helpful if you want to be able to generate text descriptions of what the final rules do, and this allows them to include descriptions or names of all of the rules that were reduced into it.
EOF
  nullable    = false
  type = map(
    object(
      {
        discrete_encapsulation = optional(map(list(object({
          primary = any
          encapsulated = list(any)
        }))), {})
        discrete_equivalents   = optional(map(list(object({
          primary = any
          alternatives = list(any)
        }))), {})
        base2_align_range_keys = optional(list(string), [])
        rules = optional(list(object({
          discretes = optional(any, {})
          ranges = optional(map(object({
            from_inclusive = number
            to_inclusive   = number
          })), {})
          metadata = optional(map(any))
        })), [])
      }
    )
  )

  // TODO:
  // - discretes object must be a map
  // - discretes can only be bools, strings, numbers, or null
  // - Check for loops in the discrete encapsulation?
  // - Useful output for each validation
  // - ensure there are no base2_align rules that don't appear in the ranges
  // - verify that all starting and ending ranges that are base2 are aligned
  // - ensure there are no more ranges than are supported


  // Ensure that no discrete equivalent type keys are in the associated values for the same discrete type
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for dev in values(group.discrete_equivalents) :
        null
        // If any of the keys are found in any of the values, that's a problem
        if length(setintersection([for pair in dev: pair.primary], flatten([for pair in dev: pair.alternatives]))) > 0
      ]
    ]))
    error_message = "For each set, none of the `primary` values for any `discrete_equivalents` key may be present in the `alternatives` values for that same key. The input does not meet this requirement:\n${join(", ", flatten([
      for group_key, group in var.rule_sets :
      [
        for dek, dev in group.discrete_equivalents :
        "\t- Set \"${group_key}\", discrete key \"${dek}\" (values: ${join(", ", distinct(setintersection([for pair in dev: pair.primary], flatten([for pair in dev: pair.alternatives]))))})"
        if length(setintersection([for pair in dev: pair.primary], flatten([for pair in dev: pair.alternatives]))) > 0
      ]
    ]))}"
  }

  // Ensure that there are no discrete equivalent duplicates
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for dev in values(group.discrete_equivalents) :
        null
        // It's invalid if the length of the distinct set is different than the length of the complete set,
        // since that means that the complete set has duplicates.
        if length(distinct(flatten([for pair in dev: pair.alternatives]))) != length(flatten([for pair in dev: pair.alternatives]))
      ]
    ]))
    error_message = "For each set, each `alternatives` value for each `discrete_equivalents` key must only appear in one `alternatives` value, and must not have any duplicates. The input does not meet this requirement:\n${join(", ", flatten([
      for group_key, group in var.rule_sets :
      [
        for dek, dev in group.discrete_equivalents :
        "\t- Set \"${group_key}\", discrete key \"${dek}\" (values: ${join(", ", [
        for v in flatten([for pair in dev: pair.alternatives]) :
          v
          // Count how many instances of this value there are. If there's more than 1, it's a duplicate.
          if length([for v2 in flatten([for pair in dev: pair.alternatives]) : v2 if v2 == v]) > 1
        ])})"
        if length(distinct(flatten([for pair in dev: pair.alternatives]))) != length(flatten([for pair in dev: pair.alternatives]))
      ]
    ]))}"
  }

  // TODO: continue from here down, ensuring all validation rules have a consistent format

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
          for discrete_encapsulation in discrete_encapsulations :
          true
          // If it's null, that's fine because it means it encapsulates everything
          if discrete_encapsulation == null ? false : length([
            for encapsulation in discrete_encapsulation :
            true
            if can(keys(encapsulation)) || can(anytrue(encapsulation))
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
            // If one is null, that's fine
            range_value.from_inclusive == null ? false : (
              range_value.to_inclusive == null ? false : (
                // They're both non-null, so if the to value is below the from value, that's a violation
                range_value.to_inclusive < range_value.from_inclusive
              )
            )
          )
        ]
      ])) > 0
    ])
    error_message = "For all ranges, either one (or both) of the `from_inclusive` and `to_inclusive` values must be null, or the `to_inclusive` value must be greater than or equal to the `from_inclusive` value."
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
