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
          primary      = any
          encapsulated = list(any)
        }))), {})
        discrete_equivalents = optional(map(list(object({
          primary      = any
          alternatives = list(any)
        }))), {})
        base2_align_range_keys = optional(list(string), [])
        rules = optional(list(object({
          discretes = optional(any, {})
          ranges = optional(map(object({
            from_inclusive = number
            to_inclusive   = number
          })), {})
          metadata = optional(any, null)
        })), [])
      }
    )
  )

  // Ensure that no discrete equivalent type keys are in the associated values for the same discrete type
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for dev in values(group.discrete_equivalents) :
        null
        // If any of the keys are found in any of the values, that's a problem
        if length(setintersection([for pair in dev : pair.primary], flatten([for pair in dev : pair.alternatives]))) > 0
      ]
    ]))
    error_message = "For each set, none of the `primary` values for any `discrete_equivalents` key may be present in the `alternatives` values for that same key. The input does not meet this requirement:\n${join("\n", flatten([
      for group_key, group in var.rule_sets :
      [
        for dek, dev in group.discrete_equivalents :
        "\t- Set \"${group_key}\", discrete key \"${dek}\" (values: ${join(", ", distinct(setintersection([for pair in dev : pair.primary], flatten([for pair in dev : pair.alternatives]))))})"
        if length(setintersection([for pair in dev : pair.primary], flatten([for pair in dev : pair.alternatives]))) > 0
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
        if length(distinct(flatten([for pair in dev : pair.alternatives]))) != length(flatten([for pair in dev : pair.alternatives]))
      ]
    ]))
    error_message = "For each set, each `alternatives` value for each `discrete_equivalents` key must only appear in one `alternatives` value, and must not have any duplicates. The input does not meet this requirement:\n${join("\n", flatten([
      for group_key, group in var.rule_sets :
      [
        for dek, dev in group.discrete_equivalents :
        "\t- Set \"${group_key}\", discrete key \"${dek}\" (values: ${join(", ", [
          for v in flatten([for pair in dev : pair.alternatives]) :
          v
          // Count how many instances of this value there are. If there's more than 1, it's a duplicate.
          if length([for v2 in flatten([for pair in dev : pair.alternatives]) : v2 if v2 == v]) > 1
        ])})"
        if length(distinct(flatten([for pair in dev : pair.alternatives]))) != length(flatten([for pair in dev : pair.alternatives]))
      ]
    ]))}"
  }

  // Ensure that the discrete encapsulation values are all valid
  validation {
    condition = length(flatten([
      // Check each set
      for key, group in var.rule_sets :
      [
        // Check each discrete encapsulation type
        for discrete_key, discrete_encapsulations in group.discrete_encapsulation :
        [
          // Check each encapsulation
          for discrete_encapsulation in discrete_encapsulations :
          // If it's null, that's fine because it means it encapsulates everything
          discrete_encapsulation.encapsulated == null ? [] : [
            for encapsulated_value in discrete_encapsulation.encapsulated :
            null
            // It can't be a map, object, or list.
            if can(keys(encapsulated_value)) || can(anytrue(encapsulated_value))
          ]
        ]
      ]
    ])) == 0
    error_message = "For each set, each value in the \"encapsulated\" sub-field of the \"discrete_encapsulation\" field must be a bool, string, number, or null. The input does not meet this requirement:\n${join("\n", flatten([
      // Check each set
      for group_key, group in var.rule_sets :
      [
        // Check each discrete encapsulation type
        for discrete_key, discrete_encapsulations in group.discrete_encapsulation :
        [
          // Check each encapsulation
          for discrete_encapsulation in discrete_encapsulations :
          // If it's null, that's fine because it means it encapsulates everything
          discrete_encapsulation.encapsulated == null ? [] : [
            for ev_idx, encapsulated_value in discrete_encapsulation.encapsulated :
            "\t- Set \"${group_key}\", discrete key \"${discrete_key}\", primary \"${discrete_encapsulation.primary}\", encapsulated value at index ${ev_idx} (value type: ${encapsulated_value == null ? "null" : can(length(encapsulated_value)) ? (
              // It's either a map, object, list, set, or string
              can(keys(encapsulated_value)) ? (
                // It has keys, so it's either a map or object
                can(tomap(encapsulated_value)) ? "map" : "object"
                ) : (
                // It doen't have keys, so it's a list, set, or string
                can(flatten(encapsulated_value)) ? (
                  // It can be flattened, so it's a list or set
                  can(coalescelist(encapsulated_value, [null])) ? "list" : "set"
                ) : "string"
              )
              ) : (
              // It's either a number or a bool
              can(tobool(encapsulated_value)) ? "bool" : "number"
            )})"
            // It can't be a map, object, or list.
            if can(keys(encapsulated_value)) || can(anytrue(encapsulated_value))
          ]
        ]
      ]
    ]))}"
  }

  // Ensure that the discrete equivalents values are all valid
  validation {
    condition = length(flatten([
      // Check each set
      for key, group in var.rule_sets :
      [
        // Check each discrete equivalent type
        for discrete_key, discrete_equivalents in group.discrete_equivalents :
        [
          // Check each equivalent
          for discrete_equivalent in discrete_equivalents :
          [
            for alternative_value in discrete_equivalent.alternatives :
            null
            // It can't be a map, object, or list.
            if can(keys(alternative_value)) || can(anytrue(alternative_value))
          ]
        ]
      ]
    ])) == 0
    error_message = "For each set, each value in the \"alternatives\" sub-field of the \"discrete_equivalents\" field must be a bool, string, number, or null. The input does not meet this requirement:\n${join("\n", flatten([
      // Check each set
      for group_key, group in var.rule_sets :
      [
        // Check each discrete equivalent type
        for discrete_key, discrete_equivalents in group.discrete_equivalents :
        [
          // Check each equivalent
          for discrete_equivalent in discrete_equivalents :
          [
            for ev_idx, alternative_value in discrete_equivalent.alternatives :
            "\t- Set \"${group_key}\", discrete key \"${discrete_key}\", primary \"${discrete_equivalent.primary}\", encapsulated value at index ${ev_idx} (value type: ${alternative_value == null ? "null" : can(length(alternative_value)) ? (
              // It's either a map, object, list, set, or string
              can(keys(alternative_value)) ? (
                // It has keys, so it's either a map or object
                can(tomap(alternative_value)) ? "map" : "object"
                ) : (
                // It doen't have keys, so it's a list, set, or string
                can(flatten(alternative_value)) ? (
                  // It can be flattened, so it's a list or set
                  can(coalescelist(alternative_value, [null])) ? "list" : "set"
                ) : "string"
              )
              ) : (
              // It's either a number or a bool
              can(tobool(alternative_value)) ? "bool" : "number"
            )})"
            // It can't be a map, object, or list.
            if can(keys(alternative_value)) || can(anytrue(alternative_value))
          ]
        ]
      ]
    ]))}"
  }

  // Ensure that every discrete key is in the discrete_encapsulation keys
  validation {
    condition = length([
      // Check each set
      for group_key, group in var.rule_sets :
      null
      if length(setsubtract(distinct(flatten([
        for rule in group.rules :
        keys(rule.discretes)
      ])), keys(group.discrete_encapsulation))) > 0
    ]) == 0
    error_message = "For each set, the \"discrete_encapsulation\" field must have an entry for each discrete key found in any of the rules in that set. The input does not meet this requirement:\n${join("\n", [
      // Check each set
      for group_key, group in var.rule_sets :
      "\t- Set \"${group_key}\" (missing \"discrete_encapsulation\" entries for discrete keys: ${join(", ",
        [
          for dk in sort(setsubtract(distinct(flatten([
            for rule in group.rules :
            keys(rule.discretes)
          ])), keys(group.discrete_encapsulation))) :
          "\"${dk}\""
        ]
      )})"
      if length(setsubtract(distinct(flatten([
        for rule in group.rules :
        keys(rule.discretes)
      ])), keys(group.discrete_encapsulation))) > 0
    ])}"
  }

  // Ensure that every discrete key is in the discrete_equivalents keys
  validation {
    condition = length([
      // Check each set
      for group_key, group in var.rule_sets :
      null
      if length(setsubtract(distinct(flatten([
        for rule in group.rules :
        keys(rule.discretes)
      ])), keys(group.discrete_equivalents))) > 0
    ]) == 0
    error_message = "For each set, the \"discrete_equivalents\" field must have an entry for each discrete key found in any of the rules in that set. The input does not meet this requirement:\n${join("\n", [
      // Check each set
      for group_key, group in var.rule_sets :
      "\t- Set \"${group_key}\" (missing \"discrete_equivalents\" entries for discrete keys: ${join(", ",
        [
          for dk in sort(setsubtract(distinct(flatten([
            for rule in group.rules :
            keys(rule.discretes)
          ])), keys(group.discrete_equivalents))) :
          "\"${dk}\""
        ]
      )})"
      if length(setsubtract(distinct(flatten([
        for rule in group.rules :
        keys(rule.discretes)
      ])), keys(group.discrete_equivalents))) > 0
    ])}"
  }

  // Ensure that for each range, the "to" must be greater than or equal to the "from"
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group.rules :
        [
          for rk, rv in rule.ranges :
          null
          if(
            // If one is null, that's fine
            rv.from_inclusive == null ? false : (
              rv.to_inclusive == null ? false : (
                // They're both non-null, so if the to value is below the from value, that's a violation
                rv.to_inclusive < rv.from_inclusive
              )
            )
          )
        ]
      ]
    ]))
    error_message = "For each range in each rule, if neither the \"from_inclusive\" nor \"to_inclusive\" value is \"null\", then the \"to_inclusive\" must be greater than or equal to the \"from_inclusive\" value. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule_idx, rule in group.rules :
          [
            for rk, rv in rule.ranges :
            "\t- Set \"${group_key}\", rule at index ${rule_idx}, range key \"${rk}\""
            if(
              // If one is null, that's fine
              rv.from_inclusive == null ? false : (
                rv.to_inclusive == null ? false : (
                  // They're both non-null, so if the to value is below the from value, that's a violation
                  rv.to_inclusive < rv.from_inclusive
                )
              )
            )
          ]
        ]
      ]))
    }"
  }

  // Ensure that the "discretes" field is a map or object
  validation {
    condition = 0 == length([
      for group_key, group in var.rule_sets :
      null
      if length([
        for rule in group.rules :
        null
        // It's a problem if the discretes field isn't a map or object
        if !can(keys(rule.discretes))
      ]) > 0
    ])
    error_message = "For all rules in a given set, the `discretes` field must be a map/object. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule in group.rules :
          "\t- Set \"${group_key}\" (type: ${
            rule.discretes == null ? "null" : can(length(rule.discretes)) ? (
              // It's either a map, object, list, set, or string
              can(keys(rule.discretes)) ? (
                // It has keys, so it's either a map or object
                can(tomap(rule.discretes)) ? "map" : "object"
                ) : (
                // It doen't have keys, so it's a list, set, or string
                can(flatten(rule.discretes)) ? (
                  // It can be flattened, so it's a list or set
                  can(coalescelist(rule.discretes, [null])) ? "list" : "set"
                ) : "string"
              )
              ) : (
              // It's either a number or a bool
              can(tobool(rule.discretes)) ? "bool" : "number"
            )
          })"
        ]
      ]))
    }"
  }

  // Ensure that each discrete value is a bool, string, number, or null
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group.rules :
        [
          for dk, dv in rule.discretes :
          null
          if !contains(["bool", "string", "number", "null"], dv == null ? "null" : can(length(dv)) ? (
            // It's either a map, object, list, set, or string
            can(keys(dv)) ? (
              // It has keys, so it's either a map or object
              can(tomap(dv)) ? "map" : "object"
              ) : (
              // It doen't have keys, so it's a list, set, or string
              can(flatten(dv)) ? (
                // It can be flattened, so it's a list or set
                can(coalescelist(dv, [null])) ? "list" : "set"
              ) : "string"
            )
            ) : (
            // It's either a number or a bool
            can(tobool(dv)) ? "bool" : "number"
          ))
        ]
      ]
    ]))
    error_message = "For all rules in a given set, all values of all key/value pairs in the `discretes` field must be a bool, string, number, or null. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule_idx, rule in group.rules :
          [
            for dk, dv in rule.discretes :
            "\t- Set \"${group_key}\", rule at index ${rule_idx}, discrete key \"${dk}\" (type: ${
              dv == null ? "null" : can(length(dv)) ? (
                // It's either a map, object, list, set, or string
                can(keys(dv)) ? (
                  // It has keys, so it's either a map or object
                  can(tomap(dv)) ? "map" : "object"
                  ) : (
                  // It doen't have keys, so it's a list, set, or string
                  can(flatten(dv)) ? (
                    // It can be flattened, so it's a list or set
                    can(coalescelist(dv, [null])) ? "list" : "set"
                  ) : "string"
                )
                ) : (
                // It's either a number or a bool
                can(tobool(dv)) ? "bool" : "number"
            )})"
            if !contains(["bool", "string", "number", "null"], dv == null ? "null" : can(length(dv)) ? (
              // It's either a map, object, list, set, or string
              can(keys(dv)) ? (
                // It has keys, so it's either a map or object
                can(tomap(dv)) ? "map" : "object"
                ) : (
                // It doen't have keys, so it's a list, set, or string
                can(flatten(dv)) ? (
                  // It can be flattened, so it's a list or set
                  can(coalescelist(dv, [null])) ? "list" : "set"
                ) : "string"
              )
              ) : (
              // It's either a number or a bool
              can(tobool(dv)) ? "bool" : "number"
              )
            )
          ]
        ]
      ]))
    }"
  }

  // Ensure that all items have the same discrete keys
  validation {
    condition = 0 == length([
      for group_key, group in var.rule_sets :
      null
      if length(group.rules) == 0 ? false : length([
        for idx in range(1, length(group.rules)) :
        null
        // It's a problem if the keys don't match
        if sort(keys(group.rules[idx].discretes)) != sort(keys(group.rules[0].discretes))
      ]) > 0
    ])
    error_message = "For all rules in a given set, the keys in the `discretes` field of each rule must be consistent. The input does not meet this requirement:\n${
      join("\n", [
        for group_key, group in var.rule_sets :
        "\t- Set \"${group_key}\" (some, but not all, rules have these discrete keys: ${
          join(", ", [
            for discrete_key in sort(
              setsubtract(
                distinct(
                  flatten([
                    for rule in group.rules :
                    keys(rule.discretes)
                  ])
                ),
                setintersection(concat([[]], [
                  for rule in group.rules :
                  keys(rule.discretes)
                ])...)
              )
            ) :
            "\"${discrete_key}\""
            ]
          )
        })"
        if length(setsubtract(
          distinct(
            flatten([
              for rule in group.rules :
              keys(rule.discretes)
            ])
          ),
          setintersection(concat([[]], [
            for rule in group.rules :
            keys(rule.discretes)
          ])...)
        )) > 0
      ])
    }"
  }

  // Ensure that for all base2-aligned ranges, the size is a power of 2
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group.rules :
        [
          for rk, rv in rule.ranges :
          null
          if !contains(group.base2_align_range_keys, rk) ? false : (
            pow(2, floor(log(rv.to_inclusive - rv.from_inclusive + 1, 2))) != rv.to_inclusive - rv.from_inclusive + 1
          )
        ]
      ]
    ]))
    error_message = "For each rule, all base2-aligned ranges must have a range size that is a power of 2. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule_idx, rule in group.rules :
          [
            for rk, rv in rule.ranges :
            "\t- Set \"${group_key}\", rule at index ${rule_idx}, range key \"${rk}\" (range size is ${rv.to_inclusive - rv.from_inclusive + 1}, log2 of this is ${log(rv.to_inclusive - rv.from_inclusive + 1, 2)}, which should be a whole number)"
            if !contains(group.base2_align_range_keys, rk) ? false : (
              pow(2, floor(log(rv.to_inclusive - rv.from_inclusive + 1, 2))) != rv.to_inclusive - rv.from_inclusive + 1
            )
          ]
        ]
      ]))
    }"
  }

  // Ensure that for all base2-aligned ranges, the from_inclusive value is aligned to the range size.
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group.rules :
        [
          for rk, rv in rule.ranges :
          null
          if !contains(group.base2_align_range_keys, rk) ? false : (
            rv.from_inclusive % (rv.to_inclusive - rv.from_inclusive + 1) != 0
          )
        ]
      ]
    ]))
    error_message = "For each rule, all base2-aligned ranges must have a \"from_inclusive\" value that is aligned according to the size of the range. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule_idx, rule in group.rules :
          [
            for rk, rv in rule.ranges :
            "\t- Set \"${group_key}\", rule at index ${rule_idx}, range key \"${rk}\" (range size is ${rv.to_inclusive - rv.from_inclusive + 1}, \"from_to\" value of ${rv.from_inclusive} is not a multiple of this)"
            if !contains(group.base2_align_range_keys, rk) ? false : (
              rv.from_inclusive % (rv.to_inclusive - rv.from_inclusive + 1) != 0
            )
          ]
        ]
      ]))
    }"
  }

  // Ensure that for all base2-aligned ranges, there are no null from/to values.
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group.rules :
        [
          for rk, rv in rule.ranges :
          null
          if !contains(group.base2_align_range_keys, rk) ? false : rv.from_inclusive == null ? true : rv.to_inclusive == null
        ]
      ]
    ]))
    error_message = "For each rule, no base2-aligned ranges can have \"null\" values for the \"from_inclusive\" or \"to_inclusive\" fields. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule_idx, rule in group.rules :
          [
            for rk, rv in rule.ranges :
            "\t- Set \"${group_key}\", rule at index ${rule_idx}, range key \"${rk}\" (null values: ${join(", ", flatten([rv.from_inclusive == null ? ["from_inclusive"] : [], rv.to_inclusive == null ? ["to_inclusive"] : []]))})"
            if !contains(group.base2_align_range_keys, rk) ? false : rv.from_inclusive == null ? true : rv.to_inclusive == null
          ]
        ]
      ]))
    }"
  }

  // Ensure that for all base2-aligned ranges, there are rules that are missing a range that another rule has
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group.rules :
        null
        if length(setsubtract(distinct(flatten([
          for rule2 in group.rules :
          [
            for rk in keys(rule2.ranges) :
            rk
            if contains(group.base2_align_range_keys, rk)
          ]
        ])), keys(rule.ranges))) > 0
      ]
    ]))
    error_message = "For each set, all rules must have the same base2-aligned ranges. The input does not meet this requirement:\n${
      join("\n", flatten([
        for group_key, group in var.rule_sets :
        [
          for rule_idx, rule in group.rules :
          "\t- Set \"${group_key}\", rule at index ${rule_idx} (missing base2-aligned range keys found in other rules in the same set: ${join(", ", [
            for rk in sort(setsubtract(distinct(flatten([
              for rule2 in group.rules :
              [
                for rk in keys(rule2.ranges) :
                rk
                if contains(group.base2_align_range_keys, rk)
              ]
            ])), keys(rule.ranges))) :
            "\"${rk}\""
          ])})"
          if length(setsubtract(distinct(flatten([
            for rule2 in group.rules :
            [
              for rk in keys(rule2.ranges) :
              rk
              if contains(group.base2_align_range_keys, rk)
            ]
          ])), keys(rule.ranges))) > 0
        ]
      ]))
    }"
  }

  // Ensure there aren't too many range keys
  validation {
    condition = 0 == length([
      for group_key, group in var.rule_sets :
      null
      if length(distinct(flatten([
        for rule in group.rules :
        keys(rule.ranges)
      ]))) > local.max_number_of_ranges
    ])
    error_message = "For each rule set, there can be no more than ${local.max_number_of_ranges} distinct range keys in the entire set. The input does not meet this requirement:\n${
      join("\n", [
        for group_key, group in var.rule_sets :
        "\t- Set \"${group_key}\" has ${length(distinct(flatten([
          for rule in group.rules :
          keys(rule.ranges)
        ])))} range keys"
        if length(distinct(flatten([
          for rule in group.rules :
          keys(rule.ranges)
        ]))) > local.max_number_of_ranges
    ])}"
  }
}
