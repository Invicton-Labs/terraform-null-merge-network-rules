variable "rule_sets" {
  nullable = false
  type = map(list(object({
    egress     = bool
    allow      = bool
    protocol   = any
    cidr_block = string
    from_port  = optional(number, null)
    to_port    = optional(number, null)
    icmp_type  = optional(string, null)
    icmp_code  = optional(number, null)
    metadata   = optional(any, null)
  })))

  // Verify that the protocol is either a string or a number
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group :
        null
        if !contains(["string", "number"], rule.protocol == null ? "null" : can(length(rule.protocol)) ? (
          // It's either a map, object, list, set, or string
          can(keys(rule.protocol)) ? (
            // It has keys, so it's either a map or object
            can(tomap(rule.protocol)) ? "map" : "object"
            ) : (
            // It doen't have keys, so it's a list, set, or string
            can(flatten(rule.protocol)) ? (
              // It can be flattened, so it's a list or set
              can(coalescelist(rule.protocol, [null])) ? "list" : "set"
            ) : "string"
          )
          ) : (
          // It's either a number or a bool
          can(tobool(rule.protocol)) ? "bool" : "number"
        ))
      ]
    ]))
    error_message = "For each rule, the `protocol` must be either a string or a number. The input does not meet this requirement:\n${join("\n", flatten([
      for group_key, group in var.rule_sets :
      [
        for idx, rule in group :
        "\t- Set \"${group_key}\", rule at index ${idx} (value: \"${rule.protocol == null || !can(tostring(rule.protocol)) ? jsonencode(rule.protocol) : rule.protocol}\")"
        if !contains(["string", "number"], rule.protocol == null ? "null" : can(length(rule.protocol)) ? (
          // It's either a map, object, list, set, or string
          can(keys(rule.protocol)) ? (
            // It has keys, so it's either a map or object
            can(tomap(rule.protocol)) ? "map" : "object"
            ) : (
            // It doen't have keys, so it's a list, set, or string
            can(flatten(rule.protocol)) ? (
              // It can be flattened, so it's a list or set
              can(coalescelist(rule.protocol, [null])) ? "list" : "set"
            ) : "string"
          )
          ) : (
          // It's either a number or a bool
          can(tobool(rule.protocol)) ? "bool" : "number"
        ))
      ]
    ]))}"
  }

  // Verify that the "allow" value is a valid boolean
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group :
        null
        if rule.allow == null
      ]
    ]))
    error_message = "For each rule, the `allow` value must be true or false (not null). The input does not meet this requirement:\n${join("\n", flatten([
      for group_key, group in var.rule_sets :
      [
        for idx, rule in group :
        "\t- Set \"${group_key}\", rule at index ${idx}"
        if rule.allow == null
      ]
    ]))}"
  }

  // Verify that the "egress" value is a valid boolean
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group :
        null
        if rule.egress == null
      ]
    ]))
    error_message = "For each rule, the `egress` value must be true or false (not null). The input does not meet this requirement:\n${join("\n", flatten([
      for group_key, group in var.rule_sets :
      [
        for idx, rule in group :
        "\t- Set \"${group_key}\", rule at index ${idx}"
        if rule.egress == null
      ]
    ]))}"
  }

  // Verify that the "cidr_block" value is valid
  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in group :
        null
        if rule.cidr_block == null ? true : !can(cidrhost(rule.cidr_block, 0))
      ]
    ]))
    error_message = "For each rule, the `cidr_block` value must be a valid CIDR block. The input does not meet this requirement:\n${join("\n", flatten([
      for group_key, group in var.rule_sets :
      [
        for idx, rule in group :
        "\t- Set \"${group_key}\", rule at index ${idx} (value: \"${rule.cidr_block == null ? "null" : rule.cidr_block}\")"
        if rule.cidr_block == null ? true : !can(cidrhost(rule.cidr_block, 0))
      ]
    ]))}"
  }
}
