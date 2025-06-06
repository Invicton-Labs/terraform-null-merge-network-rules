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
    - `cidr_ipv4`: an IPv4 CIDR block for this rule (this is just a special type of `range`)
    - `discretes`: a map of discrete values for the rule, where the key is the descrete type (e.g. "protocol") and the value is the descrete value (e.g. "tcp").
    - `ranges`: a map of range objects, where the key is the range type (e.g. "ports") and the value is an object with a `from_inclusive` and `to_inclusive`. `null` values for `from_inclusive` or `to_inclusive` represent negative and positive infinity, respectively.
    - `metadata`: anything that your heart desires. When rules are merged/reduced, the final rules will contain the metadata of all rules that were reduced into that final rule. This is particularly helpful if you want to be able to generate text descriptions of what the final rules do, and this allows them to include descriptions or names of all of the rules that were reduced into it.
EOF
  nullable    = false
  type = map(
    object(
      {
        discrete_encapsulation = optional(map(map(list(any))), {})
        discrete_equivalents   = optional(map(map(list(any))), {})
        rules = optional(list(object({
          cidr_ipv4 = optional(string)
          discretes = optional(map(any), {})
          ranges = optional(map(object({
            from_inclusive = number
            to_inclusive   = number
          })), {})
          metadata = optional(map(any))
        })), [])
      }
    )
  )

  validation {
    condition = 0 == length(flatten([
      for group_key, group in var.rule_sets :
      [
        for rule in values(group.rules) :
        null
        // If any CIDR blocks are non-null and aren't valid CIDRs, that's a problem
        if rule.cidr_ipv4 == null ? false : !can(cidrhost(rule.cidr_ipv4, 0))
      ]
    ]))
    error_message = "For each rule, the `cidr_ipv4` value must either be `null` or be a valid CIDR block. The input does not meet this requirement: ${join(", ", [
      for group_key, group in var.rule_sets :
      "${group_key} - ${join(", ", [
        for rule_idx, rule in group.rules :
        "Rule: ${rule_idx} (${rule.cidr_ipv4})"
        if rule.cidr_ipv4 == null ? false : !can(cidrhost(rule.cidr_ipv4, 0))
      ])}"
      if length([
        for rule in values(group.rules) :
        null
        // If any CIDR blocks are non-null and aren't valid CIDRs, that's a problem
        if rule.cidr_ipv4 == null ? false : !can(cidrhost(rule.cidr_ipv4, 0))
      ]) > 0
    ])}"
  }
}
