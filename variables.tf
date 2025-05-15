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
          cidr_ipv4  = optional(string, null)
        })), [])
      }
    )
  )
}

// TODO: validate CIDR block format
