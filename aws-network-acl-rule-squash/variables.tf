variable "rule_sets" {
  description = <<EOF
A list of rule groups. Rule numbers in the output rules start at 1, and are prepared in the same order that the inputs are provided.

Each rule group has:
- A `rule_action`, which can be "allow" or "deny" (whether it's a group of allow or deny rules)
- A list of rules to be squashed
EOF
  nullable    = false
  type = list(object({
    rule_action = string
    rules = list(object({
      protocol   = any
      cidr_block = string
      from_port  = optional(number, null)
      to_port    = optional(number, null)
      icmp_type  = optional(number, null)
      icmp_code  = optional(number, null)
      metadata   = optional(any, null)
    }))
  }))
}

variable "egress" {
  description = "Whether or not it's a group of egress rules. This is a separate variable because ingress and egress rules use separate rule number indexing (no crossover), so there should never be both ingress and egress rules merged in this module at the same time."
  nullable    = false
  type        = bool
}

module "squash" {
  source = "../aws-network-acl-rule-squash-no-numbers"
  rule_sets = {
    for rule_set_idx, rule_set in var.rule_sets :
    format("%020d", rule_set_idx) => [
      for rule in rule_set.rules :
      {
        egress      = var.egress
        rule_action = rule_set.rule_action
        protocol    = rule.protocol
        cidr_block  = rule.cidr_block
        from_port   = rule.from_port
        to_port     = rule.to_port
        icmp_type   = rule.icmp_type
        icmp_code   = rule.icmp_code
        metadata    = rule.metadata
      }
    ]
  }
}
