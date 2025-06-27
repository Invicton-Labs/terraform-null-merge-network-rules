output "debug" {
  value = {
    # d01_squash_input  = local.with_cidr_ranges
    d02_squash_debug = module.rule_squash.debug
    #d03_squash_output = module.rule_squash.squashed_rule_sets
  }
}

output "squashed_rule_sets" {
  description = "The squashed rule sets."
  value       = local.with_cidr_prefix
}
