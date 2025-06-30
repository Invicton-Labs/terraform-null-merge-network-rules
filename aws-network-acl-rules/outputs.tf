output "squashed_rule_sets" {
  value = local.squashed
}

output "debug" {
  value = {
    squash_ipv4 = module.squash_ipv4.debug
    # squashed_rule_sets_raw = module.squash_ipv4.squashed_rule_sets
  }
}

