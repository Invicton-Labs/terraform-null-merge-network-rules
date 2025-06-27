output "squashed_rule_sets" {
  value = local.squashed
}

output "debug" {
  value = module.squash_ipv4.debug
}