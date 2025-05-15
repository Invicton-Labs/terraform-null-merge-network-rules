output "merged_rule_sets" {
  value = {
    for k, v in local.merged_rule_sets :
    k => v.rules
  }
}
