output "debug" {
  value = {
    d00_rule_sets                        = var.rule_sets
    d01_equivalencies                    = local.equivalencies
    d02_with_encapsulations              = local.with_encapsulations
    d03_forward_pass_encapsulate         = local.forward_pass_encapsulate
    d04_reverse_pass_encapsulate         = local.reverse_pass_encapsulate
    d05_range_keys                       = local.range_keys
    d06_discrete_keys                    = local.discrete_keys
    d07_range_0_with_sort_keys           = local.range_0_with_sort_keys
    d08_range_0_sort_keys                = local.range_0_sort_keys
    d09_range_0_sorted                   = local.range_0_sorted
    d10_range_0_next_contiguous          = local.range_0_next_contiguous
    d11_range_0_contiguous_forward_count = local.range_0_contiguous_forward_count
    d12_range_0_contiguous_base2         = local.range_0_contiguous_base2
    d13_range_0_squashed                 = local.range_0_squashed
    d14_range_1_with_sort_keys           = local.range_1_with_sort_keys
    d15_range_1_sort_keys                = local.range_1_sort_keys
    d16_range_1_sorted                   = local.range_1_sorted
    d17_range_1_next_contiguous          = local.range_1_next_contiguous
    d18_range_1_contiguous_forward_count = local.range_1_contiguous_forward_count
    d19_range_1_contiguous_base2         = local.range_1_contiguous_base2
    d20_range_1_squashed                 = local.range_1_squashed
  }
}

output "squashed_rule_sets" {
  description = "The squashed rule sets."
  value       = local.sorted_squashed
}
