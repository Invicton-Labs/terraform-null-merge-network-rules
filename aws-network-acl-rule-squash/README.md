# AWS Network ACL Rules (with rule numbers)

This submodule merges AWS Network ACL rules into the minimum set of rules that is functionally identical. It handles rule numbering to ensure that rule priorities are not violated.

When using Network ACLs, it is usually the case that there will be different "groups" of rules based on whether they are allow or deny rules. For example:
- Your lowest priority rule (highest rule number) might be a default DENY on 0.0.0.0/0 and all ports so that all traffic is blocked unless explicitly allowed. 
- Then you might have multiple higher priority rule that ALLOW traffic on specific ports to specific subnets in your VPC; in complex configurations, there are often rules in this grouping that can be squashed or de-duplicated.
- Finally, you may have some super-secret resources in your VPC that you want to DENY access to, even though traffic is allowed to other IPs in the same subnet. For this, you'll have the highest-priority rules to deny this access to matching CIDRs.

This module is intended for this type of use, and takes a list of "rule sets". Each "rule set" is a group of rules that have the same priority and are all "ALLOW" or all "DENY" rules, and therefore can be squashed with no adverse consequences. Rule sets are provided in order of descending priority.

The output of this module is the minimum coverage set of rules that provide identical functionality/restrictions. Each rule will have a rule number assigned, ensuring that the priority of the input rule sets is maintained.

For an example, see the `tests` subdirectory.
