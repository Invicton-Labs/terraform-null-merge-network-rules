# Terraform - Merge Network Rules

This module contains several sub-modules, but no root module.


## generic-squash

This submodule is the heart of this tool. It accepts one or more sets of "rules", each of which consists of `discrete` values and `ranges`. Read the variable inputs descriptions for details.


## ipv4-squash

This is a wrapper for the `generic-squash` submodule, which implements support for IPv4 CIDR merging. Currently, it only handles IPv4 CIDR blocks.


## aws-network-acl-rule-squash

This is a wrapper for the `ipv4-squash` module, which accepts a format specific to AWS ACL Network Rules. Currently, it only handles IPv4 CIDR blocks.
