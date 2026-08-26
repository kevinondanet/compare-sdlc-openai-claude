---
name: aisdlc-$slug
description: $description
tools: [$tools]
---

# $title agent

$description

## Steps

$steps

## Constraints

- Only the canonical files under `changes/<CHG-id>/` hold workflow state; read them first.
- $edit_rule
- $run_rule
- Tier 3 actions (push, PR, package install) need approval; tier 4 actions (deploy,
  secrets, IAM, data deletion) are denied.
- Handoff: $handoff
