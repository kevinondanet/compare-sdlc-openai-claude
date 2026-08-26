# AI-SDLC canonical artifacts

This project uses the AI-SDLC platform. Work happens in change packages under
`changes/<CHG-id>/`; the `aisdlc` CLI creates, validates and gates them. Slash commands
`/aisdlc-*` wrap each workflow step; the `aisdlc` skill holds the full workflow.

## Change package layout

$artifacts

## Workflow

$workflow

## Tool policy

$tool_policy

Governance hook: `$hook_command --role $role` screens every tool call (PreToolUse) and
records tier >= 1 calls (PostToolUse) into the audit evidence.
