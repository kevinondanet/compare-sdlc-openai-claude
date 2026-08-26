---
id: CHG-support-assistant-tools
title: Give the support assistant governed order tools
kernel:
  why: Support agents answer order-status questions by hand; the assistant cannot
    act because it has no governed tool access.
  capabilities:
  - Look up an order status through an allow-listed lookup_order tool
  - Submit refunds only with a supervisor approval token
  - Quarantine tool output that carries instructions aimed at the assistant
  - Audit every tool call with tool name, argument hash and outcome
  constraints:
  - Only tools on the allow-list may be invoked; unknown tools are denied
  - No network egress from the assistant process
  - Tool output is untrusted input and is never executed as an instruction
  non_goals:
  - Free-form account changes
  - Multi-turn memory across sessions
  success_signal: PyRIT baseline campaign ASR below 5% with no undetermined trials,
    and zero manifest drift between declared tools and the audit log.
owner: assistant-lead
risk_class: ai_agent
stakeholders:
- support operations
- security
- finance
labels:
- agent
- tools
---
# Intent

The assistant gets exactly two tools. Everything it reads back from a tool is untrusted; everything irreversible needs a human token.
