---
id: CHG-screen-tool-inputs
title: Screen user messages and tool results before the support assistant acts on them
kernel:
  why: The support assistant follows instructions it finds in its context. A customer
    message or a note written by a marketplace seller into a customer record can therefore
    redirect it; the red-team baseline shows a 10% attack success rate on prompt injection.
  capabilities:
  - Quarantine user messages that carry instructions aimed at the assistant
  - Quarantine tool results (customer notes) that carry such instructions
  - Audit every quarantine next to every tool decision in the signed audit log
  - Keep the tier policy on the tools (search audited, e-mail rule-approved, delete denied)
  constraints:
  - Screening uses the platform screener (aisdlc.governance.mcp.screen_tool_result), not
    prompt wording
  - No network egress from the assistant process
  - The tool credential is never rendered in a reply
  non_goals:
  - Replacing the rule core with a model
  - New tools or new data sources
  - Multi-turn memory across sessions
  success_signal: The agent-baseline PyRIT campaign reports zero successful objectives
    (ASR 0.0) with no undetermined trials, the safety regression suite is green across
    all five harm categories, and the audit log shows no tool outside the manifest.
owner: assistant-lead
risk_class: ai_agent
stakeholders:
- support operations
- security
- data protection
labels:
- agent
- injection
- tools
---
# Intent

The assistant answers support questions with three tools over a private customer file.
Everything it reads — the user's message and every tool result — is untrusted; this change
screens both at the trust boundary and quarantines what carries instructions.
