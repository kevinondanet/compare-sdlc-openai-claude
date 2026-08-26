# Pilot 3 — AI agent with tool access

Project class: **ai_agent** (`risk_class: ai_agent`). The change package
`changes/CHG-support-assistant-tools` gives a customer-support assistant two tools with
an allow-list, an approval token for refunds, injection screening of tool output and an
audit line per call. Gate depth profile: every gate deep — G4 requires a complete PyRIT
campaign (`templates/pyrit/campaigns/agent-baseline.yaml`), the safety regression suite
and no drift between the declared tool/data manifest and the audit log; G6 needs two
approvals.

Walk-through (inside a git repository with a commit):

```
aisdlc intake readiness CHG-support-assistant-tools
aisdlc plan check CHG-support-assistant-tools
aisdlc run change CHG-support-assistant-tools --runner dry --yes
aisdlc security campaign run templates/pyrit/campaigns/agent-baseline.yaml --package CHG-support-assistant-tools
aisdlc gate evaluate CHG-support-assistant-tools
```
