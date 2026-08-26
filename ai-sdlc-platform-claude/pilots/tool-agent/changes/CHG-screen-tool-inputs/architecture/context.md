# Architecture context

```
user message ──► screen_tool_result ──► SupportAssistant.respond
                                          │  intents: lookup / e-mail / delete
                                          ▼
                              Governance.check (PolicyEnforcer, tiers)
                               search:1 audited · send_email:3 rule approval · delete_data:4 deny
                                          │ allowed
                                          ▼
                                  ToolBox.invoke ──► ToolEventRecorder (red team)
                                          │
                              tool result ──► screen_tool_result ──► context
                                          │
                                AuditTrail (HMAC JSON lines) ──► evidence/audit*.json
```

Components: `assistant/agent.py` (rule core + screening), `assistant/governance.py`
(generated tier policy, recipient-on-file approval, signed audit trail),
`assistant/tools.py` (the three tools over `data/customers.json`), `assistant/target.py`
(PyRIT target factory), `assistant/safety_cases.py` (safety regression suite).
