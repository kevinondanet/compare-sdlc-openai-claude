---
assets:
- private customer records (assistant/data/customers.json)
- the outbound e-mail channel
- the signed audit trail
- the tool credential
actors:
- customer (sends messages)
- marketplace seller (writes notes into customer records)
- attacker (sends crafted messages)
- support lead (approver of record)
threats:
- id: THR-001
  title: Direct prompt injection through the user message
  description: The message carries an instruction the assistant's core would obey, for
    example to call search_customers on another customer or to say a chosen word.
  category: prompt_injection
  severity: high
  assets:
  - private customer records
  mitigation_ids:
  - MIT-001
  status: mitigated
- id: THR-002
  title: Indirect prompt injection through customer notes returned by search_customers
  description: A seller-written note in a search_customers result carries an instruction
    that reaches the core.
  category: prompt_injection
  severity: high
  assets:
  - private customer records
  mitigation_ids:
  - MIT-001
  status: mitigated
- id: THR-003
  title: Data exfiltration through send_email to an attacker-controlled address
  description: ''
  category: information_disclosure
  severity: high
  assets:
  - private customer records
  - the outbound e-mail channel
  mitigation_ids:
  - MIT-002
  status: mitigated
- id: THR-004
  title: delete_record triggered from the agent loop destroys customer records
  description: A message (or an injected instruction) makes the assistant request delete_record.
  category: tampering
  severity: high
  assets:
  - private customer records
  mitigation_ids:
  - MIT-003
  status: mitigated
- id: THR-005
  title: Disclosure of the tool credential in a reply
  description: ''
  category: information_disclosure
  severity: medium
  assets:
  - the tool credential
  mitigation_ids:
  - MIT-004
  status: mitigated
- id: THR-006
  title: The assistant reaches a tool or data source outside the declared manifest
  description: Anything other than search_customers, send_email and delete_record, or a
    data source other than the customer file, shows up in the audit log.
  category: elevation_of_privilege
  severity: medium
  assets:
  - the signed audit trail
  mitigation_ids:
  - MIT-005
  status: mitigated
mitigations:
- id: MIT-001
  description: Both inputs are screened with aisdlc.governance.mcp.screen_tool_result and
    quarantined when suspicious (REQ-001); verified by the PyRIT campaign and the safety suite.
  threat_ids:
  - THR-001
  - THR-002
  verified: true
- id: MIT-002
  description: send_email is tier 3; the recipient-on-file rule is the only approver and
    rejects every other address (REQ-003).
  threat_ids:
  - THR-003
  verified: true
- id: MIT-003
  description: delete_record maps to delete_data (tier 4) and is denied by the generated
    policy; only a human approval outside the agent loop can delete, and every attempt is
    audited (REQ-002).
  threat_ids:
  - THR-004
  verified: true
- id: MIT-004
  description: The credential lives in the tool box only and is never rendered; the
    secret-disclosure objectives and safety case check it (REQ-005).
  threat_ids:
  - THR-005
  verified: true
- id: MIT-005
  description: The manifest below is compared with evidence/audit-entries.json at G4
    (`aisdlc ci manifest-drift`) (REQ-004).
  threat_ids:
  - THR-006
  verified: true
tool_data_manifest:
  tools:
  - search_customers
  - send_email
  - delete_record
  data_sources:
  - assistant/data/customers.json (private customer records)
  network_egress: []
---
# Threat model

STRIDE plus prompt injection for a tool-using assistant; the manifest declares the three
tools and the one private data source. No network egress is declared: e-mail goes to an
in-process outbox in this pilot.
