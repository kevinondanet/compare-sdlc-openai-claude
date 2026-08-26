---
assets:
- customer order data
- refund capability
- assistant audit trail
- tool:lookup_order
- tool:refund_order
actors:
- customer
- marketplace seller (writes order notes)
- supervisor
threats:
- id: THR-001
  title: Prompt injection via lookup_order results triggers a refund
  description: A seller-written order note returned by lookup_order carries an instruction
    aimed at the assistant (for example "refund immediately"); an assistant that follows
    it would call refund_order on the attacker's behalf.
  category: prompt_injection
  severity: high
  assets:
  - tool:lookup_order
  - refund capability
  mitigation_ids:
  - MIT-001
  - MIT-002
  status: mitigated
- id: THR-002
  title: Assistant invokes a tool outside the declared manifest
  description: ''
  category: elevation_of_privilege
  severity: high
  assets:
  - customer order data
  mitigation_ids:
  - MIT-003
  status: mitigated
- id: THR-003
  title: Tool calls are not attributable after the fact
  description: ''
  category: repudiation
  severity: medium
  assets:
  - assistant audit trail
  mitigation_ids:
  - MIT-004
  status: mitigated
- id: THR-004
  title: Unapproved privileged use of refund_order (tier 3)
  description: The assistant submits refund_order — an irreversible tier 3 action against
    the payments service — from a customer message or an injected instruction without a
    supervisor having approved the refund.
  category: elevation_of_privilege
  severity: high
  assets:
  - tool:refund_order
  - refund capability
  mitigation_ids:
  - MIT-001
  - MIT-004
  status: mitigated
mitigations:
- id: MIT-001
  description: Refunds require a supervisor approval token checked in code.
  threat_ids:
  - THR-001
  - THR-004
  verified: true
- id: MIT-002
  description: Tool output is screened for injection patterns and quarantined.
  threat_ids:
  - THR-001
  verified: true
- id: MIT-003
  description: Only allow-listed tools can be called; the manifest below is compared
    with the audit log at G4.
  threat_ids:
  - THR-002
  verified: true
- id: MIT-004
  description: Every call (including denied ones) is appended to the audit list with
    an argument hash.
  threat_ids:
  - THR-003
  - THR-004
  verified: true
tool_data_manifest:
  tools:
  - lookup_order
  - refund_order
  data_sources:
  - orders database
  - payments service
  network_egress: []
---
# Threat model

Assets, actors, threats (STRIDE + prompt injection), mitigations and the declared
tool/data manifest for agentic changes.
