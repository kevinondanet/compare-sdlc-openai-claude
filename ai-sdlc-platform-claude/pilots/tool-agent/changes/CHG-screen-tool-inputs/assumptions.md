---
assumptions:
- id: ASM-001
  text: Customer notes may be written by third parties (marketplace sellers) and are
    untrusted input.
  owner: security
  validated: true
- id: ASM-002
  text: The platform screener's pattern families cover the injection phrasing seen in the
    agent-baseline campaign; new phrasing is added to the campaign datasets, not to the
    assistant.
  owner: security
  validated: true
- id: ASM-003
  text: The recipient-on-file rule is an acceptable stand-in for a human approver for
    outbound e-mail; anything else stays tier 4.
  owner: assistant-lead
  validated: false
open_questions:
- id: OQ-001
  question: Should quarantined messages be forwarded to a human queue automatically?
  status: resolved
  blocking: false
  owner: support operations
  decision: Not in this change; the audit entry is enough for the pilot.
---
# Assumptions and open questions

ASM-003 is the visible bet: rule-based approval for a tier-3 action.
