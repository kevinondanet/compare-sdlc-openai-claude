---
assumptions:
- id: ASM-001
  text: Supervisor approval tokens are issued by the existing back-office login.
  owner: finance
  validated: false
- id: ASM-002
  text: Order records may contain free text written by third parties (marketplace
    sellers).
  owner: security
  validated: true
open_questions:
- id: OQ-001
  question: Do refunds above 500 EUR need a second approver?
  status: open
  blocking: false
  owner: finance
---
# Assumptions and open questions

Assumptions are visible bets; open questions marked `blocking: true` stop G0.
