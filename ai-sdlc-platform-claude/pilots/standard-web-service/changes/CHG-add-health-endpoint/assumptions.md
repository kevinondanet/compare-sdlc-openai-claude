---
assumptions:
- id: ASM-001
  text: The load balancer treats any non-2xx status as unhealthy.
  owner: platform operations
  validated: true
open_questions:
- id: OQ-001
  question: Should /health require the internal network ACL like the admin routes?
  status: open
  blocking: false
  owner: service-lead
---
# Assumptions and open questions

Assumptions are visible bets; open questions marked `blocking: true` stop G0.
