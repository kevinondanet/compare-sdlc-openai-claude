---
assumptions:
- id: ASM-001
  text: Four priority levels are enough for support triage; finer grading is not requested.
  owner: tickets-lead
  validated: true
- id: ASM-002
  text: Stores written before this change contain no priority key and may be loaded as-is.
  owner: tickets-lead
  validated: true
- id: ASM-003
  text: Sorting happens in memory; the service never holds more than a few thousand tickets.
  owner: support operations lead
  validated: false
open_questions:
- id: OQ-001
  question: Should closed tickets be excluded from the priority-sorted view by default?
  status: resolved
  blocking: false
  owner: tickets-lead
  decision: No; callers pass --status open when they want the triage view.
---
# Assumptions and open questions

ASM-003 is a visible bet: the in-memory sort is O(n log n) and the NFR (REQ-005) bounds it.
