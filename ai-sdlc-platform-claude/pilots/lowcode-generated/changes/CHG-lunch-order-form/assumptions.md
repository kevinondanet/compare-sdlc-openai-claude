---
assumptions:
- id: ASM-001
  text: 'The primary users are: Team member; Office manager.'
  validated: true
  source: discovery
- id: ASM-002
  text: No personal or otherwise sensitive data is processed by this change.
  validated: false
  source: discovery
open_questions:
- id: OQ-001
  question: 'The success measure ''Fewer lunch-related emails'' has no number: what
    is the target value and when is it measured?'
  status: resolved
  blocking: false
  decision: Lunch-related emails to the office manager drop from 20 to under 5 per
    week, measured two months after launch
  resolved_at: '2026-08-26T06:10:43.294199Z'
- id: OQ-002
  question: Who is the accountable owner of this change?
  status: resolved
  blocking: true
  decision: Sam Ortiz, office manager (office-manager@example.com)
  resolved_at: '2026-08-26T06:10:43.294190Z'
- id: OQ-003
  question: '(constraints) Any hard constraints: deadlines, budget, technology that
    must or must not be used, regulations?'
  status: resolved
  blocking: false
  decision: 'None known: no deadline, no budget, standard-library Python only'
  resolved_at: '2026-08-26T06:10:43.294206Z'
- id: OQ-004
  question: (integrations) Which other systems, services or teams does this need to
    talk to or depend on?
  status: resolved
  blocking: false
  decision: 'None: the caterer receives the CSV export by email; no system integration'
  resolved_at: '2026-08-26T06:10:43.294212Z'
- id: OQ-005
  question: '[CQ-001] CHG-lunch-order-form contains the placeholder ''TBD'': what
    should it say?'
  status: resolved
  blocking: false
  decision: CSV
  resolved_at: '2026-08-26T06:10:43.294069Z'
- id: OQ-006
  question: '[CQ-002] REQ-003 contains the placeholder ''TBD'': what should it say?'
  status: resolved
  blocking: false
  decision: CSV
  resolved_at: '2026-08-26T06:10:43.294126Z'
- id: OQ-007
  question: '[CQ-003] SCN-003-01 contains the placeholder ''TBD'': what should it
    say?'
  status: resolved
  blocking: false
  decision: CSV
  resolved_at: '2026-08-26T06:10:43.294177Z'
- id: OQ-008
  question: '[CQ-008] CHG-lunch-order-form says ''quickly'': what is the measurable
    time limit?'
  status: resolved
  blocking: false
  decision: in under one minute
  resolved_at: '2026-08-26T06:10:43.294320Z'
- id: OQ-009
  question: '[CQ-009] CHG-lunch-order-form says ''some'': what is the exact number
    or bound?'
  status: resolved
  blocking: false
  decision: all
  resolved_at: '2026-08-26T06:10:43.294397Z'
- id: OQ-010
  question: '[CQ-010] REQ-001 says ''quickly'': what is the measurable time limit?'
  status: resolved
  blocking: false
  decision: in under one minute
  resolved_at: '2026-08-26T06:10:43.294420Z'
- id: OQ-011
  question: '[CQ-011] REQ-002 says ''some'': what is the exact number or bound?'
  status: resolved
  blocking: false
  decision: all
  resolved_at: '2026-08-26T06:10:43.294441Z'
- id: OQ-012
  question: '[CQ-012] SCN-001-01 says ''quickly'': what is the measurable time limit?'
  status: resolved
  blocking: false
  decision: in under one minute
  resolved_at: '2026-08-26T06:10:43.294485Z'
- id: OQ-013
  question: '[CQ-013] SCN-002-01 says ''some'': what is the exact number or bound?'
  status: resolved
  blocking: false
  decision: all
  resolved_at: '2026-08-26T06:10:43.294517Z'
- id: OQ-014
  question: '[CQ-014] No non-functional requirements are recorded: what are the performance,
    availability and security expectations?'
  status: resolved
  blocking: false
  decision: The system SHALL list and export 500 orders within 1 second
  resolved_at: '2026-08-26T06:10:43.294552Z'
- id: OQ-015
  question: '[CQ-015] What hard limits must it honour (deadline, budget, tech, rules)?'
  status: resolved
  blocking: false
  decision: Standard-library Python only; the Friday 10:00 cut-off is fixed; the caterer
    menu has at most 10 dishes
  resolved_at: '2026-08-26T06:10:43.294581Z'
---
# Assumptions and open questions

Assumptions are visible bets; open questions marked `blocking: true` stop G0.
