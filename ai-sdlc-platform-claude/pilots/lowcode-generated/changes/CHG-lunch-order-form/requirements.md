---
requirements:
- id: REQ-001
  text: The system SHALL allow team members to submit a lunch order in a form in under
    one minute
  kind: functional
  priority: must
  scenarios:
  - id: SCN-001-01
    name: draft acceptance
    given: Team member is using the system
    when: Team member attempts to submit a lunch order in a form in under one minute
    then: '''Team members can submit a lunch order in a form in under one minute''
      is achieved and the result is visible to Team member'
    raw: ''
  rationale: 'Desired outcome stated during discovery: Team members can submit a lunch
    order in a form quickly'
  tags:
  - discovery
- id: REQ-002
  text: The system SHALL allow the office manager to see all orders in a table
  kind: functional
  priority: must
  scenarios:
  - id: SCN-002-01
    name: draft acceptance
    given: Team member is using the system
    when: Team member attempts to see all orders in a table
    then: '''The office manager can see all orders in a table'' is achieved and the
      result is visible to Team member'
    raw: ''
  rationale: 'Desired outcome stated during discovery: The office manager can see
    some orders in a table'
  tags:
  - discovery
- id: REQ-003
  text: The system SHALL allow the office manager to export the table as CSV
  kind: functional
  priority: must
  scenarios:
  - id: SCN-003-01
    name: draft acceptance
    given: Team member is using the system
    when: Team member attempts to export the table as CSV
    then: '''The office manager can export the table as CSV'' is achieved and the
      result is visible to Team member'
    raw: ''
  rationale: 'Desired outcome stated during discovery: The office manager can export
    the table as TBD'
  tags:
  - discovery
- id: REQ-004
  text: The system SHALL NOT accept an order after the Friday cut-off
  kind: functional
  priority: must
  scenarios:
  - id: SCN-004-01
    name: draft acceptance
    when: any user or process attempts to accept an order after the Friday cut-off
    then: the system refuses and records the attempt
    raw: ''
  rationale: Stated as something the system must never do.
  tags:
  - discovery
  - safety
- id: REQ-005
  text: The system SHALL list and export 500 orders within 1 second
  kind: non_functional
  priority: must
  scenarios:
  - id: SCN-005-01
    name: clarified
    when: 500 orders have been submitted
    then: listing and exporting them completes within 1 second
    raw: ''
  tags:
  - clarified
---
# Requirements

Each requirement in the front-matter uses SHALL/MUST or an EARS form and has at
least one WHEN/THEN scenario. Use this body for narrative and rationale.
