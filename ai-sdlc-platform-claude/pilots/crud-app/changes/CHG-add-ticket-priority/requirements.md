---
requirements:
- id: REQ-001
  text: WHEN a ticket is created or updated with a priority, the ticket service SHALL accept
    only low, normal, high or urgent and SHALL reject any other value with a validation error.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-001-01
    name: valid priority stored
    when: a ticket is created with priority high
    then: the stored ticket has priority high
  - id: SCN-001-02
    name: invalid priority rejected
    when: a ticket is created or updated with priority critical
    then: a validation error is raised and no ticket changes
  tags:
  - priority
- id: REQ-002
  text: WHEN a ticket is created without a priority, the ticket service SHALL assign the
    priority normal; rows stored before this change SHALL load with priority normal.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-002-01
    name: default priority
    when: a ticket is created without a priority or a legacy row without priority is loaded
    then: the ticket has priority normal
  tags:
  - priority
- id: REQ-003
  text: WHEN tickets are listed sorted by priority, the ticket service SHALL order them urgent,
    high, normal, low and SHALL keep creation order within one priority.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-003-01
    name: priority order
    given: tickets with priorities low, urgent, normal and high exist
    when: tickets are listed with sort priority
    then: they are returned in the order urgent, high, normal, low
  - id: SCN-003-02
    name: stable within a priority
    given: two high tickets created in sequence and a status filter
    when: tickets are listed with sort priority
    then: the earlier high ticket precedes the later one and the filter still applies
  tags:
  - priority
- id: REQ-004
  text: WHEN the tickets command line receives --priority, it SHALL pass the value to the
    service and SHALL exit with status 2 on an invalid value without writing the store.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-004-01
    name: CLI flag stored
    when: tickets create is run with --priority urgent
    then: the printed record has priority urgent and list --sort priority returns it first
  - id: SCN-004-02
    name: CLI rejects invalid value
    when: tickets create is run with --priority sev1
    then: the process exits 2 with a message naming the allowed values and no store is written
  tags:
  - cli
- id: REQ-005
  text: The ticket service SHALL list 10,000 tickets sorted by priority within 200 ms.
  kind: non_functional
  priority: must
  scenarios:
  - id: SCN-005-01
    name: sort cost bound
    given: 10,000 tickets with mixed priorities
    when: they are listed with sort priority
    then: the call returns within 200 ms with urgent tickets first
  tags:
  - performance
---
# Requirements

Priorities are a closed vocabulary with an explicit rank (see ADR-0001). The CLI is the
only interface (IFC-001); the JSON store format gains one optional key.
