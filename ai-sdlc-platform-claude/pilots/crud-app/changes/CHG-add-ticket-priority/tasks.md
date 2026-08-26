---
tasks:
- id: TASK-001
  title: Priority field with validation, default and legacy loading
  description: Add the priority field to Ticket, validate_priority, the normal default in
    create/from_rows and validation in update.
  requirement_ids:
  - REQ-001
  - REQ-002
  depends_on: []
  verification:
    command: python3 -m unittest -q tests.test_priority.PriorityFieldTest
    expect_exit_code: 0
  status: pending
  files:
  - tickets/service.py
  - tests/test_priority.py
- id: TASK-002
  title: Priority-sorted listing
  description: TicketService.list(sort="priority") orders urgent..low with a stable sort
    and bounded cost.
  requirement_ids:
  - REQ-003
  - REQ-005
  depends_on:
  - TASK-001
  verification:
    command: python3 -m unittest -q tests.test_priority.PrioritySortTest
    expect_exit_code: 0
  status: pending
  files:
  - tickets/service.py
- id: TASK-003
  title: CLI --priority flag and --sort priority
  description: Extend create/update/list with the priority options; invalid values exit 2.
  requirement_ids:
  - REQ-004
  depends_on:
  - TASK-001
  verification:
    command: python3 -m unittest -q tests.test_priority.PriorityCliTest
    expect_exit_code: 0
  status: pending
  files:
  - tickets/cli.py
- id: TASK-004
  title: Whole test suite (unit, integration, contract, e2e, architecture)
  description: Every layer of the portfolio passes on the merged change.
  requirement_ids:
  - REQ-001
  - REQ-002
  - REQ-003
  - REQ-004
  - REQ-005
  depends_on:
  - TASK-001
  - TASK-002
  - TASK-003
  verification:
    command: python3 -m unittest -q
    expect_exit_code: 0
  status: pending
  files:
  - tests/
---
# Tasks

Each task has an executable verification; the executor runs it inside the task's worktree
and again after the merge back.
