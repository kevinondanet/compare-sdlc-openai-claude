---
tasks:
- id: TASK-001
  title: 'Implement REQ-001: The system SHALL allow team members to submit a lunch
    order…'
  description: 'REQ-001: The system SHALL allow team members to submit a lunch order
    in a form in under one minute'
  requirement_ids:
  - REQ-001
  depends_on: []
  verification:
    command: python3 -m unittest -q
    expect_exit_code: 0
  status: done
  wave: 0
  model_tier: high
  files:
  - tests/test_req001_allow_team_members_to.py
- id: TASK-002
  title: 'Implement REQ-002: The system SHALL allow the office manager to see all
    orders…'
  description: 'REQ-002: The system SHALL allow the office manager to see all orders
    in a table'
  requirement_ids:
  - REQ-002
  depends_on: []
  verification:
    command: python3 -m unittest -q
    expect_exit_code: 0
  status: done
  wave: 0
  model_tier: high
  files:
  - tests/test_req002_allow_the_office_manager.py
- id: TASK-003
  title: 'Implement REQ-003: The system SHALL allow the office manager to export the
    tab…'
  description: 'REQ-003: The system SHALL allow the office manager to export the table
    as CSV'
  requirement_ids:
  - REQ-003
  depends_on: []
  verification:
    command: python3 -m unittest -q
    expect_exit_code: 0
  status: done
  wave: 0
  model_tier: high
  files:
  - tests/test_req003_allow_the_office_manager.py
- id: TASK-004
  title: 'Implement REQ-004: The system SHALL NOT accept an order after the Friday
    cut-o…'
  description: 'REQ-004: The system SHALL NOT accept an order after the Friday cut-off'
  requirement_ids:
  - REQ-004
  depends_on: []
  verification:
    command: python3 -m unittest -q
    expect_exit_code: 0
  status: done
  wave: 0
  model_tier: standard
  files:
  - tests/test_req004_not_accept_an_order.py
- id: TASK-005
  title: 'Implement REQ-005: The system SHALL list and export 500 orders within 1
    second'
  description: 'REQ-005: The system SHALL list and export 500 orders within 1 second'
  requirement_ids:
  - REQ-005
  depends_on: []
  verification:
    command: python3 -m unittest -q
    expect_exit_code: 0
  status: done
  wave: 0
  model_tier: standard
  files:
  - tests/test_req005_list_and_export_500.py
- id: TASK-006
  title: Run the full test suite with coverage
  description: Extend and run the whole unit suite so every scenario of REQ-001, REQ-002,
    REQ-003, REQ-004, REQ-005 is exercised.
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
  - TASK-004
  - TASK-005
  verification:
    command: python3 -m coverage run --branch --source=lowcode -m unittest -q
    expect_exit_code: 0
  status: done
  wave: 1
  model_tier: standard
  files: []
---
# Tasks

Tasks are numbered sequentially and each carries an executable verification.
