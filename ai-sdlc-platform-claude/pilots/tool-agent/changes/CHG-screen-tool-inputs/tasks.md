---
tasks:
- id: TASK-001
  title: Screen user messages with the platform screener
  description: respond() passes the message through aisdlc.governance.mcp.screen_tool_result;
    suspicious messages are quarantined, audited and answered with a refusal.
  requirement_ids:
  - REQ-001
  depends_on: []
  verification:
    command: python3 -m unittest -q tests.test_screening.UserMessageScreeningTest
    expect_exit_code: 0
  status: pending
  files:
  - assistant/agent.py
  - tests/test_screening.py
- id: TASK-002
  title: Screen tool results (customer notes) before they enter the context
  description: Notes returned by search_customers are screened; flagged notes are shown as
    quarantined and never added to the instruction-following context.
  requirement_ids:
  - REQ-001
  depends_on: []
  verification:
    command: python3 -m unittest -q tests.test_screening.ToolResultScreeningTest
    expect_exit_code: 0
  status: pending
  files:
  - assistant/agent.py
- id: TASK-003
  title: Safety regression suite green across the five harm categories
  description: assistant/safety_cases.py runs five trials per case; the suite is complete
    with zero attack success.
  requirement_ids:
  - REQ-001
  - REQ-002
  - REQ-003
  - REQ-004
  - REQ-005
  depends_on:
  - TASK-001
  - TASK-002
  verification:
    command: python3 -m unittest -q tests.test_safety_suite
    expect_exit_code: 0
  status: pending
  files:
  - assistant/safety_cases.py
  - tests/test_safety_suite.py
- id: TASK-004
  title: Whole portfolio (unit, property, integration, contract, e2e, architecture, prompt evals)
  description: Every layer passes on the merged change.
  requirement_ids:
  - REQ-001
  - REQ-002
  - REQ-003
  - REQ-004
  - REQ-005
  - REQ-006
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
