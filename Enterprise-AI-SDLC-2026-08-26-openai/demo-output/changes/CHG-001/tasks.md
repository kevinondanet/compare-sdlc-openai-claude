# Tasks

## TASK-001 — Implement host policy mediation

- Requirements: REQ-001
- Depends on: none
- Owner role: implementation
- Risk tier: 3
- Tool scopes: network, read, workspace_write
- Verification: `pytest tests/test_email_policy.py`

## TASK-002 — Verify policy and latency

- Requirements: REQ-002
- Depends on: TASK-001
- Owner role: verification
- Risk tier: 2
- Tool scopes: execute, read, workspace_write
- Verification: `pytest tests/test_email_performance.py`
