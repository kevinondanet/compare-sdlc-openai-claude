# Requirements

## REQ-001 — Mediate outbound email

The host MUST deny unapproved external recipients.

- Kind: `functional`
- Scenarios: SCN-001
- Decisions: ADR-001
- Tasks: TASK-001
- Verification: `pytest tests/test_email_policy.py`

## REQ-002 — Bound policy latency

The policy path SHALL keep p95 latency below 50 ms.

- Kind: `non_functional`
- Scenarios: SCN-002
- Decisions: ADR-001
- Tasks: TASK-002
- Verification: `pytest tests/test_email_performance.py`
