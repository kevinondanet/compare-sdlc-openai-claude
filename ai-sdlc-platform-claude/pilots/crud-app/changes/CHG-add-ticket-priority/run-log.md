# Run log — CHG-add-ticket-priority

Workspace: `/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/crud4`; pre-change `5c39616c258f`, change `bf7855d1e90d`, final HEAD `1b8480de6ff6`.

- pre-change baseline committed as 5c39616c258f in /private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/crud4

## 1. Commit the change on top of the pre-change baseline

- committed the change (tests/test_contract.py, tests/test_e2e.py, tickets/cli.py, tickets/service.py, tests/test_priority.py) as bf7855d1e90d

## 2. Intake and planning gates

### `aisdlc init --no-git` → exit 0 (0.0s)

```text
exists      aisdlc.yaml
created     org-policy.yaml
created     changes/.gitkeep
created     .aisdlc/.gitignore
created     .aisdlc/signing.key
next: aisdlc change new CHG-<slug> --title '<title>' --risk standard; aisdlc policy show
```

### `aisdlc change validate CHG-add-ticket-priority` → exit 0 (0.0s)

```text
CHG-add-ticket-priority: 0 issue(s), ambiguity score 0.01
```

### `aisdlc intake readiness CHG-add-ticket-priority --json` → exit 0 (0.0s)

```text
{
  "ambiguity_score": 0.0054,
  "ambiguity_threshold": 0.2,
  "blocking_questions": [],
  "change_id": "CHG-add-ticket-priority",
  "criteria": [
    {
      "blocking": true,
      "description": "An accountable human owner is named",
      "details": [],
      "id": "owner",
      "remediation": "Set intent.owner.",
      "satisfied": true
    },
    {
      "blocking": true,
      "description": "Kernel states why, capabilities, non-goals and a success signal",
      "details": [],
      "id": "kernel_complete",
      "remediation": "Fill every kernel part in intent.md.",
      "satisfied": true
    },
    {
      "blocking": true,
      "description": "At least one requirement is written",
      "details": [],
      "id": "requirements_present",
      "remediation": "Add SHALL/MUST requirements to requirements.md.",
      "satisfied": true
    },
    {
      "blocking": true,
      "description": "Every requirement has at least one WHEN/THEN scenario",
      "details": [],
      "id": "scenarios_present",
      "remediation": "Write a WHEN \u2026 THEN \u2026 scenario for each requirement.",
      "satisfied": true
    },
    {
      "blocking": true,
      "description": "Requirements and scenarios follow the normative grammar",
      "details": [],
      "id": "grammar",
      "remediation": "Use uppercase SHALL/MUST (or an EARS form) and WHEN/THEN scenarios.",
      "satisfied": true
    },
    {
      "blocking": true,
      "description": "No open blocking question",
      "details": [],
      "id": "no_blocking_questions",
      "remediation": "Resolve each blocking question and record the decision.",
      "satisfied": true
    },
    {
      "blocking": true,
      "description": "Ambiguity score <= 0.20",
      "details": [
        "score 0.01",
        "ASM-003: 'few'"
      ],
      "id": "ambiguity",
      "remediation": "Run `aisdlc intake clarify` and answer the ranked questions.",
      "satisfied": true
    },
    {
      "blocking": false,
      "description": "Constraints are stated (or explicitly 'none known')",
      "details": [],
      "id": "constraints_stated",
      "remediation": "Add constraints to the kernel.",
      "satisfied": true
    },
    {
      "blocking": false,
      "description": "At least one explicit assumption is recorded",
      "details": [],
      "id": "assumptions_recorded",
      "remediation": "Record the bets you are making in assumptions.md.",
      "satisfied": true
    },
    {
      "blocking": false,
      "description": "No statement leans on an unrecorded assumption",
      "details": [
        "CHG-add-ticket-priority: 'third-party' in \"No new third-party dependencies (standard library only)\""
      ],
      "id": "no_unstated_assumptions",
      "remediation": "Record each suggested assumption or rewrite the statement.",
      "satisfied": false
    },
    {
      "blocking": false,
      "description": "Success signal is measurable",
      "details": [],
      "id": "success_measurable",
      "remediation": "Add a number, threshold or metric to the success signal.",
      "satisfied": true
    },
    {
      "blocking": false,
      "description": "No open non-blocking questions",
      "details": [],
      "id": "no_open_questions",
      "remediation": "Answer or explicitly defer the remaining questions.",
      "satisfied": true
    }
  ],
  "issues": [],
  "missing_kernel_parts": [],
  "ready": true,
  "unstated_assumptions": [
    {
      "artifact_id": "CHG-add-ticket-priority",
      "cue": "third-party",
      "excerpt": "No new third-party dependencies (standard library only)",
      "suggested_text": "It is assumed that: No new third-party dependencies (standard library only)"
    }
  ]
}
```

### `aisdlc intake checklist CHG-add-ticket-priority` → exit 0 (0.0s)

```text
[PASS] owner_assigned: An accountable owner is named
[PASS] normative_grammar: Requirements use SHALL/MUST or an EARS form
[PASS] testable: Requirements and scenarios are testable
[PASS] unambiguous: No placeholders, open questions or excess ambiguity
[PASS] complete: Kernel complete, requirements present, no blocking questions
[PASS] consistent: No contradictions or conflicting quantities
[PASS] traceable: Requirements trace to the intent and to tasks
[PASS] non_goals_present: Non-goals are stated
[PASS] nfrs_present: At least one non-functional requirement
[PASS] success_signal_measurable: Success signal is measurable
[PASS] requirements_have_scenarios: Every requirement has >= 1 scenario
[PASS] scenarios_reference_requirements: Every scenario belongs to a requirement
[PASS] no_duplicates: No near-duplicate requirements
[PASS] priorities_meaningful: Priorities are set and at least one MUST exists
CHG-add-ticket-priority: PASS — 14/14 items passed
```

### `aisdlc intake analyze CHG-add-ticket-priority` → exit 0 (0.0s)

```text
LOW SCENARIO_WITHOUT_TEST [SCN-001-01]: SCN-001-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-001-02]: SCN-001-02 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-002-01]: SCN-002-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-003-01]: SCN-003-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-003-02]: SCN-003-02 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-004-01]: SCN-004-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-004-02]: SCN-004-02 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-005-01]: SCN-005-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW TERMINOLOGY_DRIFT [CHG-add-ticket-priority, REQ-001, REQ-002, REQ-003, REQ-005, TASK-002]: 'ticketservice' is written several ways: 'ticket service' (CHG-add-ticket-priority, REQ-001, REQ-002, REQ-003, REQ-005), 'ticketservice' (TASK-002)
    fix: Pick one term and use it everywhere (add it to the glossary).
CHG-add-ticket-priority: 9 finding(s) low=9
```

### `aisdlc plan check CHG-add-ticket-priority` → exit 0 (0.1s)

```text
ADVISORY TASK_MODEL_TIER_MISSING [TASK-001]: task has no model tier hint; routing will use the role default
ADVISORY TASK_MODEL_TIER_MISSING [TASK-002]: task has no model tier hint; routing will use the role default
ADVISORY TASK_MODEL_TIER_MISSING [TASK-003]: task has no model tier hint; routing will use the role default
ADVISORY TASK_MODEL_TIER_MISSING [TASK-004]: task has no model tier hint; routing will use the role default
ADVISORY PLAN_NOT_APPROVED: risk class standard requires plan approval (plan.approved_by) before wave 0 runs
ADVISORY PLAN_FINGERPRINT_UNKNOWN: plan.md carries no requirements fingerprint; staleness cannot be checked
CHG-add-ticket-priority: plan check PASS — 0 blocking, 6 advisory; requirements fingerprint unknown
```

### `aisdlc plan risk classify CHG-add-ticket-priority --path tickets/service.py` → exit 0 (0.1s)

```text
CHG-add-ticket-priority: computed standard, declared standard, effective standard
  - path tickets/service.py matches project rule 'tickets/*' (standard)
  - path tickets/service.py matches project rule 'tickets/*' (standard)
  - path tickets/service.py matches project rule 'tickets/*' (standard)
  - path tickets/cli.py matches project rule 'tickets/*' (standard)
gates: G0=standard, G1=standard, G2=standard, G3=standard, G4=standard, G5=standard, G6=standard
checks: lint, types, build, unit, coverage, mutation
```

## 3. Governed implementation run (dry runner, worktrees, independent review)

### `aisdlc governance policy generate --out-dir .aisdlc/policies --workspace-root .` → exit 0 (0.1s)

```text
.aisdlc/policies/implementer.yaml
.aisdlc/policies/reviewer.yaml
.aisdlc/policies/planner.yaml
.aisdlc/policies/security_tester.yaml
```

### `aisdlc run change CHG-add-ticket-priority --runner dry --yes --audit-log .aisdlc/audit-orchestrator.jsonl --json` → exit 0 (2.6s)

```text
{
  "change_id": "CHG-add-ticket-priority",
  "duplicate": false,
  "eval_config_hash": "3265d62e1776f0efc78ad57547f86e89cc38dead44346191afda7cd224cfbf5d",
  "evidence_consolidated": true,
  "final_review_id": "EVD-reviews-005",
  "final_review_verdict": "approved",
  "finished_at": "2026-08-26T06:10:37.918266Z",
  "handoffs_written": 45,
  "messages": [
    "evidence consolidated at 1b8480de6ff6: 4 test and 4 review record(s) archived to evidence/logs/superseded-evidence.json"
  ],
  "notes": [],
  "outcome": "success",
  "post_merge_evidence_ids": [
    "EVD-tests-005",
    "EVD-tests-006",
    "EVD-tests-007",
    "EVD-tests-008"
  ],
  "post_merge_verified": true,
  "release_approved": true,
  "review_rounds": 5,
  "source_hash": "aa6d678ce7c431fd64485cb59ee9bbb3bd69c505f347bdaad1837967783f5e09",
  "started_at": "2026-08-26T06:10:35.374315Z",
  "tasks": [
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-add-ticket-priority/TASK-001",
      "error": null,
      "evidence_ids": [
        "EVD-tests-001",
        "EVD-reviews-001",
        "EVD-tests-005"
      ],
      "fix_attempts": 0,
      "implementer_family": "gpt",
      "implementer_model": "gpt-5-mini",
      "messages": [],
      "resumed": false,
      "resumed_at_apply_back": false,
      "review_rounds": 1,
      "reviewer_family": "claude",
      "reviewer_model": "claude-sonnet-5",
      "status": "done",
      "task_id": "TASK-001",
      "usage": {
        "cached_tokens": 0,
        "calls": 2,
        "cost_usd": 0.00465,
        "input_tokens": 2000,
        "latency_ms": 100.0,
        "output_tokens": 400
      },
      "verification_passed": true,
      "wave": 0,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/crud4/.aisdlc/worktrees/CHG-add-ticket-priority/TASK-001"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-add-ticket-priority/TASK-002",
      "error": null,
      "evidence_ids": [
        "EVD-tests-002",
        "EVD-reviews-002",
        "EVD-tests-006"
      ],
      "fix_attempts": 0,
      "implementer_family": "gpt",
      "implementer_model": "gpt-5-mini",
      "messages": [],
      "resumed": false,
      "resumed_at_apply_back": false,
      "review_rounds": 1,
      "reviewer_family": "claude",
      "reviewer_model": "claude-sonnet-5",
      "status": "done",
      "task_id": "TASK-002",
      "usage": {
        "cached_tokens": 0,
        "calls": 2,
        "cost_usd": 0.00465,
        "input_tokens": 2000,
        "latency_ms": 100.0,
        "output_tokens": 400
      },
      "verification_passed": true,
      "wave": 1,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/crud4/.aisdlc/worktrees/CHG-add-ticket-priority/TASK-002"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-add-ticket-priority/TASK-003",
      "error": null,
      "evidence_ids": [
        "EVD-tests-003",
        "EVD-reviews-003",
        "EVD-tests-007"
      ],
      "fix_attempts": 0,
      "implementer_family": "gpt",
      "implementer_model": "gpt-5-mini",
      "messages": [],
      "resumed": false,
      "resumed_at_apply_back": false,
      "review_rounds": 1,
      "reviewer_family": "claude",
      "reviewer_model": "claude-sonnet-5",
      "status": "done",
      "task_id": "TASK-003",
      "usage": {
        "cached_tokens": 0,
        "calls": 2,
        "cost_usd": 0.00465,
        "input_tokens": 2000,
        "latency_ms": 100.0,
        "output_tokens": 400
      },
      "verification_passed": true,
      "wave": 1,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/crud4/.aisdlc/worktrees/CHG-add-ticket-priority/TASK-003"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-add-ticket-priority/TASK-004",
      "error": null,
      "evidence_ids": [
        "EVD-tests-004",
        "EVD-reviews-004",
        "EVD-tests-008"
      ],
      "fix_attempts": 0,
      "implementer_family": "gpt",
      "implementer_model": "gpt-5-mini",
      "messages": [],
      "resumed": false,
      "resumed_at_apply_back": false,
      "review_rounds": 1,
      "reviewer_family": "claude",
      "reviewer_model": "claude-sonnet-5",
      "status": "done",
      "task_id": "TASK-004",
      "usage": {
        "cached_tokens": 0,
        "calls": 2,
        "cost_usd": 0.00465,
        "input_tokens": 2000,
        "latency_ms": 100.0,
        "output_tokens": 400
      },
      "verification_passed": true,
      "wave": 2,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/crud4/.aisdlc/worktrees/CHG-add-ticket-priority/TASK-004"
    }
  ],
  "usage": {
    "cached_tokens": 0,
    "calls": 9,
    "cost_usd": 0.0226,
    "input_tokens": 9000,
    "latency_ms": 450.0,
    "output_tokens": 1800
  },
  "waves_executed": [
    0,
    1,
    2
  ]
}
```

### `aisdlc run status CHG-add-ticket-priority` → exit 0 (0.1s)

```text
CHG-add-ticket-priority: reviewed
  TASK-001   done         wave=0 ✓
  TASK-002   done         wave=1 ✓
  TASK-003   done         wave=1 ✓
  TASK-004   done         wave=2 ✓
handoffs:
  0001 run_start     success  
  0002 plan_approval approved 
  0003 route         success   TASK-001
  0004 brief         success   TASK-001 r1
  0005 implement     success   TASK-001 r1
  0006 verify        success   TASK-001 r1
  0007 review        success   TASK-001 r1
  0008 checkpoint    approved  TASK-001
  0009 apply_back    success   TASK-001
  0010 task_done     success   TASK-001
  0011 wave          success  
  0012 route         success   TASK-002
  0013 brief         success   TASK-002 r1
  0014 implement     success   TASK-002 r1
  0015 route         success   TASK-003
  0016 brief         success   TASK-003 r1
  0017 implement     success   TASK-003 r1
  0018 verify        success   TASK-002 r1
  0019 review        success   TASK-002 r1
  0020 verify        success   TASK-003 r1
  0021 review        success   TASK-003 r1
  0022 checkpoint    approved  TASK-002
  0023 apply_back    success   TASK-002
  0024 task_done     success   TASK-002
  0025 checkpoint    approved  TASK-003
  0026 apply_back    success   TASK-003
  0027 task_done     success   TASK-003
  0028 wave          success  
  0029 route         success   TASK-004
  0030 brief         success   TASK-004 r1
  0031 implement     success   TASK-004 r1
  0032 verify        success   TASK-004 r1
  0033 review        success   TASK-004 r1
  0034 checkpoint    approved  TASK-004
  0035 apply_back    success   TASK-004
  0036 task_done     success   TASK-004
  0037 wave          success  
  0038 checkpoint    approved 
  0039 merged_verify success   TASK-001
  0040 merged_verify success   TASK-002
  0041 merged_verify success   TASK-003
  0042 merged_verify success   TASK-004
  0043 final_review  success  
  0044 release       approved 
  0045 run_end       success
```

## 4. Test evidence: unit coverage, diff coverage, mutation, portfolio layers

### `aisdlc test run-evidence CHG-add-ticket-priority --command 'sh -c '"'"'/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage run --branch --source=tickets -m unittest -q tests.test_service tests.test_priority && /Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage json -q -o coverage.json'"'"'' --coverage-json coverage.json --diff-base 5c39616c258fa719c2f33c59e49eea63391572f1 --report-uri coverage.json --json` → exit 0 (0.4s)

Unit layer with line/branch coverage and diff coverage against the pre-change commit.

```text
{
  "id": "EVD-tests-009",
  "kind": "tests",
  "commit_sha": "1b8480de6ff67e4e72b3050c654a8aac347165a4",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:38.033760Z",
  "finished_at": "2026-08-26T06:10:38.367526Z",
  "report_uri": "coverage.json",
  "status": "complete",
  "command": "sh -c '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage run --branch --source=tickets -m unittest -q tests.test_service tests.test_priority && /Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage json -q -o coverage.json'",
  "exit_code": 0,
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "coverage": {
    "lines": 92.55,
    "branches": 88.24,
    "diff_lines": 100.0
  },
  "mutation": null
}
```

### `aisdlc test mutation --builtin tickets/service.py --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_service tests.test_priority' --package CHG-add-ticket-priority --max-mutants 20 --cwd . --json` → exit 0 (2.1s)

Built-in mutation runner over the changed module; attached to the unit evidence.

```text
{
  "tool": "aisdlc-builtin",
  "killed": 19,
  "survived": 1,
  "timeout": 0,
  "suspicious": 0,
  "skipped": 0,
  "incompetent": 0,
  "untested": 0,
  "scope": [
    "tickets/service.py"
  ],
  "excluded": [],
  "complete": true,
  "sampled": true,
  "mutants": [
    {
      "id": "service.py:30:108",
      "file": "tickets/service.py",
      "line": 30,
      "operator": "not",
      "description": "drop 'not'",
      "status": "killed"
    },
    {
      "id": "service.py:33:143",
      "file": "tickets/service.py",
      "line": 33,
      "operator": "compare",
      "description": "NotIn -> In",
      "status": "killed"
    },
    {
      "id": "service.py:40:179",
      "file": "tickets/service.py",
      "line": 40,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "service.py:40:181",
      "file": "tickets/service.py",
      "line": 40,
      "operator": "not",
      "description": "drop 'not'",
      "status": "killed"
    },
    {
      "id": "service.py:40:190",
      "file": "tickets/service.py",
      "line": 40,
      "operator": "compare",
      "description": "NotIn -> In",
      "status": "killed"
    },
    {
      "id": "service.py:45:283",
      "file": "tickets/service.py",
      "line": 45,
      "operator": "constant",
      "description": "True -> False",
      "status": "survived"
    },
    {
      "id": "service.py:67:319",
      "file": "tickets/service.py",
      "line": 67,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "service.py:69:354",
      "file": "tickets/service.py",
      "line": 69,
      "operator": "constant",
      "description": "1 -> 2",
      "status": "killed"
    },
    {
      "id": "service.py:74:370",
      "file": "tickets/service.py",
      "line": 74,
      "operator": "not",
      "description": "drop 'not'",
      "status": "killed"
    },
    {
      "id": "service.py:84:435",
      "file": "tickets/service.py",
      "line": 84,
      "operator": "constant",
      "description": "1 -> 2",
      "status": "killed"
    },
    {
      "id": "service.py:102:518",
      "file": "tickets/service.py",
      "line": 102,
      "operator": "compare",
      "description": "IsNot -> Is",
      "status": "killed"
    },
    {
      "id": "service.py:103:545",
      "file": "tickets/service.py",
      "line": 103,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "service.py:103:547",
      "file": "tickets/service.py",
      "line": 103,
      "operator": "compare",
      "description": "Is -> IsNot",
      "status": "killed"
    },
    {
      "id": "service.py:103:552",
      "file": "tickets/service.py",
      "line": 103,
      "operator": "compare",
      "description": "Eq -> NotEq",
      "status": "killed"
    },
    {
      "id": "service.py:105:575",
      "file": "tickets/service.py",
      "line": 105,
      "operator": "compare",
      "description": "Eq -> NotEq",
      "status": "killed"
    },
    {
      "id": "service.py:121:659",
      "file": "tickets/service.py",
      "line": 121,
      "operator": "compare",
      "description": "IsNot -> Is",
      "status": "killed"
    },
    {
      "id": "service.py:122:665",
      "file": "tickets/service.py",
      "line": 122,
      "operator": "not",
      "description": "drop 'not'",
      "status": "killed"
    },
    {
      "id": "service.py:125:689",
      "file": "tickets/service.py",
      "line": 125,
      "operator": "compare",
      "description": "IsNot -> Is",
      "status": "killed"
    },
    {
      "id": "service.py:127:706",
      "file": "tickets/service.py",
      "line": 127,
      "operator": "compare",
      "description": "IsNot -> Is",
      "status": "killed"
    },
    {
      "id": "service.py:156:907",
      "file": "tickets/service.py",
      "line": 156,
      "operator": "constant",
      "description": "1 -> 2",
      "status": "killed"
    }
  ],
  "notes": [
    "sampled 20 of 22 sites (seed=0)"
  ],
  "score": 0.95,
  "attached_to": "EVD-tests-009"
}
```

### `aisdlc test run-evidence CHG-add-ticket-priority --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_integration' --report-uri tests/test_integration.py --json` → exit 0 (0.2s)

```text
{
  "id": "EVD-tests-010",
  "kind": "tests",
  "commit_sha": "1b8480de6ff67e4e72b3050c654a8aac347165a4",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:40.569317Z",
  "finished_at": "2026-08-26T06:10:40.719415Z",
  "report_uri": "tests/test_integration.py",
  "status": "complete",
  "command": "/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_integration",
  "exit_code": 0,
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "coverage": {
    "lines": null,
    "branches": null,
    "diff_lines": null
  },
  "mutation": null
}
```

### `aisdlc test run-evidence CHG-add-ticket-priority --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_contract' --report-uri tests/test_contract.py --json` → exit 0 (0.1s)

```text
{
  "id": "EVD-tests-011",
  "kind": "tests",
  "commit_sha": "1b8480de6ff67e4e72b3050c654a8aac347165a4",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:40.766668Z",
  "finished_at": "2026-08-26T06:10:40.856253Z",
  "report_uri": "tests/test_contract.py",
  "status": "complete",
  "command": "/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_contract",
  "exit_code": 0,
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "coverage": {
    "lines": null,
    "branches": null,
    "diff_lines": null
  },
  "mutation": null
}
```

### `aisdlc test run-evidence CHG-add-ticket-priority --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_e2e' --report-uri tests/test_e2e.py --json` → exit 0 (0.5s)

```text
{
  "id": "EVD-tests-012",
  "kind": "tests",
  "commit_sha": "1b8480de6ff67e4e72b3050c654a8aac347165a4",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:40.899738Z",
  "finished_at": "2026-08-26T06:10:41.318594Z",
  "report_uri": "tests/test_e2e.py",
  "status": "complete",
  "command": "/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_e2e",
  "exit_code": 0,
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "coverage": {
    "lines": null,
    "branches": null,
    "diff_lines": null
  },
  "mutation": null
}
```

### `aisdlc test run-evidence CHG-add-ticket-priority --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_architecture' --report-uri tests/test_architecture.py --json` → exit 0 (0.1s)

```text
{
  "id": "EVD-tests-013",
  "kind": "tests",
  "commit_sha": "1b8480de6ff67e4e72b3050c654a8aac347165a4",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:41.356938Z",
  "finished_at": "2026-08-26T06:10:41.414941Z",
  "report_uri": "tests/test_architecture.py",
  "status": "complete",
  "command": "/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_architecture",
  "exit_code": 0,
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "coverage": {
    "lines": null,
    "branches": null,
    "diff_lines": null
  },
  "mutation": null
}
```

- scenario traceability: 8/8 scenarios referenced by tests; critical journeys in e2e 100.0%

## 5. Security evidence (plane 1 artifacts) and manifest check

- generated ci-artifacts/ruff.sarif with `ruff check --output-format sarif tickets`

### `aisdlc ci collect-security ci-artifacts --package CHG-add-ticket-priority --commit-sha 1b8480de6ff67e4e72b3050c654a8aac347165a4 --environment local` → exit 0 (0.0s)

```text
EVD-security-001: status=complete critical_open=0 high_open=0 sbom=True provenance=True
```

### `aisdlc ci manifest-drift CHG-add-ticket-priority` → exit 0 (0.0s)

```text
manifest drift: no (0 records)
  note: no tool calls observed; unused-declared lists are not meaningful
  note: audit entries not found (changes/CHG-add-ticket-priority/evidence/audit-entries.json or changes/CHG-add-ticket-priority/evidence/audit.json)
```

### `aisdlc test portfolio CHG-add-ticket-priority --layers changes/CHG-add-ticket-priority/evidence/reports/portfolio-layers.json` → exit 0 (0.1s)

Coverage portfolio over every layer now that security evidence exists.

```text
portfolio: PASS (risk standard)
  unit           passed       required passed=4 failed=0 skipped=0
  property       not_required optional passed=0 failed=0 skipped=0
  integration    passed       required passed=0 failed=0 skipped=0
  contract       passed       required passed=0 failed=0 skipped=0
  e2e            passed       required passed=0 failed=0 skipped=0
  architecture   passed       required passed=0 failed=0 skipped=0
  security       passed       required passed=0 failed=0 skipped=0
  agent_safety   not_required optional passed=0 failed=0 skipped=0
  prompt_evals   not_required optional passed=0 failed=0 skipped=0
  performance    not_required optional passed=0 failed=0 skipped=0
wrote changes/CHG-add-ticket-priority/evidence/portfolio.json
```

## 6. Cost (control plane ledger)

### `aisdlc cost report --change CHG-add-ticket-priority --group-by agent_role` → exit 0 (0.0s)

```text
                                     usage                                      
┏━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┓
┃ agent… ┃ calls ┃ tokens ┃ cached ┃ tools ┃ cost_… ┃ p50_ms ┃ p95_ms ┃ cache… ┃
┡━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━┩
│ imple… │     4 │   4800 │      0 │     0 │ 0.0026 │     50 │     50 │     0% │
│ revie… │     5 │   6000 │      0 │     0 │ 0.0200 │     50 │     50 │     0% │
└────────┴───────┴────────┴────────┴───────┴────────┴────────┴────────┴────────┘
```

## 7. Gates, human approval, signed evidence bundle

### `aisdlc gate evaluate CHG-add-ticket-priority --json` → exit 1 (0.1s)

```text
{
  "change_id": "CHG-add-ticket-priority",
  "depth": "standard",
  "results": [
    {
      "depth": "standard",
      "evidence_ids": [],
      "gate": "G0",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [],
      "gate": "G1",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-tests-005",
        "EVD-tests-006",
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013"
      ],
      "gate": "G2",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-reviews-005"
      ],
      "gate": "G3",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-security-001"
      ],
      "gate": "G4",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-cost-001"
      ],
      "gate": "G5",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-cost-001",
        "EVD-reviews-005",
        "EVD-security-001",
        "EVD-tests-005",
        "EVD-tests-006",
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013"
      ],
      "gate": "G6",
      "passed": false,
      "reasons": [
        "0 human approval(s) recorded, 1 required"
      ]
    }
  ],
  "risk_class": "standard"
}
```

### `aisdlc gate approve CHG-add-ticket-priority --role owner --approver tickets-lead --note 'release review after wave 2'` → exit 0 (0.0s)

```text
recorded approval by tickets-lead as owner (1 total)
```

### `aisdlc gate verdict CHG-add-ticket-priority --json` → exit 0 (0.1s)

```text
{
  "bundle_digest": null,
  "change_id": "CHG-add-ticket-priority",
  "commit_sha": "1b8480de6ff67e4e72b3050c654a8aac347165a4",
  "fingerprint": "bc9e8c91253c5561286e6d877026071ed9fe391844a3e8346977e02a7ab49123",
  "gate_results": [
    {
      "depth": "standard",
      "evidence_ids": [],
      "gate": "G0",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [],
      "gate": "G1",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-tests-005",
        "EVD-tests-006",
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013"
      ],
      "gate": "G2",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-reviews-005"
      ],
      "gate": "G3",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-security-001"
      ],
      "gate": "G4",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-cost-001"
      ],
      "gate": "G5",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-cost-001",
        "EVD-reviews-005",
        "EVD-security-001",
        "EVD-tests-005",
        "EVD-tests-006",
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013"
      ],
      "gate": "G6",
      "passed": true,
      "reasons": []
    }
  ],
  "overall": true,
  "produced_at": "2026-08-26T06:10:41.798803Z",
  "signatures": []
}
```

### `aisdlc gate bundle CHG-add-ticket-priority` → exit 0 (0.0s)

```text
bundle digest 162802cc45c9841886de6aad842f191191c32017e1ddcf53a84e6ca11f450ceb
signed hmac-sha256 by aisdlc
files: 6, approvals: 1
wrote changes/CHG-add-ticket-priority/evidence-bundle.json and changes/CHG-add-ticket-priority/final-verdict.json
```

### `aisdlc gate verify-bundle CHG-add-ticket-priority --json` → exit 0 (0.1s)

```text
{
  "approvals": 1,
  "digest": "162802cc45c9841886de6aad842f191191c32017e1ddcf53a84e6ca11f450ceb",
  "invalid_signatures": 0,
  "ok": true,
  "overall": true,
  "reasons": [],
  "stale": false,
  "tampered": false,
  "valid_signatures": 1
}
```

### `aisdlc change status CHG-add-ticket-priority` → exit 0 (0.0s)

```text
          change_id: CHG-add-ticket-priority
              title: Add a priority to support tickets
              owner: tickets-lead
         risk_class: standard
              state: released
       requirements: 5
          scenarios: 8
     open_questions: 0
 blocking_questions: 0
          decisions: 1
         interfaces: 1
              tasks: 4
         tasks_done: 4
           evidence: ['EVD-tests-005', 'EVD-tests-006', 'EVD-tests-007', 'EVD-tests-008', 'EVD-tests-009', 'EVD-tests-010', 'EVD-tests-011', 'EVD-tests-012', 'EVD-tests-013', 'EVD-reviews-005', 'EVD-security-001', 'EVD-cost-001']
        fingerprint: bc9e8c91253c5561286e6d877026071ed9fe391844a3e8346977e02a7ab49123
```

Total time: 7.3s
