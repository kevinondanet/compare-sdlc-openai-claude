# Run log — CHG-lunch-order-form

Workspace: `/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4`; pre-change `9fc69cdb540b`, change `ed0b2af1bcc4`, final HEAD `7c88cdb32977`.

- pre-change baseline committed as 9fc69cdb540b in /private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4

## 1. Discovery: the office manager answers the plain-language script

### `aisdlc init --no-git` → exit 0 (0.0s)

```text
exists      aisdlc.yaml
created     org-policy.yaml
created     changes/.gitkeep
created     .aisdlc/.gitignore
created     .aisdlc/signing.key
next: aisdlc change new CHG-<slug> --title '<title>' --risk standard; aisdlc policy show
```

### `aisdlc intake discover --answers answers.yaml --root . --json` → exit 0 (0.0s)

```text
{
  "assumptions": [
    {
      "id": "ASM-001",
      "owner": null,
      "source": "discovery",
      "text": "The primary users are: Team member; Office manager.",
      "validated": true
    },
    {
      "id": "ASM-002",
      "owner": null,
      "source": "discovery",
      "text": "No personal or otherwise sensitive data is processed by this change.",
      "validated": false
    }
  ],
  "change_id": "CHG-lunch-order-form",
  "interfaces": [],
  "open_questions": [
    {
      "blocking": false,
      "decision": null,
      "id": "OQ-001",
      "owner": null,
      "question": "The success measure 'Fewer lunch-related emails' has no number: what is the target value and when is it measured?",
      "resolved_at": null,
      "status": "open"
    },
    {
      "blocking": true,
      "decision": null,
      "id": "OQ-002",
      "owner": null,
      "question": "Who is the accountable owner of this change?",
      "resolved_at": null,
      "status": "open"
    },
    {
      "blocking": false,
      "decision": null,
      "id": "OQ-003",
      "owner": null,
      "question": "(constraints) Any hard constraints: deadlines, budget, technology that must or must not be used, regulations?",
      "resolved_at": null,
      "status": "open"
    },
    {
      "blocking": false,
      "decision": null,
      "id": "OQ-004",
      "owner": null,
      "question": "(integrations) Which other systems, services or teams does this need to talk to or depend on?",
      "resolved_at": null,
      "status": "open"
    }
  ],
  "package": "changes/CHG-lunch-order-form",
  "personas": [
    {
      "name": "Team member",
      "needs": "order my lunch without hunting for the paper sheet"
    },
    {
      "name": "Office manager",
      "needs": "see every order in one table and send it to the caterer"
    }
  ],
  "requirements": [
    {
      "id": "REQ-001",
      "kind": "functional",
      "priority": "must",
      "rationale": "Desired outcome stated during discovery: Team members can submit a lunch order in a form quickly",
      "scenarios": [
        {
          "given": "Team member is using the system",
          "id": "SCN-001-01",
          "name": "draft acceptance",
          "raw": "",
          "then": "'Team members can submit a lunch order in a form quickly' is achieved and the result is visible to Team member",
          "when": "Team member attempts to submit a lunch order in a form quickly"
        }
      ],
      "tags": [
        "discovery"
      ],
      "text": "The system SHALL allow team members to submit a lunch order in a form quickly"
    },
    {
      "id": "REQ-002",
      "kind": "functional",
      "priority": "must",
      "rationale": "Desired outcome stated during discovery: The office manager can see some orders in a table",
      "scenarios": [
        {
          "given": "Team member is using the system",
          "id": "SCN-002-01",
          "name": "draft acceptance",
          "raw": "",
          "then": "'The office manager can see some orders in a table' is achieved and the result is visible to Team member",
          "when": "Team member attempts to see some orders in a table"
        }
      ],
      "tags": [
        "discovery"
      ],
      "text": "The system SHALL allow the office manager to see some orders in a table"
    },
    {
      "id": "REQ-003",
      "kind": "functional",
      "priority": "must",
      "rationale": "Desired outcome stated during discovery: The office manager can export the table as TBD",
      "scenarios": [
        {
          "given": "Team member is using the system",
          "id": "SCN-003-01",
          "name": "draft acceptance",
          "raw": "",
          "then": "'The office manager can export the table as TBD' is achieved and the result is visible to Team member",
          "when": "Team member attempts to export the table as TBD"
        }
      ],
      "tags": [
        "discovery"
      ],
      "text": "The system SHALL allow the office manager to export the table as TBD"
    },
    {
      "id": "REQ-004",
      "kind": "functional",
      "priority": "must",
      "rationale": "Stated as something the system must never do.",
      "scenarios": [
        {
          "given": null,
          "id": "SCN-004-01",
          "name": "draft acceptance",
          "raw": "",
          "then": "the system refuses and records the attempt",
          "when": "any user or process attempts to accept an order after the Friday cut-off"
        }
      ],
      "tags": [
        "discovery",
        "safety"
      ],
      "text": "The system SHALL NOT accept an order after the Friday cut-off"
    }
  ],
  "risk_class": "standard"
}
```

### `aisdlc intake discover --answers answers.yaml --root . --dry-run --markdown changes/CHG-lunch-order-form/evidence/reports/brd.md` → exit 0 (0.0s)

The BRD/PRD summary the business user reviews (written to evidence/reports/brd.md).

```text
# Lunch order form

**Change:** CHG-lunch-order-form  
**Owner:** (unassigned)  
**Risk class:** standard

## 1. Problem statement

Every Friday someone walks around with a paper sheet collecting lunch orders and then retypes them into an email for the caterer.

## 2. Users and personas

| Persona | Needs |
| --- | --- |
| Team member | order my lunch without hunting for the paper sheet |
| Office manager | see every order in one table and send it to the caterer |

## 3. Current pain

Orders get lost, quantities are misread and the office manager retypes 40 orders every week.

## 4. Desired outcomes (capabilities)

- Team members can submit a lunch order in a form quickly
- The office manager can see some orders in a table
- The office manager can export the table as TBD

## 5. Out of scope (non-goals)

- Payments and expense claims
- Menu management by the caterer

## 6. Must never

- Accept an order after the Friday cut-off

## 7. Success measure

Fewer lunch-related emails

## 8. Constraints

- (none stated)

## 9. Data sensitivity

No personal data - dish names, quantities and team names only

## 10. Integrations

- (none stated)

## 11. Draft requirements

| ID | Kind | Priority | Requirement |
| --- | --- | --- | --- |
| REQ-001 | functional | must | The system SHALL allow team members to submit a lunch order in a form quickly |
| REQ-002 | functional | must | The system SHALL allow the office manager to see some orders in a table |
| REQ-003 | functional | must | The system SHALL allow the office manager to export the table as TBD |
| REQ-004 | functional | must | The system SHALL NOT accept an order after the Friday cut-off |

## 12. Assumptions

- The primary users are: Team member; Office manager.
- No personal or otherwise sensitive data is processed by this change.

## 13. Open questions

- OQ-001: The success measure 'Fewer lunch-related emails' has no number: what is the target value and when is it measured?
- OQ-002 (blocking): Who is the accountable owner of this change?
- OQ-003: (constraints) Any hard constraints: deadlines, budget, technology that must or must not be used, regulations?
- OQ-004: (integrations) Which other systems, services or teams does this need to talk to or depend on?

CHG-lunch-order-form: 4 draft requirement(s), 2 persona(s), 2 assumption(s), 4 open question(s), risk class standard
```

## 2. G0 before clarification (blocked)

### `aisdlc intake readiness CHG-lunch-order-form --json` → exit 1 (0.0s)

```text
{
  "ambiguity_score": 0.4618,
  "ambiguity_threshold": 0.2,
  "blocking_questions": [
    "OQ-002"
  ],
  "change_id": "CHG-lunch-order-form",
  "criteria": [
    {
      "blocking": true,
      "description": "An accountable human owner is named",
      "details": [],
      "id": "owner",
      "remediation": "Set intent.owner.",
      "satisfied": false
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
      "details": [
        "OQ-002"
      ],
      "id": "no_blocking_questions",
      "remediation": "Resolve each blocking question and record the decision.",
      "satisfied": false
    },
    {
      "blocking": true,
      "description": "Ambiguity score <= 0.20",
      "details": [
        "score 0.46",
        "CHG-lunch-order-form: 'quickly'",
        "CHG-lunch-order-form: 'some'",
        "CHG-lunch-order-form: 'TBD'",
        "REQ-001: 'quickly'",
        "SCN-001-01: 'quickly'",
        "SCN-001-01: 'quickly'",
        "REQ-002: 'some'",
        "SCN-002-01: 'some'",
        "SCN-002-01: 'some'",
        "REQ-003: 'TBD'"
      ],
      "id": "ambiguity",
      "remediation": "Run `aisdlc intake clarify` and answer the ranked questions.",
      "satisfied": false
    },
    {
      "blocking": false,
      "description": "Constraints are stated (or explicitly 'none known')",
      "details": [],
      "id": "constraints_stated",
      "remediation": "Add constraints to the kernel.",
      "satisfied": false
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
      "details": [],
      "id": "no_unstated_assumptions",
      "remediation": "Record each suggested assumption or rewrite the statement.",
      "satisfied": true
    },
    {
      "blocking": false,
      "description": "Success signal is measurable",
      "details": [],
      "id": "success_measurable",
      "remediation": "Add a number, threshold or metric to the success signal.",
      "satisfied": false
    },
    {
      "blocking": false,
      "description": "No open non-blocking questions",
      "details": [
        "OQ-001",
        "OQ-003",
        "OQ-004"
      ],
      "id": "no_open_questions",
      "remediation": "Answer or explicitly defer the remaining questions.",
      "satisfied": false
    }
  ],
  "issues": [
    {
      "artifact_id": "CHG-lunch-order-form",
      "code": "KERNEL_NO_CONSTRAINTS",
      "location": "intent.md:kernel.constraints",
      "message": "no constraints recorded; state 'none known' explicitly if so",
      "severity": "warning"
    },
    {
      "artifact_id": "CHG-lunch-order-form",
      "code": "KERNEL_SUCCESS_NOT_MEASURABLE",
      "location": "intent.md:kernel.success_signal",
      "message": "success signal has no number, comparative or metric \u2014 how is it measured?",
      "severity": "warning"
    },
    {
      "artifact_id": "CHG-lunch-order-form",
      "code": "KERNEL_AMBIGUOUS",
      "location": "intent.md:kernel.capabilities",
      "message": "kernel part 'capabilities' contains ambiguity markers: quickly",
      "severity": "warning"
    },
    {
      "artifact_id": "CHG-lunch-order-form",
      "code": "KERNEL_AMBIGUOUS",
      "location": "intent.md:kernel.capabilities",
      "message": "kernel part 'capabilities' contains ambiguity markers: some",
      "severity": "warning"
    },
    {
      "artifact_id": "CHG-lunch-order-form",
      "code": "KERNEL_AMBIGUOUS",
      "location": "intent.md:kernel.capabilities",
      "message": "kernel part 'capabilities' contains ambiguity markers: TBD",
      "severity": "warning"
    }
  ],
  "missing_kernel_parts": [],
  "ready": false,
  "unstated_assumptions": []
}
```

### `aisdlc gate evaluate CHG-lunch-order-form --gate G0 --json` → exit 1 (0.1s)

```text
{
  "change_id": "CHG-lunch-order-form",
  "depth": "standard",
  "results": [
    {
      "depth": "standard",
      "evidence_ids": [],
      "gate": "G0",
      "passed": false,
      "reasons": [
        "intent has no owner",
        "ambiguity score 0.46 exceeds threshold 0.20 (12 marker(s))",
        "blocking open question OQ-002: Who is the accountable owner of this change?"
      ]
    }
  ],
  "risk_class": "standard"
}
```

### `aisdlc intake checklist CHG-lunch-order-form` → exit 1 (0.0s)

```text
[FAIL] owner_assigned: An accountable owner is named
    fix: Set intent.owner to the accountable person.
[PASS] normative_grammar: Requirements use SHALL/MUST or an EARS form
[FAIL] testable: Requirements and scenarios are testable
    - REQ-001 uses vague terms: quickly
    - REQ-002 uses vague terms: some
    fix: Replace vague terms with measurable thresholds; fix WHEN/THEN scenarios.
[FAIL] unambiguous: No placeholders, open questions or excess ambiguity
    - CHG-lunch-order-form: 'TBD'
    - REQ-003: 'TBD'
    - SCN-003-01: 'TBD'
    - SCN-003-01: 'TBD'
    - ambiguity score 0.46 > threshold 0.20
    fix: Answer the ranked clarification questions (`aisdlc intake clarify`).
[FAIL] complete: Kernel complete, requirements present, no blocking questions
    - OQ-002 is open and blocking
    fix: Fill the kernel, add requirements and resolve blocking questions.
[PASS] consistent: No contradictions or conflicting quantities
[PASS] traceable: Requirements trace to the intent and to tasks
[PASS] non_goals_present: Non-goals are stated
[FAIL] nfrs_present: At least one non-functional requirement
    fix: Add performance, availability, security or cost requirements.
[FAIL] success_signal_measurable: Success signal is measurable
    fix: State a number, threshold or metric in the success signal.
[PASS] requirements_have_scenarios: Every requirement has >= 1 scenario
[PASS] scenarios_reference_requirements: Every scenario belongs to a requirement
[FAIL] no_duplicates: No near-duplicate requirements
    - REQ-002 ~ REQ-003 (0.82)
    fix: Merge near-duplicate requirements or make the difference explicit.
[PASS] priorities_meaningful: Priorities are set and at least one MUST exists
CHG-lunch-order-form: FAIL — 7/14 items passed
```

## 3. Clarification loop

### `aisdlc intake clarify CHG-lunch-order-form --limit 30 --json` → exit 0 (0.1s)

```text
{
  "ambiguity_score": 0.4618,
  "applied": [],
  "candidates": 15,
  "change_id": "CHG-lunch-order-form",
  "questions": [
    {
      "artifact_ids": [
        "CHG-lunch-order-form"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-001",
      "impact": 1.0,
      "marker": "TBD",
      "marker_category": "explicit",
      "options": [
        "Provide the missing text",
        "Record as a blocking open question",
        "Drop the statement"
      ],
      "question": "CHG-lunch-order-form contains the placeholder 'TBD': what should it say?",
      "rationale": "Explicit placeholders cannot be implemented or tested.",
      "requirement_ids": [],
      "target": null
    },
    {
      "artifact_ids": [
        "REQ-003"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-002",
      "impact": 1.0,
      "marker": "TBD",
      "marker_category": "explicit",
      "options": [
        "Provide the missing text",
        "Record as a blocking open question",
        "Drop the statement"
      ],
      "question": "REQ-003 contains the placeholder 'TBD': what should it say?",
      "rationale": "Explicit placeholders cannot be implemented or tested.",
      "requirement_ids": [
        "REQ-003"
      ],
      "target": null
    },
    {
      "artifact_ids": [
        "SCN-003-01"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-003",
      "impact": 1.0,
      "marker": "TBD",
      "marker_category": "explicit",
      "options": [
        "Provide the missing text",
        "Record as a blocking open question",
        "Drop the statement"
      ],
      "question": "SCN-003-01 contains the placeholder 'TBD': what should it say?",
      "rationale": "Explicit placeholders cannot be implemented or tested.",
      "requirement_ids": [
        "REQ-003"
      ],
      "target": null
    },
    {
      "artifact_ids": [
        "OQ-002"
      ],
      "category": "open_question",
      "details": {},
      "id": "CQ-004",
      "impact": 0.95,
      "marker": null,
      "marker_category": null,
      "options": [],
      "question": "Who is the accountable owner of this change?",
      "rationale": "Blocking open questions fail G0.",
      "requirement_ids": [],
      "target": "OQ-002"
    },
    {
      "artifact_ids": [
        "OQ-001"
      ],
      "category": "open_question",
      "details": {},
      "id": "CQ-005",
      "impact": 0.55,
      "marker": null,
      "marker_category": null,
      "options": [],
      "question": "The success measure 'Fewer lunch-related emails' has no number: what is the target value and when is it measured?",
      "rationale": "Open questions leave room for divergent implementations.",
      "requirement_ids": [],
      "target": "OQ-001"
    },
    {
      "artifact_ids": [
        "OQ-003"
      ],
      "category": "open_question",
      "details": {},
      "id": "CQ-006",
      "impact": 0.55,
      "marker": null,
      "marker_category": null,
      "options": [],
      "question": "(constraints) Any hard constraints: deadlines, budget, technology that must or must not be used, regulations?",
      "rationale": "Open questions leave room for divergent implementations.",
      "requirement_ids": [],
      "target": "OQ-003"
    },
    {
      "artifact_ids": [
        "OQ-004"
      ],
      "category": "open_question",
      "details": {},
      "id": "CQ-007",
      "impact": 0.55,
      "marker": null,
      "marker_category": null,
      "options": [],
      "question": "(integrations) Which other systems, services or teams does this need to talk to or depend on?",
      "rationale": "Open questions leave room for divergent implementations.",
      "requirement_ids": [],
      "target": "OQ-004"
    },
    {
      "artifact_ids": [
        "CHG-lunch-order-form"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-008",
      "impact": 0.5,
      "marker": "quickly",
      "marker_category": "vague",
      "options": [
        "within 200 ms at p95",
        "within 1 s at p95",
        "within 5 s at p95"
      ],
      "question": "CHG-lunch-order-form says 'quickly': what is the measurable time limit?",
      "rationale": "Vague qualifiers cannot be verified by a test.",
      "requirement_ids": [],
      "target": null
    },
    {
      "artifact_ids": [
        "CHG-lunch-order-form"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-009",
      "impact": 0.5,
      "marker": "some",
      "marker_category": "vague",
      "options": [
        "exactly <N>",
        "at least <N>",
        "at most <N>"
      ],
      "question": "CHG-lunch-order-form says 'some': what is the exact number or bound?",
      "rationale": "Vague qualifiers cannot be verified by a test.",
      "requirement_ids": [],
      "target": null
    },
    {
      "artifact_ids": [
        "REQ-001"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-010",
      "impact": 0.5,
      "marker": "quickly",
      "marker_category": "vague",
      "options": [
        "within 200 ms at p95",
        "within 1 s at p95",
        "within 5 s at p95"
      ],
      "question": "REQ-001 says 'quickly': what is the measurable time limit?",
      "rationale": "Vague qualifiers cannot be verified by a test.",
      "requirement_ids": [
        "REQ-001"
      ],
      "target": null
    },
    {
      "artifact_ids": [
        "REQ-002"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-011",
      "impact": 0.5,
      "marker": "some",
      "marker_category": "vague",
      "options": [
        "exactly <N>",
        "at least <N>",
        "at most <N>"
      ],
      "question": "REQ-002 says 'some': what is the exact number or bound?",
      "rationale": "Vague qualifiers cannot be verified by a test.",
      "requirement_ids": [
        "REQ-002"
      ],
      "target": null
    },
    {
      "artifact_ids": [
        "SCN-001-01"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-012",
      "impact": 0.5,
      "marker": "quickly",
      "marker_category": "vague",
      "options": [
        "within 200 ms at p95",
        "within 1 s at p95",
        "within 5 s at p95"
      ],
      "question": "SCN-001-01 says 'quickly': what is the measurable time limit?",
      "rationale": "Vague qualifiers cannot be verified by a test.",
      "requirement_ids": [
        "REQ-001"
      ],
      "target": null
    },
    {
      "artifact_ids": [
        "SCN-002-01"
      ],
      "category": "ambiguity",
      "details": {},
      "id": "CQ-013",
      "impact": 0.5,
      "marker": "some",
      "marker_category": "vague",
      "options": [
        "exactly <N>",
        "at least <N>",
        "at most <N>"
      ],
      "question": "SCN-002-01 says 'some': what is the exact number or bound?",
      "rationale": "Vague qualifiers cannot be verified by a test.",
      "requirement_ids": [
        "REQ-002"
      ],
      "target": null
    },
    {
      "artifact_ids": [],
      "category": "non_functional",
      "details": {},
      "id": "CQ-014",
      "impact": 0.5,
      "marker": null,
      "marker_category": null,
      "options": [
        "The system SHALL respond within <N> ms at p95",
        "The system SHALL be available 99.9% of each month",
        "The system SHALL log every privileged action"
      ],
      "question": "No non-functional requirements are recorded: what are the performance, availability and security expectations?",
      "rationale": "NFRs decide architecture and are needed for G1.",
      "requirement_ids": [],
      "target": null
    },
    {
      "artifact_ids": [
        "CHG-lunch-order-form"
      ],
      "category": "kernel",
      "details": {},
      "id": "CQ-015",
      "impact": 0.4,
      "marker": null,
      "marker_category": null,
      "options": [],
      "question": "What hard limits must it honour (deadline, budget, tech, rules)?",
      "rationale": "Kernel part 'constraints' is empty.",
      "requirement_ids": [],
      "target": "constraints"
    }
  ]
}
```

### `aisdlc intake clarify CHG-lunch-order-form --limit 30 --answers clarifications/round-1.yaml --json` → exit 0 (0.0s)

```text
{
  "ambiguity_score": 0.0,
  "applied": [
    {
      "category": "ambiguity",
      "changes": [
        "kernel.capabilities"
      ],
      "created_ids": [],
      "open_question_id": "OQ-005",
      "question_id": "CQ-001"
    },
    {
      "category": "ambiguity",
      "changes": [
        "REQ-003.text"
      ],
      "created_ids": [],
      "open_question_id": "OQ-006",
      "question_id": "CQ-002"
    },
    {
      "category": "ambiguity",
      "changes": [
        "SCN-003-01.when",
        "SCN-003-01.then"
      ],
      "created_ids": [],
      "open_question_id": "OQ-007",
      "question_id": "CQ-003"
    },
    {
      "category": "open_question",
      "changes": [
        "OQ-002 resolved"
      ],
      "created_ids": [],
      "open_question_id": null,
      "question_id": "CQ-004"
    },
    {
      "category": "open_question",
      "changes": [
        "OQ-001 resolved"
      ],
      "created_ids": [],
      "open_question_id": null,
      "question_id": "CQ-005"
    },
    {
      "category": "open_question",
      "changes": [
        "OQ-003 resolved"
      ],
      "created_ids": [],
      "open_question_id": null,
      "question_id": "CQ-006"
    },
    {
      "category": "open_question",
      "changes": [
        "OQ-004 resolved"
      ],
      "created_ids": [],
      "open_question_id": null,
      "question_id": "CQ-007"
    },
    {
      "category": "ambiguity",
      "changes": [
        "kernel.capabilities"
      ],
      "created_ids": [],
      "open_question_id": "OQ-008",
      "question_id": "CQ-008"
    },
    {
      "category": "ambiguity",
      "changes": [
        "kernel.capabilities"
      ],
      "created_ids": [],
      "open_question_id": "OQ-009",
      "question_id": "CQ-009"
    },
    {
      "category": "ambiguity",
      "changes": [
        "REQ-001.text"
      ],
      "created_ids": [],
      "open_question_id": "OQ-010",
      "question_id": "CQ-010"
    },
    {
      "category": "ambiguity",
      "changes": [
        "REQ-002.text"
      ],
      "created_ids": [],
      "open_question_id": "OQ-011",
      "question_id": "CQ-011"
    },
    {
      "category": "ambiguity",
      "changes": [
        "SCN-001-01.when",
        "SCN-001-01.then"
      ],
      "created_ids": [],
      "open_question_id": "OQ-012",
      "question_id": "CQ-012"
    },
    {
      "category": "ambiguity",
      "changes": [
        "SCN-002-01.when",
        "SCN-002-01.then"
      ],
      "created_ids": [],
      "open_question_id": "OQ-013",
      "question_id": "CQ-013"
    },
    {
      "category": "non_functional",
      "changes": [
        "requirements += REQ-005"
      ],
      "created_ids": [
        "REQ-005"
      ],
      "open_question_id": "OQ-014",
      "question_id": "CQ-014"
    },
    {
      "category": "kernel",
      "changes": [
        "kernel.constraints"
      ],
      "created_ids": [],
      "open_question_id": "OQ-015",
      "question_id": "CQ-015"
    }
  ],
  "candidates": 1,
  "change_id": "CHG-lunch-order-form",
  "questions": [
    {
      "artifact_ids": [
        "REQ-005"
      ],
      "category": "missing_scenario",
      "details": {},
      "id": "CQ-001",
      "impact": 0.9,
      "marker": null,
      "marker_category": null,
      "options": [
        "WHEN <trigger> THEN <observable result>",
        "GIVEN <state> WHEN <action> THEN <observable result>"
      ],
      "question": "REQ-005 has no acceptance scenario: WHEN what happens, THEN what is observable?",
      "rationale": "Every requirement needs at least one WHEN/THEN scenario (G0).",
      "requirement_ids": [
        "REQ-005"
      ],
      "target": null
    }
  ]
}
```

### `aisdlc intake clarify CHG-lunch-order-form --limit 30 --answers clarifications/round-2.yaml --json` → exit 0 (0.0s)

```text
{
  "ambiguity_score": 0.0,
  "applied": [
    {
      "category": "missing_scenario",
      "changes": [
        "REQ-005.scenarios += SCN-005-01"
      ],
      "created_ids": [
        "SCN-005-01"
      ],
      "open_question_id": null,
      "question_id": "CQ-001"
    }
  ],
  "candidates": 0,
  "change_id": "CHG-lunch-order-form",
  "questions": []
}
```

### `aisdlc intake kernel CHG-lunch-order-form --success 'Lunch-related emails to the office manager drop from 20 to under 5 per week within two months of launch'` → exit 0 (0.0s)

```text
why:            Every Friday someone walks around with a paper sheet collecting lunch orders and then retypes them into an email for the caterer. Today: Orders get lost, quantities are misread and the office manager retypes 40 orders every week.
capabilities:   Team members can submit a lunch order in a form in under one minute; The office manager can see all orders in a table; The office manager can export the table as CSV
constraints:    Standard-library Python only; the Friday 10:00 cut-off is fixed; the caterer menu has at most 10 dishes
non_goals:      Payments and expense claims; Menu management by the caterer
success_signal: Lunch-related emails to the office manager drop from 20 to under 5 per week within two months of launch
```

- intent signed: owner set to office-manager@example.com through the schema API (aisdlc.schema.package)

## 4. G0 after clarification (passes)

### `aisdlc intake readiness CHG-lunch-order-form --json` → exit 0 (0.0s)

```text
{
  "ambiguity_score": 0.0,
  "ambiguity_threshold": 0.2,
  "blocking_questions": [],
  "change_id": "CHG-lunch-order-form",
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
        "score 0.00"
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
      "details": [],
      "id": "no_unstated_assumptions",
      "remediation": "Record each suggested assumption or rewrite the statement.",
      "satisfied": true
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
  "unstated_assumptions": []
}
```

### `aisdlc gate evaluate CHG-lunch-order-form --gate G0 --json` → exit 0 (0.1s)

```text
{
  "change_id": "CHG-lunch-order-form",
  "depth": "standard",
  "results": [
    {
      "depth": "standard",
      "evidence_ids": [],
      "gate": "G0",
      "passed": true,
      "reasons": []
    }
  ],
  "risk_class": "standard"
}
```

### `aisdlc intake checklist CHG-lunch-order-form` → exit 0 (0.0s)

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
[FAIL] no_duplicates: No near-duplicate requirements
    - REQ-002 ~ REQ-003 (0.82)
    fix: Merge near-duplicate requirements or make the difference explicit.
[PASS] priorities_meaningful: Priorities are set and at least one MUST exists
CHG-lunch-order-form: PASS — 13/14 items passed
```

## 5. Architecture artifacts (solution architect) and the derived plan

- copied spec-overlay/architecture (context, ADR-0001, threat model) into the package

### `aisdlc plan adr validate CHG-lunch-order-form` → exit 0 (0.0s)

```text
WARNING ADR_NO_DATE [ADR-0001]: accepted ADR has no date
WARNING ADR_NO_REQUIREMENTS [ADR-0001]: ADR is not linked to any requirement
1 ADR(s), 2 issue(s)
```

### `aisdlc plan threat-model validate CHG-lunch-order-form` → exit 0 (0.1s)

```text
CHG-lunch-order-form: threat model PASS; 0 unresolved high-risk threat(s)
```

### `aisdlc plan generate CHG-lunch-order-form --no-docs-task` → exit 0 (0.1s)

```text
CHG-lunch-order-form: 6 task(s) for 5 requirement(s); risk class standard
wave 0: TASK-001, TASK-002, TASK-003, TASK-004, TASK-005
wave 1 [checkpoint]: TASK-006
  TASK-001 (high) Implement REQ-001: The system SHALL allow team members to submit a lunch order…
      verify: python3 -m unittest -q
  TASK-002 (high) Implement REQ-002: The system SHALL allow the office manager to see all orders…
      verify: python3 -m unittest -q
  TASK-003 (high) Implement REQ-003: The system SHALL allow the office manager to export the tab…
      verify: python3 -m unittest -q
  TASK-004 (standard) Implement REQ-004: The system SHALL NOT accept an order after the Friday cut-o…
      verify: python3 -m unittest -q
  TASK-005 (standard) Implement REQ-005: The system SHALL list and export 500 orders within 1 second
      verify: python3 -m unittest -q
  TASK-006 (standard) Run the full test suite with coverage
      verify: python3 -m coverage run --branch --source=lowcode -m unittest -q
note: no risk signals found; project default standard
note: plan approval required before wave 0 (set plan.approved_by)
saved changes/CHG-lunch-order-form
```

### `aisdlc plan check CHG-lunch-order-form` → exit 0 (0.1s)

```text
ADVISORY PLAN_NOT_APPROVED: risk class standard requires plan approval (plan.approved_by) before wave 0 runs
CHG-lunch-order-form: plan check PASS — 0 blocking, 1 advisory; requirements fingerprint fresh
```

### `aisdlc intake analyze CHG-lunch-order-form` → exit 0 (0.1s)

```text
MEDIUM DUPLICATE_REQUIREMENT [REQ-002, REQ-003]: REQ-002 and REQ-003 are near-duplicates (similarity 0.82)
    fix: Merge the two requirements or make their difference explicit.
LOW SCENARIO_WITHOUT_TEST [SCN-001-01]: SCN-001-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-002-01]: SCN-002-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-003-01]: SCN-003-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-004-01]: SCN-004-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
LOW SCENARIO_WITHOUT_TEST [SCN-005-01]: SCN-005-01 is not referenced by any task verification or test evidence
    fix: Reference the scenario id from the task that verifies it.
CHG-lunch-order-form: 6 finding(s) low=5, medium=1
```

### `aisdlc change validate CHG-lunch-order-form` → exit 0 (0.0s)

```text
CHG-lunch-order-form: 0 issue(s), ambiguity score 0.00
```

### `aisdlc plan risk classify CHG-lunch-order-form --path lowcode/generated/lunch_order.py` → exit 0 (0.1s)

```text
CHG-lunch-order-form: computed standard, declared standard, effective standard
  - path lowcode/generated/lunch_order.py matches project rule 'lowcode/*' (standard)
gates: G0=standard, G1=standard, G2=standard, G3=standard, G4=standard, G5=standard, G6=standard
checks: lint, types, build, unit, coverage, mutation
```

## 6. Generate the application from the form and commit it as the change

- the office manager adds forms/lunch-order.json (dish, quantity, team, notes; cut-off Friday 10:00)

### `/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m lowcode.generator forms/lunch-order.json` → exit 0 (0.1s)

```text
/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/lowcode/generated/lunch_order.py
```

- committed the change (forms/lunch-order.json, lowcode/generated/lunch_order.py, tests/test_lunch_order.py, tests/test_e2e.py, tests/test_contract.py, changes/CHG-lunch-order-form) as ed0b2af1bcc4

## 7. Governed implementation run (dry runner, worktrees, independent review)

### `aisdlc governance policy generate --out-dir .aisdlc/policies --workspace-root .` → exit 0 (0.1s)

```text
.aisdlc/policies/implementer.yaml
.aisdlc/policies/reviewer.yaml
.aisdlc/policies/planner.yaml
.aisdlc/policies/security_tester.yaml
```

### `aisdlc run change CHG-lunch-order-form --runner dry --yes --audit-log .aisdlc/audit-orchestrator.jsonl --json` → exit 0 (5.1s)

```text
{
  "change_id": "CHG-lunch-order-form",
  "duplicate": false,
  "eval_config_hash": "3265d62e1776f0efc78ad57547f86e89cc38dead44346191afda7cd224cfbf5d",
  "evidence_consolidated": true,
  "final_review_id": "EVD-reviews-007",
  "final_review_verdict": "approved",
  "finished_at": "2026-08-26T06:10:49.230696Z",
  "handoffs_written": 62,
  "messages": [
    "evidence consolidated at 7c88cdb32977: 6 test and 6 review record(s) archived to evidence/logs/superseded-evidence.json"
  ],
  "notes": [],
  "outcome": "success",
  "post_merge_evidence_ids": [
    "EVD-tests-007",
    "EVD-tests-008",
    "EVD-tests-009",
    "EVD-tests-010",
    "EVD-tests-011",
    "EVD-tests-012"
  ],
  "post_merge_verified": true,
  "release_approved": true,
  "review_rounds": 7,
  "source_hash": "11af11451869bbd0b41f2f11c08876c157d9dcec221662dc165d9e5c0ccfbd2a",
  "started_at": "2026-08-26T06:10:44.260652Z",
  "tasks": [
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-lunch-order-form/TASK-001",
      "error": null,
      "evidence_ids": [
        "EVD-tests-002",
        "EVD-reviews-002",
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
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/.aisdlc/worktrees/CHG-lunch-order-form/TASK-001"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-lunch-order-form/TASK-002",
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
      "wave": 0,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/.aisdlc/worktrees/CHG-lunch-order-form/TASK-002"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-lunch-order-form/TASK-003",
      "error": null,
      "evidence_ids": [
        "EVD-tests-003",
        "EVD-reviews-003",
        "EVD-tests-009"
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
      "wave": 0,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/.aisdlc/worktrees/CHG-lunch-order-form/TASK-003"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-lunch-order-form/TASK-004",
      "error": null,
      "evidence_ids": [
        "EVD-tests-001",
        "EVD-reviews-001",
        "EVD-tests-010"
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
      "wave": 0,
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/.aisdlc/worktrees/CHG-lunch-order-form/TASK-004"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-lunch-order-form/TASK-005",
      "error": null,
      "evidence_ids": [
        "EVD-tests-005",
        "EVD-reviews-005",
        "EVD-tests-011"
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
      "task_id": "TASK-005",
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
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/.aisdlc/worktrees/CHG-lunch-order-form/TASK-005"
    },
    {
      "applied_back": true,
      "branch": "aisdlc/CHG-lunch-order-form/TASK-006",
      "error": null,
      "evidence_ids": [
        "EVD-tests-006",
        "EVD-reviews-006",
        "EVD-tests-012"
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
      "task_id": "TASK-006",
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
      "worktree": "/private/tmp/claude-501/-Users-kevinburrowes-Documents-core-frameworks/a7348089-e083-44fc-af3e-f666786b162e/scratchpad/lc4/.aisdlc/worktrees/CHG-lunch-order-form/TASK-006"
    }
  ],
  "usage": {
    "cached_tokens": 0,
    "calls": 13,
    "cost_usd": 0.0319,
    "input_tokens": 13000,
    "latency_ms": 650.0,
    "output_tokens": 2600
  },
  "waves_executed": [
    0,
    1
  ]
}
```

## 8. Test evidence: unit coverage, diff coverage, mutation, portfolio layers

### `aisdlc test run-evidence CHG-lunch-order-form --command 'sh -c '"'"'/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage run --branch --source=lowcode -m unittest -q tests.test_engine tests.test_lunch_order && /Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage json -q -o coverage.json'"'"'' --coverage-json coverage.json --diff-base 9fc69cdb540b0c7cedfa2c7a371ad5180c5782fc --report-uri coverage.json --json` → exit 0 (0.3s)

```text
{
  "id": "EVD-tests-013",
  "kind": "tests",
  "commit_sha": "7c88cdb32977dba570e2ffa29fe3429d2adb695e",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:49.288599Z",
  "finished_at": "2026-08-26T06:10:49.565543Z",
  "report_uri": "coverage.json",
  "status": "complete",
  "command": "sh -c '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage run --branch --source=lowcode -m unittest -q tests.test_engine tests.test_lunch_order && /Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m coverage json -q -o coverage.json'",
  "exit_code": 0,
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "coverage": {
    "lines": 88.25,
    "branches": 90.62,
    "diff_lines": 95.0
  },
  "mutation": null
}
```

### `aisdlc test mutation --builtin lowcode/app.py lowcode/table.py --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_engine tests.test_lunch_order' --package CHG-lunch-order-form --max-mutants 20 --cwd . --json` → exit 0 (1.8s)

```text
{
  "tool": "aisdlc-builtin",
  "killed": 18,
  "survived": 2,
  "timeout": 0,
  "suspicious": 0,
  "skipped": 0,
  "incompetent": 0,
  "untested": 0,
  "scope": [
    "lowcode/app.py",
    "lowcode/table.py"
  ],
  "excluded": [],
  "complete": true,
  "sampled": true,
  "mutants": [
    {
      "id": "app.py:33:98",
      "file": "lowcode/app.py",
      "line": 33,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "app.py:37:128",
      "file": "lowcode/app.py",
      "line": 37,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "app.py:38:138",
      "file": "lowcode/app.py",
      "line": 38,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "app.py:38:140",
      "file": "lowcode/app.py",
      "line": 38,
      "operator": "compare",
      "description": "Is -> IsNot",
      "status": "killed"
    },
    {
      "id": "app.py:46:188",
      "file": "lowcode/app.py",
      "line": 46,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "app.py:48:207",
      "file": "lowcode/app.py",
      "line": 48,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "app.py:48:209",
      "file": "lowcode/app.py",
      "line": 48,
      "operator": "compare",
      "description": "IsNot -> Is",
      "status": "killed"
    },
    {
      "id": "app.py:48:214",
      "file": "lowcode/app.py",
      "line": 48,
      "operator": "not",
      "description": "drop 'not'",
      "status": "killed"
    },
    {
      "id": "app.py:74:375",
      "file": "lowcode/app.py",
      "line": 74,
      "operator": "constant",
      "description": "True -> False",
      "status": "survived"
    },
    {
      "id": "app.py:77:408",
      "file": "lowcode/app.py",
      "line": 77,
      "operator": "constant",
      "description": "False -> True",
      "status": "killed"
    },
    {
      "id": "app.py:91:514",
      "file": "lowcode/app.py",
      "line": 91,
      "operator": "constant",
      "description": "2 -> 3",
      "status": "survived"
    },
    {
      "id": "app.py:102:596",
      "file": "lowcode/app.py",
      "line": 102,
      "operator": "compare",
      "description": "Eq -> NotEq",
      "status": "killed"
    },
    {
      "id": "app.py:107:660",
      "file": "lowcode/app.py",
      "line": 107,
      "operator": "compare",
      "description": "Eq -> NotEq",
      "status": "killed"
    },
    {
      "id": "app.py:109:682",
      "file": "lowcode/app.py",
      "line": 109,
      "operator": "compare",
      "description": "Eq -> NotEq",
      "status": "killed"
    },
    {
      "id": "app.py:113:724",
      "file": "lowcode/app.py",
      "line": 113,
      "operator": "constant",
      "description": "2 -> 3",
      "status": "killed"
    },
    {
      "id": "app.py:114:726",
      "file": "lowcode/app.py",
      "line": 114,
      "operator": "constant",
      "description": "0 -> 1",
      "status": "killed"
    },
    {
      "id": "table.py:16:34",
      "file": "lowcode/table.py",
      "line": 16,
      "operator": "boolop",
      "description": "and <-> or",
      "status": "killed"
    },
    {
      "id": "table.py:17:51",
      "file": "lowcode/table.py",
      "line": 17,
      "operator": "binop",
      "description": "Add -> Sub",
      "status": "killed"
    },
    {
      "id": "table.py:40:213",
      "file": "lowcode/table.py",
      "line": 40,
      "operator": "binop",
      "description": "Add -> Sub",
      "status": "killed"
    },
    {
      "id": "table.py:40:222",
      "file": "lowcode/table.py",
      "line": 40,
      "operator": "constant",
      "description": "1 -> 2",
      "status": "killed"
    }
  ],
  "notes": [
    "sampled 20 of 21 sites (seed=0)"
  ],
  "score": 0.9,
  "attached_to": "EVD-tests-013"
}
```

### `aisdlc test run-evidence CHG-lunch-order-form --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_integration' --report-uri tests/test_integration.py --json` → exit 0 (0.1s)

```text
{
  "id": "EVD-tests-014",
  "kind": "tests",
  "commit_sha": "7c88cdb32977dba570e2ffa29fe3429d2adb695e",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:51.409671Z",
  "finished_at": "2026-08-26T06:10:51.480392Z",
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

### `aisdlc test run-evidence CHG-lunch-order-form --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_contract' --report-uri tests/test_contract.py --json` → exit 0 (0.1s)

```text
{
  "id": "EVD-tests-015",
  "kind": "tests",
  "commit_sha": "7c88cdb32977dba570e2ffa29fe3429d2adb695e",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:51.520037Z",
  "finished_at": "2026-08-26T06:10:51.580767Z",
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

### `aisdlc test run-evidence CHG-lunch-order-form --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_e2e' --report-uri tests/test_e2e.py --json` → exit 0 (0.4s)

```text
{
  "id": "EVD-tests-016",
  "kind": "tests",
  "commit_sha": "7c88cdb32977dba570e2ffa29fe3429d2adb695e",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:51.619722Z",
  "finished_at": "2026-08-26T06:10:51.938576Z",
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

### `aisdlc test run-evidence CHG-lunch-order-form --command '/Users/kevinburrowes/Documents/core-frameworks/ai-sdlc-platform/.venv/bin/python -m unittest -q tests.test_architecture' --report-uri tests/test_architecture.py --json` → exit 0 (0.1s)

```text
{
  "id": "EVD-tests-017",
  "kind": "tests",
  "commit_sha": "7c88cdb32977dba570e2ffa29fe3429d2adb695e",
  "environment": "local",
  "produced_by": "aisdlc.testing.evidence/0.1.0",
  "started_at": "2026-08-26T06:10:51.976839Z",
  "finished_at": "2026-08-26T06:10:52.040894Z",
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

- scenario traceability: 5/5 scenarios referenced by tests; critical journeys in e2e 100.0%

## 9. Security evidence (plane 1 artifacts), manifest check, portfolio

- generated ci-artifacts/ruff.sarif with `ruff check --output-format sarif lowcode`

### `aisdlc ci collect-security ci-artifacts --package CHG-lunch-order-form --commit-sha 7c88cdb32977dba570e2ffa29fe3429d2adb695e --environment local` → exit 0 (0.0s)

```text
EVD-security-001: status=complete critical_open=0 high_open=0 sbom=True provenance=True
```

### `aisdlc ci manifest-drift CHG-lunch-order-form` → exit 0 (0.0s)

```text
manifest drift: no (0 records)
  note: no tool calls observed; unused-declared lists are not meaningful
  note: audit entries not found (changes/CHG-lunch-order-form/evidence/audit-entries.json or changes/CHG-lunch-order-form/evidence/audit.json)
```

### `aisdlc test portfolio CHG-lunch-order-form --layers changes/CHG-lunch-order-form/evidence/reports/portfolio-layers.json` → exit 0 (0.1s)

```text
portfolio: PASS (risk standard)
  unit           passed       required passed=6 failed=0 skipped=0
  property       not_required optional passed=0 failed=0 skipped=0
  integration    passed       required passed=0 failed=0 skipped=0
  contract       passed       required passed=0 failed=0 skipped=0
  e2e            passed       required passed=0 failed=0 skipped=0
  architecture   passed       required passed=0 failed=0 skipped=0
  security       passed       required passed=0 failed=0 skipped=0
  agent_safety   not_required optional passed=0 failed=0 skipped=0
  prompt_evals   not_required optional passed=0 failed=0 skipped=0
  performance    not_required optional passed=0 failed=0 skipped=0
wrote changes/CHG-lunch-order-form/evidence/portfolio.json
```

## 10. Cost, gates, human approval, signed evidence bundle

### `aisdlc cost report --change CHG-lunch-order-form --group-by agent_role` → exit 0 (0.0s)

```text
                                     usage                                      
┏━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┓
┃ agent… ┃ calls ┃ tokens ┃ cached ┃ tools ┃ cost_… ┃ p50_ms ┃ p95_ms ┃ cache… ┃
┡━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━┩
│ imple… │     6 │   7200 │      0 │     0 │ 0.0039 │     50 │     50 │     0% │
│ revie… │     7 │   8400 │      0 │     0 │ 0.0280 │     50 │     50 │     0% │
└────────┴───────┴────────┴────────┴───────┴────────┴────────┴────────┴────────┘
```

### `aisdlc gate evaluate CHG-lunch-order-form --json` → exit 1 (0.1s)

```text
{
  "change_id": "CHG-lunch-order-form",
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
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013",
        "EVD-tests-014",
        "EVD-tests-015",
        "EVD-tests-016",
        "EVD-tests-017"
      ],
      "gate": "G2",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-reviews-007"
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
        "EVD-reviews-007",
        "EVD-security-001",
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013",
        "EVD-tests-014",
        "EVD-tests-015",
        "EVD-tests-016",
        "EVD-tests-017"
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

### `aisdlc gate approve CHG-lunch-order-form --role owner --approver office-manager@example.com --note 'the form works for the Friday run'` → exit 0 (0.0s)

```text
recorded approval by office-manager@example.com as owner (1 total)
```

### `aisdlc gate verdict CHG-lunch-order-form --json` → exit 0 (0.1s)

```text
{
  "bundle_digest": null,
  "change_id": "CHG-lunch-order-form",
  "commit_sha": "7c88cdb32977dba570e2ffa29fe3429d2adb695e",
  "fingerprint": "49f7a0fb8d5213fedaed29bd3bf5773ce6a200bf8961d7d4e46b5d0493471ef9",
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
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013",
        "EVD-tests-014",
        "EVD-tests-015",
        "EVD-tests-016",
        "EVD-tests-017"
      ],
      "gate": "G2",
      "passed": true,
      "reasons": []
    },
    {
      "depth": "standard",
      "evidence_ids": [
        "EVD-reviews-007"
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
        "EVD-reviews-007",
        "EVD-security-001",
        "EVD-tests-007",
        "EVD-tests-008",
        "EVD-tests-009",
        "EVD-tests-010",
        "EVD-tests-011",
        "EVD-tests-012",
        "EVD-tests-013",
        "EVD-tests-014",
        "EVD-tests-015",
        "EVD-tests-016",
        "EVD-tests-017"
      ],
      "gate": "G6",
      "passed": true,
      "reasons": []
    }
  ],
  "overall": true,
  "produced_at": "2026-08-26T06:10:52.460383Z",
  "signatures": []
}
```

### `aisdlc gate bundle CHG-lunch-order-form` → exit 0 (0.0s)

```text
bundle digest 2f1948526258a4de15b9b9bb1d143f2f980b407099a1b5d9a9fbbe4766440e78
signed hmac-sha256 by aisdlc
files: 6, approvals: 1
wrote changes/CHG-lunch-order-form/evidence-bundle.json and changes/CHG-lunch-order-form/final-verdict.json
```

### `aisdlc gate verify-bundle CHG-lunch-order-form --json` → exit 0 (0.1s)

```text
{
  "approvals": 1,
  "digest": "2f1948526258a4de15b9b9bb1d143f2f980b407099a1b5d9a9fbbe4766440e78",
  "invalid_signatures": 0,
  "ok": true,
  "overall": true,
  "reasons": [],
  "stale": false,
  "tampered": false,
  "valid_signatures": 1
}
```

### `aisdlc change status CHG-lunch-order-form` → exit 0 (0.0s)

```text
          change_id: CHG-lunch-order-form
              title: Lunch order form
              owner: office-manager@example.com
         risk_class: standard
              state: released
       requirements: 5
          scenarios: 5
     open_questions: 0
 blocking_questions: 0
          decisions: 1
         interfaces: 0
              tasks: 6
         tasks_done: 6
           evidence: ['EVD-tests-007', 'EVD-tests-008', 'EVD-tests-009', 'EVD-tests-010', 'EVD-tests-011', 'EVD-tests-012', 'EVD-tests-013', 'EVD-tests-014', 'EVD-tests-015', 'EVD-tests-016', 'EVD-tests-017', 'EVD-reviews-007', 'EVD-security-001', 'EVD-cost-001']
        fingerprint: 49f7a0fb8d5213fedaed29bd3bf5773ce6a200bf8961d7d4e46b5d0493471ef9
```

Total time: 9.9s
