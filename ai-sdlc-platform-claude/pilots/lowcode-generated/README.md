# Pilot 2 — business-user-led generated application (`lunch-orders`)

Project class: **low-code / generated application**, risk class `standard`. An office
manager describes a form (`forms/lunch-order.json`); the engine under `lowcode/`
validates submissions, keeps the table, exports CSV and generates a thin application
module (`lowcode/generated/lunch_order.py`). Unlike the other pilots, the change package
does **not** exist up front: `aisdlc intake discover` derives it from the office manager's
plain-language answers in [`answers.yaml`](answers.yaml), which are deliberately sparse
("quickly", "some", "TBD", an unmeasurable success measure, no owner).

## What `run.sh` does

`./run.sh` (offline, ~15 s) copies the pilot into a fresh git repository and:

1. `aisdlc init`, then `intake discover --answers answers.yaml` creates
   `changes/CHG-lunch-order-form/` (intent + kernel, draft SHALL requirements with
   WHEN/THEN scenarios, assumptions, open questions) and writes the BRD summary.
2. **G0 blocked:** `intake readiness`, `gate evaluate --gate G0` and `intake checklist`
   fail on the ambiguity score, the blocking "who owns this?" question and the missing
   owner.
3. **Clarification loop:** `intake clarify --limit 30` ranks the questions;
   [`clarifications/round-1.yaml`](clarifications/round-1.yaml) answers them (placeholders,
   vague terms, open questions, a non-functional requirement, kernel constraints);
   round 2 adds the acceptance scenario the new NFR needs; `intake kernel --success`
   makes the success signal measurable; the sponsor signs the intent (owner).
4. **G0 passes:** readiness, `gate evaluate --gate G0`, checklist.
5. The solution architect drops `spec-overlay/architecture/` (context, ADR-0001, threat
   model) into the package; `plan generate --no-docs-task` derives the tasks and waves;
   `plan check`, `intake analyze`, `change validate`, `plan risk classify`.
6. The office manager adds the form; `python -m lowcode.generator` generates the
   application; the generated module, its tests and the package are committed as the
   change (the first commit is the engine without the form).
7. `run change --runner dry --yes --audit-log …` (worktrees, verification, independent
   review, ledger).
8. Test evidence: unit coverage with diff coverage against the pre-change commit, the
   built-in mutation runner, integration/contract/e2e/architecture layers, scenario
   traceability.
9. `ruff` SARIF + sample supply-chain artifacts through `ci collect-security`,
   `ci manifest-drift`, `test portfolio`.
10. `cost report`, `gate evaluate` (fails: no approval yet), `gate approve`,
    `gate verdict`, `gate bundle`, `gate verify-bundle`.

The package produced by the last run — including the evidence, verdict, signed bundle and
the transcript `run-log.md` — is checked in under `changes/CHG-lunch-order-form/`;
`run.sh` regenerates it and rewrites the section below from the real outputs.

## Last run

<!-- run-output:start -->
Last run: 10s, pre-change `9fc69cdb540b` → change `ed0b2af1bcc4` → merged HEAD `7c88cdb32977`.

- Discovery produced `CHG-lunch-order-form` with 4 draft requirement(s), 4 open question(s), risk class `standard`
- G0 before clarification: **FAIL** — intent has no owner; ambiguity score 0.46 exceeds threshold 0.20 (12 marker(s)); blocking open question OQ-002: Who is the accountable owner of this change?
- Ambiguity score before 0.46 → after round 1 0.00 → after round 2 0.00 (readiness 0.46 → 0.00)
- Questions asked (ranked):
  - CQ-001 (ambiguity): CHG-lunch-order-form contains the placeholder 'TBD': what should it say?
  - CQ-002 (ambiguity): REQ-003 contains the placeholder 'TBD': what should it say?
  - CQ-003 (ambiguity): SCN-003-01 contains the placeholder 'TBD': what should it say?
  - CQ-004 (open_question): Who is the accountable owner of this change?
  - CQ-005 (open_question): The success measure 'Fewer lunch-related emails' has no number: what is the target value and when is it measured?
  - CQ-006 (open_question): (constraints) Any hard constraints: deadlines, budget, technology that must or must not be used, regulations?
  - CQ-007 (open_question): (integrations) Which other systems, services or teams does this need to talk to or depend on?
  - CQ-008 (ambiguity): CHG-lunch-order-form says 'quickly': what is the measurable time limit?
  - CQ-009 (ambiguity): CHG-lunch-order-form says 'some': what is the exact number or bound?
  - CQ-010 (ambiguity): REQ-001 says 'quickly': what is the measurable time limit?
  - CQ-011 (ambiguity): REQ-002 says 'some': what is the exact number or bound?
  - CQ-012 (ambiguity): SCN-001-01 says 'quickly': what is the measurable time limit?
  - CQ-013 (ambiguity): SCN-002-01 says 'some': what is the exact number or bound?
  - CQ-014 (non_functional): No non-functional requirements are recorded: what are the performance, availability and security expectations?
  - CQ-015 (kernel): What hard limits must it honour (deadline, budget, tech, rules)?
- Answers applied:
  - CQ-001: kernel.capabilities
  - CQ-002: REQ-003.text
  - CQ-003: SCN-003-01.when; SCN-003-01.then
  - CQ-004: OQ-002 resolved
  - CQ-005: OQ-001 resolved
  - CQ-006: OQ-003 resolved
  - CQ-007: OQ-004 resolved
  - CQ-008: kernel.capabilities
  - CQ-009: kernel.capabilities
  - CQ-010: REQ-001.text
  - CQ-011: REQ-002.text
  - CQ-012: SCN-001-01.when; SCN-001-01.then
  - CQ-013: SCN-002-01.when; SCN-002-01.then
  - CQ-014: requirements += REQ-005
  - CQ-015: kernel.constraints
  - CQ-001: REQ-005.scenarios += SCN-005-01
- G0 after clarification: **PASS**
- Dry run: outcome `success`; TASK-001 done, TASK-002 done, TASK-003 done, TASK-004 done, TASK-005 done, TASK-006 done; final review `approved`
- Unit coverage: lines 88.25%, branches 90.62%, diff 95.0% (vs pre-change commit); mutation score 0.90 (18 killed / 2 survived)
- Traceability: 5/5 scenarios referenced by tests, critical journeys in e2e 100.0%
- Before the human approval G6 said: 0 human approval(s) recorded, 1 required
- Final verdict overall: **PASS**; bundle OK with 1 valid signature(s), 1 approval(s)

Risk class `standard`, depth `standard`.

| Gate | Result | Depth | Reasons |
| --- | --- | --- | --- |
| G0 | PASS | standard | — |
| G1 | PASS | standard | — |
| G2 | PASS | standard | — |
| G3 | PASS | standard | — |
| G4 | PASS | standard | — |
| G5 | PASS | standard | — |
| G6 | PASS | standard | — |
<!-- run-output:end -->

## Layout

```
answers.yaml                  discovery answers (business user)
clarifications/round-*.yaml   answers to the ranked clarification questions
forms/lunch-order.json        the form definition
lowcode/                      schema.py, table.py, app.py, generator.py, generated/lunch_order.py
tests/                        engine unit tests, lunch-order unit tests (SCN ids), integration,
                              contract, e2e (subprocess), architecture (layering + freshness)
spec-overlay/architecture/    what the architect adds after discovery
ci-artifacts/                 supply-chain artifacts consumed by `ci collect-security`
changes/CHG-lunch-order-form/ the discovered package + evidence of the last run
pilot_lowcode.py, run.sh      the driver (uses ../pilotlib.py)
```

Gap noted while building this pilot: nothing in the CLI sets `intent.owner` after
discovery (`change new --owner` only works at creation), so the "sponsor signs the intent"
step uses the schema API directly.
