# Pilot 1 — internal CRUD application (`tickets`)

Project class: **small internal CRUD app**, risk class `standard`. A stdlib-only Python
service (`tickets/`) keeps support tickets in memory behind a JSON-store CLI. The change
package [`changes/CHG-add-ticket-priority`](changes/CHG-add-ticket-priority) adds a
`priority` field: kernel, five SHALL requirements with WHEN/THEN scenarios, assumptions,
an ADR, an interface contract, a threat model, a three-wave plan and four tasks with
executable verification.

## What `run.sh` does

`./run.sh` (offline, ~10 s) copies the pilot into a fresh git repository and drives the
whole standard-risk path with the platform CLI, in this order:

1. Commits the **pre-change** state (`before/` overlays the old `tickets/service.py`,
   `tickets/cli.py` and two tests; `tests/test_priority.py` does not exist yet), then the
   change itself — so diff coverage is measured against a real diff.
2. `aisdlc init`, `change validate`, `intake readiness/checklist/analyze`, `plan check`,
   `plan risk classify`.
3. `governance policy generate` (AGT tier policies for the orchestration roles) and
   `run change --runner dry --yes --audit-log …`: every task runs in its own worktree, its
   verification command is executed there and again after the merge back, an
   independent reviewer (different model family) reviews each task and the whole change,
   usage is metered in the ledger (`evidence/cost.json`).
4. `test run-evidence` for the unit layer with line/branch coverage and **diff coverage
   against the pre-change commit**, the built-in mutation runner over
   `tickets/service.py`, one `run-evidence` per portfolio layer (integration, contract,
   e2e, architecture), scenario traceability (`SCN-…` ids referenced from tests) as the
   e2e layer metrics, then `test portfolio`.
5. `ruff check --output-format sarif` as the SAST artifact plus sample dependency-review,
   gitleaks, SBOM and provenance files (`ci-artifacts/README.md`) through
   `ci collect-security`; `ci manifest-drift`.
6. `cost report`.
7. `gate evaluate` (fails: no human approval yet), `gate approve`, `gate verdict`,
   `gate bundle` (HMAC-signed) and `gate verify-bundle`.

The evidence of the last run is checked in under `changes/CHG-add-ticket-priority/`
(`evidence/`, `final-verdict.json`, `evidence-bundle.json`, `approvals.json`) together
with the full transcript `run-log.md`. `run.sh` regenerates all of it; the section below
is rewritten from the real outputs on every run.

## Last run

<!-- run-output:start -->
Last run: 7s, pre-change `5c39616c258f` → change `bf7855d1e90d` → merged HEAD `1b8480de6ff6`.

- G0 readiness: ready=True, ambiguity score 0.01
- Dry run: outcome `success`; TASK-001 done, TASK-002 done, TASK-003 done, TASK-004 done; final review `approved`; usage 9 calls, $0.0226
- Unit coverage: lines 92.55%, branches 88.24%, diff 100.0% (vs pre-change commit); mutation score 0.95 (19 killed / 1 survived, scope ['tickets/service.py'])
- Traceability: 8/8 scenarios referenced by tests, critical journeys in e2e 100.0%
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
aisdlc.yaml                   project config (risk standard, unit/coverage commands)
ruff.toml                     lint rules that feed the SAST artifact
tickets/                      service.py (CRUD + priority), cli.py, __main__.py
tests/                        unit (test_service, test_priority), integration, contract,
                              e2e (subprocess), architecture (dependency direction)
before/                       the project before the change (overlaid on the first commit)
ci-artifacts/                 supply-chain artifacts consumed by `ci collect-security`
changes/CHG-add-ticket-priority/   the change package + evidence of the last run
pilot_crud_app.py, run.sh     the driver (uses ../pilotlib.py)
```
