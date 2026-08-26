# ADR-0001: One canonical change-package model as the only workflow state

- Status: accepted
- Date: 2026-08-25
- Deciders: platform engineering
- Related: `docs/enterprise-plan.md` §4 "Architecture principles", `ARCHITECTURE.md` §0.1, §2

## Context and Problem Statement

The frameworks evaluated for the platform each keep their own state tree (`.specify/`,
`openspec/`, `.planning/`, `.copilot-tracking/`, `_bmad/`, `aidlc-docs/`). Installing more
than one next to each other produces overlapping, drifting descriptions of the same change,
and none of them carries structured evidence for "done", "tested" or "secure". How should
the platform represent a change so that intake, planning, orchestration, gates and the
control plane all read and write the same truth, across harnesses and model providers?

## Decision Drivers

- One definition of "done" per organisation, not per team or per agent.
- Every gate must derive its verdict from artifacts, never from a claim in a chat transcript.
- Human editability (Markdown) and machine validation (typed models) at the same time.
- Portability across Claude Code, Copilot, Codex, Cursor and Kiro.
- Concurrent editing by humans and agents without silent overwrites.

## Considered Options

1. **OpenSpec-derived canonical package** — `changes/<CHG-id>/` of Markdown files with YAML
   front-matter, validated by pydantic v2 models with `extra="forbid"`, stable IDs, JSON
   evidence records, state derived from files.
2. **Adopt one existing framework's tree** (OpenSpec, Spec Kit or GSD) unchanged and
   translate the others into it.
3. **Database-backed state** (SQLite/Postgres) with Markdown rendered from it.

## Decision Outcome

Chosen option: **1, the OpenSpec-derived canonical package**, because it keeps the
git-native, human-reviewable properties of OpenSpec while adding what the plan requires and
no single framework provides: the BMAD kernel, Spec Kit's clarification and checklist
rules, EARS/Given-When-Then scenarios, executable task verification, typed evidence
records with commit SHA/exit code/report URI, and content fingerprints for optimistic
concurrency.

Implementation: `src/aisdlc/schema/models.py` (models), `schema/markdown.py` (lossless
front-matter round-trip), `schema/package.py` (layout, load/save, `derive_state`,
`apply_produced_state`), `schema/fingerprint.py` (fingerprints, semantic merge),
`src/aisdlc/ids.py` (ID scheme), `templates/change/` (skeleton). Other methods are
translated in and out (`adapters/openspec.py`; harness adapters emit their native files from
the same workflow). No module may keep a parallel state store; prompts and agents are
stateless and receive narrow briefs built from the package.

### Consequences

- Good: one object flows through every layer; gates fail closed on missing or
  `incomplete` evidence because status is derived, not asserted.
- Good: state survives any harness or provider change; a repository with only the package
  and git history is fully reproducible.
- Good: concurrent human and agent edits are reconciled (`save_produced_state`,
  three-way merge) instead of clobbered.
- Bad: every new artifact needs a model, a Markdown mapping and tests; ad-hoc fields are
  rejected (`extra="forbid"`), which is deliberate friction.
- Bad: large packages are read and re-validated on every command; acceptable at the sizes
  of a single change, and mitigated by fingerprints.

## Pros and Cons of the Options

### Option 1 — canonical package

- Good: satisfies the plan's traceability chain requirement → scenario → ADR → task → test → evidence with stable IDs.
- Good: reviewable in pull requests like any other file.
- Bad: requires the platform to own the schema's evolution.

### Option 2 — one existing framework unchanged

- Good: no schema work.
- Bad: none carries evidence records, risk classes, tool manifests or cost extracts; the
  gaps would be filled by side files, recreating the parallel-state problem.
- Bad: ties the platform's contract to a third party's release cadence.

### Option 3 — database-backed state

- Good: queries and concurrency are easy.
- Bad: state leaves the repository; reviews, forks and offline work lose the source of
  truth; a second system to secure and back up.

## More Information

Proven by `tests/test_schema_models.py`, `tests/test_package.py`, `tests/test_markdown.py`,
`tests/test_fingerprint.py`, `tests/test_schema_concurrency.py`; the OpenSpec round-trip is
`tests/test_adapters_openspec.py`. Deviations from the layout are recorded in
`ARCHITECTURE.md` §9 and ADR-0005.
