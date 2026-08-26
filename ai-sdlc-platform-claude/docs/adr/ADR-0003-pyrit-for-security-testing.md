# ADR-0003: PyRIT for adversarial campaigns and judge calibration; RAMPART-style safety regression in-house

- Status: accepted
- Date: 2026-08-25
- Deciders: platform engineering
- Related: `docs/enterprise-plan.md` §2 "Plane 3", §3; `ARCHITECTURE.md` §0.8, §7, §9.4–9.5; `INTEGRATION.md` §B, §C.5, §E

## Context and Problem Statement

Plane 3 requires two things: broad adversarial campaigns with attack-success rates,
persistent results, deterministic evaluation identifiers, baseline comparison and judge
calibration against human labels (the plan names PyRIT), and product-team-authored,
pytest-native agent safety regression tests with harm categories, repeated trials,
thresholds and fail-closed handling of incomplete runs (the plan names RAMPART). The
workspace has a PyRIT development checkout (`1.1.0.dev0`, async-only initialisation, API
different from the PyPI 0.x documentation). RAMPART is a pattern, not a library in the
workspace. How should the platform obtain these capabilities without letting a heavy,
fast-moving dependency leak into the core?

## Decision Drivers

- G4 must fail closed on incomplete runs, high undetermined rates and ASR above threshold.
- Campaigns must run offline in tests and in CI without network or model keys.
- Application teams must be able to red-team their agent without writing PyRIT code.
- Judges must be calibrated before their verdicts count.
- PyRIT's base install is heavy (transformers, SQLAlchemy, azure-*); the core CLI must not require it.
- Verified quirks (`INTEGRATION.md` §E): `initialize_pyrit_async` only; targets need
  keyword-only constructors and central memory; `ScenarioResult.objective_achieved_rate()`
  counts undetermined in the denominator (unusable as ASR); token usage lives only in
  `token_usage_*` piece metadata; no cost or pricing anywhere.

## Considered Options

1. **PyRIT for campaigns, scorers, memory and scorer evaluation, wrapped behind
   `aisdlc.security`; safety regression implemented in-house in the RAMPART style.**
2. Build all adversarial testing in-house.
3. Depend on PyRIT for everything including safety regression (via scenarios).

## Decision Outcome

Chosen option: **1**.

Implementation: `src/aisdlc/security/pyrit_campaign.py` — `CampaignSpec` YAML
(objectives/datasets, attacks with converter chains or built-in scenarios, scorer config,
trials, thresholds, baseline id) → `run_campaign_async` (PyRIT `PromptSendingAttack`,
`AttackExecutor`, scenario runs) → `CampaignResult` with ASR computed as
successes ÷ (successes + failures), undetermined and error rates, `complete` derived from
scheduled versus produced trials, deterministic run id, baseline delta and usage recorded
to the ledger; a sync wrapper for the CLI. `security/targets.py` — `AppUnderTestTarget`
(keyword-only `PromptTarget` over a plain callable, with tool-event recording),
`HttpAppTarget`, offline demo targets, in-memory SQLite memory bootstrap.
`security/judges.py` — calibration against labelled JSONL/CSV, using PyRIT's
`ScorerEvaluator` when the judge is a PyRIT scorer. `security/safety_regression.py` —
`@safety_case` decorator, `SafetyReport`, shard merging with scheduled-case lists, plain
pytest collection and a plugin-free CLI runner. `control_plane/telemetry.py::from_pyrit_memory`
prices `token_usage_*` metadata through the registry. `aisdlc.security` resolves every
name lazily so importing the package never imports PyRIT; integration tests skip without it.

### Consequences

- Good: campaigns are declarative YAML checked into the repository and run offline with
  deterministic scorers; teams point `--target` at a function or URL.
- Good: G4 reads only platform models (`PyritSummary`, `SafetySummary`); PyRIT can be
  upgraded or replaced inside one module.
- Good: safety cases are ordinary pytest tests that product teams own, with fail-closed
  completeness that PyRIT scenarios do not provide.
- Bad: two evaluation vocabularies (campaign objectives vs safety cases) with separate
  evidence sections; both feed the same gate.
- Bad: PyRIT's dev API may change; `INTEGRATION.md` records the verified signatures and
  tests exercise the real library where installed.

## Pros and Cons of the Options

### Option 1 — PyRIT wrapped, RAMPART-style in-house

- Good: reuse of attacks, converters, scorers, memory and scorer evaluation; small in-house surface for the pytest-native part.
- Bad: wrapper must correct ASR semantics and completeness itself.

### Option 2 — all in-house

- Good: no heavy dependency.
- Bad: reimplements attack strategies, converters, datasets and scorer evaluation; loses the ecosystem of built-in scenarios.

### Option 3 — PyRIT for safety regression too

- Good: one vocabulary.
- Bad: product teams would write PyRIT scenarios instead of pytest; incomplete distributed
  runs are not first-class; heavy dependency in every product test suite.

## More Information

Proven by `tests/test_security_pyrit_spec.py`, `tests/test_security_pyrit_campaign.py`,
`tests/test_security_pyrit_completeness.py`, `tests/test_security_safety_regression.py`,
`tests/test_security_judges.py`, `tests/test_control_plane_telemetry.py::test_from_pyrit_memory_real_pieces`,
`tests/test_e2e_cli.py::test_e2e_pyrit_campaign_records_security_evidence`. Operational
detail: `docs/security.md` "Plane 3"; runbook `docs/runbooks/failed-g4-campaign.md`.
