# ADR-0004: Build the central model, policy, telemetry, benchmark and cost control plane in-house

- Status: accepted
- Date: 2026-08-25
- Deciders: platform engineering
- Related: `docs/enterprise-plan.md` §5 "Cost and Performance", "Final selection"; `ARCHITECTURE.md` §0.3, §5; `INTEGRATION.md` §C.3, §D.4, §E.7

## Context and Problem Statement

The plan's review found that no evaluated project provides organisation-wide token and
dollar telemetry, per-team/application budgets, a central routing policy, cost-based
throttling, attribution of cost to requirements or merged changes, benchmark-driven model
selection, centralised price tables, cross-harness usage reporting or enforced
cost/performance SLOs. The libraries in the workspace offer fragments only: AGT has
per-agent `BudgetTracker` windows, an in-memory `CostGuard` in a package that is not
installed by default, SLO objects in `agent-sre`, and no rate card; PyRIT records token
usage per message piece but has no cost or pricing. What should own the registry, routing,
ledger, budgets, benchmarks and KPIs?

## Decision Drivers

- Every model call and every privileged tool call in the platform must be metered through
  one system of record, whatever harness or library produced it.
- Routing must be driven by observed benchmark performance and price, never reputation.
- Budgets must apply per application, team, environment and change, with quotas per role
  and time-boxed, approved exceptions.
- Cost must be attributable to canonical IDs (change, task, requirement) so KPIs use
  accepted engineering outcomes as the unit.
- No network and no external service in tests; the stdlib must suffice for storage.
- The API must be optional (import-guarded) so the CLI works on developer machines.

## Considered Options

1. **In-house control plane** on SQLite (stdlib `sqlite3`) with a YAML model registry, a
   pure-Python routing policy, a budget engine, a benchmark store, telemetry importers, KPI
   computation and an optional FastAPI server.
2. Compose AGT's cost/budget primitives (`BudgetTracker`, `CostGuard`, `agent-sre` SLOs) as
   the control plane.
3. Adopt an external LLM gateway/observability product as the system of record.

## Decision Outcome

Chosen option: **1**, with AGT's per-agent windows composable underneath it.

Implementation: `src/aisdlc/control_plane/registry.py` (`ModelRegistry`, `ModelEntry`;
`templates/model-registry.yaml`; org allowlist; `AISDLC_MODEL_REGISTRY`),
`pricing.py` (price tables, cache-aware `cost_usd`, blended cost), `routing.py`
(`RoutingPolicy.route`: complexity/risk/capabilities/latency/budget/role → tier; family
exclusion for independent review; escalation; benchmark scores before price ranking),
`ledger.py` (`UsageLedger`, `UsageEvent` with team/application/user/repository/change/task/
role/harness/provider/model/prompt_version/tokens/cache/tools/latency/cost/source;
`summarize`, `cost_evidence`, duplicate-run suppression keyed by source and eval-config
hashes), `budget.py` (`BudgetPolicyEngine.check` → allow/require_approval/deny; scoped
budgets with rolling windows and soft limits; `Quotas`; `BudgetException`;
`AgtAgentWindowTracker` delegating per-agent windows to AGT when importable),
`benchmark.py` (`BenchmarkService` per category), `telemetry.py` (importers for Claude
Code JSONL, AGT audit formats, PyRIT memory pieces, OpenTelemetry GenAI spans),
`kpis.py` (`compute_kpis` → `KpiReport` with the plan's thirteen KPIs), `server.py`
(`create_app`, FastAPI, import-guarded). The orchestrator, the PyRIT campaign runner and
the CLI all record into the same ledger; G5 consumes the per-change extract.

### Consequences

- Good: one ledger and one registry across harnesses; cost per accepted requirement and
  per merged change are computable because events carry canonical IDs.
- Good: routing decisions are explainable (`reason`, `alternatives`, `benchmark_backed`)
  and testable offline.
- Good: budgets are enforced before every agent run (deny blocks, soft limit requires a
  checkpoint), not reported after the fact.
- Bad: the organisation owns price maintenance (placeholder prices are flagged until set)
  and the SQLite file's backup and concurrency (single-writer; fine per repository, a
  shared deployment should sit behind the API server).
- Bad: dashboards are JSON endpoints and CLI tables; a graphical UI is out of scope.
- Bad: importers exist for Claude Code, AGT, PyRIT and OpenTelemetry only; other harnesses
  record through `aisdlc cost record` or `POST /ledger/events` until an importer is added.

## Pros and Cons of the Options

### Option 1 — in-house

- Good: exactly the plan's scope; no external dependency; canonical IDs throughout.
- Bad: more code to maintain; no vendor dashboards.

### Option 2 — compose AGT primitives

- Good: reuse.
- Bad: per-agent only, in-memory, unconnected to each other, no rate card, no attribution
  to changes or requirements; `CostGuard` lives in the uninstalled `cli` umbrella package.

### Option 3 — external gateway/observability product

- Good: dashboards and provider integrations out of the box.
- Bad: usage leaves the organisation's control; attribution to canonical IDs and gate
  evidence would need a bridge anyway; network dependency in the development loop and tests.

## More Information

Proven by `tests/test_control_plane_registry.py`, `tests/test_control_plane_routing.py`,
`tests/test_control_plane_ledger.py`, `tests/test_control_plane_telemetry.py`,
`tests/test_control_plane_cost_import.py`, `tests/test_control_plane_server.py`,
`tests/test_orchestration_executor.py::test_budget_engine_bounds_spend_before_every_agent_run`,
`tests/test_gates_gates.py::test_g5_policy_budget_is_a_ceiling_evidence_may_only_tighten`.
Operational detail: `docs/operations.md`.
