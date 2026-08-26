# Control-plane operations

How to run the central model, policy, telemetry, benchmark and cost control plane
(`aisdlc.control_plane`, `ARCHITECTURE.md` §5). Every command below was executed against
`aisdlc 0.1.0`; the outputs are real.

Environment variables the control plane honours:

| Variable | Meaning |
| --- | --- |
| `AISDLC_LEDGER` | SQLite usage-ledger path (default `<repo>/.aisdlc/ledger.sqlite`; every `--ledger` option overrides) |
| `AISDLC_MODEL_REGISTRY` | model registry YAML (default the bundled `templates/model-registry.yaml`) |
| `AISDLC_SIGNING_KEY` | HMAC key for evidence bundles (else `.aisdlc/signing.key`) |
| `AISDLC_ED25519_PRIVATE_KEY` / `AISDLC_ED25519_PUBLIC_KEY` | PEM key pair for Ed25519 bundle signatures |
| `AISDLC_AUDIT_KEY` | HMAC key for the AGT audit chain (else `<log>.key` next to the log, 0600) |
| `AGT_CLAUDE_POLICY_PATH` | policy JSON the AGT Claude Code plugin loads (`aisdlc governance plugin emit`) |

## Model registry maintenance

The registry (`templates/model-registry.yaml`, `control_plane/registry.py::ModelRegistry`)
is the single source of model identity, capabilities, limits, prices and approved use
cases. Copy it to an organisation-owned location, set `AISDLC_MODEL_REGISTRY`, and treat
it as configuration under review.

Entry shape (all fields validated, unknown fields rejected):

```yaml
- provider: anthropic
  model: claude-sonnet-5
  version: "5"
  family: claude                       # G3 independent review needs a different family than the implementer
  capabilities: [code, reasoning, tools, vision, long_context, agentic]
  context_limit: 1000000
  max_output_tokens: 128000
  tool_support: true
  price_in_per_1m: 2.00                # USD per 1M uncached prompt tokens
  price_out_per_1m: 10.00
  price_cached_per_1m: 0.20            # prompt tokens served from cache
  price_cache_write_per_1m: 2.50       # defaults to price_in_per_1m
  approved_use_cases: [planner, plan_checker, implementer, reviewer, verifier, uat, security]   # or ["*"]
  default_tier: standard               # low | standard | high
  latency_class: medium
  typical_latency_ms: 3000
  price_configurable: false            # true = placeholder price operators must set
  deprecated: false                    # hidden from routing when true
```

Rules the loader enforces (`tests/test_control_plane_registry.py`): every entry has prices,
model ids are unique, deprecated entries are hidden, the org `models.allowlist` (fnmatch
over `provider/model`) narrows what routing may pick. Placeholder prices are flagged:

```text
$ aisdlc cost registry list
                                 model registry
┃ model  ┃ provi… ┃ family ┃ tier   ┃ ctx    ┃ $in/1M ┃ $out… ┃ $cach… ┃ caps  ┃
│ claud… │ anthr… │ claude │ high   │ 10000… │ 10.00  │ 50.00 │ 1.000  │ code… │
│ claud… │ anthr… │ claude │ stand… │ 10000… │ 2.00   │ 10.00 │ 0.200  │ code… │
│ gpt-5  │ openai │ gpt    │ high   │ 400000 │ 1.25 * │ 10.00 │ 0.125  │ code… │
...
* placeholder price — configure for your account
```

Maintenance routine: (1) add a new model as a new entry with its own `version`; never edit
prices in place without a commit message that cites the price sheet; (2) mark retired
models `deprecated: true` rather than deleting them so historical ledger rows still price;
(3) run `aisdlc cost registry list --use-case reviewer --exclude-family <implementer family>`
to confirm at least one independent-review candidate exists per family you use — routing
fails closed (`RoutingError`) when only one family qualifies; (4) `AISDLC_MODEL_REGISTRY`
must point at the same file for the CLI, the executor and the API server.

## Routing policy

`RoutingPolicy.route(TaskProfile)` (`control_plane/routing.py`) picks a model per call from
complexity, risk, required capabilities, latency target, budget remaining and role:

1. complexity → tier (`low`/`standard`/`high`); risk `high`/`critical`/`ai_agent` raises the floor;
2. the role's cap from `models.max_tier_per_role` lowers it (never exceeded, also for
   `independent_review` and `escalation`);
3. candidates are filtered by allowlist, approved use case, required capabilities and
   (for `independent_review`) excluded families;
4. ranking uses **benchmark scores** for the role's category when the benchmark store has
   ≥ `min_samples` results, otherwise registry price/latency — never reputation;
5. budget pressure downgrades the tier; a latency target prefers faster models.

```text
$ aisdlc cost route --complexity high --role implementer --risk high
gpt-5 (openai/gpt) tier=high est=$3.00/1M
alternatives: claude-opus-5, claude-fable-5
reason: complexity=high -> tier high; no benchmark data for this category;
ranked by registry price/latency; gpt-5: $3.00/1M blended, ~7000ms; price for
the chosen model is a placeholder; configure it

$ aisdlc cost route --tier independent_review --exclude-family claude --role reviewer
llama-4-maverick (meta/llama) tier=independent_review est=$0.28/1M
alternatives: gpt-5-mini, qwen3-coder-480b, mistral-large-3
reason: tier override -> independent_review; independent review excludes
families ['claude']; requires model tier >= standard; no benchmark data for this
category; ranked by registry price/latency; ...

$ aisdlc cost route --complexity low --role verifier
gpt-5-nano (openai/gpt) tier=low est=$0.12/1M
```

The executor calls the same policy (`executor.py::router_from_policy`) and records the
`routing_tier` on every ledger event, which is what the escalation-rate and
high-tier-servability KPIs read. Role caps live in `org-policy.yaml`
(`models.max_tier_per_role`; projects may only lower them).

## Budgets, quotas and exceptions

`BudgetPolicyEngine.check(scopes, forecast_cost)` returns `allow`, `require_approval` or
`deny` (`control_plane/budget.py`). Scopes are `application:<id>`, `team:<id>`,
`environment:<id>`, `change:<id>` (and `user`, `repository`, `task`); the engine sums
ledger spend per scope over the budget's rolling window.

Budgets file consumed by `aisdlc cost budget-check --budgets` (same models as `PUT
/budget/budgets` and `PUT /budget/quotas`):

```yaml
budgets:
  - {scope_type: application, scope_id: orders, limit_usd: 20.0, window: 30d, soft_limit_ratio: 0.8}
  - {scope_type: change, scope_id: CHG-add-health-endpoint, limit_usd: 5.0, window: all}
quotas:
  max_model_tier_by_role: {implementer: standard}
  max_agent_turns: 40
  max_parallel_agents: 4
  max_review_rounds: 3
  max_tool_calls: 500
  context_ceiling_tokens: 200000
  approval_threshold_usd: 10.0
exceptions:
  - {scope_type: change, scope_id: CHG-add-health-endpoint, approved_by: eng-manager,
     expires_at: "2026-09-30T00:00:00Z", extra_limit_usd: 10.0, reason: "load-test rerun"}
```

Decisions observed with that file and a ledger holding $0.29 of `application:orders` spend
(exit codes: 0 allow, 2 require_approval, 1 deny):

```text
$ aisdlc cost budget-check --scope application:orders --forecast 2.0 --role implementer --tier standard --budgets budgets.yaml
allow — within budget for application:orders (remaining $19.71)

$ aisdlc cost budget-check --scope application:orders --forecast 2.0 --role implementer --tier high --budgets budgets.yaml
deny — role 'implementer' may use at most tier 'standard'; requested 'high' (remaining $19.71)

$ aisdlc cost budget-check --scope application:orders --forecast 17.0 --budgets budgets.yaml
require_approval — application:orders: projected $17.29 above soft limit (19.71 remaining of 20.00);
forecast $17.00 exceeds approval threshold $10.00 (remaining $19.71)

$ aisdlc cost budget-check --scope application:orders --forecast 25.0 --budgets budgets.yaml
deny — application:orders: spent $0.29 + forecast $25.00 exceeds limit $20.00 (remaining $19.71)

$ aisdlc cost budget-check --scope change:CHG-add-health-endpoint --forecast 8.0 --budgets budgets.yaml
allow — within budget for change:CHG-add-health-endpoint; exceptions applied: EXC-d57c759d (remaining $14.71)
```

Operating rules:

- The org policy's `cost_limits.budgets` (per change/task/day/month) are ceilings; the
  executor builds its engine from them (`budget_engine_from_policy`) and checks **before every
  agent run**; `require_approval` becomes a human checkpoint, `deny` blocks the task (exit 3).
- Exceptions are time-boxed and carry an approver; expired ones are ignored and reported.
  Revoke by removing the entry (or `ExceptionRegister.revoke` in code).
- Duplicate-run suppression: identical `(source_hash, eval_config_hash)` returns exit 4;
  `--ignore-duplicates` forces a rerun.
- A malformed budgets file currently surfaces a pydantic traceback rather than an
  `error:` line; the field names above are the accepted ones.

## Benchmark-driven routing

`BenchmarkService` (`control_plane/benchmark.py`, SQLite) stores `BenchmarkResult` rows:

```json
{"benchmark_id": "BM-review-precision-2026q3", "category": "review_precision", "model": "claude-sonnet-5",
 "version": "5", "metric": "precision", "value": 0.91, "higher_is_better": true,
 "cost_usd": 0.42, "latency_ms": 2100, "sample_size": 120}
```

Categories map to roles (`routing.py::ROLE_BENCHMARK_CATEGORY`): planner/plan_checker/
implementer → `quality`, reviewer → `review_precision`, verifier/uat → `test_generation`,
security roles → `security`; `cost_performance` feeds cost KPIs. Load results through the
API (`POST /benchmarks`) or the Python API (`BenchmarkService(path).store(...)`), then point
routing and KPIs at the store:

```bash
aisdlc cost route --complexity standard --role reviewer --benchmarks benchmarks.sqlite
aisdlc cost kpis --outcomes outcomes.yaml --benchmarks benchmarks.sqlite
curl -s localhost:8765/benchmarks/best/review_precision?min_samples=3
```

With scores present the route reason changes from "ranked by registry price/latency" to a
benchmark-backed choice (`RoutingDecision.benchmark_backed=true`), and the KPI report can
assess which high-tier calls a cheaper model with an equal-or-better score could have served
(`high_tier_servable_by_lower_share`, `high_tier_servable_savings_usd`). Run benchmarks
from the `cost-benchmark.yml` workflow so every result carries cost and latency.

## Telemetry importers

Every model and privileged tool call must reach the ledger. Sources and how they get there:

| Source | Path into the ledger | Notes |
| --- | --- | --- |
| Platform orchestrator (`aisdlc run`) | `LedgerUsageRecorder` on every agent run, `source="platform"` | tokens, latency, routing tier, escalation, change/task/role |
| PyRIT campaigns | `pyrit_campaign.ledger_usage_sink` during `aisdlc security campaign run` (`source="pyrit"`, role `security_tester`) or `aisdlc cost import pyrit <memory.sqlite | pieces.json>` | reads `token_usage_*` piece metadata; priced via the registry when the model is known (`--model` for pieces that record none) |
| Claude Code sessions | `aisdlc cost import claude-code <session>.jsonl --change ... --role ...` | dedupes streaming duplicates by `requestId`; cache read/write tokens priced from the registry |
| AGT audit logs | `aisdlc cost import agt-audit <audit.jsonl|array.json|export.json>` | accepts the platform JSON-lines format, the AGT Python export dict and the Claude Code plugin's JSON array; one tool-call event per entry, zero token cost |
| OpenTelemetry GenAI spans | `control_plane/telemetry.py::LedgerSpanExporter` (span processor) | maps `gen_ai.*` attributes; non-GenAI spans ignored |
| Anything else | `aisdlc cost record --model ... --input-tokens ...` or `POST /ledger/events` | cost computed from the registry unless `--cost` is given |

Observed:

```text
$ aisdlc cost record --model claude-sonnet-5 --input-tokens 12000 --output-tokens 1500 --cached-tokens 4000 \
    --latency-ms 2300 --change CHG-add-health-endpoint --task TASK-001 --role implementer --team core --app orders --tier standard
recorded ee3182cb30a2488aa04459b60a173d7f model=claude-sonnet-5 cost=$0.039800

$ aisdlc cost import agt-audit .aisdlc/audit.jsonl --change CHG-support-assistant-tools
imported 14 of 14 agt_audit event(s) ($0.000000); 0 already present

$ aisdlc cost import claude-code session.jsonl --change CHG-add-health-endpoint --role implementer
imported 2 of 2 claude_code event(s) ($0.024570); 0 already present

$ aisdlc cost report --group-by source
┃ source ┃ calls ┃ tokens ┃ cached ┃ tools ┃ cost_… ┃ p50_ms ┃ p95_ms ┃ cache… ┃
│ agt_a… │    14 │      0 │      0 │    14 │ 0.0000 │      0 │      0 │     0% │
│ claud… │     2 │  14220 │  10000 │     1 │ 0.0246 │      0 │      0 │   100% │
│ cli    │     2 │  51500 │   4000 │     0 │ 0.2898 │   2300 │   9000 │    50% │
```

Imports are idempotent (events are keyed by id; "already present" counts are reported).
`--group-by` accepts one field per call (`model`, `team`, `application`, `agent_role`,
`source`, `change_id`, …). A change's ledger extract becomes G5 evidence with
`aisdlc cost report --package CHG-<slug>` (writes `evidence/cost.json`; `--budget` records
the budget the variance is measured against).

## Dashboards: the FastAPI server

`aisdlc.control_plane.server.create_app()` (import-guarded; `pip install
"ai-sdlc-platform[server]"`) exposes the control plane as JSON. It has no CLI wrapper;
run it with uvicorn's factory mode and the environment variables above:

```bash
AISDLC_LEDGER=/srv/aisdlc/ledger.sqlite AISDLC_MODEL_REGISTRY=/srv/aisdlc/model-registry.yaml \
  uvicorn --factory aisdlc.control_plane.server:create_app --host 127.0.0.1 --port 8765
```

Endpoints (from `/openapi.json` of the running server):

| Method and path | Purpose |
| --- | --- |
| `GET /health` | `{"status":"ok","models":11,"events":0,"benchmarks":0}` |
| `GET /registry/models`, `GET /registry/models/{model}`, `GET /registry/families` | registry browsing with capability/family/use-case filters |
| `POST /route` | body = `TaskProfile`; returns the `RoutingDecision` with reason and alternatives |
| `POST /ledger/events`, `GET /ledger/events`, `GET /ledger/summary`, `GET /ledger/changes/{change_id}/cost` | record, query, summarise (group_by), per-change cost extract |
| `POST /budget/check`, `GET/PUT /budget/budgets`, `GET/PUT /budget/quotas` | budget decisions and live budget/quota management |
| `POST /benchmarks`, `GET /benchmarks`, `GET /benchmarks/best/{category}` | benchmark store |
| `POST /kpis` | body = `{"outcomes": {...}, "filters": {...}, "since": ..., "until": ...}` → `KpiReport` |

Observed:

```text
$ curl -s -X POST localhost:8765/route -H 'content-type: application/json' -d '{"complexity":"high","risk":"high","role":"implementer"}'
{"model":"gpt-5","provider":"openai","family":"gpt","tier":"high","reason":"complexity=high -> tier high; ...",
 "alternatives":["claude-opus-5","claude-fable-5"],"estimated_cost_per_1k":0.003,"estimated_task_cost_usd":0.06,
 "benchmark_category":null,"benchmark_score":null,"benchmark_backed":false}
```

The server has no authentication of its own: bind it to localhost or put it behind the
organisation's gateway. Build dashboards on `GET /ledger/summary?group_by=...` and `POST /kpis`;
the CLI equivalents (`aisdlc cost report`, `aisdlc cost kpis`) print the same data as tables.

## KPI definitions

`compute_kpis(ledger, outcomes, ...)` (`control_plane/kpis.py`) over the ledger window; a
`None`/`n/a` value means the denominator was zero or the data was unavailable, and the
report's `notes` say why.

| KPI | Definition |
| --- | --- |
| `calls`, `model_calls`, `total_tokens`, `total_cost_usd` | ledger events in the window; model calls exclude tool-only events |
| `cost_per_accepted_requirement` | total cost ÷ `Outcomes.accepted_requirements` |
| `cost_per_merged_change` | total cost ÷ accepted changes (`accepted_changes`, defaulting to `merged_changes`) |
| `cost_per_defect_found`, `cost_per_vuln_found`, `cost_per_passing_benchmark` | total cost ÷ `defects_found` / `vulns_found` / `benchmarks_passed` |
| `tokens_per_accepted_task` | total tokens ÷ `accepted_tasks` |
| `escalation_rate` | events flagged `escalated` ÷ model calls |
| `cache_hit_rate`, `cached_token_share` | events with `cache_hit` ÷ model calls; cached tokens ÷ prompt tokens |
| `latency_p50_ms`, `latency_p95_ms` | percentiles of `latency_ms` over model calls |
| `turns_per_success` | model calls ÷ `successful_runs` |
| `review_rounds_per_merge` | recorded `review_round` maxima (else reviewer calls) ÷ accepted changes |
| `tool_calls_per_accepted_change` | tool-call events ÷ accepted changes |
| `high_tier_calls`, `high_tier_assessed_calls`, `high_tier_servable_by_lower_share`, `high_tier_servable_savings_usd` | calls routed at tier `high`; those with a benchmark score for their model; share whose category score is met (within `score_tolerance`) by a lower-tier model; cost delta implied |

Supply outcomes from your delivery system as a YAML/JSON file
(`accepted_requirements`, `merged_changes`, `defects_found`, `vulns_found`,
`benchmarks_passed`, `accepted_tasks`, `successful_runs`, optional `accepted_changes`) or
as CLI flags:

```text
$ aisdlc cost kpis --accepted-requirements 3 --merged-changes 1 --accepted-tasks 3 --successful-runs 1
│ calls                             │          2 │
│ model_calls                       │          2 │
│ total_tokens                      │      51500 │
│ total_cost_usd                    │     0.2898 │
│ cost_per_accepted_requirement     │     0.0966 │
│ cost_per_merged_change            │     0.2898 │
│ tokens_per_accepted_task          │ 17166.6667 │
│ escalation_rate                   │     0.0000 │
│ cache_hit_rate                    │     0.5000 │
│ latency_p50_ms                    │  2300.0000 │
│ latency_p95_ms                    │  9000.0000 │
│ turns_per_success                 │     2.0000 │
│ review_rounds_per_merge           │     1.0000 │
│ high_tier_calls                   │          1 │
│ high_tier_servable_by_lower_share │        n/a │
note: review rounds estimated from reviewer calls (no review_round recorded)
note: high-tier servability not assessed: no benchmark service provided
```

## Routine checks

| When | Command | Expect |
| --- | --- | --- |
| Daily | `aisdlc cost report --group-by team --since <yesterday>` | spend within team budgets |
| Per change | `aisdlc cost report --package CHG-<slug>` then `aisdlc gate evaluate CHG-<slug> --gate G5` | `EVD-cost-001` complete, G5 PASS |
| Weekly | `aisdlc cost kpis --outcomes outcomes.yaml --benchmarks benchmarks.sqlite` | trend review; act on `notes` |
| On registry change | `aisdlc cost registry list`, `aisdlc cost route --tier independent_review --exclude-family <family> --role reviewer` | no placeholder prices in production entries; a reviewer candidate per family |
| On policy change | `aisdlc policy validate` in every project | 0 violations |
| Runbooks | [`runbooks/budget-deny-and-escalation.md`](runbooks/budget-deny-and-escalation.md) | — |
