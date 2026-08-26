# AI-SDLC Platform — Architecture Contract

This document is the binding contract for every module in this repository. Agents
implementing modules MUST follow it; deviations require an ADR under `docs/adr/`.

## 0. Principles

1. **One canonical artifact model.** All workflow state is derived from the files in a
   change package (`changes/<change-id>/`). No module keeps its own parallel state store
   (no `.specify/`, `.planning/`, `_bmad/`, etc.). Prompts and agents are stateless.
2. **One execution orchestrator.** `aisdlc.orchestration` is the only component that
   runs agents. Everything else produces or consumes artifacts.
3. **One central control plane.** `aisdlc.control_plane` owns the model registry,
   routing policy, usage ledger, budgets, benchmarks and the policy engine. Every model
   call and every privileged tool call in the platform is metered through it.
4. **Policy is separate from implementation.** Three layers, merged narrow-only:
   organization policy (`OrgPolicy`) > project configuration (`ProjectConfig`) >
   change-specific artifacts. A project may tighten org policy; it may never weaken it.
5. **Evidence, not claims.** Every "done", "tested", "reviewed", "secure" statement must
   be backed by a structured evidence record with command, exit code, commit SHA,
   environment and report URI. Missing or incomplete evidence fails closed.
6. **Deterministic first.** Deterministic gates run before AI review; AI review only
   addresses what tools cannot detect.
7. **Portability.** Canonical artifacts never depend on a harness (Claude Code, Copilot,
   Codex, Cursor, Kiro) or a model provider. Harness adapters translate.
8. **Reuse the two governance libraries in this workspace:**
   - **Agent Governance Toolkit (AGT)** — deterministic tool/action policy enforcement,
     audit trail, approvals, MCP governance, cost primitives, Claude Code hook plugin.
   - **PyRIT** — adversarial campaigns, scenarios, scorers, memory/usage records,
     scorer calibration and baseline comparison.
   See `INTEGRATION.md` for verified import paths and signatures. Wrap them behind
   platform interfaces so they can be swapped; never leak their types into the
   canonical artifact model.

## 1. Package layout

```
ai-sdlc-platform/
  pyproject.toml                 # package name: ai-sdlc-platform, module: aisdlc, py>=3.11
  src/aisdlc/
    __init__.py                  # __version__
    ids.py                       # stable ID scheme and validators
    schema/                      # LAYER 1 — canonical artifact model (OpenSpec-derived)
      models.py                  # pydantic v2 models (see §2)
      grammar.py                 # SHALL/MUST + EARS + WHEN/THEN validation, ambiguity markers
      package.py                 # ChangePackage load/save, directory layout, state derivation
      markdown.py                # Markdown <-> models for the human-editable files
      fingerprint.py             # content fingerprints, optimistic concurrency, semantic merge
    intake/                      # LAYER 1 — intake & specification quality (Spec Kit/BMAD/HVE)
      kernel.py                  # BMAD 5-part kernel: why/capabilities/constraints/non_goals/success_signal
      clarify.py                 # ranked clarification questions, ambiguity score
      checklist.py               # requirements-quality checklist
      analyze.py                 # cross-artifact consistency analysis
      discovery.py               # plain-language coached discovery -> intent (non-developer intake)
    planning/                    # LAYER 2 — planning and architecture governance
      planner.py                 # requirements -> tasks with verification; dependency waves
      plan_checker.py            # goal-backward plan validation
      adr.py                     # ADR creation/validation
      threat_model.py            # threat model artifact + tool/data manifest
      risk.py                    # risk classification -> gate depth profile
    orchestration/               # LAYER 3 — isolated multi-agent implementation (GSD/Superpowers)
      roles.py                   # AgentRole enum: planner, plan_checker, implementer, reviewer, verifier, uat, security
      brief.py                   # AgentBrief: narrow fresh-context task brief (never full history)
      runner.py                  # AgentRunner protocol + LocalScriptRunner + ClaudeCodeRunner (subprocess) + DryRunRunner
      worktree.py                # git worktree isolation
      executor.py                # wave execution, bounded fix loops, checkpoints, resumability
      review.py                  # independent review of actual diff; scoped re-review
      handoff.py                 # durable file-based handoffs (handoffs/*.json in change package)
    governance/                  # PLANE 2 — tool & execution security (AGT)
      tiers.py                   # RiskTier 0..4 taxonomy and default behaviours
      policy.py                  # generate AGT policy YAML from tiers + project config
      enforce.py                 # PolicyEnforcer wrapping AGT govern(); approval + deny-on-timeout
      audit.py                   # audit log adapter (AGT audit -> evidence/audit.json)
      mcp.py                     # MCP gateway config + tool-result injection screening
      claude_code_plugin.py      # emit AGT claude-code hook config for a project
    security/                    # PLANE 1 + PLANE 3
      ci_templates.py            # render reusable GitHub workflows from templates/workflows/
      supply_chain.py            # SBOM/attestation/CodeQL/secret-scan evidence parsers -> security.json
      pyrit_campaign.py          # PyRIT campaign runner: scenarios, ASR, undetermined rate, baseline compare
      safety_regression.py       # RAMPART-style pytest-native agent safety tests (harm cats, trials, thresholds, fail-closed)
      judges.py                  # scorer calibration vs human labels (PyRIT scorer evaluation)
      manifest.py                # declared tool/data manifest vs observed behaviour drift
    testing/                     # test coverage portfolio
      portfolio.py               # CoveragePortfolio thresholds, layer evaluation, ratchets
      evidence.py                # TestEvidence capture: run command, parse junit/coverage -> tests.json
      mutation.py                # mutation score evidence with explicit scope disclosure
    control_plane/               # CENTRAL CONTROL PLANE
      registry.py                # ModelRegistry (provider/model/version/capabilities/limits/price/use cases)
      pricing.py                 # price tables + cost computation
      routing.py                 # RoutingPolicy: tier by complexity/risk/capabilities/latency/budget; benchmark-driven
      ledger.py                  # UsageLedger (SQLite): team/app/user/repo/change/task/model/prompt_version/tokens/cache/tools/latency/cost
      budget.py                  # BudgetPolicyEngine: budgets, quotas, allowlists, escalation limits, exceptions
      benchmark.py               # BenchmarkService: quality/security/test-gen/review-precision/cost-perf results
      telemetry.py               # importers: PyRIT usage records, Claude Code usage, AGT audit -> ledger
      kpis.py                    # KPI computation (cost per accepted requirement, etc.)
      server.py                  # optional FastAPI app (import-guarded)
    gates/
      gates.py                   # G0..G6 definitions, risk-based depth, evaluation
      verdict.py                 # final-verdict.json + signed evidence bundle (HMAC/ed25519)
    policy/
      org_policy.py              # OrgPolicy model + loader
      project_config.py          # ProjectConfig model + loader
      merge.py                   # narrow-only merge with violation reporting
    adapters/
      base.py                    # HarnessAdapter protocol
      claude_code.py             # emit .claude/ commands, skills, hooks
      copilot.py                 # emit .github/copilot-instructions + prompts
      codex.py, cursor.py, kiro.py
      openspec.py                # import/export OpenSpec change directories
    cli/
      main.py                    # typer app; subcommands registered from cli/cmd_*.py
      cmd_change.py, cmd_intake.py, cmd_plan.py, cmd_run.py, cmd_review.py, cmd_gate.py,
      cmd_security.py, cmd_cost.py, cmd_policy.py, cmd_adapter.py
  templates/
    org-policy.yaml              # default organization policy
    project-config.yaml          # default project configuration
    change/                      # skeleton change package markdown
    workflows/                   # reusable GitHub workflow YAML (SHA-pinned, least privilege)
    agt/                         # AGT policy YAML per tier + claude-code plugin config
    pyrit/                       # campaign definitions (YAML) + seed datasets
  tests/                         # pytest; mirrors src layout; no network
  docs/                          # ADRs, user guide, runbooks
  pilots/                        # three pilot project classes with change packages
```

## 2. Canonical artifact model (`aisdlc.schema.models`)

All models are pydantic v2, `extra="forbid"`, JSON-serializable, with stable IDs.

### 2.1 ID scheme (`aisdlc.ids`)

| Kind | Pattern | Example |
| --- | --- | --- |
| Change | `CHG-<slug>` | `CHG-add-login-mfa` |
| Requirement | `REQ-<nnn>` | `REQ-003` |
| Scenario | `SCN-<req>-<nn>` | `SCN-003-01` |
| Assumption | `ASM-<nnn>` | |
| Open question | `OQ-<nnn>` | |
| Architecture decision | `ADR-<nnnn>` | |
| Interface | `IFC-<nnn>` | |
| Threat | `THR-<nnn>` | |
| Task | `TASK-<nnn>` | |
| Test | `TEST-<nnn>` | |
| Finding | `FND-<nnn>` | |
| Evidence | `EVD-<kind>-<nnn>` | `EVD-tests-001` |
| Benchmark | `BM-<slug>-<version>` | |

IDs are stable across requirements, tasks, tests, findings, and benchmarks. Cross-references use these IDs only.

### 2.2 Change package directory (`changes/<change-id>/`)

```
intent.md              # Intent: title, kernel (why, capabilities, constraints, non_goals, success_signal), owner, risk_class
requirements.md        # Requirement[]: id, text (SHALL/MUST), kind functional|non_functional, priority, scenarios[]
scenarios/             # optional per-requirement scenario files (WHEN/THEN, Given/When/Then)
assumptions.md         # Assumption[], OpenQuestion[] (status open|resolved, owner, decision)
architecture/
  context.md
  decisions/ADR-0001.md
  interfaces/IFC-001.md
  threat-model.md      # ThreatModel: assets, actors, threats, mitigations, tool/data manifest
plan.md                # Plan: waves[], each with task ids, checkpoint flags
tasks.md               # Task[]: id, title, requirement_ids, verification (command + expected), status, wave
evidence/
  tests.json           # TestEvidence[]
  reviews.json         # ReviewEvidence[]
  security.json        # SecurityEvidence (sast, sca, secrets, sbom, provenance, pyrit, safety_regression, manifest)
  performance.json     # PerformanceEvidence
  cost.json            # CostEvidence (ledger extract for this change)
  audit.json           # AuditEvidence (privileged tool calls)
handoffs/              # durable agent handoffs
final-verdict.json     # FinalVerdict: gate results G0..G6, overall, signatures
.fingerprint           # base fingerprint for optimistic concurrency
```

Markdown files carry a YAML front-matter block with the structured data; the body is
human prose. `schema.markdown` round-trips front-matter <-> models losslessly.

### 2.3 Requirement grammar (`aisdlc.schema.grammar`)

- Requirement text MUST contain `SHALL` or `MUST` (OpenSpec) or match EARS forms
  (`WHEN <trigger>, the <system> SHALL <response>`; `WHILE`, `IF … THEN`, `WHERE`).
- Each requirement MUST have >= 1 scenario using `WHEN … THEN …` or `Given/When/Then`.
- Ambiguity markers are detected: `[NEEDS CLARIFICATION]`, `TBD`, `TODO`, `?`, vague
  quantifiers (`fast`, `some`, `appropriate`, `etc.`). `ambiguity_score` in [0,1].
- Task numbering is sequential; each task has a `verification` block that is executable
  (`command`, `expect_exit_code`, optional `expect_output_regex`).

### 2.4 Evidence (`schema.models` evidence types)

```yaml
test_evidence:
  id: EVD-tests-001
  command: "pytest -n auto"
  exit_code: 0
  commit_sha: "..."
  environment: "ci"
  passed: 1421
  failed: 0
  skipped: 3
  coverage: {lines: 84.2, branches: 76.1, diff_lines: 91.0}
  mutation: {score: 0.62, scope: ["src/aisdlc/gates"], excluded: ["src/aisdlc/cli"]}
  report_uri: "..."
  started_at / finished_at
```

All evidence types share `EvidenceBase`: id, kind, commit_sha, environment,
produced_by (agent/tool + version), started_at, finished_at, report_uri, status
(`complete|incomplete`). `incomplete` evidence always fails its gate.

## 3. Gates (`aisdlc.gates`)

| Gate | Evidence required | Blocks on |
| --- | --- | --- |
| G0 intent readiness | requirements, non-goals, assumptions, scenarios, ambiguity score, owner | ambiguity_score > threshold, open OQ with `blocking: true`, missing owner |
| G1 architecture readiness | plan, ADRs, interfaces, threat model, NFRs | unresolved high-risk threat, plan checker failure |
| G2 implementation quality | build/lint/types/tests/coverage/mutation evidence | deterministic failure, portfolio threshold breach |
| G3 independent review | review evidence from a different model family / independent agent | grounded blocking finding |
| G4 security & safety | SAST/SCA/secrets/SBOM/provenance + PyRIT/safety-regression + manifest | critical vuln, ASR > threshold, incomplete run, undetermined rate > threshold, manifest drift |
| G5 cost & performance | cost ledger extract, latency, load, budget variance | budget breach, unmet SLO |
| G6 release | signed evidence bundle, human approvals | missing/stale evidence, missing approval |

`RiskClass` (`docs_only`, `low`, `standard`, `high`, `critical`, `ai_agent`) selects a
`GateDepthProfile` that changes depth (which checks, thresholds, trials) — never the
meaning of the gate. Examples: docs_only → G0, G2 (lint/links), G3 light; auth change →
all gates; ai_agent → all gates + PyRIT trials + manifest validation.

## 4. Risk tiers for tool actions (`aisdlc.governance.tiers`)

| Tier | Examples | Default |
| --- | --- | --- |
| 0 | read, search, explain | automatic |
| 1 | write inside isolated worktree | automatic + audit |
| 2 | run tests/builds, local artifacts | policy-controlled |
| 3 | modify shared state, create PR, change backlog | explicit/rule-based approval |
| 4 | deploy, rotate secrets, change IAM, delete data | human approval required |

Approval timeouts and missing approvers → deny. Every tier >= 1 call is audited. Tool
results, repo files, web content, issue text are untrusted input; `governance.mcp`
screens tool results for injection patterns before they reach an agent.

## 5. Control plane (`aisdlc.control_plane`)

- `ModelRegistry`: entries `{provider, model, version, capabilities[], context_limit,
  tool_support, price_in/out/cached per 1M, approved_use_cases[], family}` loaded from
  `templates/model-registry.yaml`; org allowlist applied.
- `RoutingPolicy.route(task_profile) -> RoutingDecision` where `TaskProfile` =
  {complexity: low|standard|high, risk, required_capabilities, latency_target_ms,
  budget_remaining, role}. Tiers: low / standard / high / independent_review (different
  family from implementer) / escalation. Selection uses `BenchmarkService` scores when
  available, otherwise registry defaults. Never by reputation alone.
- `UsageLedger` (SQLite, stdlib `sqlite3`): `record(UsageEvent)`, `query(...)`,
  `summarize(group_by=...)`. `UsageEvent` = {ts, team, application, user, repository,
  change_id, task_id, agent_role, harness, provider, model, prompt_version,
  input_tokens, output_tokens, cached_tokens, reasoning_tokens, tool_calls, latency_ms,
  cost_usd, cache_hit, source}.
- `BudgetPolicyEngine.check(scope, forecast_cost) -> Decision(allow|require_approval|deny)`
  with budgets per application/team/environment/change; max model tier per role; max
  agent turns, parallel agents, review rounds, tool calls, context size; duplicate-run
  suppression keyed by (source_hash, eval_config_hash).
- `BenchmarkService`: store/query results `{benchmark_id, model, version, metric, value,
  cost, latency, ts}`; used by routing.
- `kpis.py`: cost per accepted requirement / merged change / defect / vuln / passing
  benchmark; tokens per accepted task; escalation rate; cache-hit rate; p50/p95 latency;
  turns per success; review rounds per merge; tool calls per accepted change; share of
  high-tier calls that a lower tier could have served (from benchmark data).

## 6. Orchestration (`aisdlc.orchestration`)

- Roles: planner, plan_checker, implementer, reviewer, verifier, uat, security_tester.
- `AgentBrief` contains only: change id, task, requirement + scenario text, relevant
  interfaces/ADRs, verification command, constraints, tool tier allowed, model routing
  decision. Never the conversation history.
- `AgentRunner` protocol: `run(brief) -> AgentResult` (status, diff summary, evidence
  paths, usage). Implementations: `DryRunRunner` (deterministic, used in tests),
  `LocalScriptRunner` (runs a configured command), `ClaudeCodeRunner` (invokes `claude -p`
  with a governed tool allowlist; import/exec guarded).
- `Executor.run_change(pkg)`: derive waves from task dependencies; per wave, allocate a
  worktree per task, run implementer, run verification command, run independent reviewer
  (different model family via routing), bounded fix loop (max rounds from org policy),
  record handoffs and usage in the ledger, human checkpoints at plan approval, before tier
  3+ actions, and before release. Resumable from handoffs.

## 7. Security testing (`aisdlc.security`)

- `pyrit_campaign.run_campaign(CampaignSpec, target) -> CampaignResult` where
  CampaignSpec (YAML) = {id, scenarios[], objectives/dataset, trials, scorer config,
  asr_threshold, max_undetermined_rate, baseline_id}. Result = {per-scenario ASR,
  undetermined rate, complete flag, usage (tokens/cost) recorded to the ledger, baseline
  delta}. Fail closed if incomplete.
- `safety_regression`: pytest-native, RAMPART-style. `@safety_case(category, trials,
  pass_threshold)` decorator + `SafetyReport` with per-category ASR; incomplete
  distributed runs fail closed.
- `judges.calibrate(scorer, labelled_dataset) -> CalibrationReport` (agreement, FPR/FNR,
  undetermined rate) using PyRIT scorer evaluation where possible.
- `manifest`: `ToolDataManifest` declared in threat model vs observed from audit log.

## 8. Quality bar for this repository

- Python >= 3.11, pydantic v2, typer CLI, ruff (line length 100), mypy strict on
  `src/aisdlc` (allow `ignore_missing_imports` for pyrit/agentmesh).
- Every module has tests; no network in tests; PyRIT/AGT integration tests use offline
  targets/in-memory backends and are `pytest.mark.integration` skipped if the library is
  not importable.
- No TODO/placeholder in production paths. No unverified completion claims.
- Docstrings on public API. Type hints everywhere.

## 9. Deviations (as built)

The contract above stands; the items below record where the implementation legitimately
diverged and what the divergence means for readers of the code.

1. **One `GateDepthProfile`.** The profile class lives only in `gates/depth.py`;
   `planning/risk.py` re-exports it (`gate_depth_profile()` is a thin wrapper over
   `GateDepthProfile.from_risk_class`). Per-gate depths come from the org policy's
   `gates.required_gates` / `gates.depth` for the class (the planner's private base table
   was dropped; the policy is the §3 source of truth). Planning-era field names are
   read-only aliases (`require_adr` → `require_adrs`, `human_approvals_required` →
   `min_approvals`, …). Two knobs stay distinct on purpose: `plan_approval_required` is
   the orchestration checkpoint before wave 0 (standard depth and above), while
   `require_plan_approval` makes G1 block on `Plan.approved_by` (deep only).
   `require_interfaces` is opt-in (a change need not add interfaces). Human approvals:
   high 1, critical/ai_agent 2; PyRIT trial minimum = `security_baselines.safety_trials_min`.
   `GateResult.depth` records the per-gate depth (`skipped` for gates the profile omits).
2. **CLI surface.** There is no `cmd_review.py`: independent review is `aisdlc run review`.
   Additional subcommands exist beyond §1: `governance`, `test`, `ci`, `init`. Every
   package argument accepts a directory or a bare `CHG-<slug>` id resolved under
   `changes/` from the current directory or any parent (`cli/_common.py`, not a
   subcommand). `aisdlc.yaml` is the first project-config candidate;
   `aisdlc init` scaffolds `aisdlc.yaml`, `org-policy.yaml` (copy of the org policy the
   project is governed by), `changes/`, `.aisdlc/` (git-ignored ledger + local HMAC
   signing key) and, unless already inside one, a git repository whose initial commit
   contains the whole working tree (respecting `.gitignore`, minus generated artefacts and
   anything matching the secrets patterns, which are listed as skipped) — the orchestrator
   creates worktrees from HEAD, so uncommitted sources would be invisible to agents. In an
   existing repository `init` never commits; it reports uncommitted sources, and
   `aisdlc run` refuses to start on a dirty tree unless `--allow-dirty` is given.
3. **Evidence producers write the canonical models.** `evidence/audit.json` is the
   canonical `AuditEvidence` summary (counts + integrity); the per-call entries the
   manifest drift check consumes live in `evidence/audit-entries.json`
   (`governance.audit.record_audit_evidence`, `aisdlc governance audit export --package`).
   `evidence/security.json` is merged, never replaced, by the PyRIT campaign and safety
   runners (`supply_chain.update_security_evidence`, `--package` on
   `aisdlc security campaign run` / `safety run`). `evidence/cost.json` is produced by
   `UsageLedger.cost_evidence` (used by the executor and `aisdlc cost report --package`).
   `aisdlc gate bundle` evaluates the gates and writes `final-verdict.json` itself when no
   verdict exists yet, then signs; without `$AISDLC_SIGNING_KEY` it uses
   `.aisdlc/signing.key`.
4. **Library quirks wrapped.** AGT's `PolicyEngine` reports `allowed=False` for matching
   `log`/`warn` rules; the platform's `PolicyEnforcer` treats those as allow-with-audit, so
   tier 1/2 policies must be evaluated through it, not raw `govern()`. PyRIT targets must
   have keyword-only constructors and central memory initialised; `security.targets`
   bootstraps an in-memory SQLite backend when none exists.
5. **`aisdlc.security` is lazy.** Every plane-1 and plane-3 name (and submodule) resolves
   on first access so importing the package never requires PyRIT.
