# AI-SDLC platform

A centralised, policy-driven AI development platform. One canonical change-package model,
governed multi-agent orchestration in isolated git worktrees, progressive evidence gates
G0–G6 whose depth follows the risk class of the change, and a central model/cost control
plane — built on the **Agent Governance Toolkit** (tool/action policy, approvals, signed
audit trail) and **PyRIT** (adversarial campaigns, scorers, calibration, baselines).

The platform implements the enterprise plan in [`docs/enterprise-plan.md`](docs/enterprise-plan.md);
[`ARCHITECTURE.md`](ARCHITECTURE.md) is the binding engineering contract derived from it and
[`INTEGRATION.md`](INTEGRATION.md) records the verified AGT and PyRIT APIs.
[`docs/plan-traceability.md`](docs/plan-traceability.md) maps every plan recommendation to
the module that implements it and the test that proves it.

## The five layers and the control plane

```text
                     Business or developer intent
                                 │
   ┌─────────────────────────────▼─────────────────────────────┐
   │ 1. Intake & specification contract                        │  aisdlc.schema   (canonical models, grammar, package, fingerprint)
   │    changes/<CHG-id>/ intent · requirements · scenarios    │  aisdlc.intake   (kernel, clarify, checklist, analyze, discovery)
   └─────────────────────────────┬─────────────────────────────┘
   ┌─────────────────────────────▼─────────────────────────────┐
   │ 2. Planning & architecture governance                     │  aisdlc.planning (planner, plan_checker, adr, threat_model, risk)
   │    plan.md · tasks.md (executable verification) · ADRs    │
   │    threat-model.md with tool/data manifest                │
   └─────────────────────────────┬─────────────────────────────┘
   ┌─────────────────────────────▼─────────────────────────────┐
   │ 3. Isolated multi-agent implementation                    │  aisdlc.orchestration (brief, runner, worktree, executor, review, handoff)
   │    fresh-context briefs · worktree per task · waves       │  aisdlc.governance    (tiers, AGT policy, enforce, audit, mcp, hook)
   │    bounded fix loops · independent cross-family review    │
   └─────────────────────────────┬─────────────────────────────┘
   ┌─────────────────────────────▼─────────────────────────────┐
   │ 4. Deterministic CI + independent AI review               │  aisdlc.security.ci_templates, supply_chain
   │    SHA-pinned reusable workflows · evidence parsers        │  aisdlc.testing (evidence, portfolio, mutation, performance)
   └─────────────────────────────┬─────────────────────────────┘
   ┌─────────────────────────────▼─────────────────────────────┐
   │ 5. Security, performance & release gates                  │  aisdlc.security (pyrit_campaign, safety_regression, judges, manifest)
   │    G0 … G6 · risk-based depth · signed evidence bundle    │  aisdlc.gates    (gates, depth, verdict)
   └─────────────────────────────┬─────────────────────────────┘
                                 │
        ┌────────────────────────▼────────────────────────┐
        │ Central model, policy, telemetry, benchmark and  │  aisdlc.control_plane (registry, pricing, routing, ledger,
        │ cost control plane                               │   budget, benchmark, telemetry, kpis, server)
        └─────────────────────────────────────────────────┘
        policy layers: org-policy.yaml  >  aisdlc.yaml (project, narrow-only)  >  change package      aisdlc.policy
        harness adapters: Claude Code · Copilot · Codex · Cursor · Kiro · OpenSpec I/O               aisdlc.adapters
```

### One canonical model

Everything the platform knows about a change lives in one directory,
`changes/<CHG-slug>/`, as Markdown files with a YAML front-matter block (human prose in the
body, structured data in the front-matter) plus JSON evidence records. Workflow state is
**derived** from those files (`ChangePackage.derive_state()`); no module keeps a parallel
state store, prompts and agents are stateless, and every cross-reference uses a stable ID
(`REQ-003`, `SCN-003-01`, `TASK-002`, `EVD-tests-001`, `FND-004`, `BM-<slug>-<version>`).
Other methods are translated into this model (OpenSpec import/export, harness adapters),
never installed next to it. Every "done", "tested", "reviewed" or "secure" claim must be
backed by an evidence record carrying command, exit code, commit SHA, environment and report
URI; missing or `incomplete` evidence fails its gate closed.

```text
changes/CHG-add-health-endpoint/
  intent.md            kernel (why, capabilities, constraints, non_goals, success_signal), owner, risk_class
  requirements.md      REQ-nnn SHALL/MUST or EARS text, each with WHEN/THEN scenarios
  scenarios/           optional per-requirement scenario files
  assumptions.md       ASM-nnn assumptions, OQ-nnn open questions (blocking: true stops G0)
  architecture/        context.md, decisions/ADR-nnnn.md, interfaces/IFC-nnn.md, threat-model.md
  plan.md              waves of task ids, checkpoint flags, approved_by
  tasks.md             TASK-nnn with requirement_ids and an executable verification block
  evidence/            tests.json reviews.json security.json performance.json cost.json audit.json portfolio.json
  handoffs/            durable, numbered agent handoffs (resumable runs)
  approvals.json       human approvals (G6)
  final-verdict.json   gate results G0..G6, overall, signatures
  evidence-bundle.json signed manifest of the package (HMAC-SHA256 or Ed25519)
```

## Install

Python 3.11+ (the workspace uses 3.13). The core package depends only on pydantic v2,
PyYAML, typer, rich and jsonschema; the governance and security libraries are extras.

```bash
uv venv --python 3.13 .venv && source .venv/bin/activate
uv pip install -e ".[dev,governance,security,server]"
```

`governance` pulls `agent-governance-toolkit-core`, `security` pulls `pyrit`, `server` pulls
FastAPI/uvicorn for the control-plane API. This workspace installs both governance
libraries from the sibling checkouts instead (`INTEGRATION.md` §A, §D.1, §E.1):

```bash
# AGT: three umbrella packages, installed non-editable (their build copies the source trees)
uv pip install ../agent-governance-toolkit/agent-governance-python/agent-governance-toolkit-core \
               ../agent-governance-toolkit/agent-governance-python/agt-policies \
               ../agent-governance-toolkit/agent-governance-python/agent-governance-toolkit-protocols
# PyRIT: editable, no extras (the base install is already heavy; extras hit the network)
uv pip install -e ../PyRIT
aisdlc --version            # aisdlc 0.1.0
```

Versions verified in this workspace: `agent-governance-toolkit-core 5.0.0`,
`agt-policies 5.0.0`, `agent-governance-toolkit-protocols 5.0.0`, `pyrit 1.1.0.dev0`.
Without the extras the CLI still works: `aisdlc.security` resolves lazily, AGT-backed
enforcement falls back to the platform's local tier checker, and integration tests skip.

## Ten-minute quickstart

The quickest tour runs the shipped **standard web-service pilot** through every layer. The
outputs below are pasted from a real run (`aisdlc 0.1.0`, dry runner, no model calls).

```bash
cp -r pilots/standard-web-service ~/orders-service && cd ~/orders-service
aisdlc init --name orders-service     # new repository: the whole tree is committed (secrets such
                                      # as .env are skipped and listed); agents run against HEAD
```

```text
$ aisdlc init --name orders-service
exists      aisdlc.yaml
created     org-policy.yaml
created     changes/.gitkeep
created     .aisdlc/.gitignore
created     .aisdlc/signing.key
created (17 file(s) committed) .git
next: aisdlc change new CHG-<slug> --title '<title>' --risk standard; aisdlc policy show
```

Inside an existing repository `init` never commits; it reports how many files are
uncommitted and the command that commits them. Task worktrees are created from `HEAD`, so
`aisdlc run change` / `run task` refuse to start (exit 2) while sources outside `changes/`
are uncommitted (`--allow-dirty` overrides).

**1. Look at the change and the policy it runs under.** Every command accepts a package
directory or a bare `CHG-<slug>` id resolved under `changes/` from the current directory or
any parent.

```text
$ aisdlc change list
CHG-add-health-endpoint                  planned       standard   Add a /health endpoint with dependency checks

$ aisdlc policy validate
applied  cost_limits.max_review_rounds
1 override(s) applied, 0 violation(s)
```

**2. G0 — intent readiness.**

```text
$ aisdlc intake readiness CHG-add-health-endpoint
[PASS] owner: An accountable human owner is named
[PASS] kernel_complete: Kernel states why, capabilities, non-goals and a success signal
[PASS] requirements_present: At least one requirement is written
[PASS] scenarios_present: Every requirement has at least one WHEN/THEN scenario
[PASS] grammar: Requirements and scenarios follow the normative grammar
[PASS] no_blocking_questions: No open blocking question
[PASS] ambiguity: Ambiguity score <= 0.20
[PASS] constraints_stated: Constraints are stated (or explicitly 'none known')
[PASS] assumptions_recorded: At least one explicit assumption is recorded
[PASS] no_unstated_assumptions: No statement leans on an unrecorded assumption
[PASS] success_measurable: Success signal is measurable
[WARN] no_open_questions: No open non-blocking questions
    - OQ-001
    fix: Answer or explicitly defer the remaining questions.
CHG-add-health-endpoint: READY — 11/12 criteria met, ambiguity 0.20 (threshold 0.20)
```

**3. G1 — goal-backward plan check.**

```text
$ aisdlc plan check CHG-add-health-endpoint
ADVISORY TASK_MODEL_TIER_MISSING [TASK-001]: task has no model tier hint; routing will use the role default
ADVISORY TASK_MODEL_TIER_MISSING [TASK-002]: task has no model tier hint; routing will use the role default
ADVISORY TASK_MODEL_TIER_MISSING [TASK-003]: task has no model tier hint; routing will use the role default
ADVISORY PLAN_NOT_APPROVED: risk class ai_agent requires plan approval (plan.approved_by) before wave 0 runs
ADVISORY PLAN_FINGERPRINT_UNKNOWN: plan.md carries no requirements fingerprint; staleness cannot be checked
CHG-add-health-endpoint: plan check PASS — 0 blocking, 5 advisory; requirements fingerprint unknown
```

**4. Run the change with governed, isolated agents.** The dry runner implements nothing
(the pilot ships implemented) but exercises everything else: a worktree per task, model
routing under the role's tier cap and budget, the task's real verification command inside
the worktree, an independent reviewer from a *different model family*, checkpoints before
each tier-3 apply-back and before release, a whole-change final review, and usage metered
into the ledger. `--yes` approves the checkpoints; without a TTY the default denies them.

```text
$ aisdlc run change CHG-add-health-endpoint --runner dry --yes
CHG-add-health-endpoint: success
  TASK-001   done         rounds=1 model=gpt-5-mini reviewer=claude-sonnet-5 applied=True
  TASK-002   done         rounds=1 model=gpt-5-mini reviewer=claude-sonnet-5 applied=True
  TASK-003   done         rounds=1 model=gpt-5-mini reviewer=claude-sonnet-5 applied=True
  usage: 7 call(s), 7000 in / 1400 out tokens, $0.0180
  final review: EVD-reviews-004 approved
  release checkpoint: approved
  evidence consolidated at bc96c1d0cd22: 3 test and 3 review record(s) archived to evidence/logs/superseded-evidence.json
  handoffs: 35

$ aisdlc run status CHG-add-health-endpoint
CHG-add-health-endpoint: reviewed
  TASK-001   done         wave=0 ✓
  TASK-002   done         wave=0 ✓
  TASK-003   done         wave=1 ✓
handoffs:
  0001 run_start     success
  0002 plan_approval approved
  0003 route         success   TASK-001
  0004 brief         success   TASK-001 r1
  0005 implement     success   TASK-001 r1
  ...
  0013 checkpoint    approved  TASK-001
  0014 apply_back    success   TASK-001
  ...
  0033 final_review  success
  0034 release       approved
  0035 run_end       success
```

Swap `--runner dry` for `--runner claude` to invoke Claude Code (`claude -p`) under the
generated tool allow-list and governance hook, or `--runner script --script-command ...` for
any other agent.

**5. Cost evidence from the ledger (G5).**

```text
$ aisdlc cost report --package CHG-add-health-endpoint
recorded EVD-cost-001 (complete, $0.0180) in changes/CHG-add-health-endpoint/evidence/cost.json
```

**6. Evaluate every gate.** Gates fail closed: at standard depth G2 wants coverage and the
full coverage portfolio and G4 wants supply-chain evidence, neither of which a local dry run
produces — the CI workflows (`aisdlc ci render`) and `aisdlc ci collect-security` supply them.

```text
$ aisdlc gate evaluate CHG-add-health-endpoint
CHG-add-health-endpoint: risk standard, depth standard
G0 PASS [standard] Intent readiness
G1 PASS [standard] Architecture readiness
G2 FAIL [standard] Implementation quality
    - no coverage evidence
    - portfolio: required layer integration was not executed
    - portfolio: required layer contract was not executed
    - portfolio: required layer e2e was not executed
    - portfolio: required layer architecture was not executed
    - portfolio: required layer security was not executed
    - portfolio: lines coverage not measured (required)
    - portfolio: branches coverage not measured (required)
    - portfolio: diff_lines coverage not measured (required)
    - portfolio: acceptance_criteria_with_evidence not measured (required)
G3 PASS [standard] Independent review
G4 FAIL [standard] Security and safety
    - no security evidence
G5 PASS [standard] Cost and performance
G6 FAIL [standard] Release
    - G2 failed: no coverage evidence; ...
    - G4 failed: no security evidence
    - 0 human approval(s) recorded, 1 required
```

**7. Approve, sign, verify.** `gate bundle` evaluates the gates when no verdict exists,
writes `final-verdict.json`, and signs the bundle with `$AISDLC_SIGNING_KEY` or the
`.aisdlc/signing.key` written by `init`. A negative verdict is signed too — and
`verify-bundle`, which release automation calls, refuses it.

```text
$ aisdlc gate approve CHG-add-health-endpoint --role owner --approver service-lead
recorded approval by service-lead as owner (1 total)

$ aisdlc gate bundle CHG-add-health-endpoint
no final-verdict.json; evaluated gates first (overall FAIL)
bundle digest 080ec23ec3ad95eccc363125cb3bcd795a2f73c0c841fda95c44f28100d06454
signed hmac-sha256 by aisdlc
files: 4, approvals: 1
wrote changes/CHG-add-health-endpoint/evidence-bundle.json and changes/CHG-add-health-endpoint/final-verdict.json
note: the certified verdict is negative (overall=false)

$ aisdlc gate verify-bundle CHG-add-health-endpoint
bundle FAILED digest=080ec23ec3ad95eccc363125cb3bcd795a2f73c0c841fda95c44f28100d06454
signatures valid=1 invalid=0 approvals=1 tampered=False stale=False
    - certified verdict is negative (overall=false)
```

### Starting your own change

```text
$ aisdlc change new CHG-add-health-endpoint --title "Add /health endpoint" --risk standard --owner service-lead
created changes/CHG-add-health-endpoint

$ aisdlc intake readiness CHG-add-health-endpoint
[PASS] owner: An accountable human owner is named
[FAIL] kernel_complete: Kernel states why, capabilities, non-goals and a success signal
    - missing: why
    - missing: capabilities
    - missing: non_goals
    - missing: success_signal
    fix: Fill every kernel part in intent.md.
[FAIL] requirements_present: At least one requirement is written
    fix: Add SHALL/MUST requirements to requirements.md.
[FAIL] scenarios_present: Every requirement has at least one WHEN/THEN scenario
    fix: Write a WHEN … THEN … scenario for each requirement.
...
CHG-add-health-endpoint: NOT READY — 6/12 criteria met, ambiguity 0.00 (threshold 0.20)

$ aisdlc intake kernel CHG-add-health-endpoint --why "Operators cannot tell whether the service or one of its dependencies is down." \
    -c "GET /health reports each dependency check and an overall status" \
    -k "No web framework is added; the service stays plain WSGI" -n "Readiness/liveness split" \
    -s "Load balancer probes flip to 503 within one probe interval of a dependency outage"
```

Then write requirements in `requirements.md` front-matter (SHALL/MUST or EARS text, one
WHEN/THEN scenario each — see the pilot for the shape), `aisdlc intake clarify` for ranked
clarification questions, and `aisdlc plan generate` to derive tasks with executable
verification and dependency waves:

```text
$ aisdlc plan generate CHG-add-health-endpoint
CHG-add-health-endpoint: 5 task(s) for 3 requirement(s); risk class standard
wave 0: TASK-001, TASK-002, TASK-003
wave 1 [checkpoint]: TASK-004, TASK-005
  TASK-001 (standard) Implement REQ-001: WHEN a client requests GET /health, the service SHALL respo…
      verify: pytest -q tests/test_req001_a_client_requests_get.py
  ...
  TASK-005 (low) Update documentation and change package
      verify: aisdlc change validate changes/CHG-add-health-endpoint
note: plan approval required before wave 0 (set plan.approved_by)
saved changes/CHG-add-health-endpoint
```

Non-developers start from `aisdlc intake discover` (coached plain-language questions;
`--answers file.yaml` for non-interactive use), which creates the package.
The full lifecycle per gate is in [`docs/user-guide.md`](docs/user-guide.md).

## Gates

| Gate | Evidence required | Blocks on (as implemented in `aisdlc.gates.gates`) |
| --- | --- | --- |
| **G0** intent readiness | kernel, requirements, scenarios, assumptions, owner, ambiguity score | missing owner/kernel part, no requirements or scenarios, grammar issue, `ambiguity_score` > `security_baselines.ambiguity_threshold` (0.20), open `blocking: true` question |
| **G1** architecture readiness | plan (goal-backward plan checker), ADRs, interfaces (opt-in), threat model, NFRs | plan-checker blocking issue, unresolved high-risk threat, missing threat model at standard+ depth, missing `plan.approved_by` at deep depth |
| **G2** implementation quality | build/lint/types/links/tests/coverage/mutation evidence + coverage portfolio | failing or incomplete test evidence, coverage or mutation below profile, required portfolio layer not executed, required metric not measured |
| **G3** independent review | review evidence from a different model family (standard+) / independent agent | missing or incomplete review, same-family reviewer, grounded blocking finding in the latest round |
| **G4** security & safety | SAST/SCA/secrets/SBOM/provenance + PyRIT campaign + safety regression + manifest drift + verified audit log | open critical/high finding above `max_*_vulns` (0), missing SBOM/provenance, incomplete campaign or safety run, ASR > `asr_threshold` (0.05), undetermined rate > 0.10, manifest drift |
| **G5** cost & performance | `evidence/cost.json` ledger extract, `evidence/performance.json` vs SLO targets | over budget (org budget is a ceiling; evidence may only tighten), unmet SLO, missing performance evidence when required |
| **G6** release | every required gate, fresh evidence, human approvals, signed bundle, verified audit log | stale evidence (other commit or older than `evidence_standards.max_age_hours`), missing approvals (high: 1, critical/ai_agent: 2), failed audit-chain verification |

Risk class selects a `GateDepthProfile` (`aisdlc.gates.depth`) that changes **depth, never
meaning**: `docs_only` → G0, G2 (lint/links), light G3; `low` → G0–G3 + G6, light; `standard`
→ all gates at standard depth; `high`/`critical`/`ai_agent` → all gates deep, cross-family
review, PyRIT trials, safety regression and manifest validation for `ai_agent`.

## Tool risk tiers

| Tier | Examples (`aisdlc governance policy tiers`) | Default behaviour |
| --- | --- | --- |
| 0 | read, search, explain, list, glob, grep, inspect | automatic |
| 1 | write, edit, create_file, delete_file, move_file inside the isolated worktree | automatic + audit |
| 2 | run_tests, build, lint, typecheck, execute, git_commit, network_egress to allow-listed hosts, web_search, run_campaign | policy-controlled + audit |
| 3 | git_push, create_pr, update_pr, create_issue, update_backlog, install_package, modify_shared_state, writes outside the worktree | explicit or rule-based approval; timeout or missing approver → deny |
| 4 | deploy, rotate_secrets, read/write_secrets, change_iam, delete_data, force_push, destructive, unlisted egress | human approval outside the agent loop; agents are always denied |

Unknown action types default to tier 3. A project may raise a tool's tier, never lower it.
Tool results, repository files, web content and issue text are untrusted input and are
screened for injection patterns before they reach an agent (`aisdlc governance mcp screen`).

## Coverage portfolio thresholds

Org defaults from `templates/org-policy.yaml` (`security_baselines`), narrowable per project:

| Threshold | Default | Enforced by |
| --- | --- | --- |
| Line coverage target / ratchet floor | 80% / 75% | G2 via `testing.portfolio` |
| Changed-line (diff) coverage | 90% | G2 |
| Branch coverage | 70% | G2 |
| Critical-module coverage (`critical_modules` in `aisdlc.yaml`) | 90% | G2 |
| Mutation score (scope disclosed in evidence) | 0.60, ratcheted upwards only | G2 via `testing.mutation` |
| Acceptance criteria with executable evidence | 100% | G2 portfolio metric |
| Required layers by risk class (unit … performance) | executed 100% | G2 portfolio |
| Incomplete test/eval runs | always fail closed | every gate |
| PyRIT ASR / safety ASR | ≤ 0.05 (campaign template: 0.0) | G4 |
| Undetermined judge verdicts | ≤ 0.10 | G4 |
| Ambiguity score at implementation start | ≤ 0.20 | G0 |

## KPIs (`aisdlc cost kpis`, `POST /kpis`)

cost per accepted requirement · cost per merged change · cost per defect found · cost per
vulnerability found · cost per passing benchmark · tokens per accepted task · model
escalation rate · cache-hit rate and cached-token share · p50/p95 latency · agent turns per
successful run · review rounds per merged change · tool calls per accepted change · share of
high-tier calls a lower tier could have served (from benchmark data) and the savings implied.
Definitions are in [`docs/operations.md`](docs/operations.md#kpi-definitions).

## How AGT and PyRIT are used

| Library | Used for | Wrapped in |
| --- | --- | --- |
| AGT `PolicyEngine` + generated `governance.toolkit/v1` YAML | deterministic tool/action policy per agent role, tier rules, egress allow-list | `aisdlc.governance.policy` (generator/validator), `aisdlc.governance.enforce.PolicyEnforcer` (treats `log`/`warn` matches as allow-with-audit, converts denials to `PlatformDenied`) |
| AGT approvals (`CallbackApproval`, auto-reject default) | tier-3 approvals, deny on timeout / missing approver | `aisdlc.governance.enforce` (`DeferredApproval`, executor checkpoint callback, Claude Code `ask`) |
| AGT `AuditLog` + `FileAuditSink` (HMAC hash chain) | audit of every tier ≥ 1 call; G6 verifies integrity | `aisdlc.governance.audit.AuditTrail`, `aisdlc governance audit verify/export` |
| AGT Claude Code plugin format | `policy.<role>.json`, `hooks.json` for the AGT plugin; platform PreToolUse/PostToolUse hook | `aisdlc.governance.claude_code_plugin`, `aisdlc governance hook/plugin` |
| AGT `BudgetTracker` (per-agent windows, optional) | per-agent token windows under the platform budget engine | `aisdlc.control_plane.budget.AgtAgentWindowTracker` |
| PyRIT `PromptSendingAttack`, converters, `SubStringScorer`/`RegexScorer`, `AttackExecutor`, scenarios | offline red-team campaigns with per-objective trials, ASR, undetermined rate, completeness | `aisdlc.security.pyrit_campaign` (`CampaignSpec` YAML → `CampaignResult`), `aisdlc.security.targets.AppUnderTestTarget` (wraps a plain callable or HTTP endpoint) |
| PyRIT memory (`token_usage_*` piece metadata) | usage metering of campaigns into the ledger | `aisdlc.control_plane.telemetry.from_pyrit_memory`, `aisdlc cost import pyrit` |
| PyRIT scorer evaluation (`HumanLabeledDataset`, `ScorerEvaluator`) | judge calibration vs human labels | `aisdlc.security.judges` (`aisdlc security judges calibrate`) |

AGT and PyRIT types never appear in the canonical models; both imports are guarded so the
core package works without them (`ARCHITECTURE.md` §0.8, §9.4–9.5;
[`docs/adr/`](docs/adr/) ADR-0002, ADR-0003).

## The three pilots

| Pilot (`pilots/`) | Risk class | Change | What it exercises |
| --- | --- | --- | --- |
| `docs-only-library` | `docs_only` | `CHG-document-shapes-api` | light profile: G0, G2 (link check), light G3; G1/G4/G5/G6 skipped |
| `standard-web-service` | `standard` | `CHG-add-health-endpoint` | every gate at standard depth, one human approval, cross-family review |
| `ai-agent` | `ai_agent` | `CHG-support-assistant-tools` | deep profile: PyRIT campaign, safety regression, tool/data manifest vs audit log, two approvals |

`tests/test_pilots.py` copies each pilot into a fresh git repository and drives it through
readiness → plan check → `run change --runner dry` → gate evaluation.

## Repository layout

```text
pyproject.toml          package ai-sdlc-platform, module aisdlc, py>=3.11, extras dev/governance/security/server
src/aisdlc/
  ids.py                ID scheme and validators
  schema/               canonical models, grammar, package I/O, markdown round-trip, fingerprints
  intake/               kernel, clarify, checklist, analyze, discovery
  planning/             planner, plan_checker, adr, threat_model, risk
  orchestration/        roles, brief, runner, worktree, executor, review, handoff
  governance/           tiers, policy, enforce, audit, mcp, claude_code_plugin
  security/             ci_templates, supply_chain, pyrit_campaign, safety_regression, judges, manifest, targets
  testing/              evidence, portfolio, mutation, performance
  control_plane/        registry, pricing, routing, ledger, budget, benchmark, telemetry, kpis, server
  gates/                gates, depth, verdict
  policy/               org_policy, project_config, merge
  adapters/             base, claude_code, copilot, codex, cursor, kiro, openspec
  cli/                  main.py + cmd_*.py (auto-discovered subcommands)
templates/
  org-policy.yaml, project-config.yaml, model-registry.yaml
  change/               skeleton change package
  workflows/            12 reusable GitHub workflows (SHA-pinned, least privilege) + ci/caller.yml
  agt/                  generated AGT policy YAML per role + Claude Code plugin config
  pyrit/                campaigns/, datasets/, labelled/
  adapters/             harness templates
tests/                  pytest, mirrors src; no network; AGT/PyRIT tests are offline and skip without the library
docs/                   user guide, runbooks, rollout, operations, security, traceability, ADRs
pilots/                 three pilot projects with complete change packages
```

## CLI map

| Command group | Purpose |
| --- | --- |
| `aisdlc init` | scaffold `aisdlc.yaml`, `org-policy.yaml`, `changes/`, `.aisdlc/` (ledger, signing key), git repo with the working tree committed (secrets skipped) |
| `aisdlc change` | `new`, `validate`, `status`, `list`, `fingerprint` |
| `aisdlc intake` | `discover`, `kernel`, `clarify`, `checklist`, `analyze`, `readiness` (G0) |
| `aisdlc plan` | `generate`, `check`, `waves`, `adr new/validate`, `threat-model init/validate`, `risk classify` (G1) |
| `aisdlc run` | `change`, `task`, `review`, `status` — governed orchestration (G2/G3) |
| `aisdlc test` | `run-evidence`, `portfolio`, `mutation`, `perf-evidence` (G2/G5) |
| `aisdlc ci` | `render`, `list`, `verify-pins`, `collect-security`, `manifest-drift` (plane 1, G4) |
| `aisdlc governance` | `policy generate/check/validate/tiers`, `audit verify/export`, `plugin emit/show`, `mcp screen`, `hook` (plane 2) |
| `aisdlc security` | `campaign run/compare`, `safety run`, `judges calibrate` (plane 3, G4) |
| `aisdlc cost` | `record`, `report`, `budget-check`, `kpis`, `route`, `registry list`, `import claude-code/agt-audit/pyrit` (control plane) |
| `aisdlc gate` | `evaluate`, `verdict`, `approve`, `bundle`, `verify-bundle` (G0–G6) |
| `aisdlc policy` | `show`, `validate`, `effective` |
| `aisdlc adapter` | `list`, `emit <harness>`, `import-openspec`, `export-openspec` |

Exit codes: `0` ok · `1` check/gate/run failed · `2` bad input · `3` blocked by checkpoint or
budget · `4` duplicate run suppressed (same source hash and evaluation config).

## Documentation

- [`docs/user-guide.md`](docs/user-guide.md) — the change lifecycle, command by command
- [`docs/rollout.md`](docs/rollout.md) — five-phase rollout with commands, policy knobs and KPIs
- [`docs/operations.md`](docs/operations.md) — control-plane operations
- [`docs/security.md`](docs/security.md) — the three security planes as implemented
- [`docs/plan-traceability.md`](docs/plan-traceability.md) — plan → module → test
- [`docs/runbooks/`](docs/runbooks/) — failed G4 campaign, bundle verification failure, budget deny, approval timeout, concurrent edits
- [`docs/adr/`](docs/adr/) — ADR-0001 canonical model, ADR-0002 AGT, ADR-0003 PyRIT, ADR-0004 in-house control plane, ADR-0005 gate depth profile

## Development

```bash
ruff check src tests && ruff format --check src tests
mypy
pytest -q
```

Quality bar (`ARCHITECTURE.md` §8): pydantic v2 `extra="forbid"`, mypy strict on
`src/aisdlc`, ruff line length 100, docstrings on public API, no TODO/placeholder in
production paths, no network in tests.
