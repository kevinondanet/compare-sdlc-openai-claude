# Rollout guide — the five-phase implementation sequence

Operational guide for adopting the platform in the order the enterprise plan recommends
([`enterprise-plan.md`](enterprise-plan.md), "Recommended implementation sequence"). Each
phase lists what to stand up, the platform commands that do it (all verified against
`aisdlc 0.1.0`), the organisation-policy knobs that govern it, and the KPIs to watch before
moving on. Phases build on each other; do not skip ahead — a control plane without
canonical evidence has nothing to attribute cost to.

Prerequisites for every phase: the platform installed (README "Install"), an
organisation-owned `org-policy.yaml` (start from `templates/org-policy.yaml`), and a place
to keep the ledger (`$AISDLC_LEDGER`, default `.aisdlc/ledger.sqlite` per repository).

## Phase 1 — Standardize intent and evidence

**Goal.** Every change in every repository is described in the canonical change package
with SHALL/MUST requirements, WHEN/THEN scenarios, a BMAD kernel, assumptions and open
questions, organisation-wide IDs, and an executable verification for every task. Nothing
is claimed without an evidence record.

**Stand up.**

```bash
aisdlc init --name <project>                # aisdlc.yaml, org-policy.yaml, changes/, .aisdlc/
git add -A && git commit -m "adopt aisdlc"  # existing repo: init reports the uncommitted files and
                                            # this command; `aisdlc run` refuses a dirty tree
aisdlc policy validate                      # project may only tighten the org policy
```

Per change:

```bash
aisdlc change new CHG-<slug> --title "..." --risk standard --owner <person>
aisdlc intake kernel CHG-<slug> --why "..." -c "..." -k "..." -n "..." -s "..."
aisdlc intake clarify CHG-<slug>                 # ranked questions; --answer CQ-001="..." applies one
aisdlc intake checklist CHG-<slug> --strict
aisdlc intake analyze CHG-<slug>                 # duplicates, contradictions, terminology drift
aisdlc intake readiness CHG-<slug>               # G0; exit 1 while not ready
aisdlc change validate CHG-<slug>                # grammar + cross-artifact consistency
aisdlc plan generate CHG-<slug> && aisdlc plan check CHG-<slug>
```

Non-developers: `aisdlc intake discover --answers answers.yaml --markdown brd.md` creates
the package from coached plain-language answers. Existing OpenSpec repositories:
`aisdlc adapter import-openspec openspec/changes/<id>` (and `export-openspec` to go back).

Evidence from day one, even before CI is centralised:

```bash
aisdlc test run-evidence CHG-<slug> --command "pytest -q --junitxml=junit.xml --cov --cov-report=xml" \
    --junit junit.xml --coverage-xml coverage.xml --diff-base origin/main --report-uri <url>
```

**Org-policy knobs** (`org-policy.yaml`): `security_baselines.ambiguity_threshold` (0.20),
`evidence_standards.require_commit_sha/require_report_uri/require_environment` (true),
`evidence_standards.max_age_hours` (72), `gates.required_gates.<risk_class>` (projects may
only add gates).

**Exit criteria / KPIs.** Share of changes with `aisdlc intake readiness` passing before
implementation starts; ambiguity score at implementation start (target ≤ 0.20); share of
requirements with an executable scenario (readiness criterion `scenarios_present`);
requirement-to-test traceability (`aisdlc intake analyze` reports untested scenarios).

## Phase 2 — Centralize CI

**Goal.** One organisation repository owns the reusable workflows; application repositories
consume a pinned version through a caller workflow. Every security and test artifact lands
in the change package as evidence.

**Stand up.** In the organisation `.github` repository, render the reusable workflows once
and version them:

```bash
aisdlc ci list                                          # 12 workflows + the pinned action catalogue
aisdlc ci render --out .github/workflows --no-caller    # build-and-test, architecture-tests, mutation, codeql,
                                                        # dependency-review, secret-scan, sbom-provenance, scorecard,
                                                        # ai-review, safety-regression, pyrit-campaign, cost-benchmark
aisdlc ci verify-pins .github/workflows                 # every uses: SHA-pinned; hardening lint
```

In each application repository, render only the caller pinned to the org repository's commit:

```bash
aisdlc ci render --out .github/workflows -w caller \
    --workflows-repo <org>/.github --workflows-ref <40-hex commit sha> --workflows-version v1.0.0 \
    --pyrit-target <module:callable-or-url> --safety-module <tests.safety_module>
```

(`--workflows-ref` must be a commit SHA; the renderer refuses anything else.) The
workflows call `aisdlc test run-evidence`, `aisdlc ci collect-security --package`,
`aisdlc security safety run --package`, `aisdlc security campaign run --package` and
`aisdlc cost report --package` so evidence is written into `changes/<CHG>/evidence/`.

Collecting CI artifacts locally or from a download:

```bash
aisdlc ci collect-security <artifact-dir> --package CHG-<slug> --commit-sha $(git rev-parse HEAD) --environment ci
aisdlc test portfolio CHG-<slug>          # ten-layer portfolio vs the risk class; persisted for G2
aisdlc gate evaluate CHG-<slug> --gate G2
aisdlc gate evaluate CHG-<slug> --gate G4
```

Dependabot keeps the pins fresh (`templates/ci/dependabot.yml`); re-run `aisdlc ci
verify-pins` on every workflow change.

**Org-policy knobs.** `security_baselines.coverage.{lines,lines_floor,diff_lines,branches,critical_modules}`
(80/75/90/70/90), `security_baselines.mutation_score` (0.60), `max_critical_vulns`/`max_high_vulns`
(0), `require_sbom`/`require_provenance`/`require_secret_scan` (true). Project side:
`test_commands` and `critical_modules` in `aisdlc.yaml`.

**Exit criteria / KPIs.** All repositories on the pinned caller; `aisdlc ci verify-pins`
clean; diff coverage ≥ 90% and mutation score ≥ 0.60 on changed modules (ratchet upwards with
`aisdlc test mutation --floor`); zero open critical/high findings at G4; 100% of required
portfolio layers executed for the risk class.

## Phase 3 — Add controlled orchestration

**Goal.** Agents implement changes only through the orchestrator: fresh-context briefs,
one git worktree per task, planner/checker separation, an independent reviewer from a
different model family, bounded fix loops, human checkpoints by risk, model tier routing,
and every tool call classified, enforced and audited.

**Stand up.** Generate the per-role AGT policies and the harness configuration, then
rehearse with the dry runner before enabling a real agent:

```bash
aisdlc governance policy tiers                                    # the tier table in force
aisdlc governance policy generate --out-dir .aisdlc/policies      # planner/implementer/reviewer/security_tester.yaml
aisdlc governance policy validate .aisdlc/policies/implementer.yaml
aisdlc governance plugin emit --out-dir .claude/aisdlc            # AGT plugin policy JSON + platform hook wiring
aisdlc adapter emit claude_code --out .                           # or copilot | codex | cursor | kiro | all
aisdlc run change CHG-<slug> --runner dry --yes                   # rehearsal: worktrees, verification, review, ledger
aisdlc run change CHG-<slug> --runner claude --audit-log $PWD/.aisdlc/audit.jsonl
aisdlc run status CHG-<slug>
aisdlc governance audit verify .aisdlc/audit.jsonl
aisdlc governance audit export .aisdlc/audit.jsonl --package CHG-<slug>   # evidence/audit.json + audit-entries.json
```

G4/G6 re-verify the signed log at the path recorded in the evidence: an absolute
`--audit-log` path is used as is; a relative one resolves against the current working
directory, then the repository root (never the evidence directory), so evaluate gates
from the repository root when you passed a relative path. Checkpoints (plan approval, before every tier-3 apply-back, wave
boundaries, release) are interactive; `--yes` approves all and is for rehearsals and CI
against pre-approved plans, `--non-interactive` (the default without a TTY) denies all.
`--shadow` evaluates governance without blocking (tier-4 denials stay enforced) — use it
for the first weeks to measure friction before switching to enforce mode.

Reproduce any decision: `aisdlc governance policy check '{"tool_name":"Bash","action_type":"git_push","resource":"origin/main"}' --role implementer`
(observed: tier 3, `require_approval` auto-rejected without a handler).

**Org-policy knobs.** `tool_tiers.defaults` (0 automatic … 4 human_approval; projects may
only get stricter), `tool_tiers.approval_timeout_seconds` (300), `deny_on_timeout` (true),
`audit_from_tier` (1); `models.independent_review_requires_different_family` (true),
`models.max_tier_per_role`, `models.escalation_allowed`; `cost_limits.max_review_rounds` (3),
`max_parallel_agents` (4), `max_agent_turns` (40), `context_ceiling_tokens` (200000).

**Exit criteria / KPIs.** Review rounds per merged change (target ≤ 2); agent turns per
successful task; share of tier-3 actions approved by rule vs by human; approval timeouts
(each is a denial — see `runbooks/approval-timeout.md`); zero tier-4 actions attempted by
agents; independent-review family ≠ implementer family on 100% of material changes (G3).

## Phase 4 — Build the control plane

**Goal.** One registry, one routing policy, one ledger, budgets and quotas, benchmark
results feeding routing, exceptions with approvers and expiry, and dashboards.

**Stand up.**

```bash
export AISDLC_MODEL_REGISTRY=/path/to/model-registry.yaml   # org copy of templates/model-registry.yaml with real prices
export AISDLC_LEDGER=/path/to/ledger.sqlite                  # shared ledger (SQLite file; back it up)
aisdlc cost registry list                                    # placeholder prices are marked with *
aisdlc cost route --complexity high --role implementer --risk high
aisdlc cost import claude-code ~/.claude/projects/<repo>/<session>.jsonl --change CHG-<slug> --role implementer
aisdlc cost import agt-audit .aisdlc/audit.jsonl --change CHG-<slug>
aisdlc cost import pyrit <pyrit-memory.sqlite-or-pieces.json> --change CHG-<slug>
aisdlc cost report --group-by team
aisdlc cost budget-check --scope application:<app> --forecast 12.5 --budgets budgets.yaml
aisdlc cost kpis --outcomes outcomes.yaml --benchmarks benchmarks.sqlite
uvicorn --factory aisdlc.control_plane.server:create_app --port 8765     # JSON API for dashboards
```

Details of the budgets file, exceptions, benchmark loading and the API are in
[`operations.md`](operations.md).

**Org-policy knobs.** `models.allowlist` (fnmatch over `provider/model`),
`cost_limits.budgets.{per_change_usd,per_task_usd,per_day_usd,per_month_usd}`
(50/5/500/5000), `cost_limits.max_tool_calls` (500); per-scope budgets, quotas and
time-boxed exceptions in the budgets file or via `PUT /budget/budgets` and `PUT /budget/quotas`.

**Exit criteria / KPIs.** 100% of model calls in the ledger (compare `aisdlc cost report
--group-by source` with provider invoices); cost per accepted requirement and per merged
change trending down; escalation rate; cache-hit rate; p95 latency; share of high-tier
calls a lower tier could have served (needs benchmark data — until then the KPI reports
`n/a` with a note); zero runs proceeding past a `deny` decision.

## Phase 5 — Pilot with three project classes

**Goal.** Prove the whole loop on three real project classes before organisation-wide
enforcement. The repository ships one reference pilot per class under `pilots/`:

| Plan class | Shipped pilot | Risk class | Depth profile |
| --- | --- | --- | --- |
| Small internal CRUD application | `pilots/standard-web-service` (`CHG-add-health-endpoint`) | `standard` | all gates, standard depth, 1 approval |
| Business-user-led low-code / generated application | `pilots/docs-only-library` (`CHG-document-shapes-api`) stands in; non-developer intake is `aisdlc intake discover` | `docs_only` | G0, G2 (links), light G3 |
| Tool-using AI agent with private data access (critical) | `pilots/ai-agent` (`CHG-support-assistant-tools`) | `ai_agent` | all gates deep + PyRIT + safety + manifest, 2 approvals |

Run a pilot exactly as `tests/test_pilots.py` does:

```bash
cp -r pilots/ai-agent ~/support-assistant && cd ~/support-assistant
aisdlc init --name support-assistant          # new repository: the whole tree is committed
aisdlc plan risk classify CHG-support-assistant-tools         # computed ai_agent; explains every signal
aisdlc intake readiness CHG-support-assistant-tools
aisdlc plan check CHG-support-assistant-tools
aisdlc run change CHG-support-assistant-tools --runner dry --yes --audit-log $PWD/.aisdlc/audit.jsonl
aisdlc governance audit export $PWD/.aisdlc/audit.jsonl --package CHG-support-assistant-tools
aisdlc security campaign run templates/pyrit/campaigns/agent-baseline.yaml \
    --target aisdlc.security.targets:demo_vulnerable_app --package CHG-support-assistant-tools \
    --baseline-dir .aisdlc/baselines --save-baseline agent-baseline
aisdlc security safety run <module_with_safety_cases> --package CHG-support-assistant-tools
aisdlc ci manifest-drift CHG-support-assistant-tools
aisdlc gate evaluate CHG-support-assistant-tools
```

Observed on the shipped demo target: the baseline campaign completes (153/153 trials,
undetermined 0.000) with ASR 0.157 — a **breach** of the campaign's zero-tolerance
threshold, which is the point of the vulnerable demo app. Replace `--target` with your
application's callable (`module:function` taking and returning a string) or an `http(s)://`
endpoint.

For your own pilots, choose one application per class, keep `risk_classification.rules` in
`aisdlc.yaml` honest (auth paths → `high`, agent paths → `ai_agent`), and run each change
through the full sequence with a real runner (`--runner claude`) once the dry rehearsal is
green.

**Exit criteria / KPIs.** Per pilot: a positive, signed `final-verdict.json` verified by
`aisdlc gate verify-bundle`; G4 passing with a complete campaign, ASR ≤ threshold and no
manifest drift; cost per merged change and per accepted requirement recorded; review rounds
per merge; agent attack-success rate and judge agreement (`aisdlc security judges
calibrate`) recorded as the organisation's first baselines.

## After phase 5 — steady state

- Ratchet coverage and mutation floors upward (`aisdlc test mutation --floor`,
  `PortfolioThresholds.ratchet`) — never downward.
- Store every campaign run as a baseline and compare (`aisdlc security campaign compare
  result.json --baseline-id ... --baseline-dir ...`) so regressions block G4.
- Feed benchmark results into the benchmark store so routing stops relying on price
  ranking alone (`operations.md`, "Benchmark-driven routing").
- Review the KPI report monthly; use `high_tier_servable_by_lower_share` and
  `high_tier_servable_savings_usd` to lower `models.max_tier_per_role` where benchmarks
  justify it.
