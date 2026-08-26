# AI-SDLC platform — user guide

This guide walks a change through the platform from a plain-language idea to a signed
release verdict. Everything the platform knows about a change lives in one directory,
the **change package** (`changes/CHG-<slug>/`); every command below reads and writes
those files and nothing else (ARCHITECTURE.md §0.1). Commands accept either the package
directory or the bare `CHG-<slug>` id, resolved under `changes/` from the current
directory or any parent.

Three worked examples live under [`pilots/`](../pilots): a documentation-only library
change, a standard web service change and an AI-agent change. Each `README.md` there
lists the exact commands for its risk class.

## 1. One-time setup

```
pip install -e ".[dev,governance]"      # governance = Agent Governance Toolkit (policy engine)
aisdlc init --name my-project           # aisdlc.yaml, org-policy.yaml, changes/, .aisdlc/, git init + commit of the tree
aisdlc policy show                      # effective policy = org policy narrowed by aisdlc.yaml
```

`aisdlc init` creates a git repository unless one exists and commits the **whole working
tree** in the initial commit (`.gitignore` respected): the orchestrator creates task
worktrees from `HEAD`, so uncommitted sources would be invisible to agents and their
verification commands would fail. Files matching a secrets pattern (`.env`, `.env.*`,
`*.key`, `*.pem`, `*.p12`, `*.pfx`, `settings.local.json`) and generated artefacts
(`__pycache__/`, `.venv/`, `node_modules/`, ...) are never committed and are listed in the
output. Inside an existing repository `init` commits nothing; it reports how many files
are uncommitted and the command to run (`git add -A && git commit -m 'adopt aisdlc'`).
`.aisdlc/` holds the usage ledger and the local HMAC signing key and is git-ignored.

Policy comes in three layers merged **narrow-only** (§0.4): `org-policy.yaml` sets the
widest bounds, `aisdlc.yaml` `overrides:` may only tighten them, and the change package
carries change-specific facts (risk class, threat model). `aisdlc policy validate`
reports every override that would loosen the org value.

## 2. The change lifecycle and its gates

| Step | Command(s) | Produces | Gate |
| --- | --- | --- | --- |
| Discover / create | `aisdlc intake discover`, `aisdlc change new CHG-x --title ... --risk ... --owner ...` | `intent.md` (kernel), `requirements.md`, `assumptions.md` | — |
| Specify | `aisdlc intake kernel`, `intake clarify`, `intake checklist`, `intake analyze`, `intake readiness` | SHALL/EARS requirements with WHEN/THEN scenarios, ambiguity score | **G0** intent readiness |
| Architect & plan | `aisdlc plan risk classify`, `plan generate`, `plan check`, `plan waves`; ADRs, interfaces, `architecture/threat-model.md` | `plan.md`, `tasks.md` (executable verification per task), ADRs, threat model with tool/data manifest | **G1** architecture readiness |
| Implement | `aisdlc run change CHG-x --runner dry\|script\|claude --yes` | isolated worktree per task, `evidence/tests.json` (verification runs), `evidence/reviews.json` (independent review), `evidence/cost.json`, `handoffs/` | **G2** implementation quality |
| Review | part of `run change`; `aisdlc run review CHG-x` for a whole-change re-review | review evidence from a different model family, grounded findings | **G3** independent review |
| Secure | `aisdlc ci collect-security`, `aisdlc security campaign run <campaign.yaml> --package CHG-x`, `security safety run`, `aisdlc ci manifest-drift` | `evidence/security.json` (SAST/SCA/secrets/SBOM/provenance, PyRIT ASR, safety regression, manifest drift) | **G4** security & safety |
| Measure | `aisdlc test run-evidence`, `test portfolio`, `test mutation`, `aisdlc cost report --package CHG-x` | test/coverage/mutation evidence, ledger extract, budget variance | **G2**, **G5** cost & performance |
| Release | `aisdlc gate evaluate CHG-x`, `gate approve`, `gate bundle`, `gate verify-bundle` | `final-verdict.json` + signed evidence bundle | **G6** release |

The **risk class** of the change (`docs_only`, `low`, `standard`, `high`, `critical`,
`ai_agent`) selects a gate depth profile: which gates are required and how deep they
go — never what a gate means. `aisdlc plan risk classify CHG-x` derives the class from the
project's path rules and the files a change touches; `aisdlc gate evaluate --risk ...`
lets you preview another profile.

Every gate fails closed: missing or `incomplete` evidence fails the gate, an approval
that times out is a denial, an unknown tool action is tier 3.

## 3. Step by step

### 3.1 Intake (G0)

```
aisdlc change new CHG-add-health-endpoint --title "Add /health" --risk standard --owner service-lead
aisdlc intake kernel CHG-add-health-endpoint --why "..." -c "capability" -k "constraint" -n "non-goal" -s "success signal"
aisdlc intake clarify CHG-add-health-endpoint            # ranked clarification questions
aisdlc intake clarify CHG-add-health-endpoint --answer CQ-001="..."
aisdlc intake checklist CHG-add-health-endpoint --strict
aisdlc intake readiness CHG-add-health-endpoint          # exit 1 while G0 would fail
```

Requirements are edited in `requirements.md` (front-matter) — text must use SHALL/MUST
or an EARS form and carry at least one WHEN/THEN scenario. Optional per-requirement
scenario files under `scenarios/REQ-nnn.md` are the source of truth for the scenarios
they list; the platform writes them back to the same file on save.

Non-developers can start from `aisdlc intake discover` (coached plain-language
questions, `--answers file.yaml` for non-interactive use) which creates the package.

### 3.2 Planning and architecture (G1)

```
aisdlc plan risk classify CHG-add-health-endpoint             # risk class + gate depth profile
aisdlc plan generate CHG-add-health-endpoint             # tasks with verification + waves from requirements
aisdlc plan check CHG-add-health-endpoint                # goal-backward check: every requirement covered, every task verifiable
aisdlc plan adr new CHG-add-health-endpoint "Decision title"                        # ADR skeleton under architecture/decisions/
aisdlc plan adr validate CHG-add-health-endpoint && aisdlc plan threat-model validate CHG-add-health-endpoint
```

`plan.md` groups tasks into waves; `checkpoint: true` asks a human before the next
wave. Each task's `verification` block is an executable command with an expected exit
code (and optional output regex) — the orchestrator runs it inside the task's worktree
and records the result as test evidence. The threat model
(`architecture/threat-model.md`) declares the **tool/data manifest** for agentic
changes; G4 compares it with what the audit log observed.

### 3.3 Implementation and review (G2, G3)

```
aisdlc run change CHG-add-health-endpoint --runner dry --yes          # rehearsal, no model calls
aisdlc run change CHG-add-health-endpoint --runner claude             # Claude Code under a governed tool allow-list
aisdlc run task TASK-002 --change CHG-add-health-endpoint             # one task
aisdlc run status CHG-add-health-endpoint                             # task statuses, worktrees, handoffs
aisdlc run review CHG-add-health-endpoint                             # whole-change independent review
```

Per task the executor: creates a git worktree, routes an implementer model within the
role's tier cap and budget, runs the verification command, routes an **independent
reviewer from a different model family**, loops implement/verify/review at most
`cost_limits.max_review_rounds` times, then merges the task branch back (a tier 3
action — a checkpoint). Checkpoints (plan approval, tier 3+ actions, wave boundaries,
release) are interactive; `--yes` approves all, `--non-interactive` (the default
without a TTY) denies all. Every step writes a durable handoff under `handoffs/` so an
interrupted run resumes (`--resume`, on by default). `run change` and `run task` refuse to
start (exit 2, listing the files and the commit command) while sources outside `changes/`
and `.aisdlc/` are uncommitted, because the worktrees start from `HEAD`; `--allow-dirty`
runs against `HEAD` anyway.

Tool calls are classified into risk tiers 0–4 (§4) and enforced by the Agent Governance
Toolkit policy generated per role (`aisdlc governance policy generate`, `governance policy
tiers`, `governance policy check '{...}'`). A project may **raise** a tier through
`tier_overrides`, never lower it.

A run also keeps concurrent human edits safe: the package is saved under an optimistic
concurrency guard, and when `requirements.md` (or any authored file) changed while agents
were running, only the produced state — task statuses, evidence, plan approval — is
reapplied on top of the human's version.

### 3.4 Security and safety (G4)

```
aisdlc ci render --out .github/workflows                              # SHA-pinned, least-privilege workflows
aisdlc ci collect-security <ci-artifact-dir> --package CHG-add-health-endpoint   # SARIF, dependency review, gitleaks, SBOM, provenance, VEX
aisdlc security campaign run templates/pyrit/campaigns/agent-baseline.yaml --target <module:callable> --package CHG-support-assistant-tools
aisdlc security safety run <module:suite> --package CHG-support-assistant-tools
aisdlc ci manifest-drift CHG-support-assistant-tools
```

The PyRIT campaign reports per-scenario attack success rate, the undetermined rate and
a `complete` flag; an incomplete campaign (any trial without a result) fails G4. The
safety regression suite is pytest-native (`@safety_case`). Judges are calibrated against
human labels with `aisdlc security judges calibrate`.

### 3.5 Cost and performance (G5)

```
aisdlc cost report --package CHG-add-health-endpoint                  # ledger extract -> evidence/cost.json
aisdlc cost budget-check --scope change:CHG-add-health-endpoint --forecast 12.5
aisdlc cost kpis --outcomes outcomes.yaml
aisdlc cost route --complexity high --role implementer                # what the router would pick and why
```

Every model call is metered into the SQLite usage ledger (`.aisdlc/ledger.sqlite` or
`$AISDLC_LEDGER`) with team/app/user/repo/change/task/model/prompt-version/tokens/
cache/tools/latency/cost. Budgets per application/team/environment/change and quotas
(agent turns, parallel agents, review rounds, tool calls, context size) come from the
org policy and may only be lowered by a project.

### 3.6 Release (G6)

```
aisdlc gate evaluate CHG-add-health-endpoint                          # dry evaluation of every gate
aisdlc gate approve CHG-add-health-endpoint --role owner --approver kevin   # human approval record
aisdlc gate bundle CHG-add-health-endpoint                            # final-verdict.json + signed evidence bundle
aisdlc gate verify-bundle CHG-add-health-endpoint                     # tamper check
```

`gate bundle` evaluates the gates, writes `final-verdict.json` when none exists and
signs the bundle with `$AISDLC_SIGNING_KEY` or `.aisdlc/signing.key` (HMAC-SHA256;
ed25519 when a key pair is configured). Stale evidence (older than the current commit)
or a missing approval fails G6.

## 4. Harness adapters

`aisdlc adapter emit claude-code|copilot|codex|cursor|kiro --out .` generates the
harness-specific files (commands, skills, hooks, instructions) from the canonical
templates; `aisdlc adapter import-openspec` / `export-openspec` exchange change
directories with OpenSpec. Canonical artifacts never depend on a harness.

## 5. Exit codes and error handling

`0` success · `1` the check/gate/run failed · `2` bad input (unknown change id, missing
file, invalid YAML, repository without a commit) · `3` blocked by a checkpoint or
budget · `4` duplicate run suppressed (identical inputs already ran; `--ignore-duplicates`
to force). Every error is printed as `error: ...` on stderr; a traceback is a bug.

## 6. Where to look when something fails

See the [runbooks](runbooks/): [failed G4 campaign](runbooks/failed-g4-campaign.md),
[bundle verification failure](runbooks/bundle-verification-failure.md),
[budget deny or escalation](runbooks/budget-deny-and-escalation.md),
[approval timeout](runbooks/approval-timeout.md),
[concurrent edit conflict](runbooks/concurrent-edit-conflict.md).
