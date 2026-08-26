# Enterprise AI-SDLC Plan (source document)

This is the recommendation document the platform implements, reproduced from the
original brief so that `docs/plan-traceability.md` can cite it. `ARCHITECTURE.md` is the
binding engineering contract derived from it.

# Recommended approach

**Do not adopt any one repository as the enterprise AI-SDLC.** The strongest capabilities
are distributed across several projects, while every project has material gaps —
especially in centralized cost control, organization-wide telemetry, and end-to-end
benchmark governance.

The strongest design is a **centralized, policy-driven AI development platform with five
composable layers**:

```text
Business or developer intent
        ↓
1. Intake and specification contract
        ↓
2. Planning and architecture governance
        ↓
3. Isolated multi-agent implementation
        ↓
4. Deterministic CI + independent AI review
        ↓
5. Security, performance, and release gates

     ┌────────────────────────────────────┐
     │ Central model, policy, telemetry,  │
     │ benchmark, and cost control plane  │
     └────────────────────────────────────┘
```

> **One canonical artifact model, one execution orchestrator, and one central control
> plane. Borrow patterns from the other projects; do not install several overlapping
> prompt frameworks into the same repository.**

## Recommended project roles

| Platform responsibility       | Recommended foundation             | Patterns to incorporate                                                                      |
| ----------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------- |
| Non-developer intake          | HVE/BMAD patterns                  | Design Thinking, coached discovery, BRD/PRD, personas, plain-language questions              |
| Canonical specification       | **OpenSpec**                       | Spec Kit clarification/checklist/analyze, BMAD spec kernel, AI-DLC ambiguity questions       |
| Planning and execution        | **GSD-inspired orchestration**     | Fresh-context agents, worktrees, plan checker, verifier, UAT, model routing                  |
| CI and supply-chain security  | **HVE CI patterns**                | CodeQL, secret scanning, dependency review, SBOM, provenance, pinned actions                 |
| Tool and MCP governance       | **KiroCrew patterns**              | Pre-tool policy, scoped permissions, approval modes, sandboxing, MCP gateway                 |
| AI application security       | **RAMPART + PyRIT**                | Agent safety regression tests, adversarial scenarios, calibrated judges, benchmark baselines |
| Cost and benchmark governance | **New central platform component** | GSD routing taxonomy, HVE model catalog, PyRIT usage records                                 |

OpenSpec is the strongest candidate for the canonical artifact contract (code-enforced
requirement grammar, artifact dependency graph, git-native state, broad harness support).
Spec Kit has the stronger clarification and requirements-quality workflow, so those
behaviors are incorporated into the canonical templates rather than a second spec tree.

# 1. Code Quality

Code quality is enforced through **four separate mechanisms**:

1. A machine-validatable specification.
2. Deterministic static quality gates.
3. Isolated implementation with evidence.
4. Independent semantic review.

### A. Make the specification executable as a quality contract

Every change has: goal and non-goals; functional and non-functional requirements; at
least one testable scenario per requirement; explicit acceptance criteria; assumptions and
open questions; architecture and interface implications; a verification method for every
implementation task; and a traceability chain:

```text
Requirement → Acceptance scenario → Architecture decision → Implementation task → Test → CI evidence
```

OpenSpec enforces SHALL/MUST language, WHEN/THEN scenarios, task numbering, and minimum
specification structure. Spec Kit adds clarification ranking, requirements checklists,
consistency analysis, and constitution-based governance. BMAD contributes the compact
five-part specification kernel — Why, Capabilities, Constraints, Non-goals, Success
Signal — plus mandatory assumptions, open questions, and readiness criteria.

### B. Separate implementation from review (GSD/Superpowers pattern)

Fresh-context implementation agent; narrow task brief rather than full conversation
history; isolated worktree; required tests and evidence; independent reviewer that reads
the actual diff; scoped fix and re-review cycles; whole-change final review. Model
selection distinguishes mechanical implementation from architecture and judgment work.
GSD adds dependency-wave execution, worktree isolation, separate planner/checker/verifier
roles, cross-AI review lanes, and durable file-based handoffs.

### C. Mandatory deterministic gates

Formatter; linter; strict compiler or type checker; complexity thresholds; duplication
detection; API/schema compatibility checks; architecture boundary tests; documentation and
generated-artifact drift checks; no TODO/placeholders in production paths unless
explicitly approved; no unresolved spec ambiguity markers; no unverified completion
claims. AI review only addresses concerns deterministic tools cannot reliably detect.

### Code-quality KPIs

First-pass CI success rate; rework commits after review; defects found after merge;
AI-review finding precision; percentage of findings subsequently overturned;
requirement-to-test traceability; specification ambiguity at implementation start; change
failure rate; review latency; complexity introduced per accepted change.

# 2. Code Security — three security planes

## Plane 1: Conventional application and supply-chain security (HVE CI posture)

SHA-pinned GitHub Actions; least-privilege workflow permissions; CodeQL; secret scanning;
dependency review; package audits; SBOM generation; SLSA/Sigstore provenance; OpenVEX
where applicable; template-injection checks; controlled network egress; safe-output limits
for agentic workflows. Distributed as **organization-owned reusable CI workflows**.

## Plane 2: Agent tool and execution security

Tool allowlists per agent role; read-only by default; separate read, write, execute,
network, and administrative scopes; workspace-root restrictions; worktree isolation;
command policy checks; network egress restrictions; secret indirection; human approval for
destructive or externally visible actions; deny-on-timeout / deny-on-missing approval;
audit logs for every privileged tool call; treat tool results, repository files, web
content, and issue text as untrusted data. KiroCrew's missing MCP-result injection
screening should be added.

| Risk tier | Examples                                        | Default behavior                |
| --------- | ----------------------------------------------- | ------------------------------- |
| Tier 0    | Read code, search, explain                      | Automatic                       |
| Tier 1    | Write inside isolated worktree                  | Automatic with audit            |
| Tier 2    | Run tests/builds, create local artifacts        | Policy-controlled               |
| Tier 3    | Modify shared state, create PR, change backlog  | Explicit or rule-based approval |
| Tier 4    | Deploy, rotate secrets, change IAM, delete data | Human approval required         |

## Plane 3: AI- and agent-specific security testing

- **RAMPART:** product-team-authored, pytest-native agent safety regression tests (harm
  categories, repeated trials, pass thresholds, structured reports, attack-success-rate
  summaries, fail-closed handling of incomplete distributed runs).
- **PyRIT:** broader adversarial campaigns, scenario exploration, model/app red teaming,
  scorer calibration against human labels, persistent results, deterministic evaluation
  identifiers, and baseline comparison.

### Security release gates — a release fails when

A high or critical deterministic finding is open; a required SBOM or attestation is
absent; a privileged tool was added without a threat model; an agent safety regression
exceeds the permitted attack-success threshold; a security test run is incomplete; a
security judge returns excessive `undetermined` results; the application's declared
tool/data manifest no longer matches observed behavior.

# 3. Test Coverage — a coverage portfolio

| Layer                   | What it proves                                                    |
| ----------------------- | ----------------------------------------------------------------- |
| Unit tests              | Local logic behaves correctly                                     |
| Property/boundary tests | Behavior holds across input ranges and hostile cases              |
| Integration tests       | Components and external dependencies interact correctly           |
| Contract tests          | APIs, messages, and schemas remain compatible                     |
| End-to-end tests        | User journeys work                                                |
| Architecture tests      | Dependency and boundary rules remain intact                       |
| Security tests          | Conventional vulnerabilities and misuse paths are controlled      |
| Agent safety tests      | Prompt injection, tool misuse, and side effects remain controlled |
| Prompt/agent evals      | Planning, review, and judge behaviors remain reliable             |
| Performance tests       | Latency, throughput, concurrency, and resource targets are met    |

Recommended thresholds (org defaults, documented exceptions permitted): overall line
coverage 75–80%; changed-line/diff coverage 90%; branch coverage ≥70%; critical-module
coverage ≥90%; mutation score on changed eligible modules 60% initially then ratcheted;
acceptance criteria with executable evidence 100%; critical user journeys with E2E 100%;
required agent safety scenarios executed 100%; incomplete test/eval runs always fail
closed. Mutation results must disclose their actual scope.

Do not adopt AI-DLC's "Build and Test" behavior literally (instruction documents with
command placeholders). Every claimed test result has machine evidence:

```yaml
test_evidence:
  command: "pytest -n auto"
  exit_code: 0
  commit_sha: "..."
  environment: "ci"
  passed: 1421
  failed: 0
  skipped: 3
  coverage: {lines: 84.2, branches: 76.1}
  report_uri: "..."
```

Test KPIs: escaped defects by test layer; diff coverage; mutation score; flaky-test rate;
test execution time; percentage of requirements with executable tests; agent
attack-success rate; judge agreement with human labels; `undetermined` safety-verdict
rate; cost per security or evaluation run.

# 4. Architecture

Use **OpenSpec as the canonical change-state and artifact graph**, with a GSD-inspired
execution layer. Normalized change package:

```text
/change/<change-id>/
    intent.md
    requirements.md
    scenarios/
    assumptions.md
    architecture/{context.md, decisions/, interfaces/, threat-model.md}
    plan.md
    tasks.md
    evidence/{tests.json, reviews.json, security.json, performance.json, cost.json}
    final-verdict.json
```

GSD execution architecture: planner and plan checker; dependency-wave execution; fresh
agents; worktree isolation; goal-backward verification; human checkpoints; UAT;
cross-model review; persistent state and resumability. HVE enterprise patterns: Design
Thinking to product handoff; BRD/PRD; EARS and Given/When/Then requirements; security,
privacy, accessibility, responsible-AI, SSSC plans; ADR creation; backlog decomposition;
explicit Research → Plan → Implement → Review artifacts.

### Architecture principles

- **One canonical state model** — no parallel `.specify/`, `openspec/`, `.planning/`,
  `.copilot-tracking/`, `_bmad/`, `aidlc-docs/` state. One schema; translate other
  methods into it; stateless prompts/agents; recalculate state from artifacts; structured
  evidence; IDs stable across requirements, tasks, tests, findings, benchmarks.
- **Separate policy from implementation** — organization policy (required gates, model
  allowlist, tool permissions, cost limits, security baselines, evidence standards);
  project configuration (languages, frameworks, architecture style, risk classification,
  test commands); change-specific artifacts. Projects may narrow org policy but never
  silently weaken it.
- **Portability** — canonical artifacts independent of Copilot, Claude Code, Codex,
  Cursor, Kiro, or a model provider; harness adapters translate.

Cautions: HVE is Copilot-specific (pattern source, not platform dependency); OpenSpec has a
documented concurrent-change risk (add base fingerprints, optimistic concurrency, or
semantic merge); GSD is developer-centric and high-maintenance (wrap or selectively adopt).

# 5. Cost and Performance

No reviewed project provides organization-wide token/dollar telemetry, per-team and
per-application budgets, central model-routing policy, cost-based throttling, cost
attribution to requirements or merged changes, benchmark-driven model selection,
centralized price tables, cross-harness usage reporting, or enforced cost/performance
SLOs. This must be a platform-owned component.

```text
Central AI Control Plane
├── Model registry      (provider/model/version, capabilities, context limits, tool support, price, approved use cases)
├── Routing policy      (task complexity, risk, required capabilities, latency target, budget)
├── Usage ledger        (team/application/user, repository/change/task, model and prompt version, tokens and cache, tool calls, latency, cost)
├── Benchmark service   (quality, security, test generation, review precision, cost/performance)
└── Policy engine       (budgets, quotas, model allowlists, escalation limits, exception approvals)
```

| Tier               | Typical work                                                             | Model strategy                         |
| ------------------ | ------------------------------------------------------------------------ | -------------------------------------- |
| Low                | Classification, formatting, extraction, complete-code transcription      | Cheapest qualifying model              |
| Standard           | Normal implementation, test creation, bounded debugging                  | Balanced model                         |
| High               | Architecture, ambiguous planning, security analysis, complex integration | Strong reasoning model                 |
| Independent review | Verification of material changes                                         | Different model family where practical |
| Escalation         | Failed or conflicting outputs                                            | Higher tier or different provider      |

Route based on **observed benchmark performance**, not model reputation.

Cost controls: budget per application, team, environment, and change; maximum model tier
by role; maximum agent turns; maximum parallel agents; maximum review rounds; maximum tool
calls; context-size ceilings; automatic cancellation of stale or duplicate runs;
cache-aware routing; no repeated analysis when source hash and evaluation configuration
are unchanged; explicit human approval when forecast cost exceeds a threshold.

Cost and performance KPIs (unit = accepted engineering outcome): cost per accepted
requirement; cost per merged change; cost per defect found; cost per security
vulnerability found; cost per passing benchmark; tokens per accepted task; model
escalation rate; cache-hit rate; mean and p95 agent latency; agent turns per successful
task; review rounds per merged change; tool calls per accepted change; percentage of
expensive-model calls that could have succeeded on a lower tier.

# Enterprise gate model

| Gate                            | Required evidence                                                | Blocks on                                    |
| ------------------------------- | ---------------------------------------------------------------- | -------------------------------------------- |
| **G0 — Intent readiness**       | Requirements, non-goals, assumptions, scenarios, ambiguity score | Material ambiguity or missing owner decision |
| **G1 — Architecture readiness** | Plan, ADRs, interfaces, threat model, NFRs                       | Unresolved high-risk design issue            |
| **G2 — Implementation quality** | Build, lint, types, tests, coverage, mutation evidence           | Deterministic gate failure                   |
| **G3 — Independent review**     | Cross-model or independent semantic review                       | Grounded blocking defect                     |
| **G4 — Security and safety**    | SAST/SCA/secrets/SBOM plus RAMPART/PyRIT results                 | Critical vulnerability or safety regression  |
| **G5 — Cost and performance**   | Cost ledger, latency, load results, budget variance              | Budget breach or unmet SLO                   |
| **G6 — Release**                | Signed evidence bundle and human approvals where required        | Missing or stale evidence                    |

The **risk classification changes the depth, not the meaning of the gates**:
documentation-only change → lightweight G0, G2, G3; simple bug fix → G0–G3 plus security
delta scan; authentication change → all gates; tool-enabled AI agent → all gates plus
RAMPART/PyRIT trials and tool-manifest validation.

# Recommended implementation sequence

1. **Phase 1 — Standardize intent and evidence:** canonical OpenSpec-derived schema; Spec
   Kit clarification/checklist/consistency rules; BMAD assumptions/non-goals/success-signal
   fields; organization-wide requirement, task, test, finding, and evidence IDs;
   executable verification instructions for every task.
2. **Phase 2 — Centralize CI:** reusable organization workflows for build and unit tests,
   diff coverage, mutation testing, CodeQL, dependency review, secrets, SBOM and
   provenance, architecture tests, AI review, RAMPART, PyRIT for higher-risk releases,
   cost and benchmark evidence upload. Teams consume versioned workflows.
3. **Phase 3 — Add controlled orchestration:** fresh-context agents; worktree isolation;
   planner/checker separation; independent reviewer role; bounded fix loops; human
   checkpoints based on risk; model tier routing; provider diversity for material reviews;
   tool permissions and audit.
4. **Phase 4 — Build the control plane:** model registry; routing; usage telemetry;
   budgets; benchmark results; prompt and model versions; exceptions; dashboards.
5. **Phase 5 — Pilot with three project classes:** a small internal CRUD application; a
   business-user-led low-code or generated application; a tool-using AI agent with private
   data access (critical — exercises risks normal code-generation benchmarks do not reveal).

# Final selection

- **Canonical specification and change contract:** OpenSpec-derived.
- **Clarification and requirements-quality rules:** Spec Kit + BMAD/AI-DLC patterns.
- **Execution and model-orchestration reference:** GSD.
- **Developer execution/review pattern:** Superpowers-style fresh agents and independent reviews.
- **Enterprise intake, architecture, and CI patterns:** HVE.
- **Tool and MCP governance:** KiroCrew patterns.
- **Agent safety regression testing:** RAMPART.
- **Broad red-team and benchmark campaigns:** PyRIT.
- **Central cost, telemetry, policy, and benchmark plane:** build internally.

This produces a system in which AI can increase delivery capacity without allowing
individual application teams — or individual agents — to independently choose their
process, security posture, model spend, or definition of "done."
