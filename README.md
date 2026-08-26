# SDLC Pack Comparison: OpenAI vs. Claude

_Review date: August 26, 2026_

## Executive conclusion

**Claude remains the better overall SDLC platform. OpenAI is the better assurance and release-integrity kernel. Neither should be deployed unchanged.**

The strongest production direction is to use Claude as the workflow and developer-experience chassis, then incorporate OpenAI's signed approval, evidence-provenance, issuance, and replay-protection model.

## Comparison at a glance

| Area | OpenAI pack | Claude pack | Better |
|---|---|---|---|
| Intake, requirements, and planning | Limited lower-level contracts | Coached intake, specifications, ADRs, threat models, and task planning | Claude |
| Implementation workflow | Governed-runtime primitives and a synthetic demo | Worktrees, agent runners, fix/review loops, and apply-back | Claude |
| Developer experience | Three principal SDLC commands | Broad CLI, API, templates, adapters, pilots, and runbooks | Claude |
| Security and evaluation | Strong PyRIT/RAMPART evidence contracts | Broader integrated workflow, but weaker evidence provenance | Mixed |
| Approval and release trust | Signed identities, expiry, policy/source binding, and re-evaluation | Signed final bundle, but approvals are unauthenticated text fields | OpenAI |
| CI readiness | Rigorous evidence assembler | More workflows, but several default paths are broken | OpenAI today |
| Deployment and operations | Not connected end to end | More operational tooling, but deployment remains manual | Claude, narrowly |
| Production readiness | Advanced experimental reference | Advanced prototype | Neither |

## OpenAI pack

### What it does

The OpenAI pack is best understood as a high-assurance release and evidence system. It:

- Evaluates G0-G6 release controls.
- Governs model, prompt, tool, policy, and cost usage.
- Produces and validates PyRIT and RAMPART security evidence.
- Cryptographically signs risk classifications, reviews, approvals, and releases.
- Re-evaluates protected inputs when issuing a release.
- Binds releases to source, policy, execution, deployment context, and audience to reduce evidence replay.
- Provides a tightly validated reusable evidence workflow.

The added implementation includes the meaningful PyRIT source snapshot, the complete `agent-sre` subtree, the SDLC demo, fixtures, workflow, and relevant tests. Its offline demo now runs from the pack when the required Python dependencies are available.

### What the implementation addition fixed

- The core source is locally inspectable.
- The demo no longer depends on the two external working trees at runtime.
- The focused validation completed successfully: 330 Agent SRE tests, 142 workflow tests, and 441 PyRIT tests passed.
- G0-G6 passed, readiness was reported as `ready`, and generated signatures verified.

### Remaining gaps

1. **It is not a clean standalone distribution.** The top-level README still points to external absolute paths. The included `agent-sre` project is a deprecated dependency-only packaging stub that installs no local modules and expects an omitted consolidated CLI.

2. **Only part of the wider Agent Governance Toolkit is included.** Agent OS, Mesh, Sandbox, the consolidated CLI, and most organizational workflows are absent.

3. **The demonstration is synthetic.** Tests, scans, model calls, approval identities, command outcomes, and security results are constructed as fixtures. It proves the control contracts and fail-closed state machine, not a real software delivery.

4. **Source provenance remains incomplete.** Git metadata and a signed source manifest are absent. The saved release refers to synthetic revision `abcdef1`; the copied implementation bytes are not bound into that release.

5. **Historical release verification is incomplete.** Several policies used during issuance are constructed in memory rather than persisted alongside the saved release.

6. **CI assembles evidence rather than producing all of it.** Protected organizational jobs must still run the real build, scanner, model, and PyRIT workloads.

7. **The delivery lifecycle stops too early.** Actual deployment, progressive rollout, rollback, production SLO enforcement, incident response, drift reassessment, and retirement are not connected to G0-G6.

8. **Runtime isolation is cooperative.** A privileged host can bypass callbacks, and a non-cooperative thread cannot be forcibly stopped. Production requires process/container isolation, egress controls, secret isolation, and protected storage.

## Claude pack

### What it does

The Claude pack is a broader developer-facing SDLC platform. It provides:

- Coached discovery and requirements authoring.
- Change packages, plans, ADRs, and threat models.
- Worktree-based implementation and bounded fix/review loops.
- Independent review and cross-family coding-agent support.
- Test, security, evidence, cost, and G0-G6 gate workflows.
- Adapters for Claude Code, Codex, Copilot, Cursor, Kiro, and OpenSpec.
- CI templates, an HTTP control-plane API, pilots, rollout guidance, and runbooks.

### Main strengths

- Much broader lifecycle coverage and a clearer developer workflow.
- A real product-facing CLI spanning intake, planning, execution, review, security, cost, policy, CI, gates, and adapters.
- Practical worktree orchestration and review loops.
- More integration options and better operational documentation.
- Six pilot flows, although several use dry runners or prebuilt evidence fixtures.

### Remaining gaps

1. **Computed risk can be under-gated.** Risk classification can identify a higher inferred risk without persisting it unless the operator supplies `--apply`. Subsequent gates use the declared risk instead of automatically enforcing the effective risk.

2. **Several shipped CI paths are broken.** The AI-review workflow invokes the nonexistent `aisdlc review run` command instead of `aisdlc run review`. Other defaults reference a missing PyRIT campaign or invoke safety regression without its required module.

3. **The generated wheel likely omits required assets.** Core code looks outside the Python package for CI templates, the default model registry, and PyRIT datasets, while the wheel configuration only includes `src/aisdlc`.

4. **Approval trust is weaker.** Approvals are free-form role, identity, timestamp, and note values rather than independently authenticated, policy-pinned attestations.

5. **Raw evidence is not comprehensively bound.** The signed bundle hashes evidence-summary JSON but does not necessarily bind the underlying SARIF, SBOM, JUnit, provenance, or campaign files referenced by those summaries.

6. **The supplied environment is not portable.** The bundled virtual environment contains editable references to source outside the pack. Static checks passed, but a clean PyRIT-integrated test run was not reproducible solely from the distribution.

7. **Enterprise runtime controls remain incomplete.** The control-plane API has no authentication, there is no OS-level sandbox, and production deployment remains manual.

8. **Several planned controls are not implemented.** These include complexity/duplication checks, a secret broker, additional engineering KPI producers, dedicated privacy/accessibility/responsible-AI artifacts, stale-job cancellation, cache-aware routing, and a graphical dashboard.

## Recommendation

### If one pack must be selected

Choose **Claude as the platform foundation**, after correcting the risk-classification, CI integration, packaging, and environment-reproducibility defects.

### If release assurance is the primary concern

Use the **OpenAI assurance design**, particularly its:

- Policy-pinned and cryptographically signed approver identities.
- Signed risk and independent-review attestations.
- Exact source, policy, model, prompt, execution, and cost bindings.
- Issuance-time re-evaluation of protected inputs.
- Deployment-context verification and replay resistance.

### Preferred combined architecture

Combine:

- Claude's intake, planning, orchestration, CLI/API, adapters, pilots, and runbooks.
- OpenAI's signed risk/review/approval chain, evidence provenance, strict release issuance, and verification model.

**Final decision: Claude wins overall; OpenAI wins the most security-sensitive portion; a hybrid is substantially better than either pack alone.**

## Key evidence locations

### OpenAI

- `Enterprise-AI-SDLC-2026-08-26-openai/README.md`
- `Enterprise-AI-SDLC-2026-08-26-openai/demo-output/implementation/agent-governance-toolkit/examples/enterprise-ai-sdlc/README.md`
- `Enterprise-AI-SDLC-2026-08-26-openai/demo-output/implementation/agent-governance-toolkit/examples/enterprise-ai-sdlc/demo.py`
- `Enterprise-AI-SDLC-2026-08-26-openai/demo-output/implementation/agent-governance-toolkit/agent-governance-python/agent-sre/pyproject.toml`

### Claude

- `ai-sdlc-platform-claude/README.md`
- `ai-sdlc-platform-claude/docs/plan-traceability.md`
- `ai-sdlc-platform-claude/docs/security.md`
- `ai-sdlc-platform-claude/templates/workflows/ai-review.yml`
- `ai-sdlc-platform-claude/src/aisdlc/cli/cmd_plan.py`
- `ai-sdlc-platform-claude/src/aisdlc/cli/cmd_gate.py`
- `ai-sdlc-platform-claude/src/aisdlc/gates/verdict.py`
