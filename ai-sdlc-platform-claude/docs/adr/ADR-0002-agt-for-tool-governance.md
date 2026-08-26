# ADR-0002: Agent Governance Toolkit for tool and execution governance, wrapped behind platform interfaces

- Status: accepted
- Date: 2026-08-25
- Deciders: platform engineering
- Related: `docs/enterprise-plan.md` §2 "Plane 2", `ARCHITECTURE.md` §0.8, §4, §9.4; `INTEGRATION.md` §A, §C, §D

## Context and Problem Statement

Plane 2 of the plan requires per-role tool allow-lists, five risk tiers with distinct
default behaviours, approvals that deny on timeout or missing approver, a tamper-evident
audit trail for every privileged call, MCP governance and treating tool output as untrusted
input. The workspace already contains the Agent Governance Toolkit (AGT 5.0.0), which
provides a policy engine with a YAML rule language, approval handlers, an HMAC hash-chained
audit log, budget primitives and a Claude Code hook plugin. Should the platform build its
own enforcement or build on AGT, and if the latter, how tightly?

## Decision Drivers

- Deterministic, auditable enforcement that a security team can review as data (YAML), not code.
- Fail-closed defaults: unknown actions, evaluation errors, timeouts and missing approvers must deny.
- The canonical model must not depend on a third-party type.
- The core package must work without the library (docs-only projects, CI images without AGT).
- Verified library quirks (`INTEGRATION.md` §D): `govern()` builds its audit log without a
  sink, `require_approval` auto-rejects without a handler, `log`/`warn` matches report
  `allowed=False`, the condition evaluator is a restricted regex grammar where any exception
  counts as a match, MCP denials are return values, the MCP gateway needs an ACS runtime.

## Considered Options

1. **AGT behind platform interfaces** — generate AGT policy YAML from the platform's tier
   taxonomy; drive `PolicyEngine` and `AuditLog(FileAuditSink)` directly through a
   `PolicyEnforcer`; wrap approvals; keep injection screening in-house; emit AGT plugin config.
2. **Use AGT's `govern()` decorator and plugin as-is**, writing policies by hand.
3. **Build an in-house policy engine** with the tier taxonomy hard-coded.

## Decision Outcome

Chosen option: **1**. AGT supplies the engine, approvals, audit chain and plugin format;
the platform owns the tier taxonomy, the policy generator, the enforcement semantics and the
evidence shapes.

Implementation: `src/aisdlc/governance/tiers.py` (tiers, scopes, contextual classification,
project overrides that may only raise a tier), `governance/policy.py` (renders
`governance.toolkit/v1` YAML per role with `default_action: deny`, a tier-4 deny that
outranks every other rule, conditions restricted to the evaluator's supported grammar;
validates by loading into AGT), `governance/enforce.py` (`PolicyEnforcer` calls
`engine.evaluate(agent_did, context)` with a fully formed `action.*` context, treats
`log`/`warn` as allow-with-audit, converts denials to `PlatformDenied`, defers or auto-rejects
approvals, records to a sinked `AuditLog`), `governance/audit.py` (HMAC audit trail,
`verify_integrity`, canonical `AuditEvidence`), `governance/mcp.py` (platform screening;
AGT `MCPSecurityScanner` optional), `governance/claude_code_plugin.py` (AGT plugin
policy JSON + platform hook), `control_plane/budget.py::AgtAgentWindowTracker` (optional
per-agent windows). The executor and the Claude Code runner enforce the same policies
(`orchestration/roles.py::orchestration_policy_spec`).

### Consequences

- Good: enforcement is reviewable YAML validated by the engine that executes it; every
  tier ≥ 1 decision is hash-chained and G6 verifies the chain.
- Good: the platform's fail-closed rules hold regardless of AGT defaults (unknown action →
  tier 3; evaluation error → match; no handler → deny).
- Good: AGT can be swapped: nothing outside `aisdlc.governance` imports `agentmesh`, and
  `LocalTierChecker` keeps the executor working without it.
- Bad: two policy artefacts exist for Claude Code (AGT plugin JSON and the platform hook);
  both are generated from one source to keep them aligned.
- Bad: AGT is installed non-editable from the sibling checkout and must be reinstalled after
  changes; its deprecated `agent_mcp_governance` package is avoided.

## Pros and Cons of the Options

### Option 1 — AGT behind interfaces

- Good: reuse of a maintained engine, approval and audit primitives; independent audit format.
- Bad: wrapper must encode library quirks (documented in `INTEGRATION.md`).

### Option 2 — `govern()` and hand-written policies

- Good: least code.
- Bad: no persisted audit trail by default; policies drift from the tier taxonomy; the
  `action=` kwarg convention loses tool name, resource and tier; MCP gateway needs an ACS runtime.

### Option 3 — in-house engine

- Good: full control over grammar and semantics.
- Bad: reimplements what AGT provides and forfeits its plugin ecosystem and audit-chain
  verification; more surface to secure.

## More Information

Proven by `tests/test_governance_policy.py` (`test_every_role_validates_with_agt`,
`test_engine_evaluation_matrix`), `tests/test_governance_enforce.py`,
`tests/test_governance_audit.py`, `tests/test_governance_plugin.py`,
`tests/test_governance_mcp.py`, `tests/test_orchestration_executor.py::test_run_with_agt_policy_enforcer`.
Operational detail: `docs/security.md` "Plane 2".
