# Integration Brief — Agent Governance Toolkit (AGT) and PyRIT

Verified against the local checkouts installed in `.venv` (Python 3.13):

- `agent-governance-toolkit-core==5.0.0`, `agt-policies==5.0.0`, `agent-mcp-governance==5.0.0`
  (installed non-editable from `../agent-governance-toolkit/agent-governance-python/*`).
- `pyrit==1.1.0.dev0` (installed editable from `../PyRIT`).

Everything below was executed in this environment, not copied from docs. When in doubt,
`inspect.signature()` the object before using it. Always wrap these libraries behind
platform interfaces (`aisdlc.governance.enforce`, `aisdlc.security.pyrit_campaign`) and
guard imports so the core package works without them (`pytest.importorskip` in tests).

---

## A. Agent Governance Toolkit

### A.1 Governing a callable

```python
from agentmesh.governance import govern, GovernanceDenied
safe = govern(fn, policy="policy.yaml")        # policy: str path | Policy
safe(action="read", table="x")                 # -> passthrough
safe(action="drop")                            # raises GovernanceDenied("Action denied by policy rule 'block-destructive': ...")
safe.audit_log                                 # AuditLog
safe.engine                                    # PolicyEngine
safe.close_session()
```

Full signature (verified):

```
govern(fn, *, policy: str | Policy, agent_id: str = '*', audit: bool = True,
       on_deny: Callable[[PolicyDecision], Any] | None = None,
       approval_handler: ApprovalHandler | None = None,
       advisory: AdvisoryCheck | None = None,
       conflict_strategy: str = 'deny_overrides',
       ring: ExecutionRing | None = None, session_id: str = '',
       approval_coordinator=None, approval_chain_id=None,
       approval_ttl_seconds: float = 300.0, approval_transport=None,
       trace: TraceConfig | None = None) -> GovernedCallable
```

- With no `approval_handler`, `require_approval` rules **auto-reject** (deny) — this is the
  fail-closed default we want. Message: "Approval rejected by system:auto-reject".
- The governed call derives `action.type` from the keyword argument `action=` (as in the
  README example). For platform tool calls, prefer evaluating explicitly via the engine
  (A.3) with an `ActionRequest` so `tool_name`, `resource`, `parameters` are all available.

### A.2 Policy YAML (`apiVersion: governance.toolkit/v1`)

```yaml
apiVersion: governance.toolkit/v1
name: production-policy
default_action: allow            # allow | deny
rules:
  - name: block-destructive
    condition: "action.type in ['drop', 'delete', 'truncate']"
    action: deny                 # allow | deny | warn | require_approval | log
    description: "Destructive operations require human approval"
  - name: require-approval-for-send
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: ["security-team"]
```

Condition language is a restricted Python-like expression over `action.*`
(`action.type`, `action.tool_name`, `action.resource`, `action.parameters.<k>`,
`action.requested_spend`). See scout notes in §A.8 for the exact evaluator.

### A.3 Direct engine evaluation

```python
from agentmesh.governance import PolicyEngine, ActionRequest, PolicyDecision
engine = PolicyEngine()
engine.load_yaml_file("policy.yaml")          # also load_yaml(str), load_json, load_cedar, load_rego
decision: PolicyDecision = engine.evaluate(ActionRequest(action_type="write_file",
                                                         tool_name="Write",
                                                         resource="src/x.py",
                                                         parameters={...},
                                                         requested_spend=None), agent_id="implementer")
decision.allowed, decision.action  # action in {'allow','deny','warn','require_approval','log'}
decision.matched_rule, decision.policy_name, decision.reason, decision.approvers
```

(`evaluate`'s exact parameter names: check `inspect.signature(PolicyEngine.evaluate)`.)

### A.4 Approvals

```python
from agentmesh.governance import (ApprovalHandler, ApprovalRequest, ApprovalDecision,
                                  CallbackApproval, AutoRejectApproval, ConsoleApproval, WebhookApproval)
handler = CallbackApproval(callback=lambda req: ApprovalDecision(approved=True, approver="kevin", reason="ok"),
                           timeout_seconds=300, on_timeout="deny")
```

`ApprovalRequest(action, rule_name, policy_name, agent_id, context={}, approvers=[], requested_at)`;
`ApprovalDecision(approved: bool, approver='', reason='', decided_at)`.
`ApprovalHandler` has one method: `request_approval(request) -> ApprovalDecision`.
Deny-on-timeout is the default (`on_timeout='deny'`). Use `CallbackApproval` for the
platform's approval flow (human checkpoint / rule-based auto-approval).

### A.5 Audit trail

```python
from agentmesh.governance import AuditLog, FileAuditSink, StdoutAuditSink, AuditEntry
log = AuditLog(sink=FileAuditSink(path="evidence/audit.jsonl", secret_key=b"..."))  # HMAC hash-chained
log.log(...)                       # see inspect.signature(AuditLog.log)
log.query(...); log.get_entries_for_agent(agent_did); log.verify_integrity(); log.export(); log.export_cloudevents()
```

`AuditEntry` fields: entry_id, timestamp, event_type, agent_did, action, arguments_hash,
resource, target_did, approver_did, data, outcome, policy_decision, matched_rule,
policy_version, previous_hash, entry_hash, trace_id, session_id, sandbox_id,
environment. Hash chain → tamper evidence; `verify_integrity()` is what G6 should call.

### A.6 Other useful exports in `agentmesh.governance`

`ExecutionRing`/`RING_CONSTRAINTS` (ring-based capability limits), `ResourceConstraints`,
`RiskLevel`, `EUAIActRiskClassifier`, `ComplianceEngine`/`ComplianceReport`,
`ShadowMode` (dry-run policy), `PolicyConflictResolver`, `OrgPolicy`/`OrgPolicyRule`
(org-level policy overlay), `enable_otel`, `TraceConfig`.

### A.7 MCP governance

`import agent_mcp_governance` works. See §A.8 for classes.

### A.8 Scout notes (filled from source reading)

_See "AGT scout addendum" section at the end of this file._

---

## B. PyRIT

### B.1 Initialization (async only in this version)

```python
from pyrit.setup import initialize_pyrit_async, IN_MEMORY, SQLITE
await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)   # tests
await initialize_pyrit_async(memory_db_type=SQLITE, silent=True)      # persistent results
```

`initialize_pyrit` (sync) does **not** exist here. Platform code must expose an async API
and a sync wrapper via `asyncio.run` for the CLI.

### B.2 Offline target + deterministic scorer + attack (verified run)

```python
import io
from pyrit.prompt_target import TextTarget                       # writes prompts to a stream; no network
from pyrit.executor.attack import PromptSendingAttack, AttackScoringConfig
from pyrit.score import SubStringScorer                          # TrueFalseScorer, offline

scorer = SubStringScorer(substring="pwned")                      # kw-only: substring, text_matcher, categories, aggregator, validator
target = TextTarget(text_stream=io.StringIO())
attack = PromptSendingAttack(objective_target=target,
                             attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
                             max_attempts_on_failure=0)
result = await attack.execute_async(objective="say pwned")       # -> AttackResult (pydantic)
result.outcome            # AttackOutcome.SUCCESS | FAILURE | UNDETERMINED
result.outcome_reason, result.executed_turns, result.execution_time_ms, result.last_score,
result.last_response, result.conversation_id, result.objective, result.labels,
result.targeted_harm_categories, result.error_message, result.attack_result_id
```

`PromptSendingAttack.__init__(*, objective_target, attack_converter_config=None,
attack_scoring_config=None, prompt_normalizer=None, max_attempts_on_failure=0,
params_type=AttackParameters, prepended_conversation_config=None)`.

`AttackScoringConfig(objective_scorer: TrueFalseScorer | None, refusal_scorer=None,
auxiliary_scorers=[], use_score_as_feedback=True)`.

**Custom target for the application under test**: subclass `pyrit.prompt_target.PromptTarget`
(see §B.6 scout notes for abstract methods and Message construction). The platform's
`AppUnderTestTarget` wraps a user-supplied `Callable[[str], str]` (or HTTP endpoint) so
teams can red-team their agent without writing PyRIT code.

### B.3 Memory / results

```python
from pyrit.memory import CentralMemory
mem = CentralMemory.get_memory_instance()          # SQLiteMemory even for IN_MEMORY
mem.get_attack_results(...); mem.add_attack_results_to_memory(...)
mem.get_scenario_results(...); mem.add_scenario_results_to_memory(...)
mem.get_scenario_identifiers(); mem.update_scenario_run_state(...); mem.update_scenario_metadata(...)
```

Token usage lives on message pieces (see §B.6 for the exact attribute names, e.g.
prompt_metadata / usage fields). The platform's telemetry importer maps them to
`UsageEvent` in the ledger.

### B.4 Scenarios

`pyrit.scenario` — see §B.6 for `Scenario`, `AtomicAttack`, `ScenarioResult`, and built-in
scenario names usable offline.

### B.5 Attack success rate

ASR = `#SUCCESS / #(SUCCESS+FAILURE)` per objective set; `UNDETERMINED` is tracked
separately and drives the `max_undetermined_rate` gate. If any scheduled trial did not
produce a result → campaign `complete=False` → gate fails closed.

### B.6 Scout notes

_See "PyRIT scout addendum" at the end of this file._

---

## C. Additional verified facts (main session)

### C.1 AGT `PolicyEngine.evaluate` actually takes a context dict

```python
decision = engine.evaluate(agent_did="implementer", context={"action": {"type": "write_file", "tool_name": "Write", "resource": "src/x.py", ...}}, stage="pre_tool")
```

`govern()` builds `context["action"]` from the `action=` kwarg (dict passes through as-is,
scalar becomes `{"type": str(value)}`), and copies the other kwargs into the context.
So the platform's `PolicyEnforcer` should call `engine.evaluate(agent_did, context)` with
a fully-formed `{"action": {"type": ..., "tool_name": ..., "resource": ..., "tier": ..., "parameters": {...}}}` context.

### C.2 AGT `AuditLog.log` signature

```
AuditLog.log(event_type: str, agent_did: str, action: str, resource: str | None = None,
             data: dict | None = None, outcome: str = 'success', policy_decision: str | None = None,
             trace_id: str | None = None, *, arguments_hash=None, approver_did=None,
             policy_version=None, issued_at=None, completed_at=None) -> AuditEntry
```

`FileAuditSink(path, secret_key: bytes, *, max_file_size=0)` — HMAC-keyed hash chain.

### C.3 AGT budget primitives (`agentmesh.governance.budget`)

`BudgetConfig`, `BudgetDecision`, `BudgetTracker(config)` with `record_usage(...)`,
`check_budget(...)`, `get_usage(agent_id)`, `reset(agent_id=None)`; windows parsed by
`_parse_window("1h")`. Per-agent only — the platform's `BudgetPolicyEngine` adds
team/application/change scopes on top and may delegate per-agent windows to it.

Also present: `agentmesh.governance.decision_bom` (`DecisionBOM`, `DecisionBOMReconstructor`,
`BOMField`), `agentmesh.governance.evidence_pipeline` (`EvidenceSource`, `EvidenceReport`,
`EvidencePipeline`) — use for the G6 signed evidence bundle where it fits.

### C.4 `agent_mcp_governance` is deprecated (import emits DeprecationWarning)

Use `agent-governance-toolkit-protocols` (installed). Scout addendum lists the classes.

### C.5 PyRIT custom target contract (verified from `tests/unit/mocks.py` + `text_target.py`)

```python
from pyrit.models import Message, MessagePiece
from pyrit.models.messages.conversations import construct_response_from_request
from pyrit.prompt_target import PromptTarget

class AppUnderTestTarget(PromptTarget):
    """Sends the latest user prompt to a user-supplied callable and returns its reply."""
    def __init__(self, respond: Callable[[str], str], *, max_requests_per_minute: int | None = None) -> None:
        super().__init__(max_requests_per_minute=max_requests_per_minute)
        self._respond = respond

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        message = normalized_conversation[-1]                 # current request
        request_piece = message.message_pieces[0]
        reply = self._respond(message.get_value())
        return [construct_response_from_request(request=request_piece, response_text_pieces=[reply],
                                                prompt_metadata={"input_tokens": ..., "output_tokens": ...})]

    def _validate_request(self, *, normalized_conversation: list[Message]) -> None:
        pass
```

`PromptTarget.__abstractmethods__ == {'_send_prompt_to_target_async'}`. `MessagePiece`
fields: id, role, conversation_id, sequence, timestamp, original_value, converted_value,
response_error, original_prompt_id, prompt_metadata (dict[str, str|int]),
converter_identifiers. Token usage from provider targets is recorded in
`prompt_metadata` when available — the telemetry importer must treat it as optional.

---

## D. AGT scout addendum (source-verified by a scout agent, with an install + end-to-end smoke run)

### D.1 Installation reality
- The `agent-*` subdirectories under `agent-governance-python/` are deprecation stubs (no code). All source is
  force-included by three umbrella packages: `agent-governance-toolkit-core` (agentmesh, agent_os, hypervisor,
  agent_primitives, agent_runtime, cmvk/caas/emk/iatp/amb_core/atr/nexus/mcp_kernel_server/agent_control_plane/
  agent_os_observability), `agent-governance-toolkit-cli` (agent_sre, agent_sandbox, mcp_trust_server),
  `agent-governance-toolkit-protocols` (a2a_agentmesh, mcp_receipt_governed, mcp_trust_proxy; `agent_mcp_governance` is an empty stub).
  `policy-engine/sdk/python` provides `agent_control_specification` (ACS) — a different schema, NOT used by `govern()`.
- `pip install -e` is not actually editable (force-include copies the trees). We install non-editable; reinstall after
  changing AGT. Do not additionally install `agent-mesh/`, `agent-os/`, `agent-sre/` (duplicate top-level packages).
- Import-time deps: pydantic[email], pyyaml, rich, cryptography, pynacl, httpx, structlog, click, python-dateutil, jsonschema.
  `agentmesh.governance/__init__.py` imports `hypervisor.models` at top level (ships in core).

### D.2 `govern()` behaviour details (govern.py)
- `policy` may be a file path, an inline YAML string, or a `Policy` object (govern.py:161-179).
- Call flow (govern.py:239-297): build context → ring check → `PolicyEngine.evaluate()` → approval → audit → deny/allow → execute.
- Deny raises `GovernanceDenied(decision)` with `.decision: PolicyDecision`. If `on_deny` is set it is called INSTEAD of raising
  and its return value becomes the call's return value — never use `on_deny` for privileged tools.
- `require_approval` is resolved synchronously in-process via `approval_handler.request_approval(ApprovalRequest) -> ApprovalDecision`
  (govern.py:389). Default handler is `AutoRejectApproval` (approval.py:111) → deny. `ApprovalHandler` base: approval.py:93.
- **Audit gotcha:** `GovernedCallable` builds a bare in-memory `AuditLog()` with no sink; `GovernanceConfig.audit_file` is dead code.
  To persist an audit trail, construct `AuditLog(sink=FileAuditSink(path, secret_key, max_file_size=0))` (audit_backends.py:218;
  JSON-lines + HMAC hash chain) and drive `PolicyEngine` + `AuditLog` directly (this is what `aisdlc.governance.enforce` must do).
- Audit reads: `log.query(agent_did=, event_type=, start_time=, end_time=, outcome=, limit=100) -> list[AuditEntry]` (audit.py:575);
  `log.export()` → dict with `merkle_root`/`entries` (audit.py:627); `log.export_cloudevents()`; `log.verify_integrity() -> (bool, str|None)` (audit.py:604).
  Entries are Merkle-chained (`MerkleAuditChain`, audit.py:268). `AuditEntry.to_cloudevent()` (audit.py:214).

### D.3 Policy YAML details (policy.py)
```yaml
apiVersion: governance.toolkit/v1   # policy.py:27; "1.0" is deprecated
version: "1.0"
name: my-policy                     # required
extends: [base.yaml]                # additive-only inheritance
agent: did:...                      # or agents: ["*"]
scope: global                       # global | tenant | agent
default_action: deny                # allow | deny
rules:
  - name: deny-delete               # required
    stage: pre_tool                 # pre_input | pre_tool | post_tool | pre_output  (only matching stage is evaluated, policy.py:842)
    condition: "action.type == 'delete_db'"
    action: deny                    # allow | deny | warn | require_approval | log
    approvers: [cfo@x.com]
    limit: "100/hour"
    priority: 100
    enabled: true
```
- Condition language is a hand-rolled regex evaluator (policy.py:174-247), NOT CEL/Python. Supported: `a.b == 'str'`, `!= 'str'`,
  `a.b in ['x','y']`, `>= <= > <` against numeric literals only, bare truthiness (`data.contains_pii`), and `and`/`or` by naive
  string split. No parentheses, no `not`, no field-vs-field comparison, max depth 20 / 2000 chars.
  **Any exception while evaluating a condition counts as a MATCH (fail closed)** (policy.py:159-172).
- Context attributes are entirely caller-supplied. `_build_context` (govern.py:585): `action=` kwarg → `context["action"]`
  (dict as-is; scalar → `{"type": str(v)}`); first positional → `{"type": str(args[0])}`; every other scalar kwarg →
  `{key: {"value": val}}` (so `amount=5000` is addressed as `amount.value > 1000`); dict kwargs pass through.
  Framework-injected: `ring.*` when `ring=` is set; `sql.*`/`k8s.*` via `extract_protocol_facets` (policy.py:828).
- `PolicyEngine.evaluate(agent_did, context, stage='pre_tool')` (policy.py:788). Conflict strategies: `priority_first_match`
  (engine default), `deny_overrides` (govern() default), `allow_overrides`, `most_specific_wins`.
- Generated platform policies therefore must: put every attribute under `action.*` as flat strings/numbers, keep conditions to the
  supported grammar, prefer `default_action: deny` for privileged roles, and set `stage: pre_tool`.

### D.4 Cost / budget primitives (all in-memory, unconnected)
- `agent_sre.cost.CostGuard` (agent-sre/src/agent_sre/cost/guard.py:127; in the *cli* umbrella package, not installed by default):
  `CostGuard(per_task_limit, per_agent_daily_limit, org_monthly_budget, anomaly_detection=True, auto_throttle=True,
  kill_switch_threshold=0.95, alert_thresholds=None)`; `check_and_charge(agent_id, task_id, cost_usd, breakdown=None) -> (bool, str, list[CostAlert])`
  is the only atomic call; breaches return `(False, reason)`, never raise.
- `agentmesh.governance.budget.BudgetTracker(BudgetConfig)`: `check_budget(agent_id, estimated_tokens=0) -> BudgetDecision(allowed, reason, tokens_remaining, cost_remaining)`; not re-exported; no locking.
- `agent_os.ContextScheduler` / `BudgetExceeded` (agent_os/context_budget.py:118) — the only one that raises.
- No rate card ships; `agent_sre.cost.optimizer.ModelConfig` is a card you populate. The platform ledger/budget engine is the system of record.

### D.5 agent-sre (sync; import from submodules — `agent_sre/__init__.py` re-exports nothing)
- `from agent_sre.slo import SLO, ErrorBudget, SLI, SLOSpec, SQLiteMeasurementStore, load_slo_specs`; `SLO(name, indicators, error_budget=None, ...)` (slo/objectives.py:174), `.evaluate() -> SLOStatus`, `.record_event(good: bool)`; `ErrorBudget.remaining/.remaining_percent/.is_exhausted/.burn_rate(window_seconds=None)`.
- `from agent_sre.incidents.detector import Incident, IncidentDetector, IncidentSeverity, Signal, SignalType` (P1..P4; incidents only for P1/P2).
- Circuit breaker that works: `agent_sre.cascade.circuit_breaker` (`.call()`, `CircuitOpenError`).
- Requires installing `agent-governance-toolkit-cli` — optional for the platform (G5 SLO evaluation can use it when importable).

### D.6 MCP governance (real classes)
- `from agent_os.mcp_gateway import MCPGateway` (agent_os/mcp_gateway.py:124): `MCPGateway(runtime, *, denied_tools=None, sensitive_tools=None,
  approval_callback=None, enable_builtin_sanitization=True, metrics=None, rate_limit_store=None, audit_sink=None, clock=time.time,
  response_scanner=None, response_policy=ResponsePolicy.BLOCK, rate_limit=100)`; `runtime` MUST be an ACS `AgentControl`
  (else TypeError). `intercept_tool_call(agent_id, tool_name, params) -> (allowed, reason)` (fail-closed); `intercept_tool_response(...) -> MCPResponseDecision`.
- `from agent_os import MCPSecurityScanner, MCPThreatType, ScanResult` — tool poisoning / rug-pull / typosquat: `scan_server(name, tools)`, `check_rug_pull(...)`; `load_mcp_security_config(path)`.
- `from mcp_receipt_governed import McpReceiptAdapter, GovernanceReceipt, sign_receipt, verify_receipt, verify_receipt_chain, ReceiptStore` (Ed25519, hash-chained, `.to_slsa_provenance()`).
- `from mcp_trust_proxy import TrustProxy, ToolPolicy` (DID/trust-score gating + injection arg scan; not thread-safe).
- **Denials in every MCP path are return values, never exceptions.** The platform's `governance.mcp` wrapper must convert to `PlatformDenied`.
  The platform keeps its own `screen_tool_result()` (MCPGateway requires an ACS runtime, too heavy for a default dependency); optionally
  compose `MCPSecurityScanner` for server/tool-definition scanning when importable.

### D.7 AGT Claude Code plugin (Node >= 22; never calls Python; `npm install` required in the plugin dir)
- Hooks (hooks/hooks.json), each `bin/agt-node <script>`, no matcher: `SessionStart` → session-start.mjs, `UserPromptSubmit` → user-prompt-submit.mjs,
  `PreToolUse` → pre-tool-use.mjs. Plus stdio MCP server `agt_governance` (server/agt-mcp.mjs) with `agt_policy_status` / `agt_policy_check_text`.
- Config resolution (lib/policy.mjs:59-109): env `AGT_CLAUDE_POLICY_PATH` (default `~/.claude/agt/policy.json`) and `AGT_CLAUDE_AUDIT_PATH`
  (default `~/.claude/agt/audit-log.json`). No project-local discovery. Falls back to bundled config/default-policy.json.
- Policy JSON shape (lib/policy.mjs:642-674; reference config/default-policy.json and examples/claude-code-agt/config/review-heavy-policy.json):
  `schemaVersion: 1`, `mode: "enforce"|"advisory"`, `denyOnPolicyError` (default true), `additionalContext: []`,
  `toolPolicies: {allowedTools, blockedTools, reviewTools, defaultEffect}`, `blockedToolCalls: [{id, tool, reason, effect, commandPatterns:[{source, flags}]}]`,
  `directResourcePolicies: {pathRules, urlRules}`, `poisoningPatterns: [{source, severity, reason}]`.
- Traps: a malformed policy file → blanket deny on every tool call; tool names match exactly/case-sensitively (`"Bash"`, `"mcp__server__tool"`);
  `allowedTools` does not exempt a call from command-pattern/path/URL/poisoning backends. Hook output:
  `{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny"|"ask", permissionDecisionReason}}` — `review` → `ask`; never emits `allow`.
- Audit: pretty-printed JSON array at `~/.claude/agt/audit-log.json`, SHA-256 hash-chained, ring-buffered to 10,000 entries;
  entries `{timestamp, agentId: "claude-code:<session_id>", action: "tool.<Name>"|"prompt.submit", decision, previousHash, hash}`.
  `aisdlc.control_plane.telemetry.from_agt_audit` should accept both this array format and the Python `AuditLog` JSON-lines format.

### D.8 Decision records / attestation
- `agentmesh.governance.decision_bom`: `DecisionBOM`, `DecisionBOMReconstructor.reconstruct(trace_id) -> DecisionBOM` (completeness score) over
  pluggable `AuditSource`/`TrustSource`/`PolicySource`/`TraceSource` protocols.
- TRACE trust records: `TraceConfig`, `TRACEAuditSink`, `TrustRecord`, `session_to_trust_record` (needs `agentrust-trace`).

---

## E. PyRIT scout addendum (source-verified by a scout agent; ROOT = ../PyRIT)

### E.1 Version / install
- `1.1.0.dev0` (pyproject.toml:3), `requires-python >=3.10,<3.15`. Unreleased dev checkout — API differs from PyPI 0.x docs.
- Base deps are already heavy (transformers, datasets, openai, scipy, SQLAlchemy, fastapi, azure-*); take NO extras
  (avoid `huggingface`, `gcg`, `playwright`, `speech`, `opencv`, `fairness_bias`, `litellm`, `all`).

### E.2 Initialization (async-only; MUST precede constructing any target/scorer/scenario)
- `pyrit/setup/initialization.py:70`: `async def initialize_pyrit_async(memory_db_type, *, initialization_scripts=None,
  initializers=None, load_defaults=True, env_files=None, env_akv_ref=None, env_akv_strict=True, silent=False, **memory_instance_kwargs)`.
- `MemoryDatabaseType = Literal["InMemory","SQLite","AzureSQL"]`; no DuckDB. `IN_MEMORY` = SQLite `db_path=":memory:"`.
- `load_defaults=True` runs `TechniqueInitializer` + `TargetInitializer`; pass `load_defaults=False` for hermetic runs.
- `CentralMemory.get_memory_instance()` / `set_memory_instance(passed_memory=...)` (pyrit/memory/central_memory.py:30/19).
  `PromptTarget.__init__` calls `get_memory_instance()` and raises if unset.
- Test pattern: copy `tests/unit/conftest.py` fixtures `sqlite_instance` and `patch_central_database` (:48), which patch
  `CentralMemory.get_memory_instance`.

### E.3 Custom PromptTarget (pyrit/prompt_target/common/prompt_target.py:39)
- Only abstract method: `async _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]` (:197).
  Current request is `normalized_conversation[-1]`. `send_prompt_async` is `@final` — never override.
- `__init_subclass__` enforces keyword-only `__init__` (:79-94) — positional params raise TypeError.
- Optional: `_validate_request(*, normalized_conversation)`, `_build_identifier()`, class attr `_DEFAULT_CONFIGURATION: TargetConfiguration`.
- Base `__init__` kwargs: `verbose, max_requests_per_minute, endpoint, model_name, underlying_model, custom_configuration`.
- Build responses with `MessagePiece(role="assistant", original_value=..., conversation_id=<request piece's>).to_message()` or
  `construct_response_from_request(...)` (§C.5). All pieces in a Message share conversation_id/sequence/role.
- Template: `MockPromptTarget` at tests/unit/mocks.py:196.

### E.4 Scenario / Attack API
- `from pyrit.scenario import Scenario, AtomicAttack, ScenarioResult, DatasetAttackConfiguration, BaselineAttackPolicy`.
- `Scenario` (pyrit/scenario/core/scenario.py:100, ABC). Ctor (:150): `name, version, technique_class, default_dataset_config,
  objective_scorer, scenario_result_id (resume)`. One abstract hook: `async _build_atomic_attacks_async(*, context) -> list[AtomicAttack]` (:988).
- Run pattern: `scenario.set_params_from_args(args={"objective_target": t, "dataset_config": cfg, "scenario_techniques": [...], "max_concurrency": 8})`
  → `await scenario.initialize_async()` (:529) → `result = await scenario.run_async()` (:1011) → `ScenarioResult`. Supports resume + `max_retries`.
- Built-ins: `pyrit.scenario.foundry` (RedTeamAgent, FoundryTechnique, FoundryComposite); `pyrit.scenario.garak` (Encoding, Doctor, FigStep,
  PackageHallucination, SystemPromptExtraction, WebInjection, AudioAchillesHeel); `pyrit.scenario.airt` (Jailbreak, Cyber, Leakage, Multilingual,
  Psychosocial, RapidResponse, Scam); `pyrit.scenario.benchmark.AdversarialBenchmark`; `pyrit.scenario.adaptive.TextAdaptive`. No ContentHarms.
- `AtomicAttack` (pyrit/scenario/core/atomic_attack.py:35; ctor :51): `atomic_attack_name` (unique, used for resume), `display_group`,
  `attack_technique: AttackTechnique`, `seed_groups: list[AttackSeedGroup]`, `adversarial_chat`, `objective_scorer: TrueFalseScorer | None`,
  `memory_labels`, `**attack_execute_params`. `run_async(*, executor=None, return_partial_on_failure=True, **attack_params) -> AttackExecutorResult[AttackResult]` (:264).
- `ScenarioResult` (pyrit/models/results/scenario_result.py:55): `id, scenario_identifier, attack_results: dict[str, list[AttackResult]]`
  (keyed by atomic_attack_name), `scenario_run_state, labels, creation_time/completion_time, number_tries, display_group_map, error_*`, `metadata`.
- **WARNING:** `ScenarioResult.objective_achieved_rate()` (:222) returns an int percentage whose denominator includes UNDETERMINED and ERROR.
  Do not use it for ASR.
- `AttackOutcome` (pyrit/models/results/attack_result.py:23): `SUCCESS, FAILURE, ERROR, UNDETERMINED` — four states.

### E.5 PromptSendingAttack / batch execution
- `pyrit/executor/attack/single_turn/prompt_sending.py:34`; ctor keyword-only (§B.2). `AttackScoringConfig.__post_init__` raises unless the
  objective scorer is a `TrueFalseScorer`; `refusal_scorer` is ignored by PromptSendingAttack.
- `execute_async(objective="...", next_message=None, prepended_conversation=None, memory_labels=None, **kwargs) -> AttackResult`
  (attack_strategy.py:672-688); unknown kwargs raise ValueError.
- Batch: `AttackExecutor(max_concurrency=N).execute_attack_async(*, attack, objectives: Sequence[str], field_overrides=None,
  return_partial_on_failure=False, attribution=None, **broadcast_fields) -> AttackExecutorResult` (attack_executor.py:279) with
  `completed_results: list[AttackResult]`, `incomplete_objectives: list[tuple[str, BaseException]]`, `input_indices`.
  → `incomplete_objectives` non-empty ⇒ campaign `complete=False` (fail closed).

### E.6 Scorers
- Base `Scorer` (pyrit/score/scorer.py:94): `async score_async(*, scorable: Scorable, expectation: ScoringExpectation | None = None) -> list[Score]` (:275);
  subclass hook `_score_scorable_async`. The legacy `score_async(message=..., objective=...)` path is deprecated and PyRIT's own pytest config turns
  that DeprecationWarning into an error — write against `scorable`/`expectation`.
- Offline: `SubStringScorer(*, substring, text_matcher=None, categories=None, aggregator=TrueFalseScoreAggregator.OR, validator=None)`
  (pyrit/score/true_false/substring_scorer.py:25); `RegexScorer(*, patterns: dict[str, str], ...)` (pyrit/score/true_false/regex/regex_scorer.py:16);
  `TrueFalseInverterScorer`, `TrueFalseCompositeScorer`. `TrueFalseScorer` base (true_false_scorer.py:20) returns one Score with `score_type="true_false"`.
- `Score` (pyrit/models/score/score.py:39): `score_value: str, score_type, score_category, score_rationale, score_value_description, score_metadata,
  scorer_class_identifier, message_piece_id, objective, timestamp`; `get_value() -> bool | float` (:130).
- Scorer evaluation vs human labels (pyrit/score/scorer_evaluation/): `HumanLabeledDataset.from_csv(*, csv_path, metrics_type: MetricsType, ...)`
  (human_labeled_dataset.py:189) — CSV columns `assistant_response`, `objective` (OBJECTIVE) or `harm_category` (HARM), `human_score*`, optional `data_type`.
  `ScorerEvaluator.from_scorer(scorer, metrics_type=None)` (scorer_evaluator.py:82) → `run_evaluation_async(*, dataset_files, num_scorer_trials=3, ...)` (:103)
  or `evaluate_dataset_async(...)` (:350). `ObjectiveScorerMetrics` = accuracy/precision/recall/f1 (+SE); `HarmScorerMetrics` = MAE, t-stat/p, Krippendorff alpha.
  Persisted as JSONL under `SCORER_EVALS_PATH` keyed by `scorer.get_identifier().eval_hash`.
- Aggregators: `TrueFalseScoreAggregator.AND/.OR/.MAJORITY`; `FloatScaleScoreAggregator.AVERAGE/.MAX/.MIN`.

### E.7 Memory, results, token usage (MemoryInterface, pyrit/memory/memory_interface.py:174; all keyword-only)
- `get_attack_results(*, attack_result_ids, conversation_id, objective, objective_sha256, outcome, attack_classes, atomic_attack_eval_hashes,
  converter_classes, labels, targeted_harm_categories, identifier_filters, scenario_result_id, min_turns, max_turns, limit, after)` (:3086)
- `get_scenario_results(*, scenario_result_ids, scenario_name, scenario_version, pyrit_version, added_after, added_before, labels,
  objective_target_endpoint, objective_target_model_name, identifier_filters, limit)` (:3680)
- `get_message_pieces(*, role, conversation_id, prompt_ids, labels, prompt_metadata, sent_after, sent_before, data_type, ...)` (:1892);
  `get_conversation_messages(*, conversation_id)`; `get_scores(...)`; `get_prompt_scores(...)`. No export helpers — serialize yourself.
- **Token usage:** `TokenUsage` dataclass (pyrit/models/target/token_usage.py:64: `input_tokens, output_tokens, total_tokens, reasoning_tokens,
  cached_tokens, extra`), exported from `pyrit.models`. Persisted ONLY as `MessagePiece.prompt_metadata` keys prefixed `token_usage_`
  (written by `set_token_usage_metadata(*, pieces, usage)`, pyrit/prompt_target/common/utils.py:150). **No cost field, no pricing table anywhere.**
  The platform's `AppUnderTestTarget` should call `set_token_usage_metadata` when the app reports usage; `control_plane.telemetry.from_pyrit_memory`
  aggregates `token_usage_*` over `get_message_pieces()` and prices via the platform registry.
- **ASR definition to use:** `pyrit.analytics.analyze_results(attack_results) -> {"Overall": AttackStats, "By_attack_identifier": {...}}`
  (pyrit/analytics/result_analysis.py:46); `AttackStats(success_rate = successes/(successes+failures), total_decided, successes, failures, undetermined, errors)`.

### E.8 Datasets
- `SeedPrompt`, `SeedObjective`, `SeedGroup`, `AttackSeedGroup` (exactly one objective; consumed by AtomicAttack), `SeedDataset.from_yaml_file(path)`
  (pyrit/models/seeds/seed_dataset.py:182). YAML shape: `dataset_name, harm_categories, source, seed_type: objective, seeds: [{value, harm_categories}]`
  (files use `.prompt` extension). Offline local datasets under `pyrit/datasets/seed_datasets/local/` (garak/, airt/, 0din/, examples/, adv_bench.prompt).
  Everything under `seed_datasets/remote/` hits the network.
- `DatasetAttackConfiguration(*, seeds=None, seed_groups=None, dataset_names=None, max_dataset_size=None, filters=None, validators=None, auto_fetch=True)`
  (dataset_configuration.py:536) — **set `auto_fetch=False`** for no network; exactly one of seeds/seed_groups/dataset_names.

### E.9 Baseline comparison / regression (use these for `BaselineStore.compare`)
- `BaselineAttackPolicy` enum (`Enabled/Disabled/Forbidden`, scenario.py:79); `build_baseline_atomic_attack(*, objective_target, objective_scorer,
  seed_groups, memory_labels=None, atomic_attack_name="baseline", display_group=None)` (matrix_atomic_attack_builder.py:90) → results under `attack_results["baseline"]`.
- Deterministic comparison IDs = `eval_hash` on `ComponentIdentifier` (pyrit/models/identifiers/component_identifier.py:257; `with_eval_hash()` :694) —
  behavioural-equivalence hash (seeds/scorer excluded). Exposed as `AtomicAttack.technique_eval_hash` (:176) and stamped on `AttackResult.atomic_attack_identifier`.
- `compute_technique_stats(*, technique_eval_hashes, scenario_result_id=None, targeted_harm_categories=None, memory=None) -> dict[str, AttackStats]`
  (pyrit/analytics/technique_analysis.py:20; import from that module, not `pyrit.analytics`).
- `get_cached_results_for_technique(memory_interface, *, technique_eval_hash, objective_target_eval_hash, additional_filters=None) -> list[AttackResult]`
  (result_analysis.py:116) — historical results for a (technique × target) pair, newest first.
- `await output_scenario_async(result, format="pretty", sink=None, ...)` (pyrit/output/helpers.py:89); only "pretty" is implemented.

### E.10 Test conventions in PyRIT (for reference)
- `asyncio_mode = "auto"`, `--import-mode=importlib`; no custom markers; isolation by directory; network avoided purely by mocking.
