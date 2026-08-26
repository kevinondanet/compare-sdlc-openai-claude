"""Generate Agent Governance Toolkit policies (``governance.toolkit/v1``) from risk tiers.

One policy document is produced per agent role. Each document is scoped to that role
(``agents: [<role>]``), denies by default, and embodies the tier taxonomy as rules:

* tier 4 and egress to unlisted hosts  -> ``deny``
* above the role's maximum tier         -> ``deny``
* scopes the role does not hold         -> ``deny`` (read-only-by-default)
* tier 3 / writes outside the worktree  -> ``require_approval``
* tier 1 and 2                          -> ``log`` (allowed, always audited)
* tier 0                                -> ``allow``

Every permissive rule is guarded by ``action.type in [<role allow-list>]`` so any action
type the role was not granted falls through to ``default_action: deny``.

The condition language is the AGT restricted expression grammar (equality, membership,
numeric comparison, ``and``/``or``), evaluated against :meth:`ToolAction.to_context`.
Generated documents are validated by loading them into the real AGT ``PolicyEngine``.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aisdlc.governance.tiers import (
    DEFAULT_SCOPE_TABLE,
    RiskTier,
    Scope,
    TierConfig,
    scope_for,
)

API_VERSION = "governance.toolkit/v1"

#: Policy action emitted for each tier by default.
DEFAULT_TIER_ACTIONS: dict[RiskTier, str] = {
    RiskTier.AUTOMATIC: "allow",
    RiskTier.AUTOMATIC_AUDIT: "log",
    RiskTier.POLICY_CONTROLLED: "log",
    RiskTier.APPROVAL: "require_approval",
    RiskTier.HUMAN_APPROVAL: "deny",
}

_VALID_ACTIONS = {"allow", "deny", "warn", "require_approval", "log"}

#: Egress hosts baked into the shipped templates (package registries and GitHub).
DEFAULT_TEMPLATE_EGRESS_HOSTS: list[str] = [
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "github.com",
    "api.github.com",
    "*.githubusercontent.com",
]


class GovernanceUnavailableError(RuntimeError):
    """Raised when the Agent Governance Toolkit is required but not importable."""


def agt_governance() -> Any:
    """Return the ``agentmesh.governance`` module or raise :class:`GovernanceUnavailableError`."""
    try:
        import agentmesh.governance as module
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise GovernanceUnavailableError(
            "agent-governance-toolkit-core is not installed; "
            "install the 'governance' extra to enforce policies"
        ) from exc
    return module


class RoleSpec(BaseModel):
    """Tool permissions granted to one agent role."""

    model_config = ConfigDict(extra="forbid")

    role: str
    allowed_actions: list[str]
    max_tier: RiskTier = RiskTier.APPROVAL
    approvers: list[str] = Field(default_factory=list)
    description: str = ""

    @field_validator("max_tier", mode="before")
    @classmethod
    def _coerce_tier(cls, value: Any) -> Any:
        return RiskTier.coerce(value) if isinstance(value, (int, str)) else value

    @field_validator("allowed_actions")
    @classmethod
    def _check_actions(cls, value: list[str]) -> list[str]:
        seen: list[str] = []
        for action in value:
            if " " in action or "'" in action or "," in action or "]" in action:
                raise ValueError(f"invalid action type {action!r}")
            if action not in seen:
                seen.append(action)
        return seen

    def scopes(self, config: TierConfig | None = None) -> set[Scope]:
        """Scopes implied by the allowed actions."""
        return {scope_for(a, config) for a in self.allowed_actions}


def default_roles() -> list[RoleSpec]:
    """Default role allow-lists (ARCHITECTURE.md §6 roles that call tools)."""
    read_only = ["read", "search", "explain", "list", "glob", "grep", "inspect"]
    worktree_writes = ["write", "edit", "create_file", "delete_file", "move_file"]
    local_exec = ["run_tests", "build", "lint", "typecheck", "execute", "git_commit"]
    return [
        RoleSpec(
            role="implementer",
            description="Implements tasks in an isolated worktree; may request PR/push approval.",
            allowed_actions=[
                *read_only,
                *worktree_writes,
                *local_exec,
                "network_egress",
                "web_search",
                "install_package",
                "git_push",
                "create_pr",
                "update_pr",
            ],
            max_tier=RiskTier.APPROVAL,
            approvers=["tech-lead"],
        ),
        RoleSpec(
            role="reviewer",
            description="Independent reviewer: reads the diff and may run verification only.",
            allowed_actions=[*read_only, "run_tests", "lint", "typecheck", "build"],
            max_tier=RiskTier.POLICY_CONTROLLED,
        ),
        RoleSpec(
            role="planner",
            description="Produces plan artifacts in the change package; backlog needs approval.",
            allowed_actions=[*read_only, "write", "edit", "create_file", "update_backlog"],
            max_tier=RiskTier.APPROVAL,
            approvers=["product-owner"],
        ),
        RoleSpec(
            role="security_tester",
            description="Runs adversarial campaigns against allow-listed targets; writes reports.",
            allowed_actions=[
                *read_only,
                "write",
                "create_file",
                "run_tests",
                "execute",
                "run_campaign",
                "network_egress",
                "web_search",
            ],
            max_tier=RiskTier.POLICY_CONTROLLED,
        ),
    ]


class PolicySpec(BaseModel):
    """Inputs for policy generation: tiers, roles, workspace roots and egress hosts."""

    model_config = ConfigDict(extra="forbid")

    name: str = "aisdlc"
    version: str = "1.0"
    roles: list[RoleSpec] = Field(default_factory=default_roles)
    workspace_roots: list[str] = Field(default_factory=list)
    allowed_egress_hosts: list[str] = Field(default_factory=list)
    tier_config: TierConfig = Field(default_factory=TierConfig)
    tier_actions: dict[RiskTier, str] = Field(default_factory=lambda: dict(DEFAULT_TIER_ACTIONS))

    @field_validator("tier_actions", mode="before")
    @classmethod
    def _coerce_tier_actions(cls, value: Any) -> Any:
        if isinstance(value, dict):
            merged = dict(DEFAULT_TIER_ACTIONS)
            for k, v in value.items():
                merged[RiskTier.coerce(k)] = str(v)
            return merged
        return value

    @field_validator("tier_actions")
    @classmethod
    def _check_tier_actions(cls, value: dict[RiskTier, str]) -> dict[RiskTier, str]:
        for tier, action in value.items():
            if action not in _VALID_ACTIONS:
                raise ValueError(f"invalid policy action {action!r} for tier {int(tier)}")
        if value[RiskTier.HUMAN_APPROVAL] != "deny":
            raise ValueError("tier 4 must map to 'deny' (human approval happens out of band)")
        if value[RiskTier.APPROVAL] not in {"require_approval", "deny"}:
            raise ValueError("tier 3 must map to 'require_approval' or 'deny'")
        return value

    def effective_tier_config(self) -> TierConfig:
        """Tier config with the spec's workspace roots and egress hosts merged in."""
        cfg = self.tier_config
        return cfg.model_copy(
            update={
                "allowed_egress_hosts": _merge(cfg.allowed_egress_hosts, self.allowed_egress_hosts),
                "workspace_roots": _merge(cfg.workspace_roots, self.workspace_roots),
            }
        )

    def role(self, name: str) -> RoleSpec:
        """Look up a role spec by name."""
        for role in self.roles:
            if role.role == name:
                return role
        raise KeyError(f"unknown role {name!r}; known: {[r.role for r in self.roles]}")

    def policy_name(self, role: str) -> str:
        """Name of the generated policy document for ``role``."""
        return f"{self.name}-{role}"


def template_spec() -> PolicySpec:
    """The spec the shipped ``templates/agt`` policies are generated from.

    No workspace roots are baked in (projects regenerate with ``--workspace-root``); the
    generated rules reference ``action.outside_workspace`` which the classifier computes.
    """
    return PolicySpec(allowed_egress_hosts=list(DEFAULT_TEMPLATE_EGRESS_HOSTS))


def _merge(first: list[str], second: list[str]) -> list[str]:
    out: list[str] = []
    for item in [*first, *second]:
        if item not in out:
            out.append(item)
    return out


def _list_literal(items: Iterable[str]) -> str:
    return "[" + ", ".join(f"'{item}'" for item in items) + "]"


def build_policy_document(spec: PolicySpec, role_name: str) -> dict[str, Any]:
    """Build the policy document (as a plain mapping) for one role."""
    role = spec.role(role_name)
    cfg = spec.effective_tier_config()
    allowed = _list_literal(role.allowed_actions)
    held_scopes = role.scopes(cfg)
    rules: list[dict[str, Any]] = []

    def rule(
        name: str,
        condition: str,
        action: str,
        priority: int,
        description: str,
        approvers: list[str] | None = None,
    ) -> None:
        doc: dict[str, Any] = {
            "name": name,
            "description": description,
            "condition": condition,
            "action": action,
            "priority": priority,
        }
        if approvers:
            doc["approvers"] = list(approvers)
        rules.append(doc)

    rule(
        "deny-tier-4",
        "action.tier >= 4",
        "deny",
        100,
        "Tier 4 (deploy, secrets, IAM, delete data, unlisted egress) needs a human "
        "approval outside the agent loop; agents are always denied.",
    )
    rule(
        "deny-unlisted-egress",
        "action.type == 'network_egress' and action.egress_unlisted",
        "deny",
        99,
        "Network egress to a host that is not on the allow-list is denied.",
    )
    if role.max_tier < RiskTier.HUMAN_APPROVAL:
        rule(
            f"deny-above-tier-{int(role.max_tier)}",
            f"action.tier > {int(role.max_tier)}",
            "deny",
            98,
            f"Role '{role.role}' may not act above tier {int(role.max_tier)}.",
        )
    for scope in Scope:
        if scope not in held_scopes:
            rule(
                f"deny-scope-{scope.value}",
                f"action.scope == '{scope.value}'",
                "deny",
                96,
                f"Role '{role.role}' holds no '{scope.value}' capability (read-only by default).",
            )
    tier3_action = spec.tier_actions[RiskTier.APPROVAL]
    rule(
        "approve-tier-3",
        f"action.tier >= 3 and action.type in {allowed}",
        tier3_action,
        90,
        "Tier 3 (shared state: push, PR, backlog) requires an explicit or rule-based "
        "approval; missing approver or timeout denies.",
        role.approvers,
    )
    if Scope.WRITE in held_scopes:
        rule(
            "approve-write-outside-workspace",
            f"action.scope == 'write' and action.outside_workspace and action.type in {allowed}",
            tier3_action,
            89,
            "Writes outside the isolated worktree are treated as tier 3.",
            role.approvers,
        )
    hosts = cfg.allowed_egress_hosts
    if "network_egress" in role.allowed_actions and hosts:
        rule(
            "audit-listed-egress",
            f"action.type == 'network_egress' and action.egress_host in {_list_literal(hosts)}",
            spec.tier_actions[RiskTier.POLICY_CONTROLLED],
            85,
            "Egress to allow-listed hosts is policy-controlled (tier 2) and audited.",
        )
    rule(
        "audit-tier-2",
        f"action.tier >= 2 and action.type in {allowed}",
        spec.tier_actions[RiskTier.POLICY_CONTROLLED],
        80,
        "Tier 2 (tests, builds, local artifacts) is policy-controlled and audited.",
    )
    rule(
        "audit-tier-1",
        f"action.tier >= 1 and action.type in {allowed}",
        spec.tier_actions[RiskTier.AUTOMATIC_AUDIT],
        70,
        "Tier 1 (writes inside the isolated worktree) is automatic but audited.",
    )
    rule(
        "allow-tier-0",
        f"action.tier < 1 and action.type in {allowed}",
        spec.tier_actions[RiskTier.AUTOMATIC],
        60,
        "Tier 0 (read, search, explain) is automatic.",
    )

    return {
        "apiVersion": API_VERSION,
        "name": spec.policy_name(role.role),
        "version": spec.version,
        "description": (
            f"AI-SDLC tier policy for role '{role.role}'. {role.description} "
            f"Workspace roots: {cfg.workspace_roots or ['<none>']}. "
            f"Allowed egress: {hosts or ['<none>']}."
        ).strip(),
        "agents": [role.role],
        "scope": "agent",
        "default_action": "deny",
        "rules": rules,
    }


def render_policy_yaml(spec: PolicySpec, role_name: str) -> str:
    """Render the policy document for ``role_name`` as YAML (with a provenance header)."""
    doc = build_policy_document(spec, role_name)
    header = (
        "# Generated by `aisdlc governance policy generate` from the platform tier taxonomy.\n"
        "# Do not hand-edit; change the project configuration and regenerate.\n"
    )
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=100)
    return header + str(body)


def render_all_policies(spec: PolicySpec) -> dict[str, str]:
    """Render one YAML document per role, keyed by role name."""
    return {role.role: render_policy_yaml(spec, role.role) for role in spec.roles}


def write_policies(spec: PolicySpec, out_dir: Path | str) -> list[Path]:
    """Write ``<role>.yaml`` files for every role into ``out_dir``; returns the paths."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for role, text in render_all_policies(spec).items():
        path = target / f"{role}.yaml"
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


#: Synthetic contexts every platform policy must deny, whatever else it contains.
#: ``(label, context)``; contexts are shaped like :meth:`ToolAction.to_context`.
DENY_PROBES: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "tier-4 action (deploy)",
        {
            "action": {
                "type": "deploy",
                "tool_name": "Bash",
                "resource": "prod",
                "tier": 4,
                "scope": "admin",
                "in_worktree": False,
                "outside_workspace": True,
                "egress_host": "",
                "egress_unlisted": False,
                "parameters": {},
            }
        },
    ),
    (
        "tier-4 action (rotate_secrets)",
        {
            "action": {
                "type": "rotate_secrets",
                "tool_name": "Bash",
                "resource": "vault",
                "tier": 4,
                "scope": "admin",
                "in_worktree": False,
                "outside_workspace": True,
                "egress_host": "",
                "egress_unlisted": False,
                "parameters": {},
            }
        },
    ),
    (
        "network egress to an unlisted host",
        {
            "action": {
                "type": "network_egress",
                "tool_name": "WebFetch",
                "resource": "https://unlisted.invalid/x",
                "tier": 4,
                "scope": "network",
                "in_worktree": False,
                "outside_workspace": True,
                "egress_host": "unlisted.invalid",
                "egress_unlisted": True,
                "parameters": {},
            }
        },
    ),
    (
        "action type outside every allow-list",
        {
            "action": {
                "type": "aisdlc_probe_unlisted_action",
                "tool_name": "Bash",
                "resource": "",
                "tier": 0,
                "scope": "read",
                "in_worktree": True,
                "outside_workspace": False,
                "egress_host": "",
                "egress_unlisted": False,
                "parameters": {},
            }
        },
    ),
)


def _probe_denials(engine: Any, agent_ids: Iterable[str]) -> list[str]:
    """Evaluate :data:`DENY_PROBES` for every agent id; return the probes that were not denied."""
    errors: list[str] = []
    for agent_id in agent_ids:
        for label, context in DENY_PROBES:
            probe = {"action": dict(context["action"])}
            try:
                decision = engine.evaluate(agent_id, probe, stage="pre_tool")
            except Exception as exc:  # noqa: BLE001 - any evaluator failure is a finding
                errors.append(f"agent {agent_id!r}: {label}: evaluation failed: {exc}")
                continue
            if bool(decision.allowed) or str(decision.action) != "deny":
                errors.append(
                    f"agent {agent_id!r}: {label} is not denied "
                    f"(rule {decision.matched_rule!r} -> {decision.action})"
                )
    return errors


def validate_policy_yaml(text: str) -> list[str]:
    """Validate a policy document by loading it into the AGT ``PolicyEngine``.

    Returns a list of error strings (empty when valid). Platform invariants are checked
    on top of AGT's own schema validation: current ``apiVersion``, ``default_action: deny``,
    a deny rule for tier 4, only known rule actions, and — evaluated through the engine
    with the platform's ``priority_first_match`` strategy so rule priorities are honoured —
    that every :data:`DENY_PROBES` context (tier 4, unlisted egress, an action type on no
    allow-list) is actually denied for each agent the document covers. A deny rule that
    exists but is outranked by a permissive rule therefore fails validation.
    """
    errors: list[str] = []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return ["policy must be a mapping"]
    if data.get("apiVersion") != API_VERSION:
        errors.append(f"apiVersion must be {API_VERSION!r}")
    if data.get("default_action") != "deny":
        errors.append("default_action must be 'deny' (fail closed)")
    rules = data.get("rules") or []
    if not any(
        isinstance(r, dict)
        and r.get("action") == "deny"
        and "action.tier >= 4" in str(r.get("condition"))
        for r in rules
    ):
        errors.append("missing a deny rule for tier 4 (condition 'action.tier >= 4')")
    for rule in rules:
        if isinstance(rule, dict) and rule.get("action") not in _VALID_ACTIONS:
            errors.append(f"rule {rule.get('name')!r}: invalid action {rule.get('action')!r}")

    gov = agt_governance()
    errors.extend(gov.policy.validate_policy_schema(text))
    try:
        engine = gov.PolicyEngine(conflict_strategy="priority_first_match")
        engine.load_yaml(text)
    except Exception as exc:  # AGT raises ValueError/ValidationError on bad documents
        errors.append(f"AGT PolicyEngine rejected the document: {exc}")
        return errors
    if errors:
        return errors
    agents = data.get("agents") or ([data["agent"]] if data.get("agent") else ["*"])
    agent_ids = [str(a) for a in agents if isinstance(a, (str, int))] or ["*"]
    errors.extend(_probe_denials(engine, agent_ids))
    return errors


def load_policy_engine(
    sources: Iterable[str | Path | Any],
    *,
    conflict_strategy: str = "priority_first_match",
) -> Any:
    """Create an AGT ``PolicyEngine`` and load YAML files, YAML strings or ``Policy`` objects.

    ``priority_first_match`` is required for generated policies: they rely on rule priority
    to express "the most specific tier rule wins".
    """
    gov = agt_governance()
    engine = gov.PolicyEngine(conflict_strategy=conflict_strategy)
    for source in sources:
        if isinstance(source, Path):
            engine.load_yaml_file(str(source))
        elif isinstance(source, str):
            if "\n" not in source and Path(source).exists():
                engine.load_yaml_file(source)
            else:
                engine.load_yaml(source)
        else:
            engine.load_policy(source)
    return engine


def scopes_table() -> dict[str, str]:
    """``action_type -> scope`` as plain strings (for documentation and templates)."""
    return {action: scope.value for action, scope in DEFAULT_SCOPE_TABLE.items()}
