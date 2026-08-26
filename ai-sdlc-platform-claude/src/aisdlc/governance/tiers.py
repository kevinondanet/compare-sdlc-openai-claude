"""Risk-tier taxonomy for tool actions (ARCHITECTURE.md §4).

Every tool call an agent makes is normalised into a :class:`ToolAction` and classified
into a :class:`RiskTier`. The classification is deterministic and driven by a documented
default table (:data:`DEFAULT_TIER_TABLE`) that a project may *tighten* through
:class:`TierConfig` overrides (never loosen — ARCHITECTURE.md §0.4) — and the semantics
of a tier never change:

======  ============================================================  ==================
Tier    Examples                                                      Default behaviour
======  ============================================================  ==================
0       read, search, explain, list, glob, grep                       automatic
1       write / edit / delete inside the isolated worktree            automatic + audit
2       run tests, build, lint, type-check, local commands, commits,  policy-controlled
        listed egress, provider-mediated web search
3       git push, create PR, backlog/shared-state changes,            rule-based approval
        writes outside the worktree
4       deploy, secrets, IAM, delete data, egress to unlisted host,   human approval
        any access to credential material on disk
======  ============================================================  ==================

Approval timeouts and missing approvers deny. Every tier >= 1 call is audited. Access to
credential material (:data:`CREDENTIAL_PATH_PATTERN`) is a contextual rule of
:func:`classify`, so every entry point — :func:`classify_action`, the policy enforcer,
``aisdlc governance policy check`` and the Claude Code / MCP tool mapping — inherits it
regardless of which tool names the path.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping
from enum import IntEnum, StrEnum
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskTier(IntEnum):
    """Risk tier of a tool action, ordered from harmless (0) to irreversible (4)."""

    AUTOMATIC = 0
    AUTOMATIC_AUDIT = 1
    POLICY_CONTROLLED = 2
    APPROVAL = 3
    HUMAN_APPROVAL = 4

    @property
    def default_behaviour(self) -> str:
        """Human-readable default behaviour for this tier."""
        return _TIER_BEHAVIOUR[self]

    @property
    def requires_audit(self) -> bool:
        """Whether calls at this tier must always be written to the audit trail."""
        return self >= RiskTier.AUTOMATIC_AUDIT

    @property
    def requires_approval(self) -> bool:
        """Whether calls at this tier need an approval decision before execution."""
        return self >= RiskTier.APPROVAL

    @classmethod
    def coerce(cls, value: int | str | RiskTier) -> RiskTier:
        """Coerce an int, a numeric string or a tier name (case-insensitive) to a tier."""
        if isinstance(value, RiskTier):
            return value
        if isinstance(value, int):
            return cls(value)
        text = value.strip()
        if text.lstrip("-").isdigit():
            return cls(int(text))
        try:
            return cls[text.upper().replace("+", "_").replace("-", "_")]
        except KeyError as exc:
            raise ValueError(f"unknown risk tier: {value!r}") from exc


_TIER_BEHAVIOUR: dict[RiskTier, str] = {
    RiskTier.AUTOMATIC: "automatic",
    RiskTier.AUTOMATIC_AUDIT: "automatic+audit",
    RiskTier.POLICY_CONTROLLED: "policy_controlled",
    RiskTier.APPROVAL: "approval",
    RiskTier.HUMAN_APPROVAL: "human_approval",
}


class Scope(StrEnum):
    """Coarse capability scope of a tool action."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    ADMIN = "admin"


# --------------------------------------------------------------------------------------
# Canonical action vocabulary and default table
# --------------------------------------------------------------------------------------

#: Default tier per canonical action type. Projects override entries via TierConfig.
DEFAULT_TIER_TABLE: dict[str, RiskTier] = {
    # tier 0 — read-only
    "read": RiskTier.AUTOMATIC,
    "search": RiskTier.AUTOMATIC,
    "explain": RiskTier.AUTOMATIC,
    "list": RiskTier.AUTOMATIC,
    "glob": RiskTier.AUTOMATIC,
    "grep": RiskTier.AUTOMATIC,
    "inspect": RiskTier.AUTOMATIC,
    # tier 1 — writes inside the isolated worktree (tier 3 outside, see classify())
    "write": RiskTier.AUTOMATIC_AUDIT,
    "edit": RiskTier.AUTOMATIC_AUDIT,
    "create_file": RiskTier.AUTOMATIC_AUDIT,
    "delete_file": RiskTier.AUTOMATIC_AUDIT,
    "move_file": RiskTier.AUTOMATIC_AUDIT,
    # tier 2 — local execution and local artifacts
    "run_tests": RiskTier.POLICY_CONTROLLED,
    "build": RiskTier.POLICY_CONTROLLED,
    "lint": RiskTier.POLICY_CONTROLLED,
    "typecheck": RiskTier.POLICY_CONTROLLED,
    "execute": RiskTier.POLICY_CONTROLLED,
    "git_commit": RiskTier.POLICY_CONTROLLED,
    "run_campaign": RiskTier.POLICY_CONTROLLED,
    "network_egress": RiskTier.POLICY_CONTROLLED,  # only for allow-listed hosts
    "web_search": RiskTier.POLICY_CONTROLLED,  # provider-mediated search (no host to list)
    # tier 3 — shared state
    "git_push": RiskTier.APPROVAL,
    "create_pr": RiskTier.APPROVAL,
    "update_pr": RiskTier.APPROVAL,
    "update_backlog": RiskTier.APPROVAL,
    "create_issue": RiskTier.APPROVAL,
    "modify_shared_state": RiskTier.APPROVAL,
    "install_package": RiskTier.APPROVAL,
    # tier 4 — irreversible / privileged
    "deploy": RiskTier.HUMAN_APPROVAL,
    "rotate_secrets": RiskTier.HUMAN_APPROVAL,
    "read_secrets": RiskTier.HUMAN_APPROVAL,
    "write_secrets": RiskTier.HUMAN_APPROVAL,
    "change_iam": RiskTier.HUMAN_APPROVAL,
    "delete_data": RiskTier.HUMAN_APPROVAL,
    "force_push": RiskTier.HUMAN_APPROVAL,
    "destructive": RiskTier.HUMAN_APPROVAL,
}

#: Default scope per canonical action type.
DEFAULT_SCOPE_TABLE: dict[str, Scope] = {
    "read": Scope.READ,
    "search": Scope.READ,
    "explain": Scope.READ,
    "list": Scope.READ,
    "glob": Scope.READ,
    "grep": Scope.READ,
    "inspect": Scope.READ,
    "write": Scope.WRITE,
    "edit": Scope.WRITE,
    "create_file": Scope.WRITE,
    "delete_file": Scope.WRITE,
    "move_file": Scope.WRITE,
    "run_tests": Scope.EXECUTE,
    "build": Scope.EXECUTE,
    "lint": Scope.EXECUTE,
    "typecheck": Scope.EXECUTE,
    "execute": Scope.EXECUTE,
    "git_commit": Scope.WRITE,
    "run_campaign": Scope.EXECUTE,
    "network_egress": Scope.NETWORK,
    "web_search": Scope.NETWORK,
    "git_push": Scope.NETWORK,
    "create_pr": Scope.NETWORK,
    "update_pr": Scope.NETWORK,
    "update_backlog": Scope.NETWORK,
    "create_issue": Scope.NETWORK,
    "modify_shared_state": Scope.WRITE,
    "install_package": Scope.EXECUTE,
    "deploy": Scope.ADMIN,
    "rotate_secrets": Scope.ADMIN,
    "read_secrets": Scope.ADMIN,
    "write_secrets": Scope.ADMIN,
    "change_iam": Scope.ADMIN,
    "delete_data": Scope.ADMIN,
    "force_push": Scope.ADMIN,
    "destructive": Scope.ADMIN,
}

#: Action types whose tier depends on whether the resource is inside the worktree.
WRITE_ACTIONS: frozenset[str] = frozenset(
    {"write", "edit", "create_file", "delete_file", "move_file"}
)

#: Tier for a write action whose resource is outside every workspace root.
WRITE_OUTSIDE_WORKTREE_TIER = RiskTier.APPROVAL

#: Tier for writes to a change package's evidence/verdict/approval artifacts, wherever they
#: live. ``changes/<id>/`` sits inside the repository and therefore inside every task
#: worktree; without this floor an implementer could satisfy every gate at tier 1 by
#: writing ``evidence/*.json``, ``approvals.json`` or ``final-verdict.json`` itself.
PROTECTED_PACKAGE_ARTIFACT_TIER = RiskTier.APPROVAL

#: Files directly under ``changes/<id>/`` that gates and the bundle trust.
PROTECTED_PACKAGE_FILES: frozenset[str] = frozenset(
    {"approvals.json", "final-verdict.json", "evidence-bundle.json", ".fingerprint"}
)

#: Directories under ``changes/<id>/`` whose every file is protected.
PROTECTED_PACKAGE_DIRS: frozenset[str] = frozenset({"evidence"})

#: Tier for network egress to a host that is not on the allow-list.
UNLISTED_EGRESS_TIER = RiskTier.HUMAN_APPROVAL

#: Tier used for action types that are not in the table and not overridden.
UNKNOWN_ACTION_TIER = RiskTier.APPROVAL

#: Credential / secret material on disk. Any read, search, write or execute action whose
#: resource (or a path-like parameter, see :data:`PATH_PARAMETER_KEYS`) matches is floored
#: to :data:`CREDENTIAL_ACCESS_TIER` by :func:`classify`, whatever the tool. Covers
#: ``.env`` and ``.env.*`` (samples such as ``.env.example`` excluded), ``*.pem``,
#: ``*.key``, ``*.p12``/``*.pfx``, ``id_rsa*`` and other SSH private keys, ``~/.ssh/*``,
#: ``~/.aws/*``, ``~/.azure/*``, ``~/.kube/*`` (``~/.kube/config``), ``~/.gnupg/*``,
#: ``~/.config/gcloud/*``, ``.netrc``, ``.npmrc``, ``.pypirc``, ``.pgpass``,
#: ``.git-credentials``, ``.docker/config.json``, Terraform credentials,
#: ``credentials.json``, service-account JSON, ``secret(s)*.json``, ``secret(s).<ext>``,
#: ``settings.local.json`` and ``/etc/shadow``-class files; glob forms such as ``*.pem``
#: or ``**/id_rsa*`` count too (searching for keys is reading them). The pattern is JS-compatible
#: so the AGT plugin can reuse it verbatim. Projects may only *extend* the set through
#: :attr:`TierConfig.credential_path_patterns` (narrowing what an agent may read); the
#: platform entries can never be removed.
CREDENTIAL_PATH_PATTERN = (
    r"(?:^|[\s/'\"=(,:])(?:"
    r"\.env(?!\.(?:example|sample|template|dist|test)\b)(?:\.[\w-]+)*"
    r"|id_rsa[\w.*-]*|id_ed25519[\w.*-]*|id_ecdsa[\w.*-]*|id_dsa[\w.*-]*"
    r"|\.netrc|\.git-credentials|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf"
    r"|\.docker/config\.json|\.terraform\.d/credentials\S*"
    r"|(?:\.ssh|\.aws|\.azure|\.kube|\.gnupg|\.password-store|\.config/gcloud)(?:/\S*)?"
    r"|credentials\.json|service[-_]?account\S*\.json|secrets?[\w-]*\.json"
    r"|secrets?\.(?:ya?ml|toml|ini|env|txt|properties|cfg|conf|xml)"
    r"|settings\.local\.json"
    r"|[\w.*?-]+\.(?:pem|key|p12|pfx)"
    r"|/etc/(?:shadow|gshadow|sudoers)\S*"
    r")(?=$|[\s'\";&|)>,:])"
)
_CREDENTIAL_PATH_RE = re.compile(CREDENTIAL_PATH_PATTERN, re.IGNORECASE)

#: Tier for any non-network action that touches a credential path (human approval).
CREDENTIAL_ACCESS_TIER = RiskTier.HUMAN_APPROVAL

#: Tool parameters that name files. Their values (strings or lists of strings) are checked
#: against the credential pattern in addition to the action's ``resource`` so tools that
#: take several paths (``paths``, ``patterns``) or use a different key than the harness
#: default (``path`` vs ``file_path``) cannot sidestep the floor.
PATH_PARAMETER_KEYS: tuple[str, ...] = (
    "path",
    "file_path",
    "paths",
    "patterns",
    "pattern",
    "notebook_path",
    "directory",
    "source",
    "destination",
)

_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class TierConfig(BaseModel):
    """Project-level overrides of the default tier table.

    Overrides are **tighten-only**: an override may raise the tier of an action type or
    of every action of a tool (``"tool:<ToolName>"``), never lower it below the
    platform default or below what the contextual rules in :func:`classify` derive
    (writes outside the worktree, egress to unlisted hosts). An action-type override
    below the :data:`DEFAULT_TIER_TABLE` entry is rejected at validation time; ``tool:``
    overrides and ``unknown_action_tier`` are floors applied with ``max()``. Overrides
    may only be consumed through :func:`classify`; they never change what a tier means.

    Attributes:
        overrides: ``action_type -> tier`` (or ``"tool:<ToolName>" -> tier`` to floor
            every action of a tool).
        allowed_egress_hosts: Hosts an agent may reach over the network at tier 2.
            Entries are exact host names or ``*.example.com`` suffix wildcards.
        workspace_roots: Directories that count as "inside the worktree".
        unknown_action_tier: Tier for action types absent from the table (never below
            :data:`UNKNOWN_ACTION_TIER`).
        credential_path_patterns: Additional regular expressions (matched case-insensitively
            against POSIX-normalised paths) that also count as credential material. They
            *extend* :data:`CREDENTIAL_PATH_PATTERN`; the platform set cannot be narrowed.
    """

    model_config = ConfigDict(extra="forbid")

    overrides: dict[str, RiskTier] = Field(default_factory=dict)
    allowed_egress_hosts: list[str] = Field(default_factory=list)
    workspace_roots: list[str] = Field(default_factory=list)
    unknown_action_tier: RiskTier = UNKNOWN_ACTION_TIER
    credential_path_patterns: list[str] = Field(default_factory=list)

    @field_validator("credential_path_patterns")
    @classmethod
    def _compile_credential_patterns(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for pattern in value:
            text = pattern.strip()
            if not text:
                continue
            try:
                re.compile(text, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"invalid credential_path_patterns entry {pattern!r}: {exc}"
                ) from exc
            cleaned.append(text)
        return cleaned

    @field_validator("overrides", mode="before")
    @classmethod
    def _coerce_overrides(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): RiskTier.coerce(v) for k, v in value.items()}
        return value

    @field_validator("overrides")
    @classmethod
    def _tighten_only(cls, value: dict[str, RiskTier]) -> dict[str, RiskTier]:
        loosening = {
            key: tier
            for key, tier in value.items()
            if not key.startswith("tool:")
            and key in DEFAULT_TIER_TABLE
            and tier < DEFAULT_TIER_TABLE[key]
        }
        if loosening:
            detail = ", ".join(
                f"{key}: {int(tier)} < default {int(DEFAULT_TIER_TABLE[key])}"
                for key, tier in sorted(loosening.items())
            )
            raise ValueError(f"tier overrides may only raise a tier (tighten-only): {detail}")
        return value

    @field_validator("unknown_action_tier", mode="before")
    @classmethod
    def _coerce_unknown(cls, value: Any) -> Any:
        return RiskTier.coerce(value) if isinstance(value, (int, str)) else value

    @field_validator("unknown_action_tier")
    @classmethod
    def _unknown_floor(cls, value: RiskTier) -> RiskTier:
        if value < UNKNOWN_ACTION_TIER:
            raise ValueError(
                f"unknown_action_tier may not be below {int(UNKNOWN_ACTION_TIER)} "
                "(unknown actions fail closed)"
            )
        return value

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> TierConfig:
        """Build a config from a plain mapping (e.g. the ``governance`` section of a project
        configuration). Missing keys fall back to defaults."""
        if not data:
            return cls()
        return cls.model_validate(
            {
                "overrides": data.get("tier_overrides", data.get("overrides", {})),
                "allowed_egress_hosts": list(data.get("allowed_egress_hosts", [])),
                "workspace_roots": list(data.get("workspace_roots", [])),
                "unknown_action_tier": data.get("unknown_action_tier", UNKNOWN_ACTION_TIER),
                "credential_path_patterns": list(data.get("credential_path_patterns", [])),
            }
        )

    def tier_table(self) -> dict[str, RiskTier]:
        """The effective ``action_type -> tier`` table (defaults raised by overrides)."""
        table = dict(DEFAULT_TIER_TABLE)
        for key, tier in self.overrides.items():
            if not key.startswith("tool:"):
                table[key] = max(table.get(key, tier), tier)
        return table

    def tool_floor(self, tool_name: str) -> RiskTier | None:
        """Tier floor configured for every action of ``tool_name`` (``None`` if unset)."""
        return self.overrides.get(f"tool:{tool_name}")

    def host_allowed(self, host: str | None) -> bool:
        """Whether ``host`` matches the egress allow-list."""
        return host_matches(host, self.allowed_egress_hosts)

    def is_credential_path(self, path: str | None) -> bool:
        """Whether ``path`` is credential material (platform pattern plus project extras)."""
        return is_credential_path(path, extra_patterns=self.credential_path_patterns)


def host_matches(host: str | None, allowed: list[str]) -> bool:
    """Match ``host`` against an allow-list of exact names and ``*.suffix`` wildcards."""
    if not host:
        return False
    host = host.lower().strip(".")
    for entry in allowed:
        pattern = entry.lower().strip()
        if not pattern:
            continue
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) or host == pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def extract_host(resource: str | None) -> str | None:
    """Extract a host name from a URL or ``host[:port]`` string; ``None`` if absent."""
    if not resource:
        return None
    text = resource.strip()
    if "://" in text:
        parsed = urlsplit(text)
        return parsed.hostname.lower() if parsed.hostname else None
    candidate = text.split("/", 1)[0].split(":", 1)[0]
    if re.fullmatch(r"[a-z0-9.-]+", candidate, flags=re.IGNORECASE) and "." in candidate:
        return candidate.lower()
    if candidate.lower() == "localhost":
        return "localhost"
    return None


def path_in_roots(path: str | None, roots: list[str]) -> bool:
    """Whether ``path`` lies under any of ``roots`` (POSIX semantics, no filesystem access).

    Relative paths are treated as inside the worktree when at least one root is given,
    because harness adapters resolve relative paths against the worktree. An empty
    ``roots`` list means "no isolation configured", which is treated as *outside*.
    """
    if not roots or not path:
        return False
    normalized = posixpath.normpath(path.replace("\\", "/"))
    if not normalized.startswith("/"):
        return not normalized.startswith("..")
    target = PurePosixPath(normalized)
    for root in roots:
        root_norm = PurePosixPath(posixpath.normpath(root.replace("\\", "/")))
        if target == root_norm or root_norm in target.parents:
            return True
    return False


def is_credential_path(path: str | None, *, extra_patterns: Iterable[str] = ()) -> bool:
    """Whether ``path`` names credential/secret material (``.env``, ``~/.ssh/...``, ...).

    Matches :data:`CREDENTIAL_PATH_PATTERN` (always) and any of ``extra_patterns`` (a
    project's :attr:`TierConfig.credential_path_patterns`). Windows separators are
    normalised first; matching is case-insensitive.
    """
    if not path:
        return False
    text = path.replace("\\", "/")
    if _CREDENTIAL_PATH_RE.search(text) is not None:
        return True
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in extra_patterns)


def path_parameters(parameters: Mapping[str, Any] | None) -> list[str]:
    """Path-like values found under :data:`PATH_PARAMETER_KEYS` in a tool's parameters.

    String values are returned as-is; list/tuple values contribute each string element.
    Other value types are ignored (never coerced), so an agent cannot smuggle a path
    past the check by wrapping it — nor trip it by accident with structured data.
    """
    if not parameters:
        return []
    found: list[str] = []
    for key in PATH_PARAMETER_KEYS:
        value = parameters.get(key)
        if isinstance(value, str):
            if value:
                found.append(value)
        elif isinstance(value, (list, tuple)):
            found.extend(item for item in value if isinstance(item, str) and item)
    return found


def credential_targets(
    resource: str | None,
    parameters: Mapping[str, Any] | None = None,
    *,
    config: TierConfig | None = None,
) -> list[str]:
    """The credential paths an action names via ``resource`` or its path parameters."""
    cfg = config or TierConfig()
    candidates = [resource or "", *path_parameters(parameters)]
    return [c for c in candidates if c and cfg.is_credential_path(c)]


def is_protected_package_artifact(path: str | None) -> bool:
    """Whether *path* is a gate-trusted artifact of a change package.

    Matches ``.../changes/CHG-<slug>/evidence/<anything>`` and the package-level
    ``approvals.json``, ``final-verdict.json``, ``evidence-bundle.json`` and
    ``.fingerprint`` files (absolute or relative, POSIX or Windows separators). Authored
    artifacts (``intent.md``, ``tasks.md`` …) are not protected: agents legitimately edit
    them at tier 1.
    """
    if not path:
        return False
    normalized = posixpath.normpath(path.replace("\\", "/"))
    parts = [part for part in normalized.split("/") if part and part != "."]
    for index, part in enumerate(parts):
        if part != "changes" or index + 1 >= len(parts):
            continue
        if not parts[index + 1].startswith("CHG-"):
            continue
        rest = parts[index + 2 :]
        if not rest:
            return False
        if rest[0] in PROTECTED_PACKAGE_DIRS:
            return len(rest) > 1
        return len(rest) == 1 and rest[0] in PROTECTED_PACKAGE_FILES
    return False


class ToolAction(BaseModel):
    """A normalised, classified tool call.

    Attributes:
        tool_name: Harness tool name (``Write``, ``Bash``, ``mcp__github__create_pr``...).
        action_type: Canonical action vocabulary entry (see :data:`DEFAULT_TIER_TABLE`).
        resource: Path, URL, branch or other target of the action.
        parameters: Sanitised parameters relevant to policy (never secrets).
        tier: Classified risk tier.
        scope: Capability scope.
        in_worktree: Whether ``resource`` resolves inside a workspace root.
        egress_host: Host for network actions (``None`` otherwise).
        egress_listed: Whether ``egress_host`` is on the allow-list.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    action_type: str
    resource: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    tier: RiskTier
    scope: Scope
    in_worktree: bool = False
    egress_host: str | None = None
    egress_listed: bool = False

    @field_validator("action_type")
    @classmethod
    def _check_action_type(cls, value: str) -> str:
        if not _ACTION_TYPE_RE.match(value):
            raise ValueError(f"action_type must be snake_case, got {value!r}")
        return value

    @field_validator("tier", mode="before")
    @classmethod
    def _coerce_tier(cls, value: Any) -> Any:
        return RiskTier.coerce(value) if isinstance(value, (int, str)) else value

    def to_context(self) -> dict[str, Any]:
        """Build the AGT ``PolicyEngine.evaluate`` context for this action.

        The ``action`` mapping is what generated policy rules reference:
        ``action.type``, ``action.tool_name``, ``action.resource``, ``action.tier`` (int),
        ``action.scope``, ``action.in_worktree``, ``action.outside_workspace``,
        ``action.egress_host``, ``action.egress_unlisted`` and ``action.parameters.<k>``.
        """
        return {
            "action": {
                "type": self.action_type,
                "tool_name": self.tool_name,
                "resource": self.resource,
                "tier": int(self.tier),
                "scope": self.scope.value,
                "in_worktree": self.in_worktree,
                "outside_workspace": not self.in_worktree,
                "egress_host": self.egress_host or "",
                "egress_unlisted": bool(self.egress_host) and not self.egress_listed,
                "parameters": _json_safe(self.parameters),
            }
        }


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v) for v in value]
    return str(value)


def scope_for(action_type: str, config: TierConfig | None = None) -> Scope:
    """Scope for an action type (falls back to the tier-implied scope for unknown types)."""
    scope = DEFAULT_SCOPE_TABLE.get(action_type)
    if scope is not None:
        return scope
    tier = (config or TierConfig()).tier_table().get(action_type)
    if tier is None:
        return Scope.EXECUTE
    if tier == RiskTier.HUMAN_APPROVAL:
        return Scope.ADMIN
    if tier == RiskTier.AUTOMATIC:
        return Scope.READ
    return Scope.WRITE


def classify(
    tool_name: str,
    action_type: str,
    resource: str | None,
    in_worktree: bool,
    *,
    config: TierConfig | None = None,
    parameters: Mapping[str, Any] | None = None,
) -> RiskTier:
    """Classify a tool call into a :class:`RiskTier`.

    The result is the **highest** of:

    1. the platform default for ``action_type`` (:data:`DEFAULT_TIER_TABLE`; unknown
       action types use ``config.unknown_action_tier``);
    2. the contextual rules: write actions outside the worktree -> tier 3; writes to a
       change package's evidence/approvals/verdict/bundle/fingerprint
       (:func:`is_protected_package_artifact`) -> tier 3 even inside the worktree; network
       egress to a host that is not allow-listed -> tier 4; any non-network action whose
       ``resource`` or path parameters (:data:`PATH_PARAMETER_KEYS`) name credential
       material (:data:`CREDENTIAL_PATH_PATTERN`) -> tier 4, whatever the tool — a plain
       ``Read`` of ``~/.aws/credentials`` needs the same human approval as ``read_secrets``;
    3. the project's ``action_type`` override;
    4. the project's ``tool:<tool_name>`` override.

    Overrides can therefore only tighten (ARCHITECTURE.md §0.4): no configuration can
    demote a tier-3/4 action below the approval it needs.
    """
    cfg = config or TierConfig()
    tier = DEFAULT_TIER_TABLE.get(action_type, cfg.unknown_action_tier)
    if action_type in WRITE_ACTIONS and not in_worktree:
        tier = max(tier, WRITE_OUTSIDE_WORKTREE_TIER)
    if action_type in WRITE_ACTIONS and is_protected_package_artifact(resource):
        tier = max(tier, PROTECTED_PACKAGE_ARTIFACT_TIER)
    if action_type == "network_egress" and not cfg.host_allowed(extract_host(resource)):
        tier = max(tier, UNLISTED_EGRESS_TIER)
    if scope_for(action_type, cfg) is not Scope.NETWORK and credential_targets(
        resource, parameters, config=cfg
    ):
        tier = max(tier, CREDENTIAL_ACCESS_TIER)
    action_override = cfg.overrides.get(action_type)
    if action_override is not None:
        tier = max(tier, action_override)
    tool_override = cfg.tool_floor(tool_name)
    if tool_override is not None:
        tier = max(tier, tool_override)
    return RiskTier(tier)


def classify_action(
    tool_name: str,
    action_type: str,
    resource: str | None = None,
    parameters: dict[str, Any] | None = None,
    *,
    config: TierConfig | None = None,
    in_worktree: bool | None = None,
) -> ToolAction:
    """Build a fully classified :class:`ToolAction`.

    ``in_worktree`` is derived from ``config.workspace_roots`` unless given explicitly.
    """
    cfg = config or TierConfig()
    resource_text = resource or ""
    if in_worktree is None:
        in_worktree = path_in_roots(resource_text, cfg.workspace_roots)
    host = extract_host(resource_text) if action_type == "network_egress" else None
    tier = classify(
        tool_name, action_type, resource_text, in_worktree, config=cfg, parameters=parameters
    )
    return ToolAction(
        tool_name=tool_name,
        action_type=action_type,
        resource=resource_text,
        parameters=dict(parameters or {}),
        tier=tier,
        scope=scope_for(action_type, cfg),
        in_worktree=in_worktree,
        egress_host=host,
        egress_listed=cfg.host_allowed(host) if host else False,
    )


def tier_table_markdown(config: TierConfig | None = None) -> str:
    """Render the effective tier table as a Markdown table (for docs and ``--explain``)."""
    table = (config or TierConfig()).tier_table()
    lines = ["| action_type | tier | default |", "| --- | --- | --- |"]
    for action_type, tier in sorted(table.items(), key=lambda kv: (int(kv[1]), kv[0])):
        lines.append(f"| {action_type} | {int(tier)} | {tier.default_behaviour} |")
    return "\n".join(lines)
