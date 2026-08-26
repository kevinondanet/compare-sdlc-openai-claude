# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deterministic execution planning for governed AI software delivery.

This module is deliberately a control-plane boundary.  It turns a validated
``ChangePackage`` into an immutable manifest that an external runner can execute, but
it never creates a worktree, starts an agent, invokes a tool, or writes to the usage
ledger.  Those side effects remain the responsibility of a separately governed host.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.change_contract import ChangePackage, Task, canonical_json_bytes
from agent_sre.sdlc.control_plane import PromptRegistry, RegisteredPrompt
from agent_sre.sdlc.model_registry import (
    ModelCapabilities,
    ModelIdentity,
    ModelPrice,
    ModelTier,
    RegisteredModel,
    TokenUsage,
)
from agent_sre.sdlc.review_loop import (
    ReviewAttesterTrust,
    canonical_relative_path,
    path_is_within_scope,
)
from agent_sre.sdlc.routing import (
    ModelRouter,
    RoutingDecision,
    RoutingError,
    RoutingRequest,
)
from agent_sre.sdlc.usage_ledger import PromptIdentity, ReservationRequest, UsageAttribution

POLICY_SCHEMA_VERSION: Literal["agt.orchestration-policy/v1"] = "agt.orchestration-policy/v1"
MANIFEST_SCHEMA_VERSION: Literal["agt.orchestration-manifest/v1"] = "agt.orchestration-manifest/v1"
RESERVATION_SCHEMA_VERSION: Literal["agt.usage-reservation-plan/v1"] = (
    "agt.usage-reservation-plan/v1"
)

_RUN_ID = re.compile(r"^RUN-[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOOL_SCOPES = frozenset({"read", "workspace_write", "execute", "network", "administrative"})
_PRIVILEGED_SCOPES = frozenset({"execute", "network", "administrative"})
_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NETWORK_HOST = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)


class OrchestrationError(ValueError):
    """Base error for invalid or unsafe execution planning."""


class PolicyWeakeningError(OrchestrationError):
    """Raised when a project policy attempts to weaken an enterprise policy."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = tuple(sorted(set(reasons)))
        super().__init__(f"project policy weakens enterprise policy: {', '.join(self.reasons)}")


class PlanningError(OrchestrationError):
    """Raised when a validated manifest cannot be planned safely."""


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _hash_id(prefix: str, *parts: str, length: int = 24) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:length]}"


def _finite_nonnegative(value: Decimal, *, field_name: str) -> Decimal:
    if not value.is_finite() or value < 0:
        raise ValueError(f"{field_name} must be finite and non-negative")
    if value == 0:
        return Decimal("0")
    return Decimal(format(value.normalize(), "f"))


def _sorted_unique(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{field_name} entries must be non-empty strings")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{field_name} must be sorted and unique")
    return values


def model_price_record_digest(price: ModelPrice) -> str:
    """Digest every selected effective-dated price fact used by a manifest."""

    if not isinstance(price, ModelPrice):
        raise ValueError("price must be a ModelPrice")

    def rate_text(value: Decimal | None) -> str | None:
        if value is None:
            return None
        return "0" if value == 0 else format(value.normalize(), "f")

    identity = price.identity
    payload = {
        "schema": "agt.model-price-record/v1",
        "identity": {
            "provider": identity.provider,
            "provider_family": identity.provider_family,
            "model": identity.model,
            "version": identity.version,
            "deployment": identity.deployment,
        },
        "effective_from": price.effective_from.isoformat(timespec="microseconds"),
        "effective_to": (
            price.effective_to.isoformat(timespec="microseconds")
            if price.effective_to is not None
            else None
        ),
        "input_per_million": rate_text(price.input_per_million),
        "output_per_million": rate_text(price.output_per_million),
        "cached_input_per_million": rate_text(price.cached_input_per_million),
        "reasoning_per_million": rate_text(price.reasoning_per_million),
        "provenance": price.provenance,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


class OrchestrationModel(BaseModel):
    """Strict, immutable base for policy and manifest wire models."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TokenEstimate(OrchestrationModel):
    """Conservative token estimate used for routing and cost reservation."""

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    reasoning_tokens: int = Field(default=0, ge=0)

    @field_validator(
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "reasoning_tokens",
        mode="before",
    )
    @classmethod
    def _reject_boolean_tokens(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("token estimates must be integers")
        return value

    @model_validator(mode="after")
    def _require_positive_estimate(self) -> Self:
        if (
            self.input_tokens
            + self.output_tokens
            + self.cached_input_tokens
            + self.reasoning_tokens
            == 0
        ):
            raise ValueError("at least one estimated token bucket must be positive")
        return self

    def to_usage(self) -> TokenUsage:
        """Convert the wire-safe estimate to the registry pricing primitive."""

        return TokenUsage(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            cached_input_tokens=self.cached_input_tokens,
            reasoning_tokens=self.reasoning_tokens,
        )

    def is_at_least(self, other: TokenEstimate) -> bool:
        """Return whether this estimate is no smaller in every token bucket."""

        return all(
            getattr(self, field) >= getattr(other, field)
            for field in (
                "input_tokens",
                "output_tokens",
                "cached_input_tokens",
                "reasoning_tokens",
            )
        )


class RouteProfile(OrchestrationModel):
    """Policy constraints supplied verbatim to the benchmark-driven router."""

    task_type: str = Field(min_length=1)
    use_case: str = Field(min_length=1)
    context_tokens: int = Field(gt=0)
    estimated_usage: TokenEstimate
    max_benchmark_age_seconds: int = Field(gt=0)
    max_tier: ModelTier = ModelTier.HIGH
    required_capabilities: tuple[str, ...] = ()
    min_quality: Decimal = Field(default=Decimal("0"), ge=0, le=1)
    max_latency_ms: Decimal | None = Field(default=None, ge=0)

    @field_validator("context_tokens", "max_benchmark_age_seconds", "max_tier", mode="before")
    @classmethod
    def _reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("routing integer limits must be integers")
        return value

    @field_validator("required_capabilities")
    @classmethod
    def _validate_required_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(value, field_name="required_capabilities")

    @field_validator("min_quality", "max_latency_ms")
    @classmethod
    def _validate_decimals(cls, value: Decimal | None, info: Any) -> Decimal | None:
        if value is None:
            return None
        return _finite_nonnegative(value, field_name=info.field_name)

    def weakening_reasons(self, parent: RouteProfile, *, prefix: str) -> list[str]:
        """Return fields that are less restrictive than *parent*."""

        reasons: list[str] = []
        if self.task_type != parent.task_type:
            reasons.append(f"{prefix}.task_type_changed")
        if self.use_case != parent.use_case:
            reasons.append(f"{prefix}.use_case_changed")
        if self.context_tokens > parent.context_tokens:
            reasons.append(f"{prefix}.context_tokens_increased")
        if not self.estimated_usage.is_at_least(parent.estimated_usage):
            reasons.append(f"{prefix}.estimated_usage_reduced")
        if self.max_benchmark_age_seconds > parent.max_benchmark_age_seconds:
            reasons.append(f"{prefix}.benchmark_freshness_weakened")
        if self.max_tier > parent.max_tier:
            reasons.append(f"{prefix}.model_tier_increased")
        if not set(self.required_capabilities) >= set(parent.required_capabilities):
            reasons.append(f"{prefix}.required_capabilities_removed")
        if self.min_quality < parent.min_quality:
            reasons.append(f"{prefix}.minimum_quality_reduced")
        if parent.max_latency_ms is not None and (
            self.max_latency_ms is None or self.max_latency_ms > parent.max_latency_ms
        ):
            reasons.append(f"{prefix}.latency_limit_weakened")
        return reasons


class ToolAction(str, Enum):
    """One concrete side-effect category mediated at the host boundary."""

    ADMINISTRATIVE = "administrative"
    EXECUTE = "execute"
    NETWORK = "network"
    READ = "read"
    SECRET_ACCESS = "secret_access"
    WRITE = "write"


_MANDATORY_PRIVILEGED_ACTIONS = frozenset(
    {
        ToolAction.ADMINISTRATIVE,
        ToolAction.EXECUTE,
        ToolAction.NETWORK,
        ToolAction.SECRET_ACCESS,
    }
)


class RoleToolPolicy(OrchestrationModel):
    """Exact tools, actions, and scopes available to one assignment role."""

    role: Literal["implementation", "independent_review"]
    allowed_tools: tuple[str, ...] = Field(min_length=1)
    allowed_actions: tuple[ToolAction, ...] = Field(min_length=1)
    allowed_scopes: tuple[str, ...] = Field(min_length=1)

    @field_validator("allowed_tools")
    @classmethod
    def _tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="allowed_tools")
        if any(_TOOL_NAME.fullmatch(item) is None for item in result):
            raise ValueError("allowed_tools contains an invalid tool name")
        return result

    @field_validator("allowed_actions")
    @classmethod
    def _actions(cls, value: tuple[ToolAction, ...]) -> tuple[ToolAction, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("allowed_actions must be sorted and unique")
        return value

    @field_validator("allowed_scopes")
    @classmethod
    def _scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="allowed_scopes")
        unknown = sorted(set(result) - _TOOL_SCOPES)
        if unknown:
            raise ValueError(f"unknown role tool scopes: {', '.join(unknown)}")
        return result

    def weakening_reasons(self, parent: RoleToolPolicy) -> list[str]:
        """Return role capabilities that exceed the parent allowlist."""

        reasons: list[str] = []
        if self.role != parent.role:
            return [f"tool_governance.role.{self.role}.changed"]
        if not set(self.allowed_tools) <= set(parent.allowed_tools):
            reasons.append(f"tool_governance.role.{self.role}.tools_expanded")
        if not set(self.allowed_actions) <= set(parent.allowed_actions):
            reasons.append(f"tool_governance.role.{self.role}.actions_expanded")
        if not set(self.allowed_scopes) <= set(parent.allowed_scopes):
            reasons.append(f"tool_governance.role.{self.role}.scopes_expanded")
        return reasons


def _default_role_tool_policies() -> tuple[RoleToolPolicy, ...]:
    return (
        RoleToolPolicy(
            role="independent_review",
            allowed_tools=("workspace",),
            allowed_actions=(ToolAction.READ,),
            allowed_scopes=("read",),
        ),
        RoleToolPolicy(
            role="implementation",
            allowed_tools=("workspace",),
            allowed_actions=(
                ToolAction.READ,
                ToolAction.WRITE,
            ),
            allowed_scopes=(
                "read",
                "workspace_write",
            ),
        ),
    )


class ToolGovernancePolicy(OrchestrationModel):
    """Fail-closed Plane-2 policy embedded in every executable manifest."""

    role_policies: tuple[RoleToolPolicy, ...] = Field(
        default_factory=_default_role_tool_policies,
        min_length=2,
        max_length=2,
    )
    allowed_command_prefixes: tuple[tuple[str, ...], ...] = ()
    allowed_network_hosts: tuple[str, ...] = ()
    allowed_secret_references: tuple[str, ...] = ()
    approval_required_actions: tuple[ToolAction, ...] = (
        ToolAction.ADMINISTRATIVE,
        ToolAction.EXECUTE,
        ToolAction.NETWORK,
        ToolAction.SECRET_ACCESS,
    )
    privileged_actions: tuple[ToolAction, ...] = (
        ToolAction.ADMINISTRATIVE,
        ToolAction.EXECUTE,
        ToolAction.NETWORK,
        ToolAction.SECRET_ACCESS,
    )
    max_result_bytes: int = Field(default=65_536, gt=0, le=16 * 1024 * 1024)
    blocked_result_substrings: tuple[str, ...] = (
        "-----begin private key-----",
        "ignore all previous instructions",
        "ignore previous instructions",
        "reveal system prompt",
        "system message:",
    )
    require_relative_workspace_paths: Literal[True] = True
    require_https_network: Literal[True] = True

    @field_validator("max_result_bytes", mode="before")
    @classmethod
    def _result_size(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("max_result_bytes must be an integer")
        return value

    @field_validator("role_policies")
    @classmethod
    def _roles(cls, value: tuple[RoleToolPolicy, ...]) -> tuple[RoleToolPolicy, ...]:
        roles = tuple(item.role for item in value)
        if roles != ("independent_review", "implementation"):
            raise ValueError("role_policies must contain both roles in canonical order")
        return value

    @field_validator("allowed_command_prefixes")
    @classmethod
    def _commands(cls, value: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("allowed_command_prefixes must be sorted and unique")
        for prefix in value:
            if not prefix:
                raise ValueError("command prefixes must be non-empty")
            if any(
                not isinstance(token, str)
                or not token
                or token != token.strip()
                or any(ord(char) < 32 for char in token)
                for token in prefix
            ):
                raise ValueError("command prefixes contain an invalid argv token")
        return value

    @field_validator("allowed_network_hosts")
    @classmethod
    def _network_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="allowed_network_hosts")
        if any(item != item.lower() or _NETWORK_HOST.fullmatch(item) is None for item in result):
            raise ValueError("allowed_network_hosts must contain lowercase hostnames")
        return result

    @field_validator("allowed_secret_references")
    @classmethod
    def _secret_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="allowed_secret_references")
        if any(_SAFE_ID.fullmatch(item) is None for item in result):
            raise ValueError("allowed_secret_references contains an invalid reference")
        return result

    @field_validator("approval_required_actions", "privileged_actions")
    @classmethod
    def _ordered_actions(cls, value: tuple[ToolAction, ...], info: Any) -> tuple[ToolAction, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError(f"{info.field_name} must be sorted and unique")
        return value

    @field_validator("blocked_result_substrings")
    @classmethod
    def _blocked_results(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="blocked_result_substrings")
        if any(item != item.lower() or len(item.encode("utf-8")) > 512 for item in result):
            raise ValueError("blocked result substrings must be bounded lowercase strings")
        return result

    @model_validator(mode="after")
    def _security_invariants(self) -> Self:
        if not set(self.privileged_actions) >= _MANDATORY_PRIVILEGED_ACTIONS:
            raise ValueError(
                "administrative, execute, network, and secret access actions "
                "must remain privileged"
            )
        if not set(self.approval_required_actions) >= _MANDATORY_PRIVILEGED_ACTIONS:
            raise ValueError(
                "administrative, execute, network, and secret access actions "
                "must require approval"
            )
        if not set(self.privileged_actions) <= set(self.approval_required_actions):
            raise ValueError("every privileged action must require approval")
        return self

    def for_role(self, role: str) -> RoleToolPolicy:
        """Return the exact allowlist for *role*."""

        for policy in self.role_policies:
            if policy.role == role:
                return policy
        raise ValueError(f"tool governance does not define role {role!r}")

    def weakening_reasons(self, parent: ToolGovernancePolicy) -> list[str]:
        """Return every Plane-2 expansion relative to *parent*."""

        reasons: list[str] = []
        parent_roles = {item.role: item for item in parent.role_policies}
        for role in self.role_policies:
            parent_role = parent_roles.get(role.role)
            if parent_role is None:
                reasons.append(f"tool_governance.role.{role.role}.added")
            else:
                reasons.extend(role.weakening_reasons(parent_role))
        if not set(self.allowed_command_prefixes) <= set(parent.allowed_command_prefixes):
            reasons.append("tool_governance.command_prefixes_expanded")
        if not set(self.allowed_network_hosts) <= set(parent.allowed_network_hosts):
            reasons.append("tool_governance.network_hosts_expanded")
        if not set(self.allowed_secret_references) <= set(parent.allowed_secret_references):
            reasons.append("tool_governance.secret_references_expanded")
        if not set(self.approval_required_actions) >= set(parent.approval_required_actions):
            reasons.append("tool_governance.approvals_removed")
        if not set(self.privileged_actions) >= set(parent.privileged_actions):
            reasons.append("tool_governance.privileged_audit_removed")
        if self.max_result_bytes > parent.max_result_bytes:
            reasons.append("tool_governance.result_size_increased")
        if not set(self.blocked_result_substrings) >= set(parent.blocked_result_substrings):
            reasons.append("tool_governance.result_screening_removed")
        return reasons


class ExecutionLimits(OrchestrationModel):
    """Ceilings embedded for host enforcement and post-execution reconciliation."""

    max_turns_per_assignment: int = Field(gt=0)
    max_tool_calls_per_assignment: int = Field(ge=0)
    max_parallel_agents: int = Field(gt=0)
    max_assignment_duration_seconds: int = Field(default=900, gt=0, le=86_400)
    max_review_rounds: int = Field(default=1, gt=0, le=32)
    max_cost_per_assignment_usd: Decimal = Field(ge=0)
    max_total_cost_usd: Decimal = Field(ge=0)

    @field_validator(
        "max_turns_per_assignment",
        "max_tool_calls_per_assignment",
        "max_parallel_agents",
        "max_assignment_duration_seconds",
        "max_review_rounds",
        mode="before",
    )
    @classmethod
    def _reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("execution limits must be integers")
        return value

    @field_validator("max_cost_per_assignment_usd", "max_total_cost_usd")
    @classmethod
    def _validate_costs(cls, value: Decimal, info: Any) -> Decimal:
        return _finite_nonnegative(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _validate_cost_relationship(self) -> Self:
        if self.max_cost_per_assignment_usd > self.max_total_cost_usd:
            raise ValueError("max_cost_per_assignment_usd must not exceed max_total_cost_usd")
        return self

    def weakening_reasons(self, parent: ExecutionLimits) -> list[str]:
        """Return resource ceilings that exceed *parent*."""

        reasons: list[str] = []
        for field in (
            "max_turns_per_assignment",
            "max_tool_calls_per_assignment",
            "max_parallel_agents",
            "max_assignment_duration_seconds",
            "max_review_rounds",
            "max_cost_per_assignment_usd",
            "max_total_cost_usd",
        ):
            if getattr(self, field) > getattr(parent, field):
                reasons.append(f"limits.{field}_increased")
        return reasons


class OrchestrationPolicy(OrchestrationModel):
    """Versioned enterprise or project execution policy.

    Security invariants are literals, so policy data cannot disable fresh contexts,
    isolated workspaces, known-cost routing, independent review, or final human release
    approval.  Project policies are accepted only through :meth:`assert_narrows`.
    """

    schema_version: Literal["agt.orchestration-policy/v1"] = POLICY_SCHEMA_VERSION
    policy_id: str = Field(min_length=1)
    organization_id: str = Field(min_length=1)
    team_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    allowed_tool_scopes: tuple[str, ...]
    checkpoint_tool_scopes: tuple[str, ...] = ("administrative", "network")
    checkpoint_min_risk_tier: int = Field(default=3, ge=0, le=3)
    execution_approver_role: str = Field(min_length=1)
    release_approver_role: str = Field(min_length=1)
    reservation_ttl_seconds: int = Field(gt=0, le=86_400)
    review_attestation_ttl_seconds: int = Field(default=300, gt=0, le=3_600)
    remediation_path_scopes: tuple[str, ...] = (".",)
    trusted_review_attesters: tuple[ReviewAttesterTrust, ...] = Field(min_length=1)
    implementation_route: RouteProfile
    review_route: RouteProfile
    limits: ExecutionLimits
    tool_governance: ToolGovernancePolicy = Field(default_factory=ToolGovernancePolicy)
    require_fresh_context: Literal[True] = True
    require_isolated_workspace: Literal[True] = True
    require_known_cost: Literal[True] = True
    require_independent_review: Literal[True] = True
    require_human_release_approval: Literal[True] = True

    @field_validator("policy_id")
    @classmethod
    def _validate_policy_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("policy_id contains unsupported characters")
        return value

    @field_validator(
        "reservation_ttl_seconds",
        "review_attestation_ttl_seconds",
        "checkpoint_min_risk_tier",
        mode="before",
    )
    @classmethod
    def _reject_boolean_ttl(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("reservation_ttl_seconds must be an integer")
        return value

    @field_validator("allowed_tool_scopes", "checkpoint_tool_scopes")
    @classmethod
    def _validate_scope_order(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name=info.field_name)
        unknown = sorted(set(result) - _TOOL_SCOPES)
        if unknown:
            raise ValueError(f"unknown tool scopes: {', '.join(unknown)}")
        return result

    @field_validator("remediation_path_scopes")
    @classmethod
    def _validate_remediation_path_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("remediation_path_scopes must be sorted, unique, and non-empty")
        return tuple(canonical_relative_path(item, allow_root=True) for item in value)

    @field_validator("trusted_review_attesters")
    @classmethod
    def _validate_review_attesters(
        cls,
        value: tuple[ReviewAttesterTrust, ...],
    ) -> tuple[ReviewAttesterTrust, ...]:
        identities = tuple((item.attester_id, item.public_key) for item in value)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("trusted_review_attesters must be sorted and unique")
        if len({item.attester_id for item in value}) != len(value):
            raise ValueError("trusted_review_attesters must use unique attester ids")
        return value

    @model_validator(mode="after")
    def _validate_security_invariants(self) -> Self:
        allowed = set(self.allowed_tool_scopes)
        checkpointed = set(self.checkpoint_tool_scopes)
        missing_privileged = sorted((allowed & _PRIVILEGED_SCOPES) - checkpointed)
        if missing_privileged:
            raise ValueError(
                "privileged tool scopes must require a checkpoint: " + ", ".join(missing_privileged)
            )
        if not checkpointed <= allowed:
            raise ValueError("checkpoint_tool_scopes must be allowed tool scopes")
        if "read" not in allowed:
            raise ValueError("allowed_tool_scopes must include read for independent review")
        for role_policy in self.tool_governance.role_policies:
            if not set(role_policy.allowed_scopes) <= allowed:
                raise ValueError("role tool policy scopes must be allowed by orchestration policy")
        if self.implementation_route.use_case != "implementation":
            raise ValueError("implementation_route.use_case must be 'implementation'")
        if self.review_route.use_case != "independent_review":
            raise ValueError("review_route.use_case must be 'independent_review'")
        if self.limits.max_review_rounds > 1:
            implementation_tools = self.tool_governance.for_role("implementation")
            if "workspace_write" not in allowed:
                raise ValueError("bounded remediation requires workspace_write tool scope")
            if (
                "workspace_write" not in implementation_tools.allowed_scopes
                or ToolAction.WRITE not in implementation_tools.allowed_actions
            ):
                raise ValueError("bounded remediation requires implementation write authority")
        return self

    def canonical_bytes(self) -> bytes:
        """Return stable canonical JSON bytes for policy binding."""

        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        """Return the policy's canonical SHA-256 digest."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def weakening_reasons(self, parent: OrchestrationPolicy) -> list[str]:
        """Return every way this project policy is weaker than *parent*."""

        reasons: list[str] = []
        for field in (
            "organization_id",
            "team_id",
            "user_id",
            "environment",
            "execution_approver_role",
            "release_approver_role",
        ):
            if getattr(self, field) != getattr(parent, field):
                reasons.append(f"policy.{field}_changed")
        if not set(self.allowed_tool_scopes) <= set(parent.allowed_tool_scopes):
            reasons.append("policy.allowed_tool_scopes_expanded")
        retained_parent_checkpoints = set(parent.checkpoint_tool_scopes) & set(
            self.allowed_tool_scopes
        )
        if not set(self.checkpoint_tool_scopes) >= retained_parent_checkpoints:
            reasons.append("policy.checkpoint_tool_scopes_removed")
        if self.checkpoint_min_risk_tier > parent.checkpoint_min_risk_tier:
            reasons.append("policy.checkpoint_risk_threshold_increased")
        if self.reservation_ttl_seconds > parent.reservation_ttl_seconds:
            reasons.append("policy.reservation_ttl_increased")
        if self.review_attestation_ttl_seconds > parent.review_attestation_ttl_seconds:
            reasons.append("policy.review_attestation_ttl_increased")
        if any(
            not any(
                path_is_within_scope(scope, parent_scope)
                for parent_scope in parent.remediation_path_scopes
            )
            for scope in self.remediation_path_scopes
        ):
            reasons.append("policy.remediation_path_scopes_expanded")
        if not set(self.trusted_review_attesters) <= set(parent.trusted_review_attesters):
            reasons.append("policy.trusted_review_attesters_expanded")
        reasons.extend(self.limits.weakening_reasons(parent.limits))
        reasons.extend(self.tool_governance.weakening_reasons(parent.tool_governance))
        reasons.extend(
            self.implementation_route.weakening_reasons(
                parent.implementation_route,
                prefix="implementation_route",
            )
        )
        reasons.extend(
            self.review_route.weakening_reasons(
                parent.review_route,
                prefix="review_route",
            )
        )
        return sorted(set(reasons))

    def assert_narrows(self, parent: OrchestrationPolicy) -> None:
        """Reject this policy unless it only narrows the enterprise policy."""

        if not isinstance(parent, OrchestrationPolicy):
            raise OrchestrationError("parent must be an OrchestrationPolicy")
        reasons = self.weakening_reasons(parent)
        if reasons:
            raise PolicyWeakeningError(reasons)


class ModelRegistryRecord(OrchestrationModel):
    """Complete enabled model-deployment fact selected from the central registry."""

    provider: str = Field(min_length=1)
    provider_family: str = Field(min_length=1)
    model: str = Field(min_length=1)
    version: str = Field(min_length=1)
    deployment: str = Field(min_length=1)
    model_tier: ModelTier
    max_context_tokens: int = Field(gt=0)
    capabilities: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_risk_levels: tuple[str, ...] = Field(min_length=1)
    allowed_use_cases: tuple[str, ...] = Field(min_length=1)
    enabled: Literal[True] = True

    @field_validator("max_context_tokens", "model_tier", mode="before")
    @classmethod
    def _reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("model registry integer values must be integers")
        return value

    @field_validator(
        "capabilities",
        "allowed_tools",
        "allowed_risk_levels",
        "allowed_use_cases",
    )
    @classmethod
    def _validate_ordered_sets(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return _sorted_unique(value, field_name=info.field_name)

    @property
    def identity(self) -> ModelIdentity:
        return ModelIdentity(
            provider=self.provider,
            provider_family=self.provider_family,
            model=self.model,
            version=self.version,
            deployment=self.deployment,
        )

    @property
    def record(self) -> RegisteredModel:
        return RegisteredModel(
            identity=self.identity,
            capabilities=ModelCapabilities(
                tier=self.model_tier,
                max_context_tokens=self.max_context_tokens,
                capabilities=frozenset(self.capabilities),
                allowed_tools=frozenset(self.allowed_tools),
                allowed_risk_levels=frozenset(self.allowed_risk_levels),
                allowed_use_cases=frozenset(self.allowed_use_cases),
            ),
            enabled=True,
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()

    @classmethod
    def from_registered(cls, model: RegisteredModel) -> ModelRegistryRecord:
        if not isinstance(model, RegisteredModel) or not model.enabled:
            raise PlanningError("selected model must be registered and enabled")
        identity = model.identity
        capabilities = model.capabilities
        return cls(
            provider=identity.provider,
            provider_family=identity.provider_family,
            model=identity.model,
            version=identity.version,
            deployment=identity.deployment,
            model_tier=capabilities.tier,
            max_context_tokens=capabilities.max_context_tokens,
            capabilities=tuple(sorted(capabilities.capabilities)),
            allowed_tools=tuple(sorted(capabilities.allowed_tools)),
            allowed_risk_levels=tuple(sorted(capabilities.allowed_risk_levels)),
            allowed_use_cases=tuple(sorted(capabilities.allowed_use_cases)),
        )


class ModelRouteRecord(OrchestrationModel):
    """Immutable projection of the router decision and its evidence."""

    provider: str = Field(min_length=1)
    provider_family: str = Field(min_length=1)
    model: str = Field(min_length=1)
    version: str = Field(min_length=1)
    deployment: str = Field(min_length=1)
    model_tier: ModelTier
    benchmark_id: str = Field(min_length=1)
    benchmark_quality: Decimal = Field(ge=0, le=1)
    benchmark_latency_ms: Decimal = Field(ge=0)
    benchmark_measured_at: datetime
    benchmark_valid_until: datetime | None
    benchmark_provenance: str = Field(min_length=1)
    benchmark_sample_size: int = Field(gt=0)
    price_effective_from: datetime
    price_effective_to: datetime | None
    price_provenance: str = Field(min_length=1)
    price_input_per_million: Decimal = Field(ge=0)
    price_output_per_million: Decimal = Field(ge=0)
    price_cached_input_per_million: Decimal | None = Field(default=None, ge=0)
    price_reasoning_per_million: Decimal | None = Field(default=None, ge=0)
    price_record_digest: str
    estimated_cost_usd: Decimal = Field(ge=0)
    qualifying_models: int = Field(gt=0)
    registry_record: ModelRegistryRecord

    @field_validator("model_tier", "benchmark_sample_size", "qualifying_models", mode="before")
    @classmethod
    def _reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("model route integer values must be integers")
        return value

    @field_validator(
        "benchmark_measured_at",
        "benchmark_valid_until",
        "price_effective_from",
        "price_effective_to",
    )
    @classmethod
    def _validate_timestamps(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name=info.field_name)

    @field_validator(
        "benchmark_quality",
        "benchmark_latency_ms",
        "price_input_per_million",
        "price_output_per_million",
        "price_cached_input_per_million",
        "price_reasoning_per_million",
        "estimated_cost_usd",
    )
    @classmethod
    def _validate_decimal_fields(cls, value: Decimal | None, info: Any) -> Decimal | None:
        if value is None:
            return None
        return _finite_nonnegative(value, field_name=info.field_name)

    @field_validator("price_record_digest")
    @classmethod
    def _validate_price_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("price_record_digest must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def _validate_evidence_windows(self) -> Self:
        if (
            self.benchmark_valid_until is not None
            and self.benchmark_valid_until <= self.benchmark_measured_at
        ):
            raise ValueError("benchmark_valid_until must follow benchmark_measured_at")
        if (
            self.price_effective_to is not None
            and self.price_effective_to <= self.price_effective_from
        ):
            raise ValueError("price_effective_to must follow price_effective_from")
        expected_price_digest = model_price_record_digest(self.price_record)
        if self.price_record_digest != expected_price_digest:
            raise ValueError(
                "price_record_digest does not match the selected effective price facts"
            )
        if self.registry_record.identity != self.identity:
            raise ValueError("registry_record identity does not match the selected route")
        if self.registry_record.model_tier is not self.model_tier:
            raise ValueError("registry_record tier does not match the selected route")
        return self

    @property
    def identity(self) -> ModelIdentity:
        """Reconstruct the exact immutable model identity."""

        return ModelIdentity(
            provider=self.provider,
            provider_family=self.provider_family,
            model=self.model,
            version=self.version,
            deployment=self.deployment,
        )

    @property
    def price_record(self) -> ModelPrice:
        """Reconstruct the exact price selected by the independently trusted planner."""

        return ModelPrice(
            identity=self.identity,
            effective_from=self.price_effective_from,
            effective_to=self.price_effective_to,
            input_per_million=self.price_input_per_million,
            output_per_million=self.price_output_per_million,
            cached_input_per_million=self.price_cached_input_per_million,
            reasoning_per_million=self.price_reasoning_per_million,
            provenance=self.price_provenance,
        )

    def canonical_bytes(self) -> bytes:
        """Return deterministic route-decision bytes for assignment binding."""

        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        """Return the route-decision SHA-256 digest."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_decision(cls, decision: RoutingDecision) -> ModelRouteRecord:
        """Project a fully priced routing decision into the manifest schema."""

        if decision.price is None or decision.estimated_cost_usd is None:
            raise PlanningError("routing decision lacks the price required for reservation")
        benchmark = decision.benchmark
        identity = decision.model.identity
        return cls(
            provider=identity.provider,
            provider_family=identity.provider_family,
            model=identity.model,
            version=identity.version,
            deployment=identity.deployment,
            model_tier=decision.model.capabilities.tier,
            benchmark_id=benchmark.benchmark_id,
            benchmark_quality=benchmark.quality_score,
            benchmark_latency_ms=benchmark.latency_ms,
            benchmark_measured_at=benchmark.measured_at,
            benchmark_valid_until=benchmark.valid_until,
            benchmark_provenance=benchmark.provenance,
            benchmark_sample_size=benchmark.sample_size,
            price_effective_from=decision.price.effective_from,
            price_effective_to=decision.price.effective_to,
            price_provenance=decision.price.provenance,
            price_input_per_million=decision.price.input_per_million,
            price_output_per_million=decision.price.output_per_million,
            price_cached_input_per_million=decision.price.cached_input_per_million,
            price_reasoning_per_million=decision.price.reasoning_per_million,
            price_record_digest=model_price_record_digest(decision.price),
            estimated_cost_usd=decision.estimated_cost_usd,
            qualifying_models=decision.qualifying_models,
            registry_record=ModelRegistryRecord.from_registered(decision.model),
        )


class PromptRouteRecord(OrchestrationModel):
    """Exact enabled prompt version selected from the central prompt registry."""

    prompt_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    digest: str
    provenance: str = Field(min_length=1)

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("prompt digest must be a lowercase SHA-256 digest")
        return value

    @property
    def identity(self) -> PromptIdentity:
        """Reconstruct the immutable usage-ledger prompt identity."""

        return PromptIdentity(
            prompt_id=self.prompt_id,
            version=self.version,
            digest=self.digest,
        )

    @property
    def record(self) -> RegisteredPrompt:
        """Reconstruct the enabled registry fact required by execution."""

        return RegisteredPrompt(
            identity=self.identity,
            provenance=self.provenance,
            enabled=True,
        )

    def canonical_bytes(self) -> bytes:
        """Return deterministic prompt-binding bytes."""

        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def record_digest(self) -> str:
        """Return a digest over the exact prompt identity and provenance."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_registered(cls, prompt: RegisteredPrompt) -> PromptRouteRecord:
        """Project an enabled central-registry prompt into a manifest."""

        if not isinstance(prompt, RegisteredPrompt) or not prompt.enabled:
            raise PlanningError("selected prompt must be registered and enabled")
        return cls(
            prompt_id=prompt.identity.prompt_id,
            version=prompt.identity.version,
            digest=prompt.identity.digest,
            provenance=prompt.provenance,
        )


class LedgerAttribution(OrchestrationModel):
    """Wire representation of required usage-ledger attribution."""

    organization_id: str = Field(min_length=1)
    team_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    repository: str = Field(min_length=1)
    change_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)

    def to_usage_attribution(self) -> UsageAttribution:
        """Convert to the durable usage-ledger primitive."""

        return UsageAttribution(**self.model_dump())


class ReservationPlan(OrchestrationModel):
    """A pre-execution cost reservation ready for an external ledger host."""

    schema_version: Literal["agt.usage-reservation-plan/v1"] = RESERVATION_SCHEMA_VERSION
    reservation_id: str = Field(min_length=1)
    attribution: LedgerAttribution
    amount_usd: Decimal = Field(ge=0)
    reserved_at: datetime
    expires_at: datetime

    @field_validator("amount_usd")
    @classmethod
    def _validate_amount(cls, value: Decimal) -> Decimal:
        return _finite_nonnegative(value, field_name="amount_usd")

    @field_validator("reservation_id")
    @classmethod
    def _validate_reservation_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("reservation_id contains unsupported characters")
        return value

    @field_validator("reserved_at", "expires_at")
    @classmethod
    def _validate_time(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _validate_window(self) -> Self:
        if self.expires_at <= self.reserved_at:
            raise ValueError("reservation expires_at must follow reserved_at")
        return self

    def to_request(self) -> ReservationRequest:
        """Build the immutable request accepted by :class:`UsageLedger`."""

        return ReservationRequest(
            reservation_id=self.reservation_id,
            attribution=self.attribution.to_usage_attribution(),
            amount_usd=self.amount_usd,
            reserved_at=self.reserved_at,
            expires_at=self.expires_at,
        )


class AssignmentRole(str, Enum):
    """Execution role encoded in a work assignment."""

    IMPLEMENTATION = "implementation"
    INDEPENDENT_REVIEW = "independent_review"
    REMEDIATION = "remediation"


class WorkAssignment(OrchestrationModel):
    """One isolated, bounded unit that an external agent host may execute."""

    assignment_id: str = Field(min_length=1)
    role: AssignmentRole
    contract_task_ids: tuple[str, ...] = Field(min_length=1)
    depends_on_assignment_ids: tuple[str, ...] = ()
    schedule_index: int = Field(ge=0)
    dependency_wave_index: int = Field(ge=0)
    context_id: str = Field(min_length=1)
    workspace_key: str = Field(min_length=1)
    fresh_context: Literal[True] = True
    isolated_workspace: Literal[True] = True
    tool_scopes: tuple[str, ...]
    risk_tier: int = Field(ge=0, le=4)
    max_turns: int = Field(gt=0)
    max_tool_calls: int = Field(ge=0)
    max_cost_usd: Decimal = Field(ge=0)
    prompt: PromptRouteRecord
    route: ModelRouteRecord
    reservation: ReservationPlan
    checkpoint_ids: tuple[str, ...] = ()
    remediation_path_scopes: tuple[str, ...] = ()

    @field_validator("assignment_id", "context_id", "workspace_key")
    @classmethod
    def _validate_safe_ids(cls, value: str, info: Any) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator(
        "schedule_index",
        "dependency_wave_index",
        "max_turns",
        "max_tool_calls",
        "risk_tier",
        mode="before",
    )
    @classmethod
    def _reject_boolean_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("assignment limits and indexes must be integers")
        return value

    @field_validator(
        "contract_task_ids",
        "depends_on_assignment_ids",
        "tool_scopes",
        "checkpoint_ids",
    )
    @classmethod
    def _validate_ordered_sets(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return _sorted_unique(value, field_name=info.field_name)

    @field_validator("remediation_path_scopes")
    @classmethod
    def _remediation_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("remediation_path_scopes must be sorted and unique")
        return tuple(canonical_relative_path(item, allow_root=True) for item in value)

    @field_validator("tool_scopes")
    @classmethod
    def _validate_tool_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - _TOOL_SCOPES)
        if unknown:
            raise ValueError(f"unknown tool scopes: {', '.join(unknown)}")
        return value

    @field_validator("max_cost_usd")
    @classmethod
    def _validate_max_cost(cls, value: Decimal) -> Decimal:
        return _finite_nonnegative(value, field_name="max_cost_usd")

    @model_validator(mode="after")
    def _validate_binding(self) -> Self:
        if self.role is AssignmentRole.IMPLEMENTATION and len(self.contract_task_ids) != 1:
            raise ValueError("implementation assignments must bind exactly one contract task")
        if self.role is AssignmentRole.INDEPENDENT_REVIEW and self.tool_scopes != ("read",):
            raise ValueError("independent review assignments are read-only")
        if self.role is AssignmentRole.REMEDIATION:
            if self.tool_scopes != ("read", "workspace_write"):
                raise ValueError("remediation assignments have exact read/write workspace scope")
            if not self.remediation_path_scopes:
                raise ValueError("remediation assignments require predeclared path scopes")
        elif self.remediation_path_scopes:
            raise ValueError("only remediation assignments may declare remediation path scopes")
        if self.route.estimated_cost_usd > self.max_cost_usd:
            raise ValueError("route estimated cost exceeds assignment maximum")
        if self.reservation.amount_usd != self.route.estimated_cost_usd:
            raise ValueError("reservation must equal the route estimated cost")
        if self.reservation.attribution.task_id != self.assignment_id:
            raise ValueError("reservation task attribution must equal assignment_id")
        registry = self.route.registry_record
        if f"tier-{self.risk_tier}" not in registry.allowed_risk_levels:
            raise ValueError("route registry record does not allow the assignment risk tier")
        if not set(self.tool_scopes) <= set(registry.allowed_tools):
            raise ValueError("route registry record does not allow the assignment tool scopes")
        return self


class ExecutionWave(OrchestrationModel):
    """A dependency-safe batch bounded by the parallel-agent ceiling."""

    schedule_index: int = Field(ge=0)
    dependency_wave_index: int = Field(ge=0)
    batch_index: int = Field(ge=0)
    assignments: tuple[WorkAssignment, ...] = Field(min_length=1)

    @field_validator("schedule_index", "dependency_wave_index", "batch_index", mode="before")
    @classmethod
    def _reject_boolean_indexes(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("wave indexes must be integers")
        return value

    @model_validator(mode="after")
    def _validate_assignments(self) -> Self:
        if tuple(item.assignment_id for item in self.assignments) != tuple(
            sorted(item.assignment_id for item in self.assignments)
        ):
            raise ValueError("wave assignments must be ordered by assignment_id")
        for assignment in self.assignments:
            if assignment.role is not AssignmentRole.IMPLEMENTATION:
                raise ValueError("execution waves may contain only implementation assignments")
            if assignment.schedule_index != self.schedule_index:
                raise ValueError("assignment schedule_index does not match its wave")
            if assignment.dependency_wave_index != self.dependency_wave_index:
                raise ValueError("assignment dependency_wave_index does not match its wave")
        return self


class ConditionalReviewRound(OrchestrationModel):
    """One predeclared fix and re-review pair after a blocking verdict."""

    round_number: int = Field(ge=2, le=32)
    remediation_assignment: WorkAssignment
    review_assignment: WorkAssignment

    @field_validator("round_number", mode="before")
    @classmethod
    def _round_number(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("round_number must be an integer")
        return value

    @model_validator(mode="after")
    def _validate_round(self) -> Self:
        remediation = self.remediation_assignment
        review = self.review_assignment
        if remediation.role is not AssignmentRole.REMEDIATION:
            raise ValueError("conditional round remediation assignment has the wrong role")
        if review.role is not AssignmentRole.INDEPENDENT_REVIEW:
            raise ValueError("conditional round review assignment has the wrong role")
        if review.depends_on_assignment_ids != (remediation.assignment_id,):
            raise ValueError("conditional re-review must depend on its exact remediation")
        if review.contract_task_ids != remediation.contract_task_ids:
            raise ValueError("conditional fix and re-review must cover the same contract tasks")
        return self


class CheckpointPhase(str, Enum):
    """Point at which human authorization is required."""

    BEFORE_ASSIGNMENT = "before_assignment"
    BEFORE_RELEASE = "before_release"


class HumanCheckpoint(OrchestrationModel):
    """Human authorization requirement; the planner never grants it itself."""

    checkpoint_id: str = Field(min_length=1)
    phase: CheckpointPhase
    assignment_ids: tuple[str, ...] = Field(min_length=1)
    approver_role: str = Field(min_length=1)
    reason_codes: tuple[str, ...] = Field(min_length=1)
    required: Literal[True] = True

    @field_validator("assignment_ids", "reason_codes")
    @classmethod
    def _validate_ordered_sets(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return _sorted_unique(value, field_name=info.field_name)

    @field_validator("checkpoint_id")
    @classmethod
    def _validate_checkpoint_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("checkpoint_id contains unsupported characters")
        return value


class OrchestrationManifest(OrchestrationModel):
    """Canonical, side-effect-free execution and review plan."""

    schema_version: Literal["agt.orchestration-manifest/v1"] = MANIFEST_SCHEMA_VERSION
    manifest_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    planned_at: datetime
    policy_id: str = Field(min_length=1)
    policy_digest: str
    change_id: str = Field(min_length=1)
    change_digest: str
    source_revision: str = Field(min_length=1)
    limits: ExecutionLimits
    tool_governance: ToolGovernancePolicy
    implementation_route: RouteProfile
    review_route: RouteProfile
    allowed_tool_scopes: tuple[str, ...]
    checkpoint_tool_scopes: tuple[str, ...]
    checkpoint_min_risk_tier: int = Field(ge=0, le=3)
    reservation_ttl_seconds: int = Field(gt=0, le=86_400)
    review_attestation_ttl_seconds: int = Field(default=300, gt=0, le=3_600)
    remediation_path_scopes: tuple[str, ...] = (".",)
    trusted_review_attesters: tuple[ReviewAttesterTrust, ...] = Field(min_length=1)
    execution_waves: tuple[ExecutionWave, ...] = Field(min_length=1)
    review_assignment: WorkAssignment
    conditional_review_rounds: tuple[ConditionalReviewRound, ...] = ()
    human_checkpoints: tuple[HumanCheckpoint, ...] = Field(min_length=1)
    total_estimated_cost_usd: Decimal = Field(ge=0)

    @field_validator("run_id")
    @classmethod
    def _validate_run_id(cls, value: str) -> str:
        if not _RUN_ID.fullmatch(value):
            raise ValueError("run_id must match RUN-[A-Za-z0-9._-]+")
        return value

    @field_validator("manifest_id")
    @classmethod
    def _validate_manifest_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("manifest_id contains unsupported characters")
        return value

    @field_validator(
        "checkpoint_min_risk_tier",
        "reservation_ttl_seconds",
        "review_attestation_ttl_seconds",
        mode="before",
    )
    @classmethod
    def _reject_boolean_policy_integers(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("manifest policy limits must be integers")
        return value

    @field_validator("policy_digest", "change_digest")
    @classmethod
    def _validate_digest(cls, value: str, info: Any) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError(f"{info.field_name} must be a lowercase SHA-256 digest")
        return value

    @field_validator("planned_at")
    @classmethod
    def _validate_planned_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="planned_at")

    @field_validator("allowed_tool_scopes", "checkpoint_tool_scopes")
    @classmethod
    def _validate_scopes(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name=info.field_name)
        unknown = sorted(set(result) - _TOOL_SCOPES)
        if unknown:
            raise ValueError(f"unknown tool scopes: {', '.join(unknown)}")
        return result

    @field_validator("remediation_path_scopes")
    @classmethod
    def _validate_remediation_path_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("remediation_path_scopes must be sorted, unique, and non-empty")
        return tuple(canonical_relative_path(item, allow_root=True) for item in value)

    @field_validator("trusted_review_attesters")
    @classmethod
    def _validate_review_attesters(
        cls,
        value: tuple[ReviewAttesterTrust, ...],
    ) -> tuple[ReviewAttesterTrust, ...]:
        identities = tuple((item.attester_id, item.public_key) for item in value)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("trusted_review_attesters must be sorted and unique")
        if len({item.attester_id for item in value}) != len(value):
            raise ValueError("trusted_review_attesters must use unique attester ids")
        return value

    @field_validator("total_estimated_cost_usd")
    @classmethod
    def _validate_total_cost(cls, value: Decimal) -> Decimal:
        return _finite_nonnegative(value, field_name="total_estimated_cost_usd")

    @model_validator(mode="after")
    def _validate_manifest_graph(self) -> Self:
        waves = self.execution_waves
        if tuple(wave.schedule_index for wave in waves) != tuple(range(len(waves))):
            raise ValueError("execution wave schedule indexes must be contiguous")
        wave_keys = tuple((wave.dependency_wave_index, wave.batch_index) for wave in waves)
        if wave_keys != tuple(sorted(wave_keys)):
            raise ValueError("dependency waves and batches must be in canonical order")
        dependency_wave_ids = sorted({wave.dependency_wave_index for wave in waves})
        if dependency_wave_ids != list(range(len(dependency_wave_ids))):
            raise ValueError("dependency wave indexes must be contiguous")
        for dependency_wave_index in dependency_wave_ids:
            batches = [
                wave.batch_index
                for wave in waves
                if wave.dependency_wave_index == dependency_wave_index
            ]
            if batches != list(range(len(batches))):
                raise ValueError("batch indexes must be contiguous within a dependency wave")
        for wave in waves:
            if len(wave.assignments) > self.limits.max_parallel_agents:
                raise ValueError("execution wave exceeds max_parallel_agents")

        implementations = tuple(assignment for wave in waves for assignment in wave.assignments)
        if self.review_assignment.role is not AssignmentRole.INDEPENDENT_REVIEW:
            raise ValueError("review_assignment must have the independent_review role")
        if self.review_assignment.schedule_index != len(waves):
            raise ValueError("review assignment must follow all execution waves")
        if self.review_assignment.dependency_wave_index != max(dependency_wave_ids) + 1:
            raise ValueError("review assignment must follow the final dependency wave")

        if len(self.conditional_review_rounds) != self.limits.max_review_rounds - 1:
            raise ValueError("manifest must predeclare every allowed conditional review round")
        expected_round_numbers = tuple(range(2, self.limits.max_review_rounds + 1))
        if (
            tuple(item.round_number for item in self.conditional_review_rounds)
            != expected_round_numbers
        ):
            raise ValueError("conditional review rounds must be contiguous and canonically ordered")
        prior_review = self.review_assignment
        task_ids_expected = tuple(
            sorted(task_id for item in implementations for task_id in item.contract_task_ids)
        )
        for offset, conditional in enumerate(self.conditional_review_rounds):
            remediation = conditional.remediation_assignment
            rereview = conditional.review_assignment
            expected_fix_schedule = len(waves) + offset * 2 + 1
            expected_review_schedule = expected_fix_schedule + 1
            if remediation.schedule_index != expected_fix_schedule:
                raise ValueError("conditional remediation schedule_index is not canonical")
            if rereview.schedule_index != expected_review_schedule:
                raise ValueError("conditional review schedule_index is not canonical")
            if (
                remediation.dependency_wave_index != prior_review.dependency_wave_index + 1
                or rereview.dependency_wave_index != remediation.dependency_wave_index + 1
            ):
                raise ValueError("conditional dependency wave indexes are not canonical")
            if remediation.depends_on_assignment_ids != (prior_review.assignment_id,):
                raise ValueError("remediation must depend on the immediately prior review")
            if remediation.contract_task_ids != task_ids_expected:
                raise ValueError("remediation must be scoped to every contract task")
            if remediation.remediation_path_scopes != self.remediation_path_scopes:
                raise ValueError("remediation paths must exactly match the manifest policy")
            prior_review = rereview

        assignment_ids = [item.assignment_id for item in implementations]
        conditional_assignments = tuple(
            assignment
            for item in self.conditional_review_rounds
            for assignment in (item.remediation_assignment, item.review_assignment)
        )
        all_assignments = (*implementations, self.review_assignment, *conditional_assignments)
        if len(set(assignment_ids)) != len(assignment_ids):
            raise ValueError("implementation assignment ids must be unique")
        if len({item.assignment_id for item in all_assignments}) != len(all_assignments):
            raise ValueError("every planned assignment id must be unique")
        if self.review_assignment.depends_on_assignment_ids != tuple(sorted(assignment_ids)):
            raise ValueError("review assignment must depend on every implementation assignment")

        task_ids = [task_id for item in implementations for task_id in item.contract_task_ids]
        if len(set(task_ids)) != len(task_ids):
            raise ValueError("each contract task must have exactly one implementation assignment")
        if self.review_assignment.contract_task_ids != tuple(sorted(task_ids)):
            raise ValueError("review assignment must cover every contract task")

        seen_assignments: set[str] = set()
        for wave in waves:
            for assignment in wave.assignments:
                unknown = set(assignment.depends_on_assignment_ids) - seen_assignments
                if unknown:
                    raise ValueError("assignment dependency is not in an earlier execution wave")
            seen_assignments.update(item.assignment_id for item in wave.assignments)

        context_ids = [item.context_id for item in all_assignments]
        workspace_keys = [item.workspace_key for item in all_assignments]
        if len(set(context_ids)) != len(context_ids):
            raise ValueError("every assignment must receive a unique fresh context_id")
        if len(set(workspace_keys)) != len(workspace_keys):
            raise ValueError("every assignment must receive an isolated workspace_key")

        allowed_scopes = set(self.allowed_tool_scopes)
        checkpoint_scopes = set(self.checkpoint_tool_scopes)
        if "read" not in allowed_scopes:
            raise ValueError("manifest must allow read for independent review")
        for role_policy in self.tool_governance.role_policies:
            if not set(role_policy.allowed_scopes) <= allowed_scopes:
                raise ValueError("manifest role tool scopes must be globally allowed")
        if not checkpoint_scopes <= allowed_scopes:
            raise ValueError("manifest checkpoint scopes must be allowed")
        missing_privileged = (allowed_scopes & _PRIVILEGED_SCOPES) - checkpoint_scopes
        if missing_privileged:
            raise ValueError("manifest privileged tool scopes must require checkpoints")
        checkpoints_by_id = {item.checkpoint_id: item for item in self.human_checkpoints}
        if len(checkpoints_by_id) != len(self.human_checkpoints):
            raise ValueError("human checkpoint ids must be unique")
        if tuple(item.checkpoint_id for item in self.human_checkpoints) != tuple(
            sorted(checkpoints_by_id)
        ):
            raise ValueError("human checkpoints must be ordered by checkpoint_id")
        known_assignment_ids = {item.assignment_id for item in all_assignments}
        for checkpoint in self.human_checkpoints:
            if not set(checkpoint.assignment_ids) <= known_assignment_ids:
                raise ValueError("human checkpoint references an unknown assignment")

        referenced_assignment_checkpoints: set[str] = set()
        checkpointed_assignments = (
            *implementations,
            *(item.remediation_assignment for item in self.conditional_review_rounds),
        )
        for assignment in checkpointed_assignments:
            if not set(assignment.tool_scopes) <= allowed_scopes:
                raise ValueError("assignment requests a tool scope not allowed by policy")
            expected_reasons = tuple(
                sorted(
                    (
                        [f"risk_tier:{assignment.risk_tier}"]
                        if assignment.risk_tier >= self.checkpoint_min_risk_tier
                        else []
                    )
                    + [
                        f"tool_scope:{scope}"
                        for scope in assignment.tool_scopes
                        if scope in checkpoint_scopes
                    ]
                )
            )
            needs_checkpoint = bool(expected_reasons)
            unknown_checkpoint_ids = set(assignment.checkpoint_ids) - set(checkpoints_by_id)
            if unknown_checkpoint_ids:
                raise ValueError("assignment references an unknown human checkpoint")
            bound = [checkpoints_by_id[item] for item in assignment.checkpoint_ids]
            referenced_assignment_checkpoints.update(assignment.checkpoint_ids)
            if needs_checkpoint and len(bound) != 1:
                raise ValueError("risk or privileged tool scope requires one human checkpoint")
            if not needs_checkpoint and bound:
                raise ValueError("assignment has a checkpoint without a policy reason")
            if any(
                item.phase is not CheckpointPhase.BEFORE_ASSIGNMENT
                or item.assignment_ids != (assignment.assignment_id,)
                or item.reason_codes != expected_reasons
                for item in bound
            ):
                raise ValueError(
                    "assignment checkpoints must exactly authorize its risk and tool scopes"
                )

        release = [
            item for item in self.human_checkpoints if item.phase is CheckpointPhase.BEFORE_RELEASE
        ]
        if (
            len(release) != 1
            or release[0].assignment_ids
            != tuple(
                item.assignment_id
                for item in (
                    self.review_assignment,
                    *(
                        round_plan.review_assignment
                        for round_plan in self.conditional_review_rounds
                    ),
                )
            )
            or release[0].reason_codes != ("release_approval",)
            or self.review_assignment.checkpoint_ids
        ):
            raise ValueError("exactly one final human release checkpoint is required")
        before_assignment_ids = {
            item.checkpoint_id
            for item in self.human_checkpoints
            if item.phase is CheckpointPhase.BEFORE_ASSIGNMENT
        }
        if before_assignment_ids != referenced_assignment_checkpoints:
            raise ValueError("before-assignment checkpoints must be referenced exactly once")

        implementation_families = {
            item.route.provider_family
            for item in (
                *implementations,
                *(
                    round_plan.remediation_assignment
                    for round_plan in self.conditional_review_rounds
                ),
            )
        }
        if self.review_assignment.route.provider_family in implementation_families:
            raise ValueError("review provider family must be independent of implementation")
        if any(
            item.review_assignment.route.provider_family in implementation_families
            for item in self.conditional_review_rounds
        ):
            raise ValueError("every re-review provider family must be independent")

        expected_total = sum(
            (item.route.estimated_cost_usd for item in all_assignments),
            Decimal("0"),
        )
        if self.total_estimated_cost_usd != expected_total:
            raise ValueError("total_estimated_cost_usd does not match assignment routes")
        if self.total_estimated_cost_usd > self.limits.max_total_cost_usd:
            raise ValueError("total estimated cost exceeds the manifest limit")
        reservation_ids = [item.reservation.reservation_id for item in all_assignments]
        if len(set(reservation_ids)) != len(reservation_ids):
            raise ValueError("every assignment must have a unique reservation_id")
        for assignment in all_assignments:
            if not set(assignment.tool_scopes) <= allowed_scopes:
                raise ValueError("assignment requests a tool scope not allowed by policy")
            if assignment.max_turns != self.limits.max_turns_per_assignment:
                raise ValueError("assignment max_turns does not match manifest limits")
            if assignment.max_tool_calls != self.limits.max_tool_calls_per_assignment:
                raise ValueError("assignment max_tool_calls does not match manifest limits")
            if assignment.max_cost_usd != self.limits.max_cost_per_assignment_usd:
                raise ValueError("assignment max_cost_usd does not match manifest limits")
            if assignment.reservation.attribution.change_id != self.change_id:
                raise ValueError("reservation change attribution does not match manifest")
            if assignment.reservation.reserved_at != self.planned_at:
                raise ValueError("reservation time does not match manifest planned_at")
            if assignment.reservation.expires_at != self.planned_at + timedelta(
                seconds=self.reservation_ttl_seconds
            ):
                raise ValueError("reservation expiry does not match manifest policy")
            route = assignment.route
            profile = (
                self.review_route
                if assignment.role is AssignmentRole.INDEPENDENT_REVIEW
                else self.implementation_route
            )
            registry = route.registry_record
            if profile.use_case not in registry.allowed_use_cases:
                raise ValueError("route registry record does not allow the protected use case")
            if not set(profile.required_capabilities) <= set(registry.capabilities):
                raise ValueError("route registry record lacks a protected required capability")
            if profile.context_tokens > registry.max_context_tokens:
                raise ValueError("route registry context capacity is below the protected request")
            if route.model_tier > profile.max_tier:
                raise ValueError("route model tier exceeds the protected route maximum")
            if route.benchmark_quality < profile.min_quality:
                raise ValueError("routing benchmark quality is below the protected minimum")
            if (
                profile.max_latency_ms is not None
                and route.benchmark_latency_ms > profile.max_latency_ms
            ):
                raise ValueError("routing benchmark latency exceeds the protected maximum")
            if self.planned_at - route.benchmark_measured_at > timedelta(
                seconds=profile.max_benchmark_age_seconds
            ):
                raise ValueError("routing benchmark exceeds the protected maximum age")
            expected_estimated_cost = route.price_record.calculate(
                profile.estimated_usage.to_usage()
            )
            if route.estimated_cost_usd != expected_estimated_cost:
                raise ValueError(
                    "route estimated_cost_usd does not match protected usage and price"
                )
            if route.benchmark_measured_at > self.planned_at:
                raise ValueError("routing benchmark was not available at planning time")
            if (
                route.benchmark_valid_until is not None
                and self.planned_at >= route.benchmark_valid_until
            ):
                raise ValueError("routing benchmark was expired at planning time")
            if route.price_effective_from > self.planned_at:
                raise ValueError("routing price was not effective at planning time")
            if route.price_effective_to is not None and self.planned_at >= route.price_effective_to:
                raise ValueError("routing price was expired at planning time")
        return self

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 JSON used for persistence and signing."""

        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        """Return the canonical manifest SHA-256 digest."""

        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def reservation_requests(self) -> tuple[ReservationRequest, ...]:
        """Return deterministic ledger requests without writing them."""

        assignments = [
            assignment for wave in self.execution_waves for assignment in wave.assignments
        ]
        assignments.append(self.review_assignment)
        assignments.extend(
            assignment
            for item in self.conditional_review_rounds
            for assignment in (item.remediation_assignment, item.review_assignment)
        )
        return tuple(item.reservation.to_request() for item in assignments)


class OrchestrationPlanner:
    """Create canonical execution manifests from change and control-plane facts."""

    def __init__(
        self,
        *,
        router: ModelRouter,
        prompt_registry: PromptRegistry,
        implementation_prompt: PromptIdentity,
        review_prompt: PromptIdentity,
        enterprise_policy: OrchestrationPolicy,
        project_policy: OrchestrationPolicy | None = None,
    ) -> None:
        if not isinstance(router, ModelRouter):
            raise OrchestrationError("router must be a ModelRouter")
        if not isinstance(enterprise_policy, OrchestrationPolicy):
            raise OrchestrationError("enterprise_policy must be an OrchestrationPolicy")
        if not isinstance(prompt_registry, PromptRegistry):
            raise OrchestrationError("prompt_registry must be a PromptRegistry")
        try:
            OrchestrationPolicy.model_validate(enterprise_policy.model_dump(mode="python"))
        except ValueError as exc:
            raise OrchestrationError("enterprise_policy failed strict revalidation") from exc
        if project_policy is not None:
            if not isinstance(project_policy, OrchestrationPolicy):
                raise OrchestrationError("project_policy must be an OrchestrationPolicy")
            try:
                OrchestrationPolicy.model_validate(project_policy.model_dump(mode="python"))
            except ValueError as exc:
                raise OrchestrationError("project_policy failed strict revalidation") from exc
            project_policy.assert_narrows(enterprise_policy)
        self._router = router
        self._policy = project_policy or enterprise_policy
        self._implementation_prompt = self._select_prompt(
            prompt_registry,
            implementation_prompt,
            role="implementation",
        )
        self._review_prompt = self._select_prompt(
            prompt_registry,
            review_prompt,
            role="independent review",
        )

    @staticmethod
    def _select_prompt(
        registry: PromptRegistry,
        identity: PromptIdentity,
        *,
        role: str,
    ) -> PromptRouteRecord:
        if not isinstance(identity, PromptIdentity):
            raise OrchestrationError(f"{role} prompt must be a PromptIdentity")
        selected = registry.get(identity)
        if selected is None:
            raise PlanningError(f"{role} prompt is not registered")
        if not selected.enabled:
            raise PlanningError(f"{role} prompt is disabled")
        try:
            return PromptRouteRecord.from_registered(selected)
        except ValueError as exc:
            raise PlanningError(f"{role} prompt failed strict validation") from exc

    @property
    def policy(self) -> OrchestrationPolicy:
        """Return the effective immutable policy."""

        return self._policy

    def plan(
        self,
        change: ChangePackage,
        *,
        run_id: str,
        planned_at: datetime,
    ) -> OrchestrationManifest:
        """Plan bounded work and independent review without performing side effects."""

        if not isinstance(change, ChangePackage):
            raise PlanningError("change must be a ChangePackage")
        try:
            ChangePackage.model_validate(change.model_dump(mode="python"))
        except ValueError as exc:
            raise PlanningError("change failed strict structural revalidation") from exc
        if not _RUN_ID.fullmatch(run_id):
            raise PlanningError("run_id must match RUN-[A-Za-z0-9._-]+")
        when = _utc(planned_at, field_name="planned_at")
        if when < change.updated_at:
            raise PlanningError("planned_at must not precede the change's updated_at")
        issues = change.contract_issues()
        if issues:
            summary = ", ".join(f"{item.code}@{item.location}" for item in issues)
            raise PlanningError(f"change contract is not ready for execution: {summary}")

        task_by_id = {task.task_id: task for task in change.tasks}
        assignment_by_task: dict[str, WorkAssignment] = {}
        execution_waves: list[ExecutionWave] = []
        implementation_identities: list[ModelIdentity] = []
        schedule_index = 0

        for dependency_wave_index, task_ids in enumerate(change.dependency_waves()):
            maximum = self._policy.limits.max_parallel_agents
            for batch_index, start in enumerate(range(0, len(task_ids), maximum)):
                batch = task_ids[start : start + maximum]
                assignments: list[WorkAssignment] = []
                for task_id in batch:
                    task = task_by_id[task_id]
                    assignment = self._plan_task(
                        change=change,
                        task=task,
                        run_id=run_id,
                        planned_at=when,
                        schedule_index=schedule_index,
                        dependency_wave_index=dependency_wave_index,
                    )
                    assignment_by_task[task_id] = assignment
                    assignments.append(assignment)
                    implementation_identities.append(assignment.route.identity)
                execution_waves.append(
                    ExecutionWave(
                        schedule_index=schedule_index,
                        dependency_wave_index=dependency_wave_index,
                        batch_index=batch_index,
                        assignments=tuple(sorted(assignments, key=lambda item: item.assignment_id)),
                    )
                )
                schedule_index += 1

        implementation_families = {item.provider_family for item in implementation_identities}
        if len(implementation_families) != 1:
            raise PlanningError(
                "whole-change independent review requires one implementation provider family"
            )
        implementation_family = next(iter(implementation_families))
        if (
            change.implementation_model_family is not None
            and change.implementation_model_family != implementation_family
        ):
            raise PlanningError(
                "routed implementation provider family does not match the change contract"
            )

        review = self._plan_review(
            change=change,
            run_id=run_id,
            planned_at=when,
            schedule_index=schedule_index,
            implementation_identity=implementation_identities[0],
            implementation_assignments=assignment_by_task,
        )
        if review.route.provider_family == implementation_family:
            raise PlanningError("independent review routed to the implementation provider family")

        conditional_review_rounds = self._plan_conditional_review_rounds(
            change=change,
            run_id=run_id,
            planned_at=when,
            first_schedule_index=schedule_index + 1,
            implementation_identity=implementation_identities[0],
            prior_review=review,
            implementation_assignments=assignment_by_task,
        )
        checkpoints = self._checkpoints(
            change=change,
            run_id=run_id,
            assignments=assignment_by_task,
            review=review,
            conditional_review_rounds=conditional_review_rounds,
        )
        all_assignments = [
            *assignment_by_task.values(),
            review,
            *(
                assignment
                for item in conditional_review_rounds
                for assignment in (item.remediation_assignment, item.review_assignment)
            ),
        ]
        total_cost = sum(
            (item.route.estimated_cost_usd for item in all_assignments),
            Decimal("0"),
        )
        if total_cost > self._policy.limits.max_total_cost_usd:
            raise PlanningError(
                f"planned cost {total_cost} exceeds total limit "
                f"{self._policy.limits.max_total_cost_usd}"
            )

        execution_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "execution_waves": [item.model_dump(mode="json") for item in execution_waves],
                    "review_assignment": review.model_dump(mode="json"),
                    "conditional_review_rounds": [
                        item.model_dump(mode="json") for item in conditional_review_rounds
                    ],
                    "human_checkpoints": [item.model_dump(mode="json") for item in checkpoints],
                }
            )
        ).hexdigest()
        manifest_seed = _hash_id(
            "MAN",
            change.digest,
            self._policy.digest,
            run_id,
            when.isoformat(),
            execution_digest,
            length=32,
        )
        return OrchestrationManifest(
            manifest_id=manifest_seed,
            run_id=run_id,
            planned_at=when,
            policy_id=self._policy.policy_id,
            policy_digest=self._policy.digest,
            change_id=change.change_id,
            change_digest=change.digest,
            source_revision=change.source_revision,
            limits=self._policy.limits,
            tool_governance=self._policy.tool_governance,
            implementation_route=self._policy.implementation_route,
            review_route=self._policy.review_route,
            allowed_tool_scopes=self._policy.allowed_tool_scopes,
            checkpoint_tool_scopes=self._policy.checkpoint_tool_scopes,
            checkpoint_min_risk_tier=self._policy.checkpoint_min_risk_tier,
            reservation_ttl_seconds=self._policy.reservation_ttl_seconds,
            review_attestation_ttl_seconds=self._policy.review_attestation_ttl_seconds,
            remediation_path_scopes=self._policy.remediation_path_scopes,
            trusted_review_attesters=self._policy.trusted_review_attesters,
            execution_waves=tuple(execution_waves),
            review_assignment=review,
            conditional_review_rounds=conditional_review_rounds,
            human_checkpoints=checkpoints,
            total_estimated_cost_usd=total_cost,
        )

    def _plan_task(
        self,
        *,
        change: ChangePackage,
        task: Task,
        run_id: str,
        planned_at: datetime,
        schedule_index: int,
        dependency_wave_index: int,
    ) -> WorkAssignment:
        invalid_scopes = sorted(set(task.tool_scopes) - set(self._policy.allowed_tool_scopes))
        if invalid_scopes:
            raise PlanningError(
                f"{task.task_id} requests policy-disallowed tool scopes: "
                + ", ".join(invalid_scopes)
            )
        assignment_id = f"impl:{task.task_id}"
        route = self._route(
            profile=self._policy.implementation_route,
            risk_tier=task.risk_tier,
            tool_scopes=task.tool_scopes,
            planned_at=planned_at,
        )
        checkpoint_ids = self._task_checkpoint_ids(
            task=task,
            assignment_id=assignment_id,
            change=change,
            run_id=run_id,
        )
        prompt = self._implementation_prompt
        return WorkAssignment(
            assignment_id=assignment_id,
            role=AssignmentRole.IMPLEMENTATION,
            contract_task_ids=(task.task_id,),
            depends_on_assignment_ids=tuple(
                sorted(f"impl:{dependency}" for dependency in task.depends_on)
            ),
            schedule_index=schedule_index,
            dependency_wave_index=dependency_wave_index,
            context_id=_hash_id(
                "ctx",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
                prompt.record_digest,
            ),
            workspace_key=_hash_id(
                "workspace",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
                prompt.record_digest,
            ),
            tool_scopes=task.tool_scopes,
            risk_tier=task.risk_tier,
            max_turns=self._policy.limits.max_turns_per_assignment,
            max_tool_calls=self._policy.limits.max_tool_calls_per_assignment,
            max_cost_usd=self._policy.limits.max_cost_per_assignment_usd,
            prompt=prompt,
            route=route,
            reservation=self._reservation(
                change=change,
                assignment_id=assignment_id,
                run_id=run_id,
                planned_at=planned_at,
                route=route,
            ),
            checkpoint_ids=checkpoint_ids,
        )

    def _plan_review(
        self,
        *,
        change: ChangePackage,
        run_id: str,
        planned_at: datetime,
        schedule_index: int,
        implementation_identity: ModelIdentity,
        implementation_assignments: dict[str, WorkAssignment],
        round_number: int = 1,
        depends_on_assignment_ids: tuple[str, ...] | None = None,
        dependency_wave_index: int | None = None,
    ) -> WorkAssignment:
        assignment_id = (
            "review:whole-change"
            if round_number == 1
            else f"review:whole-change:round-{round_number}"
        )
        maximum_risk = max(task.risk_tier for task in change.tasks)
        route = self._route(
            profile=self._policy.review_route,
            risk_tier=maximum_risk,
            tool_scopes=("read",),
            planned_at=planned_at,
            independent_review_of=implementation_identity,
        )
        prompt = self._review_prompt
        return WorkAssignment(
            assignment_id=assignment_id,
            role=AssignmentRole.INDEPENDENT_REVIEW,
            contract_task_ids=tuple(sorted(implementation_assignments)),
            depends_on_assignment_ids=(
                tuple(sorted(item.assignment_id for item in implementation_assignments.values()))
                if depends_on_assignment_ids is None
                else depends_on_assignment_ids
            ),
            schedule_index=schedule_index,
            dependency_wave_index=(
                len(change.dependency_waves())
                if dependency_wave_index is None
                else dependency_wave_index
            ),
            context_id=_hash_id(
                "ctx",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
                prompt.record_digest,
            ),
            workspace_key=_hash_id(
                "workspace",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
                prompt.record_digest,
            ),
            tool_scopes=("read",),
            risk_tier=maximum_risk,
            max_turns=self._policy.limits.max_turns_per_assignment,
            max_tool_calls=self._policy.limits.max_tool_calls_per_assignment,
            max_cost_usd=self._policy.limits.max_cost_per_assignment_usd,
            prompt=prompt,
            route=route,
            reservation=self._reservation(
                change=change,
                assignment_id=assignment_id,
                run_id=run_id,
                planned_at=planned_at,
                route=route,
            ),
        )

    def _plan_conditional_review_rounds(
        self,
        *,
        change: ChangePackage,
        run_id: str,
        planned_at: datetime,
        first_schedule_index: int,
        implementation_identity: ModelIdentity,
        prior_review: WorkAssignment,
        implementation_assignments: dict[str, WorkAssignment],
    ) -> tuple[ConditionalReviewRound, ...]:
        """Predeclare every possible scoped fix and fresh whole-change re-review."""

        rounds: list[ConditionalReviewRound] = []
        maximum_risk = max(task.risk_tier for task in change.tasks)
        task_ids = tuple(sorted(implementation_assignments))
        for round_number in range(2, self._policy.limits.max_review_rounds + 1):
            fix_schedule = first_schedule_index + (round_number - 2) * 2
            remediation = self._plan_remediation(
                change=change,
                run_id=run_id,
                planned_at=planned_at,
                schedule_index=fix_schedule,
                round_number=round_number,
                prior_review=prior_review,
                contract_task_ids=task_ids,
                risk_tier=maximum_risk,
            )
            rereview = self._plan_review(
                change=change,
                run_id=run_id,
                planned_at=planned_at,
                schedule_index=fix_schedule + 1,
                implementation_identity=implementation_identity,
                implementation_assignments=implementation_assignments,
                round_number=round_number,
                depends_on_assignment_ids=(remediation.assignment_id,),
                dependency_wave_index=remediation.dependency_wave_index + 1,
            )
            rounds.append(
                ConditionalReviewRound(
                    round_number=round_number,
                    remediation_assignment=remediation,
                    review_assignment=rereview,
                )
            )
            prior_review = rereview
        return tuple(rounds)

    def _plan_remediation(
        self,
        *,
        change: ChangePackage,
        run_id: str,
        planned_at: datetime,
        schedule_index: int,
        round_number: int,
        prior_review: WorkAssignment,
        contract_task_ids: tuple[str, ...],
        risk_tier: int,
    ) -> WorkAssignment:
        assignment_id = f"remediate:round-{round_number}"
        tool_scopes = ("read", "workspace_write")
        route = self._route(
            profile=self._policy.implementation_route,
            risk_tier=risk_tier,
            tool_scopes=tool_scopes,
            planned_at=planned_at,
        )
        prompt = self._implementation_prompt
        reasons = self._checkpoint_reasons(risk_tier=risk_tier, tool_scopes=tool_scopes)
        checkpoint_ids = self._assignment_checkpoint_ids(
            change=change,
            run_id=run_id,
            assignment_id=assignment_id,
            reasons=reasons,
        )
        return WorkAssignment(
            assignment_id=assignment_id,
            role=AssignmentRole.REMEDIATION,
            contract_task_ids=contract_task_ids,
            depends_on_assignment_ids=(prior_review.assignment_id,),
            schedule_index=schedule_index,
            dependency_wave_index=prior_review.dependency_wave_index + 1,
            context_id=_hash_id(
                "ctx",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
                prompt.record_digest,
            ),
            workspace_key=_hash_id(
                "workspace",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
                prompt.record_digest,
            ),
            tool_scopes=tool_scopes,
            risk_tier=risk_tier,
            max_turns=self._policy.limits.max_turns_per_assignment,
            max_tool_calls=self._policy.limits.max_tool_calls_per_assignment,
            max_cost_usd=self._policy.limits.max_cost_per_assignment_usd,
            prompt=prompt,
            route=route,
            reservation=self._reservation(
                change=change,
                assignment_id=assignment_id,
                run_id=run_id,
                planned_at=planned_at,
                route=route,
            ),
            checkpoint_ids=checkpoint_ids,
            remediation_path_scopes=self._policy.remediation_path_scopes,
        )

    def _route(
        self,
        *,
        profile: RouteProfile,
        risk_tier: int,
        tool_scopes: tuple[str, ...],
        planned_at: datetime,
        independent_review_of: ModelIdentity | None = None,
    ) -> ModelRouteRecord:
        try:
            decision = self._router.route(
                RoutingRequest(
                    task_type=profile.task_type,
                    use_case=profile.use_case,
                    risk_level=f"tier-{risk_tier}",
                    context_tokens=profile.context_tokens,
                    estimated_usage=profile.estimated_usage.to_usage(),
                    as_of=planned_at,
                    max_benchmark_age=timedelta(seconds=profile.max_benchmark_age_seconds),
                    max_tier=profile.max_tier,
                    required_capabilities=frozenset(profile.required_capabilities),
                    required_tools=frozenset(tool_scopes),
                    min_quality=profile.min_quality,
                    max_latency_ms=profile.max_latency_ms,
                    max_estimated_cost_usd=self._policy.limits.max_cost_per_assignment_usd,
                    require_known_cost=True,
                    independent_review_of=independent_review_of,
                )
            )
        except RoutingError as exc:
            raise PlanningError(f"no safe model route: {exc}") from exc
        return ModelRouteRecord.from_decision(decision)

    def _reservation(
        self,
        *,
        change: ChangePackage,
        assignment_id: str,
        run_id: str,
        planned_at: datetime,
        route: ModelRouteRecord,
    ) -> ReservationPlan:
        attribution = LedgerAttribution(
            organization_id=self._policy.organization_id,
            team_id=self._policy.team_id,
            application_id=change.application,
            user_id=self._policy.user_id,
            environment=self._policy.environment,
            repository=change.repository,
            change_id=change.change_id,
            task_id=assignment_id,
        )
        return ReservationPlan(
            reservation_id=_hash_id(
                "reservation",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                route.digest,
            ),
            attribution=attribution,
            amount_usd=route.estimated_cost_usd,
            reserved_at=planned_at,
            expires_at=planned_at + timedelta(seconds=self._policy.reservation_ttl_seconds),
        )

    def _task_checkpoint_ids(
        self,
        *,
        task: Task,
        assignment_id: str,
        change: ChangePackage,
        run_id: str,
    ) -> tuple[str, ...]:
        reasons = self._task_checkpoint_reasons(task)
        return self._assignment_checkpoint_ids(
            change=change,
            run_id=run_id,
            assignment_id=assignment_id,
            reasons=reasons,
        )

    def _assignment_checkpoint_ids(
        self,
        *,
        change: ChangePackage,
        run_id: str,
        assignment_id: str,
        reasons: tuple[str, ...],
    ) -> tuple[str, ...]:
        if not reasons:
            return ()
        return (
            _hash_id(
                "checkpoint",
                change.digest,
                self._policy.digest,
                run_id,
                assignment_id,
                *reasons,
            ),
        )

    def _task_checkpoint_reasons(self, task: Task) -> tuple[str, ...]:
        return self._checkpoint_reasons(
            risk_tier=task.risk_tier,
            tool_scopes=task.tool_scopes,
        )

    def _checkpoint_reasons(
        self,
        *,
        risk_tier: int,
        tool_scopes: tuple[str, ...],
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if risk_tier >= self._policy.checkpoint_min_risk_tier:
            reasons.append(f"risk_tier:{risk_tier}")
        reasons.extend(
            f"tool_scope:{scope}"
            for scope in tool_scopes
            if scope in self._policy.checkpoint_tool_scopes
        )
        return tuple(sorted(reasons))

    def _checkpoints(
        self,
        *,
        change: ChangePackage,
        run_id: str,
        assignments: dict[str, WorkAssignment],
        review: WorkAssignment,
        conditional_review_rounds: tuple[ConditionalReviewRound, ...],
    ) -> tuple[HumanCheckpoint, ...]:
        checkpoints: list[HumanCheckpoint] = []
        task_by_id = {item.task_id: item for item in change.tasks}
        for task_id, assignment in sorted(assignments.items()):
            reasons = self._task_checkpoint_reasons(task_by_id[task_id])
            if not reasons:
                continue
            checkpoints.append(
                HumanCheckpoint(
                    checkpoint_id=assignment.checkpoint_ids[0],
                    phase=CheckpointPhase.BEFORE_ASSIGNMENT,
                    assignment_ids=(assignment.assignment_id,),
                    approver_role=self._policy.execution_approver_role,
                    reason_codes=reasons,
                )
            )
        for conditional in conditional_review_rounds:
            remediation = conditional.remediation_assignment
            reasons = self._checkpoint_reasons(
                risk_tier=remediation.risk_tier,
                tool_scopes=remediation.tool_scopes,
            )
            if not reasons:
                continue
            checkpoints.append(
                HumanCheckpoint(
                    checkpoint_id=remediation.checkpoint_ids[0],
                    phase=CheckpointPhase.BEFORE_ASSIGNMENT,
                    assignment_ids=(remediation.assignment_id,),
                    approver_role=self._policy.execution_approver_role,
                    reason_codes=reasons,
                )
            )
        checkpoints.append(
            HumanCheckpoint(
                checkpoint_id=_hash_id(
                    "checkpoint",
                    change.digest,
                    self._policy.digest,
                    run_id,
                    "release",
                ),
                phase=CheckpointPhase.BEFORE_RELEASE,
                assignment_ids=(
                    review.assignment_id,
                    *(item.review_assignment.assignment_id for item in conditional_review_rounds),
                ),
                approver_role=self._policy.release_approver_role,
                reason_codes=("release_approval",),
            )
        )
        return tuple(sorted(checkpoints, key=lambda item: item.checkpoint_id))


__all__ = [
    "AssignmentRole",
    "CheckpointPhase",
    "ConditionalReviewRound",
    "ExecutionLimits",
    "ExecutionWave",
    "HumanCheckpoint",
    "LedgerAttribution",
    "MANIFEST_SCHEMA_VERSION",
    "ModelRouteRecord",
    "ModelRegistryRecord",
    "OrchestrationError",
    "OrchestrationManifest",
    "OrchestrationPlanner",
    "OrchestrationPolicy",
    "POLICY_SCHEMA_VERSION",
    "PlanningError",
    "PolicyWeakeningError",
    "PromptRouteRecord",
    "ReviewAttesterTrust",
    "RESERVATION_SCHEMA_VERSION",
    "RoleToolPolicy",
    "ReservationPlan",
    "RouteProfile",
    "TokenEstimate",
    "ToolAction",
    "ToolGovernancePolicy",
    "WorkAssignment",
    "model_price_record_digest",
]
