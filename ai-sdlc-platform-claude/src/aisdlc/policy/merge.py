"""Narrow-only merge of organization policy and project overrides.

A project may tighten any bound the organization sets and may never loosen one. Every
override leaf is checked against a direction rule; a loosening attempt is recorded as a
:class:`PolicyViolation` and the organization value is kept. Callers decide whether
violations are fatal (``strict=True`` raises :class:`PolicyViolationError`).
"""

from __future__ import annotations

import copy
import re
from collections.abc import Sequence
from enum import StrEnum
from fnmatch import fnmatch
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.policy.org_policy import OrgPolicy, TierBehaviour
from aisdlc.policy.project_config import ProjectConfig
from aisdlc.schema.models import GateDepth, ModelTier

__all__ = [
    "Direction",
    "RULES",
    "PolicyViolation",
    "PolicyViolationError",
    "EffectivePolicy",
    "rule_for",
    "is_tightening",
    "effective_policy",
    "validate_project_against_org",
]


class Direction(StrEnum):
    """Which direction a project override may move a value."""

    DECREASE_ONLY = "decrease_only"  # numbers: project <= org
    INCREASE_ONLY = "increase_only"  # numbers: project >= org
    TRUE_ONLY = "true_only"  # booleans: may only become/stay True
    FALSE_ONLY = "false_only"  # booleans: may only become/stay False
    SUPERSET_ONLY = "superset_only"  # lists: project ⊇ org
    SUBSET_ONLY = "subset_only"  # lists: every project item covered by an org item/pattern
    RANK_UP_ONLY = "rank_up_only"  # ranked enums: stricter/deeper only
    RANK_DOWN_ONLY = "rank_down_only"  # ranked enums: lower only (model tiers)


RULES: dict[str, Direction] = {
    "gates.required_gates.*": Direction.SUPERSET_ONLY,
    "gates.depth.*": Direction.RANK_UP_ONLY,
    "models.allowlist": Direction.SUBSET_ONLY,
    "models.independent_review_requires_different_family": Direction.TRUE_ONLY,
    "models.max_tier_per_role.*": Direction.RANK_DOWN_ONLY,
    "models.escalation_allowed": Direction.FALSE_ONLY,
    "tool_tiers.defaults.*": Direction.RANK_UP_ONLY,
    "tool_tiers.approval_timeout_seconds": Direction.DECREASE_ONLY,
    "tool_tiers.deny_on_timeout": Direction.TRUE_ONLY,
    "tool_tiers.audit_from_tier": Direction.DECREASE_ONLY,
    "cost_limits.budgets.*": Direction.DECREASE_ONLY,
    "cost_limits.max_agent_turns": Direction.DECREASE_ONLY,
    "cost_limits.max_parallel_agents": Direction.DECREASE_ONLY,
    "cost_limits.max_review_rounds": Direction.DECREASE_ONLY,
    "cost_limits.max_tool_calls": Direction.DECREASE_ONLY,
    "cost_limits.context_ceiling_tokens": Direction.DECREASE_ONLY,
    "security_baselines.asr_threshold": Direction.DECREASE_ONLY,
    "security_baselines.max_undetermined_rate": Direction.DECREASE_ONLY,
    "security_baselines.coverage.*": Direction.INCREASE_ONLY,
    "security_baselines.mutation_score": Direction.INCREASE_ONLY,
    "security_baselines.ambiguity_threshold": Direction.DECREASE_ONLY,
    "security_baselines.max_critical_vulns": Direction.DECREASE_ONLY,
    "security_baselines.max_high_vulns": Direction.DECREASE_ONLY,
    "security_baselines.require_sbom": Direction.TRUE_ONLY,
    "security_baselines.require_provenance": Direction.TRUE_ONLY,
    "security_baselines.require_secret_scan": Direction.TRUE_ONLY,
    "security_baselines.safety_asr_threshold": Direction.DECREASE_ONLY,
    "security_baselines.safety_trials_min": Direction.INCREASE_ONLY,
    "evidence_standards.max_age_hours": Direction.DECREASE_ONLY,
    "evidence_standards.require_commit_sha": Direction.TRUE_ONLY,
    "evidence_standards.require_report_uri": Direction.TRUE_ONLY,
    "evidence_standards.require_environment": Direction.TRUE_ONLY,
    "evidence_standards.require_signatures": Direction.TRUE_ONLY,
    "evidence_standards.signature_algorithms": Direction.SUBSET_ONLY,
    "evidence_standards.min_signatures": Direction.INCREASE_ONLY,
}
"""Direction rule per override path; ``*`` matches one path segment (dict key)."""


class PolicyViolation(BaseModel):
    """A project override that would weaken organization policy."""

    model_config = ConfigDict(extra="forbid")

    path: str
    rule: Direction
    org_value: Any = None
    project_value: Any = None
    message: str = ""

    def __str__(self) -> str:
        return (
            f"{self.path}: {self.message} (org={self.org_value!r}, project={self.project_value!r})"
        )


class PolicyViolationError(ValueError):
    """Raised by :func:`effective_policy` in strict mode when violations exist."""

    def __init__(self, violations: Sequence[PolicyViolation]) -> None:
        self.violations = list(violations)
        lines = "\n".join(f"  - {v}" for v in self.violations)
        super().__init__(f"project configuration weakens organization policy:\n{lines}")


class EffectivePolicy(OrgPolicy):
    """Org policy with project narrowing applied, plus the project itself.

    ``applied`` lists override paths that took effect; ``violations`` lists the ones that
    were rejected (org value kept).
    """

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    applied: list[str] = Field(default_factory=list)
    violations: list[PolicyViolation] = Field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """``True`` when no override was rejected."""
        return not self.violations

    def model_allowed(self, model: str) -> bool:
        """Whether ``provider/model`` matches the effective allowlist."""
        return any(fnmatch(model, pattern) for pattern in self.models.allowlist)

    def max_tier_for(self, role: str) -> ModelTier:
        """Tier cap for *role* (``escalation`` when uncapped)."""
        return self.models.max_tier_per_role.get(role, ModelTier.ESCALATION)

    def tier_behaviour(self, tier: int) -> TierBehaviour:
        """Behaviour for a tool tier (``human_approval`` when unspecified)."""
        return self.tool_tiers.defaults.get(tier, TierBehaviour.HUMAN_APPROVAL)


def rule_for(path: str) -> Direction | None:
    """Direction rule matching *path* (``*`` in a rule matches one segment)."""
    for pattern, direction in RULES.items():
        regex = "^" + re.escape(pattern).replace(r"\*", r"[^.]+") + "$"
        if re.match(regex, path):
            return direction
    return None


def _rank(value: Any) -> int:
    if isinstance(value, GateDepth | ModelTier | TierBehaviour):
        return value.rank
    for enum_type in (GateDepth, ModelTier, TierBehaviour):
        try:
            return enum_type(value).rank
        except ValueError:
            continue
    raise TypeError(f"value {value!r} has no rank")


def _covered(item: str, org_items: Sequence[str]) -> bool:
    return any(item == pattern or fnmatch(item, pattern) for pattern in org_items)


def is_tightening(direction: Direction, org_value: Any, project_value: Any) -> bool:
    """``True`` when moving from *org_value* to *project_value* obeys *direction*.

    ``org_value`` may be ``None`` when the organization sets no value for a dict key
    (e.g. a role cap that only the project defines); adding a constraint is tightening.
    """
    if org_value is None:
        return True
    if direction is Direction.DECREASE_ONLY:
        return bool(project_value <= org_value)
    if direction is Direction.INCREASE_ONLY:
        return bool(project_value >= org_value)
    if direction is Direction.TRUE_ONLY:
        return bool(project_value) or not bool(org_value)
    if direction is Direction.FALSE_ONLY:
        return not bool(project_value) or bool(org_value)
    if direction is Direction.SUPERSET_ONLY:
        return set(_as_strs(org_value)) <= set(_as_strs(project_value))
    if direction is Direction.SUBSET_ONLY:
        org_items = _as_strs(org_value)
        return all(_covered(item, org_items) for item in _as_strs(project_value))
    if direction is Direction.RANK_UP_ONLY:
        return _rank(project_value) >= _rank(org_value)
    if direction is Direction.RANK_DOWN_ONLY:
        return _rank(project_value) <= _rank(org_value)
    raise AssertionError(f"unhandled direction {direction}")  # pragma: no cover


def _as_strs(value: Any) -> list[str]:
    return [str(getattr(v, "value", v)) for v in value]


def _plain(value: Any) -> Any:
    """Enums -> their values (recursively) so violations print and serialise cleanly."""
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {_plain(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def _get(data: dict[str, Any], path: list[str]) -> Any:
    node: Any = data
    for segment in path:
        if not isinstance(node, dict):
            return None
        node = _lookup(node, segment)
        if node is None:
            return None
    return node


def _lookup(node: dict[Any, Any], segment: str) -> Any:
    if segment in node:
        return node[segment]
    for key, value in node.items():
        if str(getattr(key, "value", key)) == segment:
            return value
    return None


def _set(data: dict[str, Any], path: list[str], value: Any) -> None:
    node: Any = data
    for segment in path[:-1]:
        existing = _lookup(node, segment)
        if not isinstance(existing, dict):
            existing = {}
            node[_key_for(node, segment)] = existing
        node = existing
    node[_key_for(node, path[-1])] = value


def _key_for(node: dict[Any, Any], segment: str) -> Any:
    for key in node:
        if str(getattr(key, "value", key)) == segment:
            return key
    return segment


def _describe(direction: Direction) -> str:
    return {
        Direction.DECREASE_ONLY: "project may only lower this value",
        Direction.INCREASE_ONLY: "project may only raise this value",
        Direction.TRUE_ONLY: "project may not disable this requirement",
        Direction.FALSE_ONLY: "project may not enable this allowance",
        Direction.SUPERSET_ONLY: "project may only add to this list",
        Direction.SUBSET_ONLY: "project may only narrow this list",
        Direction.RANK_UP_ONLY: "project may only make this stricter/deeper",
        Direction.RANK_DOWN_ONLY: "project may only lower this cap",
    }[direction]


def effective_policy(
    org: OrgPolicy, project: ProjectConfig, *, strict: bool = False
) -> EffectivePolicy:
    """Merge *project* overrides into *org*, allowing tightening only.

    Every set leaf in ``project.overrides`` is compared with the org value using the
    direction in :data:`RULES`. Tightening (or equal) values are applied; loosening values
    are reported as :class:`PolicyViolation` and the org value is kept. Paths with no rule
    are rejected as well (``rule`` is reported as ``subset_only`` with an explanatory
    message) so that new policy fields cannot be silently overridden.

    With ``strict=True`` a non-empty violation list raises :class:`PolicyViolationError`.
    """
    data: dict[str, Any] = copy.deepcopy(org.model_dump())
    applied: list[str] = []
    violations: list[PolicyViolation] = []

    for path, value in project.overrides.leaves().items():
        segments = path.split(".")
        direction = rule_for(path)
        org_value = _get(data, segments)
        if direction is None:
            violations.append(
                PolicyViolation(
                    path=path,
                    rule=Direction.SUBSET_ONLY,
                    org_value=_plain(org_value),
                    project_value=_plain(value),
                    message="no narrowing rule is defined for this path; override ignored",
                )
            )
            continue
        if is_tightening(direction, org_value, value):
            _set(data, segments, value)
            applied.append(path)
        else:
            violations.append(
                PolicyViolation(
                    path=path,
                    rule=direction,
                    org_value=_plain(org_value),
                    project_value=_plain(value),
                    message=_describe(direction),
                )
            )

    if strict and violations:
        raise PolicyViolationError(violations)

    return EffectivePolicy.model_validate(
        {**data, "project": project, "applied": applied, "violations": violations}
    )


def validate_project_against_org(org: OrgPolicy, project: ProjectConfig) -> list[PolicyViolation]:
    """Violations a project would incur against *org* (empty list when clean)."""
    return effective_policy(org, project).violations
