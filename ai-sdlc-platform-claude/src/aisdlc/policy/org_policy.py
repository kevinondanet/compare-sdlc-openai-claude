"""Organization policy (the top policy layer; ARCHITECTURE.md §0 principle 4).

Defaults here are the platform defaults and are mirrored one-to-one by
``templates/org-policy.yaml`` (a test asserts they stay in sync).
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aisdlc.schema.models import GateDepth, GateId, ModelTier, RiskClass

__all__ = [
    "PolicyModel",
    "PolicyLoadError",
    "TierBehaviour",
    "GatePolicy",
    "ModelPolicy",
    "ToolTierPolicy",
    "Budgets",
    "CostLimits",
    "CoverageThresholds",
    "SecurityBaselines",
    "EvidenceStandards",
    "OrgPolicy",
    "ORG_POLICY_CANDIDATES",
    "default_org_policy",
    "load_org_policy",
    "dump_org_policy",
    "find_org_policy",
]

ALL_GATES: tuple[GateId, ...] = tuple(GateId)


class PolicyModel(BaseModel):
    """Base for policy models: strict, unknown keys rejected."""

    model_config = ConfigDict(extra="forbid")


class PolicyLoadError(ValueError):
    """A policy/config file could not be read or validated."""


class TierBehaviour(StrEnum):
    """Default behaviour of a tool risk tier (ARCHITECTURE.md §4), least to most strict."""

    AUTOMATIC = "automatic"
    AUTOMATIC_AUDIT = "automatic_audit"
    POLICY_CONTROLLED = "policy_controlled"
    APPROVAL = "approval"
    HUMAN_APPROVAL = "human_approval"

    @property
    def rank(self) -> int:
        """Strictness rank (automatic=0 … human_approval=4)."""
        return list(TierBehaviour).index(self)


def _default_required_gates() -> dict[RiskClass, list[GateId]]:
    return {
        RiskClass.DOCS_ONLY: [GateId.G0, GateId.G2, GateId.G3],
        RiskClass.LOW: [GateId.G0, GateId.G1, GateId.G2, GateId.G3, GateId.G6],
        RiskClass.STANDARD: list(ALL_GATES),
        RiskClass.HIGH: list(ALL_GATES),
        RiskClass.CRITICAL: list(ALL_GATES),
        RiskClass.AI_AGENT: list(ALL_GATES),
    }


def _default_depth() -> dict[RiskClass, GateDepth]:
    return {
        RiskClass.DOCS_ONLY: GateDepth.LIGHT,
        RiskClass.LOW: GateDepth.LIGHT,
        RiskClass.STANDARD: GateDepth.STANDARD,
        RiskClass.HIGH: GateDepth.DEEP,
        RiskClass.CRITICAL: GateDepth.DEEP,
        RiskClass.AI_AGENT: GateDepth.DEEP,
    }


class GatePolicy(PolicyModel):
    """Which gates a risk class must pass and at which depth."""

    required_gates: dict[RiskClass, list[GateId]] = Field(default_factory=_default_required_gates)
    depth: dict[RiskClass, GateDepth] = Field(default_factory=_default_depth)

    @field_validator("required_gates")
    @classmethod
    def _sorted_unique(cls, value: dict[RiskClass, list[GateId]]) -> dict[RiskClass, list[GateId]]:
        return {k: sorted(set(v), key=lambda g: list(GateId).index(g)) for k, v in value.items()}


def _default_max_tier_per_role() -> dict[str, ModelTier]:
    return {
        "planner": ModelTier.HIGH,
        "plan_checker": ModelTier.STANDARD,
        "implementer": ModelTier.STANDARD,
        "reviewer": ModelTier.INDEPENDENT_REVIEW,
        "verifier": ModelTier.LOW,
        "uat": ModelTier.STANDARD,
        "security_tester": ModelTier.STANDARD,
    }


class ModelPolicy(PolicyModel):
    """Model allowlist and per-role tier caps."""

    allowlist: list[str] = Field(
        default_factory=lambda: ["anthropic/claude-*", "openai/gpt-*", "google/gemini-*"],
        description="fnmatch patterns over ``provider/model``.",
    )
    independent_review_requires_different_family: bool = True
    max_tier_per_role: dict[str, ModelTier] = Field(default_factory=_default_max_tier_per_role)
    escalation_allowed: bool = True


def _default_tier_defaults() -> dict[int, TierBehaviour]:
    return {
        0: TierBehaviour.AUTOMATIC,
        1: TierBehaviour.AUTOMATIC_AUDIT,
        2: TierBehaviour.POLICY_CONTROLLED,
        3: TierBehaviour.APPROVAL,
        4: TierBehaviour.HUMAN_APPROVAL,
    }


class ToolTierPolicy(PolicyModel):
    """Tool risk tier defaults (§4)."""

    defaults: dict[int, TierBehaviour] = Field(default_factory=_default_tier_defaults)
    approval_timeout_seconds: int = Field(default=300, ge=1)
    deny_on_timeout: bool = True
    audit_from_tier: int = Field(default=1, ge=0, le=4)

    @field_validator("defaults")
    @classmethod
    def _tiers_in_range(cls, value: dict[int, TierBehaviour]) -> dict[int, TierBehaviour]:
        for tier in value:
            if not 0 <= tier <= 4:
                raise ValueError(f"tool tier {tier} outside 0..4")
        return value


class Budgets(PolicyModel):
    """USD budgets by scope."""

    per_change_usd: float = Field(default=50.0, ge=0)
    per_task_usd: float = Field(default=5.0, ge=0)
    per_day_usd: float = Field(default=500.0, ge=0)
    per_month_usd: float = Field(default=5000.0, ge=0)


class CostLimits(PolicyModel):
    """Budgets and execution ceilings (§5)."""

    budgets: Budgets = Field(default_factory=Budgets)
    max_agent_turns: int = Field(default=40, ge=1)
    max_parallel_agents: int = Field(default=4, ge=1)
    max_review_rounds: int = Field(default=3, ge=1)
    max_tool_calls: int = Field(default=500, ge=1)
    context_ceiling_tokens: int = Field(default=200_000, ge=1000)


class CoverageThresholds(PolicyModel):
    """Coverage thresholds in percent."""

    lines: float = Field(default=80.0, ge=0, le=100, description="Target line coverage.")
    lines_floor: float = Field(default=75.0, ge=0, le=100, description="Ratchet floor.")
    diff_lines: float = Field(default=90.0, ge=0, le=100)
    branches: float = Field(default=70.0, ge=0, le=100)
    critical_modules: float = Field(default=90.0, ge=0, le=100)


class SecurityBaselines(PolicyModel):
    """Security and quality baselines used by G0/G2/G4."""

    asr_threshold: float = Field(default=0.05, ge=0, le=1)
    max_undetermined_rate: float = Field(default=0.10, ge=0, le=1)
    coverage: CoverageThresholds = Field(default_factory=CoverageThresholds)
    mutation_score: float = Field(default=0.60, ge=0, le=1)
    ambiguity_threshold: float = Field(default=0.20, ge=0, le=1)
    max_critical_vulns: int = Field(default=0, ge=0)
    max_high_vulns: int = Field(default=0, ge=0)
    require_sbom: bool = True
    require_provenance: bool = True
    require_secret_scan: bool = True
    safety_asr_threshold: float = Field(default=0.05, ge=0, le=1)
    safety_trials_min: int = Field(default=5, ge=1)


class EvidenceStandards(PolicyModel):
    """What every evidence record must carry to count."""

    max_age_hours: int = Field(default=72, ge=1)
    require_commit_sha: bool = True
    require_report_uri: bool = True
    require_environment: bool = True
    require_signatures: bool = True
    signature_algorithms: list[str] = Field(default_factory=lambda: ["hmac-sha256", "ed25519"])
    min_signatures: int = Field(default=1, ge=0)


class OrgPolicy(PolicyModel):
    """Organization-wide policy: the widest bounds any project may operate in."""

    version: int = Field(default=1, ge=1)
    name: str = "default"
    gates: GatePolicy = Field(default_factory=GatePolicy)
    models: ModelPolicy = Field(default_factory=ModelPolicy)
    tool_tiers: ToolTierPolicy = Field(default_factory=ToolTierPolicy)
    cost_limits: CostLimits = Field(default_factory=CostLimits)
    security_baselines: SecurityBaselines = Field(default_factory=SecurityBaselines)
    evidence_standards: EvidenceStandards = Field(default_factory=EvidenceStandards)

    def required_gates_for(self, risk_class: RiskClass) -> list[GateId]:
        """Gates required for *risk_class* (all gates when unspecified)."""
        return list(self.gates.required_gates.get(risk_class, list(ALL_GATES)))

    def depth_for(self, risk_class: RiskClass) -> GateDepth:
        """Gate depth for *risk_class* (``deep`` when unspecified)."""
        return self.gates.depth.get(risk_class, GateDepth.DEEP)


ORG_POLICY_CANDIDATES: tuple[str, ...] = (
    "org-policy.yaml",
    ".aisdlc/org-policy.yaml",
    "templates/org-policy.yaml",
)


def default_org_policy() -> OrgPolicy:
    """The built-in default policy (identical to ``templates/org-policy.yaml``)."""
    return OrgPolicy()


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyLoadError(f"{path}: not found") from exc
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"{path}: invalid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PolicyLoadError(f"{path}: top level must be a mapping")
    return data


def load_org_policy(path: str | Path) -> OrgPolicy:
    """Load an :class:`OrgPolicy` from YAML; missing keys take the defaults."""
    file = Path(path)
    try:
        return OrgPolicy.model_validate(_read_yaml(file))
    except ValidationError as exc:
        raise PolicyLoadError(f"{file}: {exc}") from exc


def dump_org_policy(policy: OrgPolicy) -> str:
    """Render a policy as YAML (stable key order)."""
    return str(yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False, allow_unicode=True))


def find_org_policy(start: str | Path = ".") -> Path | None:
    """First existing candidate under *start* (see :data:`ORG_POLICY_CANDIDATES`)."""
    base = Path(start)
    for candidate in ORG_POLICY_CANDIDATES:
        if (base / candidate).is_file():
            return base / candidate
    return None
