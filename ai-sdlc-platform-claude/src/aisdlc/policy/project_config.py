"""Project configuration (the middle policy layer).

A project describes itself (languages, frameworks, test commands, critical modules, risk
classification) and may *narrow* organization policy through ``overrides``. Every field
in :class:`PolicyOverrides` is optional; unset fields inherit the org value.
"""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError

from aisdlc.policy.org_policy import PolicyLoadError, PolicyModel, TierBehaviour
from aisdlc.schema.models import GateDepth, GateId, ModelTier, RiskClass

__all__ = [
    "RISK_ORDER",
    "RiskRule",
    "RiskClassification",
    "TestCommands",
    "GateOverrides",
    "ModelOverrides",
    "ToolTierOverrides",
    "BudgetOverrides",
    "CostLimitOverrides",
    "CoverageOverrides",
    "SecurityOverrides",
    "EvidenceOverrides",
    "PolicyOverrides",
    "ProjectConfig",
    "PROJECT_CONFIG_CANDIDATES",
    "default_project_config",
    "load_project_config",
    "dump_project_config",
    "find_project_config",
]

RISK_ORDER: dict[RiskClass, int] = {
    RiskClass.DOCS_ONLY: 0,
    RiskClass.LOW: 1,
    RiskClass.STANDARD: 2,
    RiskClass.HIGH: 3,
    RiskClass.CRITICAL: 4,
    RiskClass.AI_AGENT: 5,
}
"""Ordering used when several rules match: the highest class wins."""


class RiskRule(PolicyModel):
    """Path glob (``fnmatch`` semantics) mapped to a risk class."""

    pattern: str
    risk_class: RiskClass


class RiskClassification(PolicyModel):
    """Default risk class plus path rules."""

    default: RiskClass = RiskClass.STANDARD
    rules: list[RiskRule] = Field(default_factory=list)

    def classify(self, paths: Iterable[str]) -> RiskClass:
        """Highest risk class among matching rules for *paths*; ``default`` if none match.

        The first matching rule decides for each path; across paths the highest class
        wins. The default is not a floor: a ``docs_only`` rule may classify below it.
        """
        best: RiskClass | None = None
        for path in paths:
            for rule in self.rules:
                if fnmatch(path, rule.pattern):
                    if best is None or RISK_ORDER[rule.risk_class] > RISK_ORDER[best]:
                        best = rule.risk_class
                    break
        return best if best is not None else self.default


class TestCommands(PolicyModel):
    """Commands the platform runs to produce deterministic evidence."""

    __test__ = False  # not a pytest test class despite the name

    unit: str | None = "pytest -q"
    lint: str | None = "ruff check ."
    types: str | None = "mypy"
    build: str | None = None
    integration: str | None = None
    e2e: str | None = None
    coverage: str | None = None
    mutation: str | None = None

    def defined(self) -> dict[str, str]:
        """Only the commands that are set."""
        return {k: v for k, v in self.model_dump().items() if isinstance(v, str) and v.strip()}


class GateOverrides(PolicyModel):
    """May add gates or deepen depth."""

    required_gates: dict[RiskClass, list[GateId]] | None = None
    depth: dict[RiskClass, GateDepth] | None = None


class ModelOverrides(PolicyModel):
    """May narrow the allowlist, lower tier caps, forbid escalation."""

    allowlist: list[str] | None = None
    independent_review_requires_different_family: bool | None = None
    max_tier_per_role: dict[str, ModelTier] | None = None
    escalation_allowed: bool | None = None


class ToolTierOverrides(PolicyModel):
    """May make tiers stricter, shorten timeouts, audit earlier."""

    defaults: dict[int, TierBehaviour] | None = None
    approval_timeout_seconds: int | None = Field(default=None, ge=1)
    deny_on_timeout: bool | None = None
    audit_from_tier: int | None = Field(default=None, ge=0, le=4)


class BudgetOverrides(PolicyModel):
    """May lower budgets."""

    per_change_usd: float | None = Field(default=None, ge=0)
    per_task_usd: float | None = Field(default=None, ge=0)
    per_day_usd: float | None = Field(default=None, ge=0)
    per_month_usd: float | None = Field(default=None, ge=0)


class CostLimitOverrides(PolicyModel):
    """May lower limits."""

    budgets: BudgetOverrides | None = None
    max_agent_turns: int | None = Field(default=None, ge=1)
    max_parallel_agents: int | None = Field(default=None, ge=1)
    max_review_rounds: int | None = Field(default=None, ge=1)
    max_tool_calls: int | None = Field(default=None, ge=1)
    context_ceiling_tokens: int | None = Field(default=None, ge=1000)


class CoverageOverrides(PolicyModel):
    """May raise thresholds."""

    lines: float | None = Field(default=None, ge=0, le=100)
    lines_floor: float | None = Field(default=None, ge=0, le=100)
    diff_lines: float | None = Field(default=None, ge=0, le=100)
    branches: float | None = Field(default=None, ge=0, le=100)
    critical_modules: float | None = Field(default=None, ge=0, le=100)


class SecurityOverrides(PolicyModel):
    """May tighten every baseline."""

    asr_threshold: float | None = Field(default=None, ge=0, le=1)
    max_undetermined_rate: float | None = Field(default=None, ge=0, le=1)
    coverage: CoverageOverrides | None = None
    mutation_score: float | None = Field(default=None, ge=0, le=1)
    ambiguity_threshold: float | None = Field(default=None, ge=0, le=1)
    max_critical_vulns: int | None = Field(default=None, ge=0)
    max_high_vulns: int | None = Field(default=None, ge=0)
    require_sbom: bool | None = None
    require_provenance: bool | None = None
    require_secret_scan: bool | None = None
    safety_asr_threshold: float | None = Field(default=None, ge=0, le=1)
    safety_trials_min: int | None = Field(default=None, ge=1)


class EvidenceOverrides(PolicyModel):
    """May tighten evidence standards."""

    max_age_hours: int | None = Field(default=None, ge=1)
    require_commit_sha: bool | None = None
    require_report_uri: bool | None = None
    require_environment: bool | None = None
    require_signatures: bool | None = None
    signature_algorithms: list[str] | None = None
    min_signatures: int | None = Field(default=None, ge=0)


class PolicyOverrides(PolicyModel):
    """Partial :class:`~aisdlc.policy.org_policy.OrgPolicy`; narrowing only."""

    gates: GateOverrides | None = None
    models: ModelOverrides | None = None
    tool_tiers: ToolTierOverrides | None = None
    cost_limits: CostLimitOverrides | None = None
    security_baselines: SecurityOverrides | None = None
    evidence_standards: EvidenceOverrides | None = None

    def leaves(self) -> dict[str, Any]:
        """Dotted-path → value for every set leaf (dict keys become path segments)."""
        out: dict[str, Any] = {}

        def walk(prefix: str, value: Any) -> None:
            if isinstance(value, dict):
                for key, inner in value.items():
                    walk(f"{prefix}.{key}" if prefix else str(key), inner)
            else:
                out[prefix] = value

        walk("", self.model_dump(exclude_none=True))
        return out


class ProjectConfig(PolicyModel):
    """Project-level configuration and narrowing overrides."""

    name: str = "project"
    languages: list[str] = Field(default_factory=lambda: ["python"])
    frameworks: list[str] = Field(default_factory=list)
    architecture_style: str = "modular_monolith"
    risk_classification: RiskClassification = Field(default_factory=RiskClassification)
    test_commands: TestCommands = Field(default_factory=TestCommands)
    critical_modules: list[str] = Field(default_factory=list)
    overrides: PolicyOverrides = Field(default_factory=PolicyOverrides)

    def is_critical(self, path: str) -> bool:
        """``True`` when *path* falls under a critical module pattern."""
        return any(
            fnmatch(path, pattern) or path.startswith(pattern) for pattern in self.critical_modules
        )


PROJECT_CONFIG_CANDIDATES: tuple[str, ...] = (
    "aisdlc.yaml",
    "project-config.yaml",
    ".aisdlc/project-config.yaml",
    "templates/project-config.yaml",
)


def default_project_config() -> ProjectConfig:
    """Built-in default configuration (identical to ``templates/project-config.yaml``)."""
    return ProjectConfig()


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


def load_project_config(path: str | Path) -> ProjectConfig:
    """Load a :class:`ProjectConfig` from YAML; missing keys take the defaults."""
    file = Path(path)
    try:
        return ProjectConfig.model_validate(_read_yaml(file))
    except ValidationError as exc:
        raise PolicyLoadError(f"{file}: {exc}") from exc


def dump_project_config(config: ProjectConfig) -> str:
    """Render a project config as YAML (stable key order)."""
    return str(yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False, allow_unicode=True))


def find_project_config(start: str | Path = ".") -> Path | None:
    """First existing candidate under *start* (see :data:`PROJECT_CONFIG_CANDIDATES`)."""
    base = Path(start)
    for candidate in PROJECT_CONFIG_CANDIDATES:
        if (base / candidate).is_file():
            return base / candidate
    return None
