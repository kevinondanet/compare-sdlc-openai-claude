"""Risk-based gate depth profiles (ARCHITECTURE.md §3).

A :class:`GateDepthProfile` is the *only* thing that varies between risk classes: which
gates are required, at which depth each gate runs, which checks inside each gate are
enabled, the thresholds those checks use, and how many trials/approvals/signatures are
needed. It never changes the meaning of a gate. Profiles are built from the effective
policy so that organization and project narrowing flows straight into gate evaluation.

This module is the **single definition** of the profile. The planning layer
(:mod:`aisdlc.planning.risk`) owns *classification* (paths -> risk class) and re-exports
:class:`GateDepthProfile`, :class:`QualityCheck` and :func:`profile_for` (as
``gate_depth_profile``) so that planner, plan checker and gates all consume one object.

Two vocabularies are supported on purpose:

* the gate knobs (``coverage_lines_min``, ``pyrit_required``, ``min_approvals`` …) that
  :mod:`aisdlc.gates.gates` enforces, and
* the planning vocabulary (``depths``, ``checks``, ``plan_approval_required``,
  ``checkpoint_before_tier3`` …) that the planner and plan checker use to place human
  checkpoints and verification tasks. Planning-era aliases (``require_adr``,
  ``pyrit_campaign_required``, ``human_approvals_required`` …) are read-only properties
  over the gate knobs so no caller has to learn two names for one setting.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.policy.org_policy import OrgPolicy, default_org_policy
from aisdlc.schema.models import GateDepth, GateId, RiskClass

__all__ = [
    "GateDepthProfile",
    "QualityCheck",
    "profile_for",
]


class QualityCheck(StrEnum):
    """Deterministic checks the plan schedules and G2 may enforce."""

    LINT = "lint"
    LINKS = "links"
    TYPES = "types"
    BUILD = "build"
    UNIT = "unit"
    COVERAGE = "coverage"
    MUTATION = "mutation"
    INTEGRATION = "integration"
    E2E = "e2e"


_DEEP_APPROVALS: Final[dict[RiskClass, int]] = {
    RiskClass.HIGH: 1,
    RiskClass.CRITICAL: 2,
    RiskClass.AI_AGENT: 2,
}

_CHECKS_BY_DEPTH: Final[dict[GateDepth, tuple[QualityCheck, ...]]] = {
    GateDepth.SKIPPED: (),
    GateDepth.LIGHT: (QualityCheck.LINT, QualityCheck.UNIT),
    GateDepth.STANDARD: (
        QualityCheck.LINT,
        QualityCheck.TYPES,
        QualityCheck.BUILD,
        QualityCheck.UNIT,
        QualityCheck.COVERAGE,
        QualityCheck.MUTATION,
    ),
    GateDepth.DEEP: (
        QualityCheck.LINT,
        QualityCheck.TYPES,
        QualityCheck.BUILD,
        QualityCheck.UNIT,
        QualityCheck.COVERAGE,
        QualityCheck.MUTATION,
        QualityCheck.INTEGRATION,
        QualityCheck.E2E,
    ),
}
"""G2 checks per depth; ``docs_only`` replaces unit tests with a link check."""


def _at_least(depth: GateDepth, floor: GateDepth) -> bool:
    return depth is not GateDepth.SKIPPED and depth.rank >= floor.rank


class GateDepthProfile(BaseModel):
    """Explicit per-gate configuration for one risk class.

    Every knob a gate consults is a named field here so that a profile can be printed,
    diffed and overridden without reading gate code. ``None`` thresholds mean "not
    checked". Missing evidence for an enabled check always fails closed.
    """

    model_config = ConfigDict(extra="forbid")

    risk_class: RiskClass
    depth: GateDepth = Field(description="Headline depth of the risk class (org policy).")
    depths: dict[GateId, GateDepth] = Field(
        default_factory=dict, description="Depth per gate; ``skipped`` when not required."
    )
    required_gates: list[GateId] = Field(default_factory=list)

    # -- G0 intent readiness ---------------------------------------------------------
    ambiguity_threshold: float = Field(default=0.20, ge=0, le=1)
    require_owner: bool = True
    require_kernel_complete: bool = True
    require_non_goals: bool = True
    require_assumptions: bool = False
    require_scenarios: bool = True
    block_on_open_questions: bool = True

    # -- G1 architecture readiness ---------------------------------------------------
    require_plan: bool = True
    require_plan_approval: bool = Field(
        default=False, description="G1 blocks unless ``Plan.approved_by`` is recorded."
    )
    require_threat_model: bool = True
    threat_model_min_threats: int = Field(default=0, ge=0)
    require_nfrs: bool = True
    require_adrs: bool = False
    require_interfaces: bool = False

    # -- G2 implementation quality ---------------------------------------------------
    checks: list[QualityCheck] = Field(
        default_factory=list, description="Deterministic checks the plan should schedule."
    )
    require_test_evidence: bool = True
    coverage_lines_min: float | None = Field(default=None, ge=0, le=100)
    coverage_diff_lines_min: float | None = Field(default=None, ge=0, le=100)
    coverage_branches_min: float | None = Field(default=None, ge=0, le=100)
    coverage_critical_modules_min: float | None = Field(default=None, ge=0, le=100)
    mutation_required: bool = False
    mutation_score_min: float | None = Field(default=None, ge=0, le=1)
    lint_required: bool = True
    types_required: bool = True
    build_required: bool = False
    links_required: bool = Field(
        default=False,
        description="G2 needs link-check evidence (docs_only replaces unit tests with it).",
    )

    # -- G3 independent review -------------------------------------------------------
    review_required: bool = True
    cross_family_required: bool = True
    max_review_rounds: int = Field(default=3, ge=1)

    # -- G4 security & safety --------------------------------------------------------
    security_required: bool = True
    sast_required: bool = True
    sca_required: bool = True
    secrets_scan_required: bool = True
    sbom_required: bool = True
    provenance_required: bool = True
    delta_scan_only: bool = Field(
        default=False, description="Only the diff is scanned (light security depth)."
    )
    max_critical_vulns: int = Field(default=0, ge=0)
    max_high_vulns: int = Field(default=0, ge=0)
    pyrit_required: bool = False
    asr_threshold: float = Field(default=0.05, ge=0, le=1)
    max_undetermined_rate: float = Field(default=0.10, ge=0, le=1)
    trials: int = Field(default=0, ge=0, description="Minimum PyRIT trials when required.")
    fail_on_baseline_regression: bool = False
    safety_regression_required: bool = False
    safety_asr_threshold: float = Field(default=0.05, ge=0, le=1)
    safety_trials_min: int = Field(default=5, ge=1)
    manifest_validation_required: bool = False

    # -- G5 cost & performance -------------------------------------------------------
    cost_required: bool = True
    budget_usd: float | None = Field(default=None, ge=0)
    performance_required: bool = False

    # -- G6 release ------------------------------------------------------------------
    require_signatures: bool = True
    min_signatures: int = Field(default=1, ge=0)
    signature_algorithms: list[str] = Field(default_factory=lambda: ["hmac-sha256", "ed25519"])
    evidence_max_age_hours: int = Field(default=72, ge=1)
    require_commit_sha: bool = True
    require_report_uri: bool = True
    require_environment: bool = True
    human_approval_required: bool = True
    min_approvals: int = Field(default=1, ge=0)
    required_approval_roles: list[str] = Field(default_factory=list)
    audit_required: bool = False

    # -- Human checkpoints (orchestration / planning) ----------------------------------
    plan_approval_required: bool = Field(
        default=False,
        description="The executor pauses for a human plan approval before the first wave.",
    )
    checkpoint_before_tier3: bool = Field(
        default=False, description="Pause before the first wave holding tier >= 3 actions."
    )
    checkpoint_before_release: bool = Field(
        default=False, description="Pause after the last wave, before release."
    )

    # -- helpers -----------------------------------------------------------------------

    def requires(self, gate: GateId) -> bool:
        """Whether *gate* must be evaluated (and passed) for this profile."""
        return gate in self.required_gates

    def applies(self, gate: GateId) -> bool:
        """Alias of :meth:`requires` (planning vocabulary)."""
        return self.requires(gate)

    def gate_depth(self, gate: GateId) -> GateDepth:
        """Depth recorded on the gate result: ``skipped`` when the gate is not required."""
        if not self.requires(gate):
            return GateDepth.SKIPPED
        return self.depths.get(gate, self.depth)

    def depth_for(self, gate: GateId) -> GateDepth:
        """Alias of :meth:`gate_depth` (planning vocabulary)."""
        return self.gate_depth(gate)

    # -- planning-era aliases (read-only) ----------------------------------------------

    @property
    def require_plan_check(self) -> bool:
        """G1 runs the plan checker (alias of :attr:`require_plan`)."""
        return self.require_plan

    @property
    def require_adr(self) -> bool:
        """Alias of :attr:`require_adrs`."""
        return self.require_adrs

    @property
    def critical_modules_coverage_min(self) -> float | None:
        """Alias of :attr:`coverage_critical_modules_min`."""
        return self.coverage_critical_modules_min

    @property
    def cross_family_review_required(self) -> bool:
        """Alias of :attr:`cross_family_required`."""
        return self.cross_family_required

    @property
    def secret_scan_required(self) -> bool:
        """Alias of :attr:`secrets_scan_required`."""
        return self.secrets_scan_required

    @property
    def pyrit_campaign_required(self) -> bool:
        """Alias of :attr:`pyrit_required`."""
        return self.pyrit_required

    @property
    def pyrit_trials_min(self) -> int:
        """Alias of :attr:`trials`."""
        return self.trials

    @property
    def cost_evidence_required(self) -> bool:
        """Alias of :attr:`cost_required`."""
        return self.cost_required

    @property
    def performance_evidence_required(self) -> bool:
        """Alias of :attr:`performance_required`."""
        return self.performance_required

    @property
    def human_approvals_required(self) -> int:
        """Number of human approvals G6 demands (0 when none are required)."""
        return self.min_approvals if self.human_approval_required else 0

    @property
    def signed_bundle_required(self) -> bool:
        """Alias of :attr:`require_signatures`."""
        return self.require_signatures

    # -- construction ------------------------------------------------------------------

    @classmethod
    def from_risk_class(
        cls, risk_class: RiskClass, policy: OrgPolicy | None = None
    ) -> GateDepthProfile:
        """Build the profile for *risk_class* from *policy* (defaults when omitted).

        The policy's ``gates.required_gates`` and ``gates.depth`` for the class decide
        which gates run and at which depth (§3); every threshold comes from the policy's
        security baselines, evidence standards and cost limits. Depth ladder:

        * ``light`` (docs_only, low) — G0 ambiguity/owner/blocking questions/scenarios;
          G1 plan presence only; G2 lint + test exit codes, no coverage; G3 review present,
          cross-family not required; no human approval for release.
        * ``standard`` — every check above plus kernel completeness, non-goals, threat
          model + NFRs, coverage floor/diff/branches, types, cross-family review, full
          SAST/SCA/secrets/SBOM/provenance, budget, one human approval, a plan-approval
          checkpoint before the first wave.
        * ``deep`` (high, critical, ai_agent) — plus assumptions, plan approval recorded,
          >= 1 threat, ADRs + interfaces, target line coverage, critical-module coverage,
          mutation score, build evidence, performance SLO, audit integrity, two approvals
          for critical/ai_agent. ``ai_agent`` additionally requires PyRIT trials, the
          safety regression suite and tool/data manifest validation.
        """
        pol = policy if policy is not None else default_org_policy()
        headline = pol.depth_for(risk_class)
        sec = pol.security_baselines
        cov = sec.coverage
        std = pol.evidence_standards
        project_cmds: dict[str, str] = {}
        project = getattr(pol, "project", None)
        if project is not None:
            project_cmds = project.test_commands.defined()

        if headline is GateDepth.SKIPPED:
            required: list[GateId] = []
        else:
            required = list(pol.required_gates_for(risk_class))
        depths = {g: (headline if g in required else GateDepth.SKIPPED) for g in GateId}
        d = depths
        agentic = risk_class is RiskClass.AI_AGENT
        docs = risk_class is RiskClass.DOCS_ONLY

        checks = list(_CHECKS_BY_DEPTH[d[GateId.G2]])
        if docs and checks:
            checks = [QualityCheck.LINT, QualityCheck.LINKS]
        coverage_checked = QualityCheck.COVERAGE in checks
        g2_deep = d[GateId.G2] is GateDepth.DEEP

        def required_cmd(label: str, check: QualityCheck) -> bool:
            if check not in checks:
                return False
            return label in project_cmds if project_cmds else True

        security_on = d[GateId.G4] is not GateDepth.SKIPPED
        pyrit_required = agentic and security_on
        g6_std = _at_least(d[GateId.G6], GateDepth.STANDARD)
        if not g6_std:
            approvals = 0
        elif d[GateId.G6] is GateDepth.DEEP:
            approvals = _DEEP_APPROVALS.get(risk_class, 1)
        else:
            approvals = 1

        values: dict[str, Any] = {
            "risk_class": risk_class,
            "depth": headline,
            "depths": depths,
            "required_gates": required,
            # G0
            "ambiguity_threshold": sec.ambiguity_threshold,
            "require_owner": True,
            "require_kernel_complete": _at_least(d[GateId.G0], GateDepth.STANDARD),
            "require_non_goals": _at_least(d[GateId.G0], GateDepth.STANDARD),
            "require_assumptions": d[GateId.G0] is GateDepth.DEEP,
            "require_scenarios": True,
            "block_on_open_questions": True,
            # G1
            "require_plan": d[GateId.G1] is not GateDepth.SKIPPED,
            "require_plan_approval": d[GateId.G1] is GateDepth.DEEP,
            "require_threat_model": _at_least(d[GateId.G1], GateDepth.STANDARD),
            "threat_model_min_threats": 1 if d[GateId.G1] is GateDepth.DEEP else 0,
            "require_nfrs": _at_least(d[GateId.G1], GateDepth.STANDARD),
            "require_adrs": d[GateId.G1] is GateDepth.DEEP,
            # Opt-in: a change need not introduce interface contracts at any depth.
            "require_interfaces": False,
            # G2
            "checks": checks,
            "require_test_evidence": d[GateId.G2] is not GateDepth.SKIPPED,
            "coverage_lines_min": (cov.lines if g2_deep else cov.lines_floor)
            if coverage_checked
            else None,
            "coverage_diff_lines_min": cov.diff_lines if coverage_checked else None,
            "coverage_branches_min": cov.branches if coverage_checked else None,
            "coverage_critical_modules_min": cov.critical_modules if g2_deep else None,
            "mutation_required": g2_deep,
            "mutation_score_min": sec.mutation_score if QualityCheck.MUTATION in checks else None,
            "lint_required": required_cmd("lint", QualityCheck.LINT),
            "types_required": required_cmd("types", QualityCheck.TYPES),
            "build_required": g2_deep and "build" in project_cmds,
            "links_required": QualityCheck.LINKS in checks,
            # G3
            "review_required": d[GateId.G3] is not GateDepth.SKIPPED,
            "cross_family_required": d[GateId.G3] is GateDepth.DEEP
            or (
                d[GateId.G3] is GateDepth.STANDARD
                and pol.models.independent_review_requires_different_family
            ),
            "max_review_rounds": pol.cost_limits.max_review_rounds,
            # G4
            "security_required": security_on,
            "sast_required": security_on,
            "sca_required": security_on,
            "secrets_scan_required": security_on and sec.require_secret_scan,
            "sbom_required": _at_least(d[GateId.G4], GateDepth.STANDARD) and sec.require_sbom,
            "provenance_required": _at_least(d[GateId.G4], GateDepth.STANDARD)
            and sec.require_provenance,
            "delta_scan_only": d[GateId.G4] is GateDepth.LIGHT,
            "max_critical_vulns": sec.max_critical_vulns,
            "max_high_vulns": sec.max_high_vulns,
            "pyrit_required": pyrit_required,
            "asr_threshold": sec.asr_threshold,
            "max_undetermined_rate": sec.max_undetermined_rate,
            "trials": sec.safety_trials_min if pyrit_required else 0,
            "fail_on_baseline_regression": d[GateId.G4] is GateDepth.DEEP,
            "safety_regression_required": pyrit_required,
            "safety_asr_threshold": sec.safety_asr_threshold,
            "safety_trials_min": sec.safety_trials_min,
            "manifest_validation_required": pyrit_required,
            # G5
            "cost_required": d[GateId.G5] is not GateDepth.SKIPPED,
            "budget_usd": pol.cost_limits.budgets.per_change_usd,
            "performance_required": d[GateId.G5] is GateDepth.DEEP,
            # G6
            "require_signatures": std.require_signatures and d[GateId.G6] is not GateDepth.SKIPPED,
            "min_signatures": std.min_signatures,
            "signature_algorithms": list(std.signature_algorithms),
            "evidence_max_age_hours": std.max_age_hours,
            "require_commit_sha": std.require_commit_sha,
            "require_report_uri": std.require_report_uri and headline is not GateDepth.LIGHT,
            "require_environment": std.require_environment,
            "human_approval_required": g6_std,
            "min_approvals": approvals,
            "required_approval_roles": ["security"] if agentic and g6_std else [],
            "audit_required": d[GateId.G6] is GateDepth.DEEP,
            # checkpoints
            "plan_approval_required": _at_least(d[GateId.G1], GateDepth.STANDARD),
            "checkpoint_before_tier3": not docs and headline is not GateDepth.SKIPPED,
            "checkpoint_before_release": not docs and headline is not GateDepth.SKIPPED,
        }
        return cls(**values)


def profile_for(
    risk_class: RiskClass, effective_policy: OrgPolicy | None = None
) -> GateDepthProfile:
    """Profile for *risk_class* under *effective_policy* (org policy or effective policy)."""
    return GateDepthProfile.from_risk_class(risk_class, effective_policy)
