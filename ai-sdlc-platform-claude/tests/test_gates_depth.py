"""Tests for aisdlc.gates.depth."""

from __future__ import annotations

from aisdlc.gates.depth import GateDepthProfile, profile_for
from aisdlc.policy import (
    OrgPolicy,
    PolicyOverrides,
    ProjectConfig,
    TestCommands,
    default_org_policy,
    effective_policy,
)
from aisdlc.schema.models import GateDepth, GateId, RiskClass


def test_light_profile_for_docs_only() -> None:
    profile = GateDepthProfile.from_risk_class(RiskClass.DOCS_ONLY)
    assert profile.depth is GateDepth.LIGHT
    assert profile.required_gates == [GateId.G0, GateId.G2, GateId.G3]
    assert profile.requires(GateId.G0) and not profile.requires(GateId.G4)
    assert profile.gate_depth(GateId.G4) is GateDepth.SKIPPED
    assert profile.gate_depth(GateId.G2) is GateDepth.LIGHT
    assert profile.coverage_lines_min is None
    assert profile.cross_family_required is False
    assert profile.human_approval_required is False
    assert profile.require_threat_model is False
    assert profile.lint_required is True


def test_standard_profile_uses_policy_thresholds() -> None:
    org = default_org_policy()
    profile = profile_for(RiskClass.STANDARD, org)
    assert profile.depth is GateDepth.STANDARD
    assert profile.required_gates == list(GateId)
    assert profile.coverage_lines_min == org.security_baselines.coverage.lines_floor
    assert profile.coverage_diff_lines_min == org.security_baselines.coverage.diff_lines
    assert profile.coverage_branches_min == org.security_baselines.coverage.branches
    assert profile.coverage_critical_modules_min is None
    assert profile.mutation_required is False
    assert profile.mutation_score_min == org.security_baselines.mutation_score
    assert profile.ambiguity_threshold == org.security_baselines.ambiguity_threshold
    assert profile.max_review_rounds == org.cost_limits.max_review_rounds
    assert profile.budget_usd == org.cost_limits.budgets.per_change_usd
    assert profile.pyrit_required is False
    assert profile.min_approvals == 1
    assert profile.cross_family_required is True


def test_deep_profiles() -> None:
    high = GateDepthProfile.from_risk_class(RiskClass.HIGH)
    assert high.depth is GateDepth.DEEP
    assert high.mutation_required and high.require_adrs and high.require_plan_approval
    assert high.coverage_lines_min == 80.0
    assert high.coverage_critical_modules_min == 90.0
    assert high.performance_required and high.audit_required
    assert high.min_approvals == 1
    assert high.pyrit_required is False

    critical = GateDepthProfile.from_risk_class(RiskClass.CRITICAL)
    assert critical.min_approvals == 2

    agent = GateDepthProfile.from_risk_class(RiskClass.AI_AGENT)
    assert agent.pyrit_required and agent.safety_regression_required
    assert agent.manifest_validation_required
    assert agent.trials == default_org_policy().security_baselines.safety_trials_min
    assert agent.required_approval_roles == ["security"]
    assert agent.fail_on_baseline_regression


def test_project_narrowing_flows_into_profile() -> None:
    org = default_org_policy()
    project = ProjectConfig(
        overrides=PolicyOverrides.model_validate(
            {
                "security_baselines": {"ambiguity_threshold": 0.1, "coverage": {"lines": 95}},
                "cost_limits": {"max_review_rounds": 2},
            }
        ),
        test_commands=TestCommands(lint="ruff check .", types=None, build="make build"),
    )
    eff = effective_policy(org, project)
    assert eff.is_clean
    profile = profile_for(RiskClass.HIGH, eff)
    assert profile.ambiguity_threshold == 0.1
    assert profile.coverage_lines_min == 95.0
    assert profile.max_review_rounds == 2
    assert profile.types_required is False
    assert profile.build_required is True


def test_skipped_depth_requires_nothing() -> None:
    org = OrgPolicy.model_validate({"gates": {"depth": {"docs_only": "skipped"}}})
    profile = profile_for(RiskClass.DOCS_ONLY, org)
    assert profile.depth is GateDepth.SKIPPED
    assert profile.required_gates == []


def test_profile_is_strict() -> None:
    import pytest

    with pytest.raises(ValueError):
        GateDepthProfile(risk_class=RiskClass.LOW, depth=GateDepth.LIGHT, bogus=1)  # type: ignore[call-arg]
