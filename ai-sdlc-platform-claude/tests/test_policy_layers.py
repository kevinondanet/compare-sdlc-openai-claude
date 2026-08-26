"""Tests for aisdlc.policy (org policy, project config, narrow-only merge)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.policy import (
    BudgetOverrides,
    CostLimitOverrides,
    CoverageOverrides,
    Direction,
    EvidenceOverrides,
    GateOverrides,
    ModelOverrides,
    OrgPolicy,
    PolicyLoadError,
    PolicyOverrides,
    PolicyViolationError,
    ProjectConfig,
    RiskClassification,
    RiskRule,
    SecurityOverrides,
    TestCommands,
    TierBehaviour,
    ToolTierOverrides,
    default_org_policy,
    default_project_config,
    dump_org_policy,
    dump_project_config,
    effective_policy,
    find_org_policy,
    find_project_config,
    is_tightening,
    load_org_policy,
    load_project_config,
    rule_for,
    validate_project_against_org,
)
from aisdlc.schema.models import GateDepth, GateId, ModelTier, RiskClass

REPO = Path(__file__).resolve().parents[1]


def test_templates_match_defaults() -> None:
    assert load_org_policy(REPO / "templates" / "org-policy.yaml") == default_org_policy()
    assert (
        load_project_config(REPO / "templates" / "project-config.yaml") == default_project_config()
    )


def test_org_defaults_match_plan() -> None:
    org = default_org_policy()
    cov = org.security_baselines.coverage
    assert (cov.lines, cov.lines_floor, cov.diff_lines, cov.branches, cov.critical_modules) == (
        80.0,
        75.0,
        90.0,
        70.0,
        90.0,
    )
    assert org.security_baselines.mutation_score == 0.60
    assert org.security_baselines.ambiguity_threshold == 0.20
    assert org.required_gates_for(RiskClass.DOCS_ONLY) == [GateId.G0, GateId.G2, GateId.G3]
    assert org.required_gates_for(RiskClass.AI_AGENT) == list(GateId)
    assert org.depth_for(RiskClass.HIGH) is GateDepth.DEEP
    assert org.tool_tiers.defaults[4] is TierBehaviour.HUMAN_APPROVAL
    assert org.tool_tiers.deny_on_timeout is True
    assert org.cost_limits.max_review_rounds == 3


def test_org_gate_lists_are_normalised() -> None:
    org = OrgPolicy.model_validate({"gates": {"required_gates": {"low": ["G3", "G0", "G3"]}}})
    assert org.gates.required_gates[RiskClass.LOW] == [GateId.G0, GateId.G3]
    assert org.required_gates_for(RiskClass.HIGH) == list(GateId)  # unspecified -> all
    assert OrgPolicy().depth_for(RiskClass.LOW) is GateDepth.LIGHT


def test_loaders_partial_and_errors(tmp_path: Path) -> None:
    partial = tmp_path / "org.yaml"
    partial.write_text("name: acme\ncost_limits:\n  max_agent_turns: 12\n")
    org = load_org_policy(partial)
    assert org.name == "acme" and org.cost_limits.max_agent_turns == 12
    assert org.cost_limits.max_tool_calls == 500
    (tmp_path / "empty.yaml").write_text("")
    assert load_org_policy(tmp_path / "empty.yaml") == OrgPolicy()
    (tmp_path / "bad.yaml").write_text("unknown_key: 1\n")
    with pytest.raises(PolicyLoadError, match="unknown_key"):
        load_org_policy(tmp_path / "bad.yaml")
    (tmp_path / "list.yaml").write_text("- a\n")
    with pytest.raises(PolicyLoadError, match="mapping"):
        load_org_policy(tmp_path / "list.yaml")
    (tmp_path / "broken.yaml").write_text("a: [\n")
    with pytest.raises(PolicyLoadError, match="invalid YAML"):
        load_org_policy(tmp_path / "broken.yaml")
    with pytest.raises(PolicyLoadError, match="not found"):
        load_org_policy(tmp_path / "missing.yaml")
    (tmp_path / "tier.yaml").write_text("tool_tiers:\n  defaults: {7: automatic}\n")
    with pytest.raises(PolicyLoadError, match="outside 0..4"):
        load_org_policy(tmp_path / "tier.yaml")

    proj = tmp_path / "project.yaml"
    proj.write_text(
        "name: svc\ncritical_modules: [src/auth]\noverrides:\n  cost_limits: {max_agent_turns: 5}\n"
    )
    cfg = load_project_config(proj)
    assert cfg.name == "svc" and cfg.overrides.cost_limits is not None
    with pytest.raises(PolicyLoadError):
        load_project_config(tmp_path / "list.yaml")
    with pytest.raises(PolicyLoadError):
        load_project_config(tmp_path / "broken.yaml")
    with pytest.raises(PolicyLoadError, match="not found"):
        load_project_config(tmp_path / "nope.yaml")
    (tmp_path / "badproj.yaml").write_text("overrides:\n  nope: 1\n")
    with pytest.raises(PolicyLoadError):
        load_project_config(tmp_path / "badproj.yaml")


def test_dump_round_trip(tmp_path: Path) -> None:
    org = OrgPolicy(name="x")
    (tmp_path / "o.yaml").write_text(dump_org_policy(org))
    assert load_org_policy(tmp_path / "o.yaml") == org
    cfg = ProjectConfig(
        name="p",
        overrides=PolicyOverrides(models=ModelOverrides(allowlist=["anthropic/claude-*"])),
    )
    (tmp_path / "p.yaml").write_text(dump_project_config(cfg))
    assert load_project_config(tmp_path / "p.yaml") == cfg


def test_find_policy_files(tmp_path: Path) -> None:
    assert find_org_policy(tmp_path) is None
    assert find_project_config(tmp_path) is None
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "org-policy.yaml").write_text("")
    assert find_org_policy(tmp_path) == tmp_path / "templates" / "org-policy.yaml"
    (tmp_path / "org-policy.yaml").write_text("")
    assert find_org_policy(tmp_path) == tmp_path / "org-policy.yaml"
    (tmp_path / ".aisdlc").mkdir()
    (tmp_path / ".aisdlc" / "project-config.yaml").write_text("")
    assert find_project_config(tmp_path) == tmp_path / ".aisdlc" / "project-config.yaml"
    assert find_org_policy(REPO) is not None


def test_risk_classification() -> None:
    rc = RiskClassification(
        default=RiskClass.LOW,
        rules=[
            RiskRule(pattern="docs/*", risk_class=RiskClass.DOCS_ONLY),
            RiskRule(pattern="src/auth/*", risk_class=RiskClass.HIGH),
            RiskRule(pattern="src/agents/*", risk_class=RiskClass.AI_AGENT),
        ],
    )
    assert rc.classify(["README.md"]) is RiskClass.LOW
    assert rc.classify(["docs/a.md"]) is RiskClass.DOCS_ONLY
    assert rc.classify(["docs/a.md", "src/auth/login.py"]) is RiskClass.HIGH
    assert rc.classify(["src/agents/x.py", "src/auth/y.py"]) is RiskClass.AI_AGENT
    assert rc.classify([]) is RiskClass.LOW


def test_project_helpers() -> None:
    cfg = ProjectConfig(critical_modules=["src/aisdlc/gates", "src/*/security/*"])
    assert cfg.is_critical("src/aisdlc/gates/gates.py")
    assert cfg.is_critical("src/x/security/a.py")
    assert not cfg.is_critical("src/aisdlc/cli/main.py")
    assert TestCommands(build=None, unit="pytest").defined() == {
        "unit": "pytest",
        "lint": "ruff check .",
        "types": "mypy",
    }
    assert PolicyOverrides().leaves() == {}


def test_effective_policy_applies_tightening() -> None:
    org = default_org_policy()
    project = ProjectConfig(
        name="tight",
        overrides=PolicyOverrides(
            gates=GateOverrides(
                required_gates={RiskClass.DOCS_ONLY: [GateId.G0, GateId.G2, GateId.G3, GateId.G4]},
                depth={RiskClass.LOW: GateDepth.DEEP},
            ),
            models=ModelOverrides(
                allowlist=["anthropic/claude-sonnet-4", "openai/gpt-5*"],
                max_tier_per_role={"implementer": ModelTier.LOW, "new_role": ModelTier.HIGH},
                escalation_allowed=False,
            ),
            tool_tiers=ToolTierOverrides(
                defaults={2: TierBehaviour.APPROVAL},
                approval_timeout_seconds=60,
                audit_from_tier=0,
                deny_on_timeout=True,
            ),
            cost_limits=CostLimitOverrides(
                budgets=BudgetOverrides(per_change_usd=20), max_agent_turns=10
            ),
            security_baselines=SecurityOverrides(
                coverage=CoverageOverrides(lines=90, branches=70),
                mutation_score=0.7,
                ambiguity_threshold=0.1,
                asr_threshold=0.01,
                require_sbom=True,
            ),
            evidence_standards=EvidenceOverrides(
                max_age_hours=24, signature_algorithms=["ed25519"], min_signatures=2
            ),
        ),
    )
    eff = effective_policy(org, project, strict=True)
    assert eff.is_clean
    assert eff.project.name == "tight"
    assert eff.required_gates_for(RiskClass.DOCS_ONLY) == [
        GateId.G0,
        GateId.G2,
        GateId.G3,
        GateId.G4,
    ]
    assert eff.required_gates_for(RiskClass.LOW) == org.required_gates_for(RiskClass.LOW)
    assert eff.depth_for(RiskClass.LOW) is GateDepth.DEEP
    assert eff.models.allowlist == ["anthropic/claude-sonnet-4", "openai/gpt-5*"]
    assert eff.model_allowed("openai/gpt-5-mini") and not eff.model_allowed("google/gemini-2")
    assert eff.max_tier_for("implementer") is ModelTier.LOW
    assert eff.max_tier_for("new_role") is ModelTier.HIGH
    assert eff.max_tier_for("planner") is ModelTier.HIGH
    assert eff.max_tier_for("unknown") is ModelTier.ESCALATION
    assert eff.models.escalation_allowed is False
    assert eff.tier_behaviour(2) is TierBehaviour.APPROVAL
    assert eff.tier_behaviour(3) is TierBehaviour.APPROVAL
    assert eff.tier_behaviour(9) is TierBehaviour.HUMAN_APPROVAL
    assert eff.tool_tiers.approval_timeout_seconds == 60 and eff.tool_tiers.audit_from_tier == 0
    assert (
        eff.cost_limits.budgets.per_change_usd == 20 and eff.cost_limits.budgets.per_task_usd == 5
    )
    assert eff.cost_limits.max_agent_turns == 10
    assert eff.security_baselines.coverage.lines == 90
    assert eff.security_baselines.coverage.diff_lines == 90
    assert eff.security_baselines.mutation_score == 0.7
    assert eff.evidence_standards.signature_algorithms == ["ed25519"]
    assert "cost_limits.budgets.per_change_usd" in eff.applied
    assert "security_baselines.coverage.branches" in eff.applied  # equal is allowed
    assert validate_project_against_org(org, project) == []


def test_effective_policy_rejects_weakening() -> None:
    org = default_org_policy()
    project = ProjectConfig(
        overrides=PolicyOverrides(
            gates=GateOverrides(
                required_gates={RiskClass.LOW: [GateId.G0]}, depth={RiskClass.HIGH: GateDepth.LIGHT}
            ),
            models=ModelOverrides(
                allowlist=["anthropic/*", "mistral/large"],
                independent_review_requires_different_family=False,
                max_tier_per_role={"verifier": ModelTier.HIGH},
                escalation_allowed=True,
            ),
            tool_tiers=ToolTierOverrides(
                defaults={4: TierBehaviour.AUTOMATIC},
                approval_timeout_seconds=900,
                deny_on_timeout=False,
                audit_from_tier=3,
            ),
            cost_limits=CostLimitOverrides(
                budgets=BudgetOverrides(per_day_usd=10_000), context_ceiling_tokens=400_000
            ),
            security_baselines=SecurityOverrides(
                coverage=CoverageOverrides(lines=50),
                mutation_score=0.1,
                ambiguity_threshold=0.9,
                max_critical_vulns=3,
                require_provenance=False,
                safety_trials_min=1,
            ),
            evidence_standards=EvidenceOverrides(
                max_age_hours=999,
                require_commit_sha=False,
                signature_algorithms=["md5"],
                min_signatures=0,
            ),
        ),
    )
    eff = effective_policy(org, project)
    assert not eff.is_clean
    paths = {v.path: v for v in eff.violations}
    expected = {
        "gates.required_gates.low": Direction.SUPERSET_ONLY,
        "gates.depth.high": Direction.RANK_UP_ONLY,
        "models.allowlist": Direction.SUBSET_ONLY,
        "models.independent_review_requires_different_family": Direction.TRUE_ONLY,
        "models.max_tier_per_role.verifier": Direction.RANK_DOWN_ONLY,
        "tool_tiers.defaults.4": Direction.RANK_UP_ONLY,
        "tool_tiers.approval_timeout_seconds": Direction.DECREASE_ONLY,
        "tool_tiers.deny_on_timeout": Direction.TRUE_ONLY,
        "tool_tiers.audit_from_tier": Direction.DECREASE_ONLY,
        "cost_limits.budgets.per_day_usd": Direction.DECREASE_ONLY,
        "cost_limits.context_ceiling_tokens": Direction.DECREASE_ONLY,
        "security_baselines.coverage.lines": Direction.INCREASE_ONLY,
        "security_baselines.mutation_score": Direction.INCREASE_ONLY,
        "security_baselines.ambiguity_threshold": Direction.DECREASE_ONLY,
        "security_baselines.max_critical_vulns": Direction.DECREASE_ONLY,
        "security_baselines.require_provenance": Direction.TRUE_ONLY,
        "security_baselines.safety_trials_min": Direction.INCREASE_ONLY,
        "evidence_standards.max_age_hours": Direction.DECREASE_ONLY,
        "evidence_standards.require_commit_sha": Direction.TRUE_ONLY,
        "evidence_standards.signature_algorithms": Direction.SUBSET_ONLY,
        "evidence_standards.min_signatures": Direction.INCREASE_ONLY,
    }
    assert {p: v.rule for p, v in paths.items()} == expected
    # escalation_allowed=True equals org -> applied, not a violation
    assert "models.escalation_allowed" in eff.applied
    # org values are kept for every violation
    assert eff == effective_policy(
        org,
        ProjectConfig(overrides=PolicyOverrides(models=ModelOverrides(escalation_allowed=True))),
    ).model_copy(update={"violations": eff.violations, "project": project, "applied": eff.applied})
    assert eff.required_gates_for(RiskClass.LOW) == org.required_gates_for(RiskClass.LOW)
    assert eff.security_baselines.coverage.lines == 80
    v = paths["cost_limits.budgets.per_day_usd"]
    assert v.org_value == 500.0 and v.project_value == 10_000 and "lower" in str(v)
    assert paths["gates.depth.high"].org_value == "deep"
    with pytest.raises(PolicyViolationError) as excinfo:
        effective_policy(org, project, strict=True)
    assert len(excinfo.value.violations) == len(expected)
    assert "weakens organization policy" in str(excinfo.value)


def test_rule_lookup_and_direction_semantics() -> None:
    assert rule_for("cost_limits.budgets.per_task_usd") is Direction.DECREASE_ONLY
    assert rule_for("gates.required_gates.ai_agent") is Direction.SUPERSET_ONLY
    assert rule_for("gates.required_gates") is None
    assert rule_for("nonexistent.path") is None
    assert is_tightening(Direction.DECREASE_ONLY, None, 5)  # org has no value -> constraint added
    assert is_tightening(Direction.TRUE_ONLY, False, False)
    assert not is_tightening(Direction.TRUE_ONLY, True, False)
    assert is_tightening(Direction.FALSE_ONLY, True, True)
    assert not is_tightening(Direction.FALSE_ONLY, False, True)
    assert is_tightening(Direction.SUBSET_ONLY, ["a/*"], ["a/b", "a/*"])
    assert not is_tightening(Direction.SUBSET_ONLY, ["a/b-*"], ["a/*"])
    assert is_tightening(Direction.RANK_UP_ONLY, "light", GateDepth.DEEP)
    assert is_tightening(Direction.RANK_DOWN_ONLY, ModelTier.HIGH, "low")
    with pytest.raises(TypeError, match="no rank"):
        is_tightening(Direction.RANK_UP_ONLY, "bogus", "deep")


def test_effective_policy_serialises() -> None:
    eff = effective_policy(default_org_policy(), default_project_config())
    data = eff.model_dump(mode="json")
    assert data["gates"]["required_gates"]["standard"] == [g.value for g in GateId]
    assert data["tool_tiers"]["defaults"]["0"] == "automatic"
    assert data["project"]["name"] == "project"
