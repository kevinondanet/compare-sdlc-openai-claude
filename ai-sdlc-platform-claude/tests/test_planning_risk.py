"""Risk classification table and gate depth profiles."""

from __future__ import annotations

import pytest

from aisdlc.planning import risk
from aisdlc.policy.org_policy import OrgPolicy
from aisdlc.policy.project_config import ProjectConfig, RiskClassification, RiskRule
from aisdlc.schema.models import (
    GateDepth,
    GateId,
    Intent,
    Kernel,
    Requirement,
    RiskClass,
    Scenario,
    ToolDataManifest,
)


def _intent(title: str, *, labels: list[str] | None = None, risk: RiskClass = RiskClass.STANDARD):
    return Intent(
        id="CHG-x", title=title, owner="kev", labels=labels or [], risk_class=risk, kernel=Kernel()
    )


def _req(num: int, text: str, tags: list[str] | None = None) -> Requirement:
    return Requirement(
        id=f"REQ-{num:03d}",
        text=text,
        tags=tags or [],
        scenarios=[Scenario(id=f"SCN-{num:03d}-01", when="x", then="y")],
    )


@pytest.mark.parametrize(
    ("title", "req_text", "paths", "expected"),
    [
        ("Update README", "The system SHALL document the CLI.", ["docs/cli.md"], "docs_only"),
        ("Fix typo in error message", "The system SHALL spell correctly.", [], "low"),
        ("Add pagination", "The system SHALL page results.", ["src/app/list.py"], "standard"),
        ("Add login MFA", "The system SHALL require MFA on login.", [], "high"),
        ("Charge cards", "The system SHALL process payments.", [], "critical"),
        ("Rotate keys", "The system SHALL rotate the signing key.", [], "critical"),
        ("Purge users", "The system SHALL drop table sessions nightly.", [], "critical"),
        ("Summarise tickets", "The system SHALL call an LLM to summarise.", [], "ai_agent"),
        ("Agent loop", "The system SHALL run the agent with tool calls.", [], "ai_agent"),
        ("Auth in agent dir", "The system SHALL log.", ["src/agents/loop.py"], "ai_agent"),
        ("Login path", "The system SHALL log.", ["src/app/auth/session.py"], "high"),
        ("Track requests", "The system SHALL log the user agent header.", [], "standard"),
        ("MFA prompt", "WHEN a user logs in, the system SHALL show a prompt.", [], "high"),
    ],
)
def test_classification_table(title: str, req_text: str, paths: list[str], expected: str) -> None:
    assessment = risk.classify(_intent(title), [_req(1, req_text)], ProjectConfig(), paths=paths)
    assert assessment.computed.value == expected, assessment.reasons


def test_manifest_forces_ai_agent_and_reasons_explain() -> None:
    manifest = ToolDataManifest(tools=["web_fetch"])
    assessment = risk.classify(
        _intent("Add pagination"), [_req(1, "The system SHALL page.")], ProjectConfig(), manifest
    )
    assert assessment.computed is RiskClass.AI_AGENT
    assert any("web_fetch" in r for r in assessment.reasons)
    assert assessment.escalated  # declared standard -> ai_agent


def test_declared_class_is_never_lowered() -> None:
    intent = _intent("Update README", risk=RiskClass.HIGH)
    assessment = risk.classify(intent, [_req(1, "The system SHALL document.")], paths=["docs/a.md"])
    assert assessment.computed is RiskClass.DOCS_ONLY
    assert assessment.effective is RiskClass.HIGH
    assert assessment.below_declared and not assessment.escalated
    assert any("declared risk class high is higher" in r for r in assessment.reasons)


def test_docs_only_needs_no_code_paths() -> None:
    intent = _intent("Docs refresh", labels=["docs"])
    assert risk.classify(intent, []).computed is RiskClass.DOCS_ONLY
    mixed = risk.classify(intent, [], paths=["docs/a.md", "src/x.py"])
    assert mixed.computed is RiskClass.STANDARD


def test_project_rules_and_critical_modules_and_default() -> None:
    config = ProjectConfig(
        risk_classification=RiskClassification(
            default=RiskClass.LOW,
            rules=[RiskRule(pattern="infra/*", risk_class=RiskClass.CRITICAL)],
        ),
        critical_modules=["src/core/"],
    )
    plain = risk.classify(_intent("Tidy"), [_req(1, "The system SHALL tidy.")], config)
    assert plain.computed is RiskClass.LOW
    assert "project default" in plain.reasons[0]
    ruled = risk.classify(_intent("Tidy"), [], config, paths=["infra/main.tf"])
    assert ruled.computed is RiskClass.CRITICAL
    critical = risk.classify(_intent("Tidy"), [], config, paths=["src/core/x.py"])
    assert critical.computed is RiskClass.HIGH


def test_is_docs_path() -> None:
    assert risk.is_docs_path("docs/guide.md")
    assert risk.is_docs_path("README.md")
    assert risk.is_docs_path("pkg/docs/x.rst")
    assert not risk.is_docs_path("src/x.py")


def test_max_risk() -> None:
    assert risk.max_risk(RiskClass.LOW, RiskClass.HIGH, RiskClass.STANDARD) is RiskClass.HIGH
    with pytest.raises(ValueError):
        risk.max_risk()


# -- gate depth profile ------------------------------------------------------------------


def test_profile_docs_only() -> None:
    profile = risk.gate_depth_profile(RiskClass.DOCS_ONLY)
    assert profile.required_gates == [GateId.G0, GateId.G2, GateId.G3]
    assert profile.depth_for(GateId.G0) is GateDepth.LIGHT
    assert profile.depth_for(GateId.G3) is GateDepth.LIGHT
    assert not profile.applies(GateId.G4)
    assert [c.value for c in profile.checks] == ["lint", "links"]
    assert not profile.require_threat_model and not profile.plan_approval_required
    assert profile.human_approvals_required == 0
    assert not profile.checkpoint_before_release


def test_profile_low_bug_fix() -> None:
    profile = risk.gate_depth_profile(RiskClass.LOW)
    # org policy: low -> [G0, G1, G2, G3, G6] at light depth
    assert profile.required_gates == [GateId.G0, GateId.G1, GateId.G2, GateId.G3, GateId.G6]
    assert profile.depth_for(GateId.G2) is GateDepth.LIGHT
    assert not profile.applies(GateId.G4) and not profile.applies(GateId.G5)
    assert not profile.delta_scan_only
    assert [c.value for c in profile.checks] == ["lint", "unit"]
    assert profile.coverage_lines_min is None  # light: exit codes only
    assert profile.mutation_score_min is None
    assert not profile.pyrit_campaign_required
    assert not profile.require_threat_model and not profile.plan_approval_required
    assert profile.human_approvals_required == 0
    assert profile.checkpoint_before_tier3 and profile.checkpoint_before_release


def test_profile_low_policy_can_add_light_security_gate() -> None:
    policy = OrgPolicy()
    policy.gates.required_gates[RiskClass.LOW] = [
        *policy.gates.required_gates[RiskClass.LOW],
        GateId.G4,
    ]
    profile = risk.gate_depth_profile(RiskClass.LOW, policy)
    assert profile.depth_for(GateId.G4) is GateDepth.LIGHT
    assert profile.delta_scan_only and profile.sast_required
    assert not profile.sbom_required and not profile.provenance_required


def test_profile_standard_all_gates_standard() -> None:
    profile = risk.gate_depth_profile(RiskClass.STANDARD)
    assert profile.required_gates == list(GateId)
    assert all(d is GateDepth.STANDARD for d in profile.depths.values())
    assert profile.coverage_lines_min == 75.0  # ratchet floor; the 80.0 target applies at deep
    assert profile.coverage_diff_lines_min == 90.0
    assert profile.mutation_score_min == 0.60
    assert profile.cross_family_review_required  # policy default requires different family
    assert profile.plan_approval_required  # human checkpoint before the first wave
    assert not profile.require_plan_approval  # G1 only demands approved_by at deep
    assert profile.human_approvals_required == 1
    assert profile.ambiguity_threshold == 0.20


def test_profile_high_and_critical_deep_cross_family() -> None:
    for cls, approvals in ((RiskClass.HIGH, 1), (RiskClass.CRITICAL, 2)):
        profile = risk.gate_depth_profile(cls)
        assert all(d is GateDepth.DEEP for d in profile.depths.values())
        assert profile.cross_family_review_required
        assert profile.require_adr and not profile.require_interfaces  # interfaces opt-in
        assert profile.require_plan_approval and profile.plan_approval_required
        assert profile.coverage_lines_min == 80.0 and profile.critical_modules_coverage_min == 90.0
        assert profile.human_approvals_required == approvals
        assert profile.performance_evidence_required
        assert not profile.pyrit_campaign_required


def test_profile_ai_agent_adds_pyrit_safety_manifest() -> None:
    profile = risk.gate_depth_profile(RiskClass.AI_AGENT)
    trials = OrgPolicy().security_baselines.safety_trials_min
    assert profile.pyrit_campaign_required and profile.pyrit_trials_min == trials
    assert profile.human_approvals_required == 2
    assert profile.safety_regression_required and profile.safety_trials_min == 5
    assert profile.manifest_validation_required
    assert profile.asr_threshold == 0.05 and profile.max_undetermined_rate == 0.10


def test_profile_policy_can_only_deepen() -> None:
    policy = OrgPolicy()
    policy.gates.required_gates[RiskClass.DOCS_ONLY] = [GateId.G0, GateId.G2, GateId.G3, GateId.G4]
    policy.gates.depth[RiskClass.DOCS_ONLY] = GateDepth.STANDARD
    profile = risk.gate_depth_profile(RiskClass.DOCS_ONLY, policy)
    assert profile.depth_for(GateId.G4) is GateDepth.STANDARD
    assert profile.depth_for(GateId.G0) is GateDepth.STANDARD
    assert not profile.applies(GateId.G5)
    # thresholds come from the policy
    policy.security_baselines.ambiguity_threshold = 0.05
    assert risk.gate_depth_profile(RiskClass.STANDARD, policy).ambiguity_threshold == 0.05


def test_profile_is_plain_pydantic_and_serialisable() -> None:
    profile = risk.gate_depth_profile(RiskClass.HIGH)
    data = profile.model_dump(mode="json")
    assert data["depths"]["G4"] == "deep"
    assert risk.GateDepthProfile.model_validate(data) == profile


def test_manifest_data_source_alone_does_not_imply_ai_agent() -> None:
    """ARCHITECTURE §3: ai_agent needs tools or model calls; a data source is not agentic."""
    intent = _intent("Add health endpoint")
    reqs = [_req(1, "The system SHALL report dependency status.")]
    plain = ToolDataManifest(data_sources=["orders database (ping only)"])
    assessment = risk.classify(intent, reqs, ProjectConfig(), plain)
    assert assessment.computed is RiskClass.STANDARD and not assessment.escalated
    assert not any(s.risk_class is RiskClass.AI_AGENT for s in assessment.signals)
    assert any("does not make the change agentic" in r for r in assessment.reasons)

    sensitive = ToolDataManifest(data_sources=["customer_db", "payments service"])
    assessment = risk.classify(intent, reqs, ProjectConfig(), sensitive)
    assert assessment.computed is RiskClass.HIGH
    high = {s.matched for s in assessment.signals if s.risk_class is RiskClass.HIGH}
    assert high == {"customer_db", "payments service"}
    assert risk.is_sensitive_data_source("assistant/data/customers.json (private records)")
    assert not risk.is_sensitive_data_source("dashboard metrics")  # 'card' is not a token

    # a data source never lowers a declared class either
    declared_high = risk.classify(
        _intent("Add health endpoint", risk=RiskClass.HIGH), reqs, ProjectConfig(), plain
    )
    assert declared_high.effective is RiskClass.HIGH and not declared_high.escalated


def test_manifest_egress_is_ai_agent_only_for_model_providers() -> None:
    intent = _intent("Summaries")
    reqs = [_req(1, "The system SHALL summarise tickets nightly.")]
    provider = ToolDataManifest(network_egress=["api.anthropic.com"])
    assessment = risk.classify(intent, reqs, ProjectConfig(), provider)
    assert assessment.computed is RiskClass.AI_AGENT
    assert any("model provider" in r for r in assessment.reasons)

    plain = ToolDataManifest(network_egress=["api.github.com", "https://hooks.example.com:8443/x"])
    assessment = risk.classify(intent, reqs, ProjectConfig(), plain)
    assert assessment.computed is RiskClass.STANDARD
    assert not any(s.risk_class is RiskClass.AI_AGENT for s in assessment.signals)

    assert risk.is_llm_provider_host("https://eu.api.openai.azure.com/v1")
    assert risk.is_llm_provider_host("bedrock-runtime.eu-west-1.amazonaws.com:443")
    assert not risk.is_llm_provider_host("api.github.com")
    assert not risk.is_llm_provider_host("")

    tools = ToolDataManifest(tools=["lookup_order"], data_sources=["orders database"])
    assert risk.classify(intent, reqs, ProjectConfig(), tools).computed is RiskClass.AI_AGENT


def test_constraints_and_non_goals_are_not_scanned_for_risk_keywords() -> None:
    """A constraint saying what must NOT happen is not a signal that the change does it."""
    intent = Intent(
        id="CHG-x",
        title="Add health endpoint",
        owner="kev",
        risk_class=RiskClass.STANDARD,
        kernel=Kernel(
            why="Operators need a liveness probe.",
            capabilities=["Expose GET /health returning dependency status."],
            constraints=["Must not expose connection strings or credentials."],
            non_goals=["No changes to payments or IAM."],
            success_signal="Probe answers within 200 ms.",
        ),
    )
    reqs = [_req(1, "The system SHALL report dependency status.")]
    assessment = risk.classify(intent, reqs, ProjectConfig())
    assert assessment.computed is RiskClass.STANDARD, assessment.reasons
    assert not any(s.source == "intent" for s in assessment.signals)

    # the same words in a capability (what the change DOES) still escalate
    doing = intent.model_copy(
        update={"kernel": Kernel(capabilities=["Rotate database credentials nightly."])}
    )
    assert risk.classify(doing, reqs, ProjectConfig()).computed is RiskClass.CRITICAL
