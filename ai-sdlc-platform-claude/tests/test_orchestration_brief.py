"""AgentBrief construction, rendering, size enforcement; role profiles."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.control_plane.routing import Complexity, RoutingDecision, RoutingTier
from aisdlc.governance.policy import validate_policy_yaml
from aisdlc.governance.tiers import RiskTier
from aisdlc.orchestration.brief import (
    TRUNCATION_ORDER,
    AgentBrief,
    OutputContract,
    brief_to_json,
    build_brief,
    enforce_size,
    estimate_tokens,
    relevant_decisions,
    relevant_interfaces,
)
from aisdlc.orchestration.roles import (
    ROLE_PROFILES,
    AgentRole,
    default_complexity,
    default_tool_tier,
    orchestration_policy_spec,
    profile_for,
    role_spec,
)
from aisdlc.schema.models import (
    ArchitectureDecision,
    Interface,
    Task,
    Verification,
)
from tests.orchestration_support import make_package


def _routing() -> RoutingDecision:
    return RoutingDecision(
        model="claude-sonnet-5",
        provider="anthropic",
        family="claude",
        tier=RoutingTier.standard,
        reason="r",
        estimated_cost_per_1k=0.001,
        estimated_task_cost_usd=0.01,
    )


# --------------------------------------------------------------------------------------
# roles
# --------------------------------------------------------------------------------------


def test_role_profiles_cover_every_role() -> None:
    assert set(ROLE_PROFILES) == set(AgentRole)
    assert default_tool_tier(AgentRole.IMPLEMENTER) is RiskTier.APPROVAL
    assert default_tool_tier("plan_checker") is RiskTier.AUTOMATIC
    assert default_complexity(AgentRole.PLANNER) is Complexity.high
    assert default_complexity(AgentRole.VERIFIER) is Complexity.low
    assert all(p.max_tool_tier < RiskTier.HUMAN_APPROVAL for p in ROLE_PROFILES.values())
    assert profile_for("reviewer").allowed_actions[0] == "read"
    spec = role_spec(AgentRole.IMPLEMENTER)
    assert spec.role == "implementer" and "modify_shared_state" in spec.allowed_actions
    assert spec.max_tier is RiskTier.APPROVAL and spec.approvers == ["tech-lead"]


def test_orchestration_policy_spec_renders_valid_agt_policies() -> None:
    pytest.importorskip("agentmesh")
    from aisdlc.governance.policy import render_all_policies

    spec = orchestration_policy_spec(workspace_roots=["/wt"], allowed_egress_hosts=["pypi.org"])
    docs = render_all_policies(spec)
    assert set(docs) == {r.value for r in AgentRole}
    for text in docs.values():
        assert validate_policy_yaml(text) == []


# --------------------------------------------------------------------------------------
# brief building
# --------------------------------------------------------------------------------------


def test_build_brief_contains_only_task_scoped_material(tmp_repo: Path) -> None:
    pkg = make_package(tmp_repo)
    task = pkg.task("TASK-003")
    assert task is not None
    brief = build_brief(
        pkg,
        task,
        routing=_routing(),
        worktree="/wt/TASK-003",
        constraints=["Extra rule"],
        context=["Previous round failed"],
        context_ceiling_tokens=200_000,
    )
    assert brief.change_id == "CHG-demo" and brief.role is AgentRole.IMPLEMENTER
    assert [r.id for r in brief.requirements] == ["REQ-001", "REQ-002"]
    assert brief.requirements[0].scenarios == [
        "WHEN a task runs THEN a marker file named after the task exists"
    ]
    assert brief.verification == Verification(command="test -f TASK-003.dryrun")
    assert brief.allowed_tool_tier is RiskTier.APPROVAL
    assert brief.max_tokens == 50_000 and brief.worktree == "/wt/TASK-003"
    assert brief.interfaces and brief.interfaces[0].startswith("IFC-001 MarkerStore")
    assert brief.decisions and brief.decisions[0].startswith("ADR-0001 Use marker files")
    text = brief.render_markdown()
    for expected in (
        "# Implementer brief — TASK-003",
        "The system SHALL write a marker file",
        "WHEN a task runs THEN",
        "Depends on: TASK-001, TASK-002",
        "`test -f TASK-003.dryrun`",
        "Extra rule",
        "Constraint: Keep changes small",
        "Non-goal (do not do this): No UI work",
        "Previous round failed",
        "Model: `claude-sonnet-5`",
        "Allowed tool tier: 3",
        "Only modify files inside the worktree `/wt/TASK-003`",
        "## Output contract",
        "`status`: success | failed | blocked",
    ):
        assert expected in text, expected
    assert "conversation" not in text.lower() and "history" not in text.lower()
    assert brief.warnings == [] and brief.truncated == []
    assert brief.model == "claude-sonnet-5"
    # deterministic hash ignores routing/warnings
    other = build_brief(
        pkg,
        task,
        routing=None,
        worktree="/wt/TASK-003",
        constraints=["Extra rule"],
        context=["Previous round failed"],
    )
    assert other.content_hash() == brief.content_hash()
    assert '"change_id": "CHG-demo"' in brief_to_json(brief)


def test_relevance_filters_by_mention(tmp_repo: Path) -> None:
    interfaces = [
        Interface(id="IFC-001", name="Alpha", description="a"),
        Interface(id="IFC-002", name="Beta", description="b"),
    ]
    decisions = [
        ArchitectureDecision(id="ADR-0001", title="Use Alpha", decision="x"),
        ArchitectureDecision(id="ADR-0002", title="Deprecated thing", status="deprecated"),
    ]
    task = Task(id="TASK-001", title="Wire IFC-002 into Beta")
    assert [i.split()[0] for i in relevant_interfaces(interfaces, task, [])] == ["IFC-002"]
    assert [d.split()[0] for d in relevant_decisions(decisions, task, [])] == ["ADR-0001"]
    generic = Task(id="TASK-002", title="unrelated")
    assert len(relevant_interfaces(interfaces, generic, [])) == 2  # fall back to all
    mentioned = Task(id="TASK-003", title="see ADR-0002")
    assert [d.split()[0] for d in relevant_decisions(decisions, mentioned, [])] == ["ADR-0002"]


def test_enforce_size_truncates_low_priority_sections_deterministically() -> None:
    long = "x" * 2000
    brief = AgentBrief(
        change_id="CHG-demo",
        task=Task(id="TASK-001", title="t", description="d" * 3000),
        decisions=[f"ADR-{i} {long}" for i in range(5)],
        interfaces=[f"IFC-{i} {long}" for i in range(5)],
        context=[long, long],
        max_tokens=2500,
    )
    assert brief.estimated_tokens > brief.max_tokens
    first = enforce_size(brief.model_copy(deep=True))
    second = enforce_size(brief.model_copy(deep=True))
    assert first.render_markdown() == second.render_markdown()
    assert first.estimated_tokens <= first.max_tokens
    assert first.decisions == [] and 0 < len(first.interfaces) < 5  # lowest priority first
    assert first.context == [long, long]  # higher-priority context untouched
    assert first.truncated == list(TRUNCATION_ORDER[:2])
    assert first.warnings and "truncated sections" in first.warnings[0]
    assert "## Brief warnings" in first.render_markdown()
    assert first.task.description  # task text survives (possibly clipped)
    tiny = AgentBrief(change_id="CHG-demo", task=Task(id="TASK-001", title="t"), max_tokens=100)
    enforced = enforce_size(tiny)
    assert any("still exceeds" in w for w in enforced.warnings)


def test_build_brief_budget_from_policy_ceiling(tmp_repo: Path) -> None:
    pkg = make_package(tmp_repo)
    task = pkg.task("TASK-001")
    assert task is not None
    brief = build_brief(pkg, task, context_ceiling_tokens=4000, brief_share=0.5)
    assert brief.max_tokens == 2000
    explicit = build_brief(pkg, task, max_tokens=150, role="reviewer", allowed_tool_tier=1)
    assert explicit.max_tokens == 150 and explicit.role is AgentRole.REVIEWER
    assert explicit.allowed_tool_tier is RiskTier.AUTOMATIC_AUDIT
    assert explicit.truncated and explicit.estimated_tokens <= 150 or explicit.warnings


def test_estimate_tokens_and_contract() -> None:
    assert (
        estimate_tokens("") == 0 and estimate_tokens("abcd") == 1 and estimate_tokens("abcde") == 2
    )
    contract = OutputContract()
    rendered = contract.render()
    assert "`findings`" in rendered and "final line" in rendered
