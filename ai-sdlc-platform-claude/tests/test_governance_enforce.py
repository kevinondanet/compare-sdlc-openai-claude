"""PolicyEnforcer and govern() wrapper against the real AGT engine (offline)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aisdlc.governance.audit import AuditTrail
from aisdlc.governance.enforce import (
    ApprovalOutcome,
    ApprovalRequestInfo,
    EnforcementDecision,
    PlatformDenied,
    PolicyEnforcer,
    govern_callable,
)
from aisdlc.governance.policy import PolicySpec, render_policy_yaml
from aisdlc.governance.tiers import RiskTier, TierConfig, ToolAction, classify_action

pytestmark = pytest.mark.integration
agentmesh = pytest.importorskip("agentmesh")


@pytest.fixture
def spec() -> PolicySpec:
    return PolicySpec(workspace_roots=["/wt/c1"], allowed_egress_hosts=["pypi.org"])


@pytest.fixture
def cfg(spec: PolicySpec) -> TierConfig:
    return spec.effective_tier_config()


@pytest.fixture
def policy_text(spec: PolicySpec) -> str:
    return render_policy_yaml(spec, "implementer")


def _action(cfg: TierConfig, action_type: str, resource: str = "x") -> ToolAction:
    return classify_action("tool", action_type, resource, config=cfg)


def test_allow_tier0_not_audited(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(policy_text, "implementer", tier_config=cfg)
    decision = enforcer.check(_action(cfg, "read", "/wt/c1/a.py"))
    assert decision.allowed and decision.policy_action == "allow"
    assert decision.tier == RiskTier.AUTOMATIC and decision.audit_entry_id is None
    assert enforcer.audit.entries() == []


def test_log_rule_is_allowed_and_audited(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(policy_text, "implementer", tier_config=cfg)
    decision = enforcer.check(_action(cfg, "write", "/wt/c1/a.py"))
    assert decision.allowed and decision.policy_action == "log"
    assert decision.matched_rule == "audit-tier-1" and decision.audit_entry_id
    entries = enforcer.audit.entries()
    assert len(entries) == 1 and entries[0]["outcome"] == "allowed" and entries[0]["tier"] == 1
    decision2 = enforcer.check(_action(cfg, "run_tests", "pytest"))
    assert decision2.allowed and decision2.tier == RiskTier.POLICY_CONTROLLED
    assert len(enforcer.audit.entries()) == 2


def test_deny_tier4_raises_platform_denied(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(policy_text, "implementer", tier_config=cfg)
    action = _action(cfg, "deploy", "prod")
    decision = enforcer.check(action)
    assert not decision.allowed and decision.matched_rule == "deny-tier-4"
    with pytest.raises(PlatformDenied) as excinfo:
        enforcer.enforce(action)
    assert excinfo.value.decision.matched_rule == "deny-tier-4"
    assert "deny-tier-4" in str(excinfo.value)
    from agentmesh.governance import GovernanceDenied

    assert isinstance(excinfo.value, GovernanceDenied)
    assert enforcer.audit.entries()[-1]["outcome"] == "denied"


def test_require_approval_without_handler_auto_rejects(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(policy_text, "implementer", tier_config=cfg)
    decision = enforcer.check(_action(cfg, "git_push", "origin"))
    assert not decision.allowed and decision.approval_requested
    assert decision.approver == "system:auto-reject" and decision.policy_action == "deny"
    assert decision.matched_rule == "approve-tier-3"
    assert enforcer.audit.entries()[-1]["outcome"] == "denied"


def test_require_approval_with_callback(policy_text: str, cfg: TierConfig) -> None:
    seen: list[ApprovalRequestInfo] = []

    def approve(req: ApprovalRequestInfo) -> ApprovalOutcome:
        seen.append(req)
        return ApprovalOutcome(
            approved=req.action.action_type == "git_push", approver="lead", reason="ok"
        )

    enforcer = PolicyEnforcer(policy_text, "implementer", approval_handler=approve, tier_config=cfg)
    pushed = enforcer.check(_action(cfg, "git_push", "origin"))
    assert pushed.allowed and pushed.approver == "lead" and pushed.approval_requested
    assert seen[0].rule_name == "approve-tier-3" and seen[0].approvers == ["tech-lead"]
    assert seen[0].action.resource == "origin"
    assert enforcer.audit.entries()[-1]["outcome"] == "approved"
    pr = enforcer.check(_action(cfg, "create_pr", "main"))
    assert not pr.allowed and pr.approver == "lead"


def test_boolean_callback_is_accepted(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(
        policy_text, "implementer", approval_handler=lambda req: True, tier_config=cfg
    )
    assert enforcer.check(_action(cfg, "git_push", "origin")).allowed


def test_approval_timeout_denies(policy_text: str, cfg: TierConfig) -> None:
    def slow(req: ApprovalRequestInfo) -> ApprovalOutcome:
        time.sleep(0.03)
        return ApprovalOutcome(approved=True, approver="lead")

    enforcer = PolicyEnforcer(
        policy_text,
        "implementer",
        approval_handler=slow,
        approval_timeout_seconds=0.001,
        tier_config=cfg,
    )
    decision = enforcer.check(_action(cfg, "git_push", "origin"))
    assert not decision.allowed and decision.approver == "system:timeout"
    assert "timed out" in decision.reason


def test_approval_callback_error_denies(policy_text: str, cfg: TierConfig) -> None:
    def broken(req: ApprovalRequestInfo) -> ApprovalOutcome:
        raise RuntimeError("boom")

    enforcer = PolicyEnforcer(policy_text, "implementer", approval_handler=broken, tier_config=cfg)
    decision = enforcer.check(_action(cfg, "git_push", "origin"))
    assert not decision.allowed and decision.approver == "system:error"


def test_native_agt_handler_is_accepted(policy_text: str, cfg: TierConfig) -> None:
    from agentmesh.governance import ApprovalDecision, CallbackApproval

    handler = CallbackApproval(lambda req: ApprovalDecision(approved=True, approver="agt"))
    enforcer = PolicyEnforcer(policy_text, "implementer", approval_handler=handler, tier_config=cfg)
    assert enforcer.check(_action(cfg, "git_push", "origin")).approver == "agt"
    with pytest.raises(TypeError):
        PolicyEnforcer(policy_text, "implementer", approval_handler=42)


def test_wrong_agent_id_fails_closed(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(policy_text, "somebody-else", tier_config=cfg)
    decision = enforcer.check(_action(cfg, "read", "/wt/c1/a.py"))
    assert not decision.allowed and decision.matched_rule is None


def test_shadow_mode_records_without_blocking(policy_text: str, cfg: TierConfig) -> None:
    calls: list[str] = []
    enforcer = PolicyEnforcer(
        policy_text,
        "implementer",
        shadow=True,
        tier_config=cfg,
        approval_handler=lambda r: calls.append("x"),
    )
    # Tier 4 has no dry run: deploy is denied even in shadow mode (and audited as such).
    with pytest.raises(PlatformDenied):
        enforcer.enforce(_action(cfg, "deploy", "prod"))
    denied = enforcer.check(_action(cfg, "deploy", "prod"))
    assert not denied.allowed and denied.shadow
    # Tier 3 in shadow: reported (approval would be required) but not blocked.
    approval = enforcer.enforce(_action(cfg, "git_push", "origin"))
    assert not approval.allowed and approval.approval_requested and "[shadow]" in approval.reason
    assert calls == []  # shadow never consults the approval handler
    assert all(e["outcome"].startswith("shadow:") for e in enforcer.audit.entries())


def test_enforcer_from_file_and_multiple_sources(
    tmp_path: Path, spec: PolicySpec, cfg: TierConfig
) -> None:
    impl = tmp_path / "implementer.yaml"
    impl.write_text(render_policy_yaml(spec, "implementer"), encoding="utf-8")
    rev = tmp_path / "reviewer.yaml"
    rev.write_text(render_policy_yaml(spec, "reviewer"), encoding="utf-8")
    enforcer = PolicyEnforcer([impl, str(rev)], "reviewer", tier_config=cfg)
    assert enforcer.check(_action(cfg, "run_tests", "pytest")).allowed
    assert not enforcer.check(_action(cfg, "write", "/wt/c1/a.py")).allowed
    assert enforcer.check(_action(cfg, "write", "/wt/c1/a.py")).matched_rule == "deny-scope-write"
    with pytest.raises(ValueError):
        enforcer.govern_callable(lambda: None, action=_action(cfg, "read"))
    assert enforcer.classify("Read", "read", "/wt/c1/a.py").tier == RiskTier.AUTOMATIC


def test_govern_callable_paths(policy_text: str, cfg: TierConfig) -> None:
    trail = AuditTrail()
    log: list[str] = []

    def push(remote: str) -> str:
        log.append(remote)
        return f"pushed {remote}"

    governed = govern_callable(
        push,
        policy=policy_text,
        agent_id="implementer",
        action=lambda remote: classify_action("Bash", "git_push", remote, config=cfg),
        approval_handler=lambda req: ApprovalOutcome(approved=True, approver="lead"),
        audit_sink=trail,
    )
    assert governed("origin") == "pushed origin"
    assert governed.last_decision is not None
    assert governed.last_decision.approver == "lead" and governed.last_decision.allowed
    assert governed.__name__ == "push"

    write = govern_callable(
        lambda path: "written",
        policy=policy_text,
        agent_id="implementer",
        action=lambda path: classify_action("Write", "write", path, config=cfg),
        audit_sink=trail,
    )
    assert write("/wt/c1/a.py") == "written"  # log rule -> call through
    assert write.last_decision is not None and write.last_decision.policy_action == "log"
    with pytest.raises(PlatformDenied) as excinfo:
        write("/etc/hosts")  # tier 3, no handler -> auto-reject
    assert excinfo.value.decision.approval_requested
    assert excinfo.value.policy_decision is not None

    read = govern_callable(
        lambda: "content",
        policy=policy_text,
        agent_id="implementer",
        action=classify_action("Read", "read", "/wt/c1/a.py", config=cfg),
        audit_sink=trail,
    )
    assert read() == "content"
    deploy = govern_callable(
        lambda: "deployed",
        policy=policy_text,
        agent_id="implementer",
        action=classify_action("Bash", "deploy", "prod", config=cfg),
        audit_sink=trail,
    )
    with pytest.raises(PlatformDenied):
        deploy()
    shadow_deploy = govern_callable(
        lambda: "deployed",
        policy=policy_text,
        agent_id="implementer",
        action=classify_action("Bash", "deploy", "prod", config=cfg),
        audit_sink=trail,
        shadow=True,
    )
    with pytest.raises(PlatformDenied):  # tier 4 stays enforced in shadow mode
        shadow_deploy()
    assert shadow_deploy.last_decision is not None and shadow_deploy.last_decision.shadow
    shadow_push = govern_callable(
        lambda: "pushed",
        policy=policy_text,
        agent_id="implementer",
        action=classify_action("Bash", "git_push", "origin", config=cfg),
        audit_sink=trail,
        shadow=True,
    )
    assert shadow_push() == "pushed"  # tier 3 in shadow: recorded, not blocked
    assert shadow_push.last_decision is not None and shadow_push.last_decision.shadow
    outcomes = [e["outcome"] for e in trail.entries()]
    assert "approved" in outcomes and "denied" in outcomes and "shadow:denied" in outcomes
    assert "shadow:approval_pending" in outcomes
    assert trail.verify_integrity().ok


def test_enforcer_govern_callable_method(policy_text: str, cfg: TierConfig) -> None:
    enforcer = PolicyEnforcer(policy_text, "implementer", tier_config=cfg)
    governed = enforcer.govern_callable(lambda: 1, action=_action(cfg, "run_tests", "pytest"))
    assert governed() == 1
    assert enforcer.audit.entries()[-1]["action"] == "run_tests"


def test_decision_model_is_strict() -> None:
    with pytest.raises(ValueError):
        EnforcementDecision(
            allowed=True,
            action=ToolAction(tool_name="t", action_type="read", tier=0, scope="read"),
            tier=0,
            policy_action="allow",
            agent_id="a",
            bogus=1,  # type: ignore[call-arg]
        )


def test_enforcer_classifies_credential_reads_at_tier_4_and_denies(
    policy_text: str, cfg: TierConfig
) -> None:
    enforcer = PolicyEnforcer(policy_text, "implementer", tier_config=cfg)
    for tool in ("Read", "Grep", "mcp__filesystem__read_file"):
        action = enforcer.classify(tool, "read", "/Users/me/.aws/credentials")
        assert action.tier == RiskTier.HUMAN_APPROVAL and action.action_type == "read"
        decision = enforcer.check(action)
        assert not decision.allowed and decision.policy_action == "deny"
        assert decision.matched_rule == "deny-tier-4"
    # parameters alone are enough (multi-path MCP tool with an innocuous resource)
    hidden = enforcer.classify(
        "mcp__filesystem__read_multiple_files",
        "read",
        "read_multiple_files",
        {"paths": ["/wt/c1/README.md", "/wt/c1/.env"]},
    )
    assert hidden.tier == RiskTier.HUMAN_APPROVAL
    with pytest.raises(PlatformDenied):
        enforcer.enforce(hidden)
    # the same read of a benign file stays tier 0 and allowed
    benign = enforcer.classify("Read", "read", "/wt/c1/README.md")
    assert benign.tier == RiskTier.AUTOMATIC and enforcer.check(benign).allowed
