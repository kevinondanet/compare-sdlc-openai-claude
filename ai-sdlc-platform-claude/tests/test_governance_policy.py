"""Policy generation validated against the real AGT PolicyEngine (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aisdlc.governance.policy import (
    API_VERSION,
    PolicySpec,
    RoleSpec,
    build_policy_document,
    default_roles,
    load_policy_engine,
    render_all_policies,
    render_policy_yaml,
    template_spec,
    validate_policy_yaml,
    write_policies,
)
from aisdlc.governance.tiers import RiskTier, TierConfig, classify_action

pytestmark = pytest.mark.integration
agentmesh = pytest.importorskip("agentmesh")


@pytest.fixture
def spec() -> PolicySpec:
    return PolicySpec(workspace_roots=["/wt/c1"], allowed_egress_hosts=["pypi.org", "*.github.com"])


def test_document_shape(spec: PolicySpec) -> None:
    doc = build_policy_document(spec, "implementer")
    assert doc["apiVersion"] == API_VERSION
    assert doc["default_action"] == "deny"
    assert doc["agents"] == ["implementer"]
    names = [r["name"] for r in doc["rules"]]
    assert names[0] == "deny-tier-4"
    assert "approve-tier-3" in names and "audit-tier-1" in names and "allow-tier-0" in names
    by_name = {r["name"]: r for r in doc["rules"]}
    assert by_name["deny-tier-4"]["action"] == "deny"
    assert by_name["approve-tier-3"]["action"] == "require_approval"
    assert by_name["approve-tier-3"]["approvers"] == ["tech-lead"]
    assert by_name["audit-tier-1"]["action"] == "log"
    assert by_name["audit-tier-2"]["action"] == "log"
    assert by_name["allow-tier-0"]["action"] == "allow"
    # priorities strictly descending so priority_first_match is deterministic
    priorities = [r["priority"] for r in doc["rules"]]
    assert priorities == sorted(priorities, reverse=True) and len(set(priorities)) == len(
        priorities
    )


def test_read_only_roles_deny_other_scopes(spec: PolicySpec) -> None:
    names = {r["name"] for r in build_policy_document(spec, "reviewer")["rules"]}
    assert {"deny-scope-write", "deny-scope-network", "deny-scope-admin"} <= names
    assert "deny-scope-execute" not in names  # reviewer may run verification
    assert "deny-above-tier-2" in names


def test_every_role_validates_with_agt(spec: PolicySpec) -> None:
    for role, text in render_all_policies(spec).items():
        assert validate_policy_yaml(text) == [], role
        loaded = yaml.safe_load(text)
        assert loaded["name"] == f"aisdlc-{role}"


def test_validate_rejects_bad_documents() -> None:
    assert validate_policy_yaml("not: [valid") != []
    errors = validate_policy_yaml(
        "apiVersion: governance.toolkit/v1\nname: x\ndefault_action: allow\nrules: []\n"
    )
    assert any("default_action" in e for e in errors)
    assert any("tier 4" in e for e in errors)
    errors = validate_policy_yaml(
        "apiVersion: governance.toolkit/v9\nname: x\ndefault_action: deny\nrules: []\n"
    )
    assert any("apiVersion" in e for e in errors)
    errors = validate_policy_yaml(
        "apiVersion: governance.toolkit/v1\nname: x\ndefault_action: deny\n"
        "rules:\n  - name: a\n    condition: 'action.tier >= 4'\n    action: deny\n"
        "  - name: b\n    condition: 'x'\n    action: explode\n"
    )
    assert any("invalid action" in e for e in errors)


def test_engine_evaluation_matrix(spec: PolicySpec) -> None:
    cfg = spec.effective_tier_config()
    engine = load_policy_engine([render_policy_yaml(spec, "implementer")])
    expectations = [
        ("read", "/wt/c1/a.py", "allow", "allow-tier-0"),
        ("write", "/wt/c1/a.py", "log", "audit-tier-1"),
        ("write", "/etc/hosts", "require_approval", "approve-tier-3"),
        ("run_tests", "pytest", "log", "audit-tier-2"),
        ("git_push", "origin", "require_approval", "approve-tier-3"),
        ("deploy", "prod", "deny", "deny-tier-4"),
        ("network_egress", "https://pypi.org/x", "log", "audit-listed-egress"),
        ("network_egress", "https://evil.io/x", "deny", "deny-tier-4"),
    ]
    for action_type, resource, expected_action, expected_rule in expectations:
        action = classify_action("tool", action_type, resource, config=cfg)
        decision = engine.evaluate("implementer", action.to_context(), stage="pre_tool")
        assert decision.action == expected_action, (action_type, resource, decision)
        assert decision.matched_rule == expected_rule, (action_type, resource, decision)
    # unknown action type falls through to default deny
    decision = engine.evaluate(
        "implementer", classify_action("t", "frobnicate", None, config=cfg).to_context()
    )
    assert decision.action == "deny" and decision.matched_rule is None
    # other agent ids are not covered by this policy -> fail closed
    assert not engine.evaluate("reviewer", {"action": {"type": "read", "tier": 0}}).allowed


def test_unlisted_egress_denied_even_if_tier_is_forged(spec: PolicySpec) -> None:
    engine = load_policy_engine([render_policy_yaml(spec, "implementer")])
    ctx = {
        "action": {"type": "network_egress", "tier": 2, "egress_unlisted": True, "scope": "network"}
    }
    decision = engine.evaluate("implementer", ctx)
    assert decision.action == "deny" and decision.matched_rule == "deny-unlisted-egress"


def test_custom_role_and_tier_actions() -> None:
    spec = PolicySpec(
        roles=[RoleSpec(role="bot", allowed_actions=["read", "write"], max_tier=1)],
        tier_actions={1: "warn", 3: "deny"},
    )
    text = render_policy_yaml(spec, "bot")
    assert validate_policy_yaml(text) == []
    engine = load_policy_engine([text])
    ctx = classify_action("t", "write", "x", config=TierConfig(), in_worktree=True).to_context()
    assert engine.evaluate("bot", ctx).action == "warn"
    with pytest.raises(ValueError):
        PolicySpec(tier_actions={4: "allow"})
    with pytest.raises(ValueError):
        PolicySpec(tier_actions={3: "log"})
    with pytest.raises(KeyError):
        spec.role("missing")


def test_write_policies_and_load_from_files(tmp_path: Path, spec: PolicySpec) -> None:
    paths = write_policies(spec, tmp_path)
    assert {p.name for p in paths} == {f"{r.role}.yaml" for r in default_roles()}
    engine = load_policy_engine(paths)
    assert set(engine.list_policies()) == {f"aisdlc-{r.role}" for r in default_roles()}
    engine2 = load_policy_engine([str(paths[0])])
    assert engine2.list_policies() == ["aisdlc-implementer"]


def test_template_spec_has_no_roots_but_egress_hosts() -> None:
    spec = template_spec()
    assert spec.workspace_roots == [] and "pypi.org" in spec.allowed_egress_hosts
    assert spec.role("security_tester").max_tier == RiskTier.POLICY_CONTROLLED


def test_validate_rejects_policy_where_permissive_rule_outranks_tier_4_deny() -> None:
    """A deny-tier-4 rule that exists but loses to a higher-priority allow must fail validation."""
    doc = build_policy_document(PolicySpec(), "implementer")
    doc["rules"].insert(
        0,
        {
            "name": "oops-allow-deploy",
            "condition": "action.type == 'deploy'",
            "action": "allow",
            "priority": 500,
        },
    )
    errors = validate_policy_yaml(yaml.safe_dump(doc, sort_keys=False))
    assert any("tier-4" in e and "oops-allow-deploy" in e for e in errors), errors
    # same for an allow-list bypass and for unlisted egress
    doc = build_policy_document(PolicySpec(), "reviewer")
    doc["rules"].insert(
        0,
        {"name": "allow-all", "condition": "action.tier >= 0", "action": "allow", "priority": 999},
    )
    errors = validate_policy_yaml(yaml.safe_dump(doc, sort_keys=False))
    assert any("unlisted host" in e for e in errors) and any("allow-list" in e for e in errors)
    # the generated documents themselves pass the probes for every role
    for text in render_all_policies(template_spec()).values():
        assert validate_policy_yaml(text) == []


def test_tier_lowering_override_cannot_reach_the_policy() -> None:
    """Finding: a project override used to demote git_push to tier 0 -> allow-tier-0."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="tighten-only"):
        PolicySpec(tier_config=TierConfig(overrides={"git_push": 0}))
    spec = PolicySpec(tier_config=TierConfig(overrides={"tool:Bash": 0}))
    cfg = spec.effective_tier_config()
    engine = load_policy_engine([render_policy_yaml(spec, "implementer")])
    action = classify_action("Bash", "git_push", "origin main", config=cfg)
    assert action.tier == RiskTier.APPROVAL
    decision = engine.evaluate("implementer", action.to_context(), stage="pre_tool")
    assert decision.action == "require_approval" and decision.matched_rule == "approve-tier-3"
