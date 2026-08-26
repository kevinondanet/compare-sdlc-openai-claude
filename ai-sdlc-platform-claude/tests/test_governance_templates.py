"""Shipped templates under templates/agt are valid and in sync with the generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from aisdlc.governance.claude_code_plugin import build_agt_hooks_json, build_agt_plugin_policy
from aisdlc.governance.policy import default_roles, render_policy_yaml, template_spec

ROOT = Path(__file__).resolve().parents[1]
AGT_DIR = ROOT / "templates" / "agt"
CLAUDE_DIR = AGT_DIR / "claude-code"
ROLES = [r.role for r in default_roles()]


@pytest.mark.parametrize("role", ROLES)
def test_role_template_exists_and_matches_generator(role: str) -> None:
    path = AGT_DIR / f"{role}.yaml"
    assert path.exists(), (
        f"missing {path}; run: aisdlc governance policy generate --out-dir templates/agt"
    )
    assert path.read_text(encoding="utf-8") == render_policy_yaml(template_spec(), role)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["apiVersion"] == "governance.toolkit/v1"
    assert doc["default_action"] == "deny" and doc["agents"] == [role]
    assert doc["rules"][0] == {
        **doc["rules"][0],
        "name": "deny-tier-4",
        "action": "deny",
        "condition": "action.tier >= 4",
    }


@pytest.mark.integration
@pytest.mark.parametrize("role", ROLES)
def test_role_template_loads_in_agt(role: str) -> None:
    pytest.importorskip("agentmesh")
    from aisdlc.governance.policy import validate_policy_yaml

    assert validate_policy_yaml((AGT_DIR / f"{role}.yaml").read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("role", ROLES)
def test_claude_code_policy_templates(role: str) -> None:
    path = CLAUDE_DIR / f"policy.{role}.json"
    assert path.exists()
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc == build_agt_plugin_policy(template_spec(), role)
    assert doc["schemaVersion"] == 1 and doc["denyOnPolicyError"] is True
    assert (CLAUDE_DIR / f"settings.hooks.{role}.json").exists()
    hooks = json.loads((CLAUDE_DIR / f"settings.hooks.{role}.json").read_text(encoding="utf-8"))
    assert f"--role {role}" in hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert f"templates/agt/{role}.yaml" in hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


def test_claude_code_hooks_template_matches_agt_plugin_wiring() -> None:
    doc = json.loads((CLAUDE_DIR / "hooks.json").read_text(encoding="utf-8"))
    assert doc == build_agt_hooks_json()
    agt_plugin = (
        ROOT.parent
        / "agent-governance-toolkit"
        / "agent-governance-claude-code"
        / "hooks"
        / "hooks.json"
    )
    if agt_plugin.exists():  # same events and same command/args shape as the upstream plugin
        upstream = json.loads(agt_plugin.read_text(encoding="utf-8"))
        assert set(upstream["hooks"]) == set(doc["hooks"])
        for event in upstream["hooks"]:
            ours = doc["hooks"][event][0]["hooks"][0]
            theirs = upstream["hooks"][event][0]["hooks"][0]
            assert ours["command"] == theirs["command"] and ours["args"] == theirs["args"]
    assert (CLAUDE_DIR / "README.md").exists()
