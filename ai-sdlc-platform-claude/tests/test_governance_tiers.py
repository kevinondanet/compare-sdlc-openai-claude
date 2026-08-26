"""Tier taxonomy and classification (no AGT dependency)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aisdlc.governance.tiers import (
    DEFAULT_TIER_TABLE,
    RiskTier,
    Scope,
    TierConfig,
    ToolAction,
    classify,
    classify_action,
    credential_targets,
    extract_host,
    host_matches,
    is_credential_path,
    path_in_roots,
    path_parameters,
    tier_table_markdown,
)


def test_tier_enum_order_and_defaults() -> None:
    assert [int(t) for t in RiskTier] == [0, 1, 2, 3, 4]
    assert RiskTier.AUTOMATIC.default_behaviour == "automatic"
    assert RiskTier.AUTOMATIC_AUDIT.default_behaviour == "automatic+audit"
    assert RiskTier.POLICY_CONTROLLED.default_behaviour == "policy_controlled"
    assert RiskTier.APPROVAL.default_behaviour == "approval"
    assert RiskTier.HUMAN_APPROVAL.default_behaviour == "human_approval"
    assert not RiskTier.AUTOMATIC.requires_audit
    assert all(t.requires_audit for t in RiskTier if t >= 1)
    assert RiskTier.APPROVAL.requires_approval and not RiskTier.POLICY_CONTROLLED.requires_approval


@pytest.mark.parametrize(
    "value,expected",
    [
        (3, RiskTier.APPROVAL),
        ("2", RiskTier.POLICY_CONTROLLED),
        ("human_approval", RiskTier.HUMAN_APPROVAL),
        ("automatic+audit", RiskTier.AUTOMATIC_AUDIT),
        (RiskTier.AUTOMATIC, RiskTier.AUTOMATIC),
    ],
)
def test_tier_coerce(value: object, expected: RiskTier) -> None:
    assert RiskTier.coerce(value) is expected  # type: ignore[arg-type]


def test_tier_coerce_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        RiskTier.coerce("nope")
    with pytest.raises(ValueError):
        RiskTier.coerce(7)


@pytest.mark.parametrize(
    "action_type,in_worktree,expected",
    [
        ("read", True, 0),
        ("search", False, 0),
        ("explain", False, 0),
        ("write", True, 1),
        ("edit", True, 1),
        ("write", False, 3),
        ("delete_file", False, 3),
        ("run_tests", True, 2),
        ("build", True, 2),
        ("git_push", True, 3),
        ("create_pr", True, 3),
        ("update_backlog", True, 3),
        ("modify_shared_state", True, 3),
        ("deploy", True, 4),
        ("rotate_secrets", True, 4),
        ("change_iam", True, 4),
        ("delete_data", True, 4),
    ],
)
def test_default_table(action_type: str, in_worktree: bool, expected: int) -> None:
    assert classify("tool", action_type, "res", in_worktree) == RiskTier(expected)


def test_network_egress_depends_on_allowlist() -> None:
    cfg = TierConfig(allowed_egress_hosts=["pypi.org", "*.github.com"])
    assert classify("WebFetch", "network_egress", "https://pypi.org/simple", True, config=cfg) == 2
    assert classify("WebFetch", "network_egress", "https://api.github.com/x", True, config=cfg) == 2
    assert classify("WebFetch", "network_egress", "https://evil.example", True, config=cfg) == 4
    assert classify("WebFetch", "network_egress", "https://pypi.org/x", True) == 4  # no allow-list


def test_unknown_action_type_defaults_to_approval_tier() -> None:
    assert classify("x", "frobnicate", None, True) == RiskTier.APPROVAL
    cfg = TierConfig(unknown_action_tier=4)
    assert classify("x", "frobnicate", None, True, config=cfg) == RiskTier.HUMAN_APPROVAL


def test_project_overrides_by_action_and_tool() -> None:
    cfg = TierConfig.from_mapping(
        {"tier_overrides": {"run_tests": 3, "tool:DangerTool": "human_approval"}}
    )
    assert classify("Bash", "run_tests", None, True, config=cfg) == RiskTier.APPROVAL
    assert classify("DangerTool", "read", None, True, config=cfg) == RiskTier.HUMAN_APPROVAL
    assert cfg.tier_table()["run_tests"] == RiskTier.APPROVAL
    assert cfg.tier_table()["deploy"] == RiskTier.HUMAN_APPROVAL


@pytest.mark.parametrize(
    "overrides",
    [
        {"git_push": 0},
        {"deploy": 3},
        {"run_tests": "automatic"},
        {"write": 0},
    ],
)
def test_action_override_below_default_is_rejected(overrides: dict[str, object]) -> None:
    """Overrides are tighten-only (ARCHITECTURE.md §0.4): lowering a default tier is an error."""
    with pytest.raises(ValidationError, match="tighten-only"):
        TierConfig(overrides=overrides)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="tighten-only"):
        TierConfig.from_mapping({"tier_overrides": overrides})


def test_tool_override_is_a_floor_never_a_demotion() -> None:
    """`tool:Bash: 0` must not demote every shell action; a tool override only raises."""
    cfg = TierConfig(overrides={"tool:Bash": 0, "tool:Web": 2})
    assert classify("Bash", "git_push", "origin main", True, config=cfg) == RiskTier.APPROVAL
    assert classify("Bash", "deploy", "prod", True, config=cfg) == RiskTier.HUMAN_APPROVAL
    assert classify("Bash", "read", "x", True, config=cfg) == RiskTier.AUTOMATIC
    assert classify("Web", "read", "x", True, config=cfg) == RiskTier.POLICY_CONTROLLED
    assert classify("Web", "git_push", "x", True, config=cfg) == RiskTier.APPROVAL


def test_overrides_never_undercut_contextual_rules() -> None:
    """Writes outside the worktree stay tier 3 and unlisted egress tier 4, whatever the config."""
    cfg = TierConfig(overrides={"write": 1, "network_egress": 2, "tool:Write": 1})
    assert classify("Write", "write", "/etc/hosts", False, config=cfg) == RiskTier.APPROVAL
    assert classify("Write", "write", "/wt/a.py", True, config=cfg) == RiskTier.AUTOMATIC_AUDIT
    assert (
        classify("Web", "network_egress", "https://evil.io/", True, config=cfg)
        == RiskTier.HUMAN_APPROVAL
    )
    unknown_raise = TierConfig(overrides={"frobnicate": 4})
    assert classify("x", "frobnicate", None, True, config=unknown_raise) == RiskTier.HUMAN_APPROVAL
    with pytest.raises(ValidationError, match="unknown_action_tier"):
        TierConfig(unknown_action_tier=0)


def test_from_mapping_empty_is_default() -> None:
    assert TierConfig.from_mapping(None) == TierConfig()
    assert TierConfig.from_mapping({}).tier_table() == DEFAULT_TIER_TABLE


def test_path_in_roots() -> None:
    roots = ["/wt/change-1"]
    assert path_in_roots("/wt/change-1/src/x.py", roots)
    assert path_in_roots("/wt/change-1", roots)
    assert not path_in_roots("/wt/change-2/src/x.py", roots)
    assert not path_in_roots("/wt/change-1/../change-2/x", roots)
    assert not path_in_roots("/etc/passwd", roots)
    assert path_in_roots("src/x.py", roots)  # relative resolves inside the worktree
    assert not path_in_roots("../x.py", roots)
    assert not path_in_roots("src/x.py", [])  # no isolation configured -> outside


def test_extract_host_and_matching() -> None:
    assert extract_host("https://api.github.com:443/repos") == "api.github.com"
    assert extract_host("pypi.org/simple") == "pypi.org"
    assert extract_host("localhost:8000") == "localhost"
    assert extract_host("not a host") is None
    assert host_matches("a.b.github.com", ["*.github.com"])
    assert host_matches("github.com", ["*.github.com"])
    assert not host_matches("github.com.evil.net", ["*.github.com"])
    assert not host_matches(None, ["x"])


def test_classify_action_builds_context() -> None:
    cfg = TierConfig(workspace_roots=["/wt/c1"], allowed_egress_hosts=["pypi.org"])
    action = classify_action("Write", "write", "/wt/c1/a.py", {"content": "x"}, config=cfg)
    assert action.tier == RiskTier.AUTOMATIC_AUDIT and action.scope is Scope.WRITE
    ctx = action.to_context()["action"]
    assert ctx["type"] == "write" and ctx["tier"] == 1 and ctx["in_worktree"] is True
    assert ctx["outside_workspace"] is False and ctx["egress_unlisted"] is False
    assert ctx["parameters"] == {"content": "x"}

    egress = classify_action("WebFetch", "network_egress", "https://evil.io/x", config=cfg)
    assert egress.tier == RiskTier.HUMAN_APPROVAL and egress.egress_host == "evil.io"
    assert egress.to_context()["action"]["egress_unlisted"] is True
    listed = classify_action("WebFetch", "network_egress", "https://pypi.org/x", config=cfg)
    assert listed.tier == RiskTier.POLICY_CONTROLLED and listed.egress_listed


def test_tool_action_validation() -> None:
    with pytest.raises(ValueError):
        ToolAction(tool_name="x", action_type="Not Valid", tier=0, scope=Scope.READ)
    action = ToolAction(tool_name="x", action_type="read", tier="0", scope="read")
    assert action.tier is RiskTier.AUTOMATIC and action.scope is Scope.READ
    with pytest.raises(ValueError):
        ToolAction(tool_name="x", action_type="read", tier=0, scope="read", extra=1)  # type: ignore[call-arg]


def test_tier_table_markdown_lists_every_action() -> None:
    text = tier_table_markdown()
    for action_type in DEFAULT_TIER_TABLE:
        assert f"| {action_type} |" in text


# --------------------------------------------------------------------------------------
# credential-path floor (contextual rule of classify(); every entry point inherits it)
# --------------------------------------------------------------------------------------

CREDENTIAL_PATHS = [
    "/Users/me/.aws/credentials",
    "~/.aws/config",
    "/home/me/.kube/config",
    "/home/me/.ssh/id_rsa",
    "/home/me/.ssh/id_ed25519.pub",
    "/wt/c1/.env",
    "/wt/c1/.env.production",
    "/srv/certs/server.pem",
    "/srv/certs/tls.key",
    "/srv/certs/client.p12",
    "/srv/certs/client.pfx",
    "/wt/c1/.claude/settings.local.json",
    "/wt/c1/config/secrets.yaml",
    "/wt/c1/config/secrets-prod.json",
    "C:\\Users\\me\\.aws\\credentials",
]

BENIGN_PATHS = [
    "/wt/c1/.env.example",
    "/wt/c1/src/environment.py",
    "/wt/c1/src/secret_manager.py",
    "/wt/c1/docs/keys.md",
    "/wt/c1/settings.json",
    "/wt/c1/README.md",
]


@pytest.mark.parametrize("path", CREDENTIAL_PATHS)
def test_credential_paths_are_recognised(path: str) -> None:
    assert is_credential_path(path)


@pytest.mark.parametrize("path", BENIGN_PATHS)
def test_benign_paths_are_not_credentials(path: str) -> None:
    assert not is_credential_path(path)


@pytest.mark.parametrize("path", CREDENTIAL_PATHS)
@pytest.mark.parametrize("action_type", ["read", "search", "grep", "glob", "list", "inspect"])
def test_classify_floors_any_read_of_a_credential_path_to_tier_4(
    action_type: str, path: str
) -> None:
    # inside or outside the worktree, tool name irrelevant
    assert classify("Read", action_type, path, True) == RiskTier.HUMAN_APPROVAL
    assert classify("mcp__fs__read_file", action_type, path, False) == RiskTier.HUMAN_APPROVAL
    assert classify_action("Read", action_type, path).tier == RiskTier.HUMAN_APPROVAL


@pytest.mark.parametrize("path", BENIGN_PATHS)
def test_classify_keeps_benign_reads_at_tier_0(path: str) -> None:
    assert classify("Read", "read", path, True) == RiskTier.AUTOMATIC
    assert classify_action("Read", "read", path).tier == RiskTier.AUTOMATIC


def test_classify_floors_writes_and_execution_on_credential_paths() -> None:
    cfg = TierConfig(workspace_roots=["/wt/c1"])
    assert classify("Write", "write", "/wt/c1/.env", True, config=cfg) == RiskTier.HUMAN_APPROVAL
    assert classify("Edit", "edit", "/wt/c1/tls.key", True, config=cfg) == RiskTier.HUMAN_APPROVAL
    assert classify("Bash", "execute", "/wt/c1/.env", True, config=cfg) == RiskTier.HUMAN_APPROVAL
    assert (
        classify("Bash", "git_commit", "/wt/c1/.env", True, config=cfg) == RiskTier.HUMAN_APPROVAL
    )


def test_classify_floor_comes_from_path_parameters_too() -> None:
    # A multi-path tool with a harmless first path still trips on the hidden credential.
    for key in ("path", "file_path", "paths", "patterns", "pattern"):
        value: str | list[str] = ["/wt/c1/README.md", "/home/me/.aws/credentials"]
        if key in {"path", "file_path", "pattern"}:
            value = "/home/me/.aws/credentials"
        action = classify_action("mcp__fs__read_files", "read", "read_files", {key: value})
        assert action.tier == RiskTier.HUMAN_APPROVAL, key
    assert (
        classify("mcp__fs__read_files", "read", "", True, parameters={"paths": ["/wt/c1/a.py"]})
        == RiskTier.AUTOMATIC
    )
    # Non-string values are ignored (never coerced).
    assert (
        classify("mcp__fs__read_files", "read", "", True, parameters={"paths": [1, None, {}]})
        == RiskTier.AUTOMATIC
    )
    assert path_parameters({"paths": ["a", 1, "b"], "path": "c", "pattern": 3}) == ["c", "a", "b"]
    assert path_parameters(None) == [] and path_parameters({"other": "/x/.env"}) == []


def test_credential_floor_skips_network_scope() -> None:
    # A URL or search query mentioning ".env" is egress/search, not a credential read.
    cfg = TierConfig(allowed_egress_hosts=["github.com"])
    assert (
        classify("WebFetch", "network_egress", "https://github.com/x/.env", False, config=cfg)
        == RiskTier.POLICY_CONTROLLED
    )
    assert (
        classify("WebSearch", "web_search", "how to load a .env file", False)
        == RiskTier.POLICY_CONTROLLED
    )


def test_credential_floor_cannot_be_lowered_by_overrides() -> None:
    cfg = TierConfig(overrides={"tool:Read": 0})
    assert classify("Read", "read", "/home/me/.ssh/id_rsa", True, config=cfg) == 4
    assert credential_targets("/home/me/.ssh/id_rsa", {"paths": ["/x/.env"]}) == [
        "/home/me/.ssh/id_rsa",
        "/x/.env",
    ]


def test_credential_patterns_extend_only() -> None:
    cfg = TierConfig(credential_path_patterns=[r"/vault/", r"\.license$"])
    assert cfg.is_credential_path("/srv/vault/token")
    assert cfg.is_credential_path("/wt/c1/app.license")
    assert cfg.is_credential_path("/home/me/.aws/credentials")  # platform set still applies
    assert not cfg.is_credential_path("/wt/c1/app.py")
    assert classify("Read", "read", "/srv/vault/token", True, config=cfg) == RiskTier.HUMAN_APPROVAL
    assert classify("Read", "read", "/srv/vault/token", True) == RiskTier.AUTOMATIC
    assert TierConfig.from_mapping(
        {"credential_path_patterns": [" /vault/ ", ""]}
    ).credential_path_patterns == ["/vault/"]
    with pytest.raises(ValidationError, match="invalid credential_path_patterns"):
        TierConfig(credential_path_patterns=["("])
