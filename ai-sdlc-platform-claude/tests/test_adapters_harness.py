"""Tests for the harness adapters (Claude Code, Copilot, Codex, Cursor, Kiro)."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

from aisdlc import adapters
from aisdlc.adapters import base, claude_code, codex, copilot, cursor, kiro
from aisdlc.adapters.base import CANONICAL_ARTIFACTS, CANONICAL_COMMANDS, AdapterContext
from aisdlc.policy import (
    EffectivePolicy,
    ProjectConfig,
    TierBehaviour,
    default_org_policy,
    default_project_config,
    effective_policy,
)


def _ctx(**overrides: object) -> tuple[ProjectConfig, EffectivePolicy]:
    project = default_project_config()
    policy = effective_policy(default_org_policy(), project)
    for tier, behaviour in overrides.items():
        policy.tool_tiers.defaults[int(tier.removeprefix("tier"))] = TierBehaviour(str(behaviour))
    return project, policy


def _all_text(files: base.EmittedFiles) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in files.paths)


@pytest.mark.parametrize("name", adapters.adapter_names())
def test_every_adapter_emits_the_canonical_workflow(tmp_path: Path, name: str) -> None:
    project, policy = _ctx()
    result = adapters.get_adapter(name).emit(project, policy, tmp_path)
    assert result.harness == name
    assert result.files, name
    for emitted in result.files:
        assert emitted.path.is_file()
        assert emitted.relative and not Path(emitted.relative).is_absolute()
        assert emitted.description
    text = _all_text(result)
    for command in CANONICAL_COMMANDS:
        assert command.cli in text, (name, command.key)
        assert command.brief in text, (name, command.key)
    for artifact in CANONICAL_ARTIFACTS:
        assert f"`{artifact.path}`" in text, (name, artifact.path)
    assert "pytest -q" in text
    assert "aisdlc governance hook" in text
    # tool policy carried in every host
    assert "git push --force" in text
    assert "human_approval" in text


def test_claude_code_layout_and_commands(tmp_path: Path) -> None:
    project, policy = _ctx()
    result = claude_code.ClaudeCodeAdapter().emit(project, policy, tmp_path)
    rel = set(result.relative_paths())
    for command in CANONICAL_COMMANDS:
        assert f".claude/commands/aisdlc-{command.slug}.md" in rel
    assert {
        ".claude/skills/aisdlc/SKILL.md",
        ".claude/settings.json",
        ".claude/CLAUDE.aisdlc.md",
    } <= rel
    run_task = (tmp_path / ".claude/commands/aisdlc-run-task.md").read_text()
    assert run_task.startswith("---\ndescription:")
    assert "allowed-tools:" in run_task and "Edit" in run_task
    assert "$ARGUMENTS" in run_task
    validate = (tmp_path / ".claude/commands/aisdlc-change-validate.md").read_text()
    assert "Edit" not in validate.split("---")[1]  # read-only command has no edit tools
    skill = (tmp_path / ".claude/skills/aisdlc/SKILL.md").read_text()
    assert skill.startswith("---\nname: aisdlc\n")
    assert "| 4 | deploy" in skill
    fragment = (tmp_path / ".claude/CLAUDE.aisdlc.md").read_text()
    assert (
        "`requirements.md`" in fragment and "aisdlc governance hook --role implementer" in fragment
    )


def test_claude_settings_json_permissions_and_hooks(tmp_path: Path) -> None:
    project, policy = _ctx()
    claude_code.ClaudeCodeAdapter().emit(project, policy, tmp_path)
    settings = json.loads((tmp_path / ".claude/settings.json").read_text())
    allow = settings["permissions"]["allow"]
    deny = settings["permissions"]["deny"]
    ask = settings["permissions"]["ask"]
    assert {"Read", "Glob", "Grep"} <= set(allow)
    assert "Bash(aisdlc:*)" in allow
    assert "Bash(pytest -q)" in allow and "Bash(pytest:*)" in allow
    assert "Bash(ruff check .)" in allow and "Bash(mypy)" in allow
    assert "Bash(git status:*)" in allow
    assert "Edit" not in allow and "Write" not in allow  # read-only by default
    assert "Bash(git push --force:*)" in deny
    assert "Bash(kubectl delete:*)" in deny and "Bash(aws iam:*)" in deny
    assert "Read(./.env)" in deny and "Read(**/*.pem)" in deny
    assert "Bash(git push:*)" in ask and "Bash(pip install:*)" in ask
    assert not set(allow) & set(deny)
    hooks = settings["hooks"]
    pre = hooks["PreToolUse"][0]
    assert pre["matcher"] == ""
    assert pre["hooks"][0]["command"] == "aisdlc governance hook --role implementer"
    assert hooks["PostToolUse"][0]["hooks"][0]["command"].startswith("aisdlc governance hook")
    assert "SessionStart" in hooks


def test_claude_settings_merge_keeps_user_entries_and_is_idempotent(tmp_path: Path) -> None:
    project, policy = _ctx()
    settings_path = tmp_path / ".claude/settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "model": "opus",
                "permissions": {"allow": ["Bash(make:*)"], "deny": ["WebFetch"]},
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
                    ]
                },
            }
        )
    )
    adapter = claude_code.ClaudeCodeAdapter()
    adapter.emit(project, policy, tmp_path)
    adapter.emit(project, policy, tmp_path)  # second run must not duplicate
    settings = json.loads(settings_path.read_text())
    assert settings["model"] == "opus"
    assert settings["permissions"]["allow"][0] == "Bash(make:*)"
    assert "Bash(aisdlc:*)" in settings["permissions"]["allow"]
    assert settings["permissions"]["allow"].count("Bash(aisdlc:*)") == 1
    assert "WebFetch" in settings["permissions"]["deny"]
    pre = settings["hooks"]["PreToolUse"]
    assert pre[0]["hooks"][0]["command"] == "echo hi"
    ours = [e for e in pre if e["hooks"][0]["command"].startswith("aisdlc governance hook")]
    assert len(ours) == 1


def test_tier_policy_drives_allowlist(tmp_path: Path) -> None:
    project, policy = _ctx(tier2="approval")
    ctx = AdapterContext(project=project, policy=policy)
    assert not ctx.tests_auto_allowed()
    perms = claude_code.build_permissions(ctx)
    assert "Bash(pytest -q)" not in perms["allow"]
    assert "Bash(pytest:*)" not in perms["allow"]
    assert "Bash(aisdlc:*)" in perms["allow"]
    assert "Bash(git push --force:*)" in perms["deny"]
    md = ctx.tool_policy_markdown()
    assert "| 2 | run tests/builds, local artifacts | approval |" in md


def test_context_with_extra_allowed_shell() -> None:
    project, policy = _ctx()
    ctx = base.default_context(project, policy, extra_allowed_shell=("make lint",))
    assert "make lint" in ctx.allowed_shell_commands()
    assert "make" in ctx.allowed_shell_prefixes()
    with pytest.raises(TypeError):
        base.default_context(project, policy, nope=1)


def test_codex_config_is_valid_toml_and_reflects_tiers(tmp_path: Path) -> None:
    project, policy = _ctx()
    result = codex.CodexAdapter().emit(project, policy, tmp_path)
    assert set(result.relative_paths()) == {"AGENTS.md", ".codex/config.toml"}
    config = tomllib.loads((tmp_path / ".codex/config.toml").read_text())
    assert config["sandbox_mode"] == "workspace-write"
    assert config["approval_policy"] == "on-request"
    assert config["sandbox_workspace_write"]["network_access"] is False
    assert "pytest -q" in config["aisdlc"]["allowed_commands"]
    assert "git push --force" in config["aisdlc"]["denied_commands"]
    assert config["aisdlc"]["tiers"]["tier_4"] == "human_approval"
    agents = (tmp_path / "AGENTS.md").read_text()
    assert agents.startswith("# AGENTS.md")
    assert "| `aisdlc gate evaluate changes/<CHG-id>` | gate |" in agents

    _project, strict = _ctx(tier1="approval", tier2="approval")
    strict_cfg = tomllib.loads(codex.config_toml(AdapterContext(project=project, policy=strict)))
    assert strict_cfg["sandbox_mode"] == "read-only"
    assert strict_cfg["approval_policy"] == "untrusted"


def test_copilot_layout_and_agent_tools(tmp_path: Path) -> None:
    project, policy = _ctx()
    result = copilot.CopilotAdapter().emit(project, policy, tmp_path)
    rel = set(result.relative_paths())
    assert ".github/copilot-instructions.md" in rel
    for command in CANONICAL_COMMANDS:
        assert f".github/prompts/aisdlc-{command.slug}.prompt.md" in rel
    for stage in ("research", "plan", "implement", "review"):
        assert f".github/agents/aisdlc-{stage}.agent.md" in rel
    research = (tmp_path / ".github/agents/aisdlc-research.agent.md").read_text()
    assert research.startswith("---\nname: aisdlc-research\n")
    assert "editFiles" not in research and "runCommands" not in research
    assert "aisdlc intake clarify" in research
    implement = (tmp_path / ".github/agents/aisdlc-implement.agent.md").read_text()
    assert "'editFiles'" in implement and "'runCommands'" in implement
    assert "aisdlc run task" in implement
    review = (tmp_path / ".github/agents/aisdlc-review.agent.md").read_text()
    assert "Do not edit source" in review and "aisdlc gate evaluate" in review
    prompt = (tmp_path / ".github/prompts/aisdlc-plan-generate.prompt.md").read_text()
    assert prompt.startswith("---\nmode: agent\n") and "${input:change" in prompt


def test_cursor_rules_front_matter(tmp_path: Path) -> None:
    project, policy = _ctx()
    result = cursor.CursorAdapter().emit(project, policy, tmp_path)
    rel = set(result.relative_paths())
    assert rel == {
        ".cursor/rules/aisdlc-workflow.mdc",
        ".cursor/rules/aisdlc-artifacts.mdc",
        ".cursor/rules/aisdlc-tool-policy.mdc",
        ".cursor/rules/aisdlc-commands.mdc",
    }
    workflow = (tmp_path / ".cursor/rules/aisdlc-workflow.mdc").read_text()
    assert "alwaysApply: true" in workflow.split("---")[1]
    artifacts = (tmp_path / ".cursor/rules/aisdlc-artifacts.mdc").read_text()
    assert "globs: changes/**" in artifacts
    commands = (tmp_path / ".cursor/rules/aisdlc-commands.mdc").read_text()
    assert "### Implement one task (`run.task`)" in commands


def test_kiro_steering_and_hooks(tmp_path: Path) -> None:
    project, policy = _ctx()
    result = kiro.KiroAdapter().emit(project, policy, tmp_path)
    rel = set(result.relative_paths())
    assert ".kiro/steering/aisdlc-workflow.md" in rel
    assert ".kiro/steering/aisdlc-artifacts.md" in rel
    assert ".kiro/hooks/aisdlc-validate-on-save.kiro.hook" in rel
    artifacts = (tmp_path / ".kiro/steering/aisdlc-artifacts.md").read_text()
    assert "inclusion: fileMatch" in artifacts and 'fileMatchPattern: "changes/**"' in artifacts
    hook = json.loads((tmp_path / ".kiro/hooks/aisdlc-validate-on-save.kiro.hook").read_text())
    assert hook["when"]["type"] == "fileEdited"
    assert "changes/**/requirements.md" in hook["when"]["patterns"]
    assert "aisdlc change validate" in hook["then"]["prompt"]
    gov = json.loads((tmp_path / ".kiro/hooks/aisdlc-governance.kiro.hook").read_text())
    assert "git push --force" in gov["then"]["prompt"]
    assert "aisdlc governance hook" in gov["then"]["prompt"]


@pytest.mark.parametrize("module", [claude_code, copilot, codex, cursor, kiro])
def test_repo_templates_match_embedded_defaults(module: ModuleType) -> None:
    templates_dir = base.adapter_templates_dir()
    assert templates_dir is not None
    harness: str = module.HARNESS
    defaults: dict[str, str] = module.DEFAULT_TEMPLATES
    for name, text in defaults.items():
        path = templates_dir / harness / name
        assert path.is_file(), path
        assert path.read_text(encoding="utf-8") == text, path


def test_render_template_prefers_templates_dir_and_keeps_unknown_placeholders(
    tmp_path: Path,
) -> None:
    (tmp_path / "codex").mkdir()
    (tmp_path / "codex" / "AGENTS.md").write_text("custom $project_name $ARGUMENTS\n")
    project, policy = _ctx()
    ctx = AdapterContext(project=project, policy=policy)
    out = codex.agents_markdown(ctx, templates_dir=tmp_path)
    assert out == "custom project $ARGUMENTS\n"
    fallback = codex.agents_markdown(ctx, templates_dir=tmp_path / "missing")
    assert fallback.startswith("# AGENTS.md")


def test_registry_aliases_and_protocol() -> None:
    assert isinstance(adapters.get_adapter("claude-code"), claude_code.ClaudeCodeAdapter)
    assert isinstance(adapters.get_adapter("claude"), claude_code.ClaudeCodeAdapter)
    assert isinstance(adapters.get_adapter("Kiro"), kiro.KiroAdapter)
    for name in adapters.adapter_names():
        assert isinstance(adapters.get_adapter(name), base.HarnessAdapter)
    with pytest.raises(KeyError):
        adapters.get_adapter("vim")
    assert base.command_by_key("gate.evaluate").phase is base.WorkflowPhase.GATE
    with pytest.raises(KeyError):
        base.command_by_key("nope")


def test_canonical_command_set_is_complete_and_unique() -> None:
    keys = [c.key for c in CANONICAL_COMMANDS]
    assert len(keys) == len(set(keys))
    assert len({c.slug for c in CANONICAL_COMMANDS}) == len(keys)
    assert set(keys) == {
        "change.new",
        "change.validate",
        "intake.clarify",
        "intake.checklist",
        "intake.analyze",
        "plan.generate",
        "plan.check",
        "run.task",
        "review",
        "gate.evaluate",
        "security.campaign",
        "security.safety",
        "cost.report",
    }
    for command in CANONICAL_COMMANDS:
        assert command.cli.startswith("aisdlc ")


def test_canonical_commands_resolve_against_the_real_cli() -> None:
    """Every canonical CLI string must name a real ``aisdlc`` subcommand and real options."""
    import shlex

    from typer.testing import CliRunner

    from aisdlc.cli.main import app

    runner = CliRunner()
    env = {"COLUMNS": "200", "TERMINAL_WIDTH": "200"}
    for command in CANONICAL_COMMANDS:
        tokens = shlex.split(command.cli)
        assert tokens[0] == "aisdlc", command.key
        path: list[str] = []
        for token in tokens[1:]:
            if token.startswith(("<", "-")) or "/" in token:
                break
            path.append(token)
        result = runner.invoke(app, [*path, "--help"], env=env)
        assert result.exit_code == 0, (command.key, path, result.output)
        for option in (t for t in tokens if t.startswith("--")):
            assert option in result.output, (command.key, option, result.output)
