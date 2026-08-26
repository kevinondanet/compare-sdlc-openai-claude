"""Tests for the ``aisdlc adapter`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.schema import package as pkgio

runner = CliRunner()

SPEC = """## ADDED Requirements

### Requirement: Login
The system SHALL let users log in.

#### Scenario: Ok
- **WHEN** credentials are valid
- **THEN** a session is created
"""


def _openspec(tmp_path: Path) -> Path:
    change = tmp_path / "openspec" / "changes" / "login"
    (change / "specs" / "auth").mkdir(parents=True)
    (change / "proposal.md").write_text(
        "# Change: Login\n\n## Why\nNeed login.\n\n## What Changes\n- Login form\n"
    )
    (change / "tasks.md").write_text(
        "## 1. Work\n- [ ] 1.1 Build form\n  - verify: `pytest -q` (exit 0)\n"
    )
    (change / "specs" / "auth" / "spec.md").write_text(SPEC)
    return change


def test_list() -> None:
    result = runner.invoke(app, ["adapter", "list"])
    assert result.exit_code == 0, result.output
    for name in ("claude_code", "copilot", "codex", "cursor", "kiro"):
        assert name in result.output
    as_json = runner.invoke(app, ["adapter", "list", "--json"])
    assert [row["name"] for row in json.loads(as_json.output)][0] == "claude_code"


def test_emit_single_and_all(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["adapter", "emit", "claude-code", "--out", str(tmp_path), "--role", "reviewer"]
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".claude" / "settings.json").is_file()
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"].endswith("--role reviewer")
    assert ".claude/commands/aisdlc-run-task.md" in result.output
    every = runner.invoke(app, ["adapter", "emit", "all", "--out", str(tmp_path), "--json"])
    assert every.exit_code == 0, every.output
    payload = json.loads(every.output)
    assert {row["harness"] for row in payload} == {
        "claude_code",
        "copilot",
        "codex",
        "cursor",
        "kiro",
    }
    assert (tmp_path / "AGENTS.md").is_file() and (tmp_path / ".kiro" / "steering").is_dir()
    bad = runner.invoke(app, ["adapter", "emit", "emacs", "--out", str(tmp_path)])
    assert bad.exit_code == 2 and "unknown harness" in bad.output


def test_emit_uses_project_config(tmp_path: Path) -> None:
    cfg = tmp_path / "project-config.yaml"
    cfg.write_text("name: demo\ntest_commands:\n  unit: make test\n  lint: null\n  types: null\n")
    result = runner.invoke(
        app, ["adapter", "emit", "claude_code", "--out", str(tmp_path), "--project", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert "Bash(make test)" in settings["permissions"]["allow"]
    assert "Bash(pytest -q)" not in settings["permissions"]["allow"]
    skill = (tmp_path / ".claude" / "skills" / "aisdlc" / "SKILL.md").read_text()
    assert "project `demo`" in skill


def test_import_then_export_openspec(tmp_path: Path) -> None:
    change = _openspec(tmp_path)
    root = tmp_path / "repo"
    result = runner.invoke(
        app, ["adapter", "import-openspec", str(change), "--root", str(root), "--owner", "kev"]
    )
    assert result.exit_code == 0, result.output
    assert "imported CHG-login" in result.output
    package_dir = root / "changes" / "CHG-login"
    pkg = pkgio.load(package_dir)
    assert pkg.intent.owner == "kev"
    assert [r.id for r in pkg.requirements] == ["REQ-001"]
    assert pkg.requirements[0].scenarios[0].when == "credentials are valid"
    assert pkg.tasks[0].verification is not None
    assert pkg.threat_model is not None and pkg.plan is not None
    validate = runner.invoke(app, ["change", "validate", str(package_dir)])
    assert validate.exit_code == 0, validate.output

    again = runner.invoke(app, ["adapter", "import-openspec", str(change), "--root", str(root)])
    assert again.exit_code == 2 and "already exists" in again.output
    forced = runner.invoke(
        app, ["adapter", "import-openspec", str(change), "--root", str(root), "--force", "--json"]
    )
    assert forced.exit_code == 0, forced.output
    payload = json.loads(forced.output)
    assert payload["requirements"] == 1 and payload["id_map"]["Login"] == "REQ-001"

    out = tmp_path / "exported"
    export = runner.invoke(app, ["adapter", "export-openspec", str(package_dir), "--out", str(out)])
    assert export.exit_code == 0, export.output
    assert (out / "specs" / "auth" / "spec.md").is_file() and (out / "tasks.md").is_file()
    spec = (out / "specs" / "auth" / "spec.md").read_text()
    assert "### Requirement: Login" in spec and "<!-- aisdlc-id: REQ-001" in spec
    export_json = runner.invoke(
        app, ["adapter", "export-openspec", str(package_dir), "--out", str(out), "--json"]
    )
    assert export_json.exit_code == 0
    assert json.loads(export_json.output)["change_id"] == "CHG-login"

    missing = runner.invoke(app, ["adapter", "export-openspec", str(tmp_path / "nope")])
    assert missing.exit_code == 2
    bad_import = runner.invoke(
        app, ["adapter", "import-openspec", str(tmp_path / "nope"), "--root", str(root)]
    )
    assert bad_import.exit_code == 2
