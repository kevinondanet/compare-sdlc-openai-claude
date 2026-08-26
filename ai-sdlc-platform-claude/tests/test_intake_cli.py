"""Tests for the ``aisdlc intake`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.policy import default_org_policy, dump_org_policy
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ChangePackage
from tests.intake_fixtures import ambiguous_package, clean_package, planned_package
from tests.test_intake_discovery import ANSWERS

runner = CliRunner()


def _write(root: Path, pkg: ChangePackage) -> Path:
    directory = root / "changes" / pkg.change_id
    pkgio.save(pkg, directory)
    return directory


def test_readiness_command(tmp_path: Path) -> None:
    clean = _write(tmp_path, clean_package())
    result = runner.invoke(app, ["intake", "readiness", str(clean)])
    assert result.exit_code == 0, result.output
    assert "READY" in result.output and "[PASS] owner" in result.output

    fuzzy = _write(tmp_path, ambiguous_package())
    result = runner.invoke(app, ["intake", "readiness", str(fuzzy)])
    assert result.exit_code == 1
    assert "[FAIL] owner" in result.output and "[WARN] assumptions_recorded" in result.output
    result = runner.invoke(app, ["intake", "readiness", str(fuzzy), "--json", "--threshold", "1"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["ready"] is False and data["ambiguity_threshold"] == 1.0
    assert next(c for c in data["criteria"] if c["id"] == "ambiguity")["satisfied"] is True

    missing = runner.invoke(app, ["intake", "readiness", str(tmp_path / "nope")])
    assert missing.exit_code == 2


def test_readiness_picks_up_org_policy_threshold(tmp_path: Path) -> None:
    policy = default_org_policy()
    policy.security_baselines.ambiguity_threshold = 0.9
    (tmp_path / "org-policy.yaml").write_text(dump_org_policy(policy))
    fuzzy = _write(tmp_path, ambiguous_package())
    result = runner.invoke(app, ["intake", "readiness", str(fuzzy), "--json"])
    assert json.loads(result.output)["ambiguity_threshold"] == 0.9


def test_checklist_command(tmp_path: Path) -> None:
    clean = _write(tmp_path, clean_package())
    result = runner.invoke(app, ["intake", "checklist", str(clean), "--strict"])
    assert result.exit_code == 0, result.output
    assert "14/14 items passed" in result.output
    fuzzy = _write(tmp_path, ambiguous_package())
    result = runner.invoke(app, ["intake", "checklist", str(fuzzy)])
    assert result.exit_code == 1
    assert "[FAIL] unambiguous" in result.output and "fix:" in result.output
    result = runner.invoke(app, ["intake", "checklist", str(fuzzy), "--json"])
    data = json.loads(result.output)
    assert data["passed"] is False and len(data["items"]) == 14


def test_analyze_command(tmp_path: Path) -> None:
    clean = _write(tmp_path, clean_package())
    assert runner.invoke(app, ["intake", "analyze", str(clean)]).exit_code == 0
    planned = _write(tmp_path, planned_package())
    result = runner.invoke(app, ["intake", "analyze", str(planned)])
    assert result.exit_code == 1
    assert "HIGH PLAN_UNKNOWN_TASK" in result.output
    result = runner.invoke(app, ["intake", "analyze", str(planned), "--fail-on", "critical"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["intake", "analyze", str(planned), "--json"])
    data = json.loads(result.output)
    assert data["passed"] is False and data["counts"]["high"] >= 5


def test_clarify_command_lists_and_applies(tmp_path: Path) -> None:
    fuzzy = _write(tmp_path, ambiguous_package())
    result = runner.invoke(app, ["intake", "clarify", str(fuzzy), "--limit", "2"])
    assert result.exit_code == 0, result.output
    assert "CQ-001" in result.output and "CQ-003" not in result.output
    assert "2 of" in result.output

    result = runner.invoke(
        app,
        [
            "intake",
            "clarify",
            str(fuzzy),
            "--answer",
            "CQ-001=Reports must render in under 3 seconds",
            "--answer",
            "CQ-003=CSV and PDF",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "applied CQ-001" in result.output and "applied CQ-003" in result.output
    reloaded = pkgio.load(fuzzy)
    assert "TBD" not in reloaded.intent.kernel.why
    assert next(q for q in reloaded.open_questions if q.id == "OQ-001").decision == "CSV and PDF"

    bad = runner.invoke(app, ["intake", "clarify", str(fuzzy), "--answer", "CQ-999=x"])
    assert bad.exit_code == 2
    malformed = runner.invoke(app, ["intake", "clarify", str(fuzzy), "--answer", "nonsense"])
    assert malformed.exit_code != 0

    listing = json.loads(runner.invoke(app, ["intake", "clarify", str(fuzzy), "--json"]).output)
    scenario_q = next(q["id"] for q in listing["questions"] if q["category"] == "missing_scenario")
    answers = tmp_path / "answers.yaml"
    answers.write_text(yaml.safe_dump({scenario_q: "WHEN a report is requested THEN it renders"}))
    result = runner.invoke(
        app, ["intake", "clarify", str(fuzzy), "--answers", str(answers), "--dry-run", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["applied"][0]["created_ids"] == ["SCN-001-01"]
    assert pkgio.load(fuzzy).requirement("REQ-001").scenarios == []  # dry run


def test_kernel_command(tmp_path: Path) -> None:
    fuzzy = _write(tmp_path, ambiguous_package())
    result = runner.invoke(app, ["intake", "kernel", str(fuzzy)])
    assert result.exit_code == 1
    assert "KERNEL_MISSING_CAPABILITIES" in result.output
    result = runner.invoke(
        app,
        [
            "intake",
            "kernel",
            str(fuzzy),
            "--why",
            "Reports take minutes",
            "-c",
            "Export a report in under 3 seconds",
            "-n",
            "Dashboards",
            "-k",
            "No new infrastructure",
            "-s",
            "Report p95 drops below 3 seconds",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["missing"] == [] and data["kernel"]["non_goals"] == ["Dashboards"]
    assert pkgio.load(fuzzy).intent.kernel.is_complete()


def test_discover_non_interactive(tmp_path: Path) -> None:
    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps(ANSWERS))
    summary = tmp_path / "out" / "brd.md"
    result = runner.invoke(
        app,
        [
            "intake",
            "discover",
            "--answers",
            str(answers),
            "--root",
            str(tmp_path),
            "--markdown",
            str(summary),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "created" in result.output and "6 draft requirement(s)" in result.output
    package_dir = tmp_path / "changes" / "CHG-self-service-password-reset"
    assert pkgio.load(package_dir).intent.owner == "kevin"
    assert summary.read_text().startswith("# Self-service password reset")
    ready = runner.invoke(app, ["intake", "readiness", str(package_dir)])
    assert ready.exit_code == 0, ready.output

    duplicate = runner.invoke(
        app, ["intake", "discover", "--answers", str(answers), "--root", str(tmp_path)]
    )
    assert duplicate.exit_code == 2

    result = runner.invoke(
        app, ["intake", "discover", "--answers", str(answers), "--dry-run", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["package"] is None and data["risk_class"] == "high"
    assert len(data["requirements"]) == 6

    incomplete = tmp_path / "partial.json"
    incomplete.write_text(json.dumps({"title": "only a title"}))
    result = runner.invoke(app, ["intake", "discover", "--answers", str(incomplete), "--dry-run"])
    assert result.exit_code == 2 and "missing required" in result.output


def test_discover_interactive(tmp_path: Path) -> None:
    lines = [
        ANSWERS["title"],
        "",  # problem: required, re-asked
        ANSWERS["problem"],
        "Employee: reset my password; Help desk agent: fewer tickets",
        ANSWERS["current_pain"],
        "Employees can reset their password from the login page",
        "Changing the password policy",
        "",  # must_not_do skipped
        ANSWERS["success_measure"],
        "",  # constraints skipped
        "none",
        "",  # integrations skipped
        "kevin",
    ]
    result = runner.invoke(
        app,
        ["intake", "discover", "--root", str(tmp_path), "--summary"],
        input="\n".join(lines) + "\n",
    )
    assert result.exit_code == 0, result.output
    assert "## 1. Problem statement" in result.output
    pkg = pkgio.load(tmp_path / "changes" / "CHG-self-service-password-reset")
    assert pkg.intent.risk_class.value == "standard"
    assert [p for p in pkg.intent.stakeholders] == ["Employee", "Help desk agent"]
    assert len(pkg.requirements) == 2
