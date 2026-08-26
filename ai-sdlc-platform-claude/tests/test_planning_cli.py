"""``aisdlc plan`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import Requirement, Scenario

runner = CliRunner()


def _package(root: Path, name: str = "CHG-demo", *reqs: str) -> Path:
    result = runner.invoke(
        app, ["change", "new", name, "--owner", "kev", "--why", "because", "--root", str(root)]
    )
    assert result.exit_code == 0, result.output
    directory = root / "changes" / name
    pkg = pkgio.load(directory)
    pkg.requirements = [
        Requirement(
            id=f"REQ-{i:03d}",
            text=text,
            scenarios=[Scenario(id=f"SCN-{i:03d}-01", when="x", then="y")],
        )
        for i, text in enumerate(reqs, start=1)
    ]
    pkg.save()
    return directory


def test_generate_check_waves(tmp_path: Path) -> None:
    directory = _package(
        tmp_path, "CHG-demo", "The system SHALL export.", "The system SHALL email after REQ-001."
    )
    dry = runner.invoke(app, ["plan", "generate", str(directory), "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert "nothing saved" in dry.output and pkgio.load(directory).tasks == []
    gen = runner.invoke(app, ["plan", "generate", str(directory), "--json"])
    assert gen.exit_code == 0, gen.output
    payload = json.loads(gen.output)
    assert payload["saved"] and len(payload["tasks"]) == 4
    assert payload["plan"]["waves"][-1]["checkpoint"] is True
    check = runner.invoke(app, ["plan", "check", str(directory)])
    assert check.exit_code == 0, check.output
    assert "PLAN_NOT_APPROVED" in check.output and "plan check PASS" in check.output
    waves = runner.invoke(app, ["plan", "waves", str(directory), "--json"])
    assert waves.exit_code == 0
    assert json.loads(waves.output)["waves"] == [
        ["TASK-001"],
        ["TASK-002"],
        ["TASK-003", "TASK-004"],
    ]
    text = runner.invoke(app, ["plan", "waves", str(directory)])
    assert "wave 2:" in text.output
    # edit a requirement -> stale plan blocks
    pkg = pkgio.load(directory)
    pkg.requirements[0].text = "The system SHALL export twice."
    pkg.save()
    stale = runner.invoke(app, ["plan", "check", str(directory), "--json"])
    assert stale.exit_code == 1
    assert json.loads(stale.output)["fingerprint_status"] == "stale"
    # cycle -> waves fails
    pkg = pkgio.load(directory)
    pkg.tasks[0].depends_on = ["TASK-002"]
    pkg.save()
    cyc = runner.invoke(app, ["plan", "waves", str(directory)])
    assert cyc.exit_code == 1 and "cycle" in cyc.output
    missing = runner.invoke(app, ["plan", "check", str(tmp_path)])
    assert missing.exit_code == 2


def test_adr_new_and_validate(tmp_path: Path) -> None:
    directory = _package(tmp_path, "CHG-demo", "The system SHALL export.")
    new = runner.invoke(
        app,
        [
            "plan",
            "adr",
            "new",
            str(directory),
            "Use TOTP",
            "-r",
            "REQ-001",
            "--context",
            "c",
            "--decision",
            "d",
            "-c",
            "x",
            "-a",
            "SMS",
            "--status",
            "accepted",
            "-d",
            "kev",
        ],
    )
    assert new.exit_code == 0, new.output
    assert (directory / "architecture" / "decisions" / "ADR-0001.md").is_file()
    assert pkgio.load(directory).decisions[0].title == "Use TOTP"
    validate = runner.invoke(app, ["plan", "adr", "validate", str(directory), "--json"])
    assert validate.exit_code == 0, validate.output
    assert json.loads(validate.output)["adrs"] == ["ADR-0001"]
    bad = runner.invoke(app, ["plan", "adr", "new", str(directory), "Second", "-r", "REQ-009"])
    assert bad.exit_code == 1 and "unknown requirement" in bad.output
    empty = runner.invoke(
        app, ["plan", "adr", "new", str(directory), "Empty", "--status", "accepted"]
    )
    assert empty.exit_code == 0
    failing = runner.invoke(app, ["plan", "adr", "validate", str(directory)])
    assert failing.exit_code == 1 and "ADR_CONTEXT_EMPTY" in failing.output


def test_threat_model_init_and_validate(tmp_path: Path) -> None:
    directory = _package(tmp_path, "CHG-demo", "The system SHALL summarise tickets with an LLM.")
    init = runner.invoke(
        app,
        [
            "plan",
            "threat-model",
            "init",
            str(directory),
            "--tool",
            "web_fetch",
            "--tool",
            "git_push",
            "--egress",
            "api.example.com",
        ],
    )
    assert init.exit_code == 0, init.output
    assert "threat(s)" in init.output and "open high" in init.output
    model = pkgio.load(directory).threat_model
    assert model is not None and model.tool_data_manifest.tools == ["web_fetch", "git_push"]
    validate = runner.invoke(app, ["plan", "threat-model", "validate", str(directory), "--json"])
    assert validate.exit_code == 1
    payload = json.loads(validate.output)
    assert payload["passed"] is False and payload["unresolved_high_risk"]
    assert {i["code"] for i in payload["issues"]} == {"TM_UNRESOLVED_HIGH_RISK"}
    # accept every threat -> passes
    pkg = pkgio.load(directory)
    assert pkg.threat_model is not None
    for threat in pkg.threat_model.threats:
        threat.status = "mitigated" if threat.mitigation_ids else "accepted"  # type: ignore[assignment]
    pkg.save()
    ok = runner.invoke(app, ["plan", "threat-model", "validate", str(directory)])
    assert ok.exit_code == 0, ok.output
    reset = runner.invoke(app, ["plan", "threat-model", "init", str(directory), "--reset"])
    assert reset.exit_code == 0
    model = pkgio.load(directory).threat_model
    assert model is not None and model.tool_data_manifest.tools == []


def test_risk_classify_and_apply(tmp_path: Path) -> None:
    directory = _package(tmp_path, "CHG-demo", "The system SHALL require MFA on login.")
    shown = runner.invoke(app, ["plan", "risk", "classify", str(directory)])
    assert shown.exit_code == 0, shown.output
    assert "computed high, declared standard, effective high" in shown.output
    assert pkgio.load(directory).intent.risk_class.value == "standard"
    applied = runner.invoke(app, ["plan", "risk", "classify", str(directory), "--apply", "--json"])
    assert applied.exit_code == 0
    payload = json.loads(applied.output)
    assert payload["effective"] == "high" and payload["profile"]["depths"]["G4"] == "deep"
    assert pkgio.load(directory).intent.risk_class.value == "high"
    with_path = runner.invoke(
        app, ["plan", "risk", "classify", str(directory), "--path", "src/agents/x.py", "--json"]
    )
    assert json.loads(with_path.output)["computed"] == "ai_agent"
