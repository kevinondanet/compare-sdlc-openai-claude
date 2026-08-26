"""Tests for the ``aisdlc change`` and ``aisdlc policy`` CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import Requirement, Scenario

runner = CliRunner()


def _new(root: Path, name: str = "CHG-demo", *extra: str) -> Path:
    result = runner.invoke(
        app,
        ["change", "new", name, "--owner", "kev", "--why", "because", "--root", str(root), *extra],
    )
    assert result.exit_code == 0, result.output
    return root / "changes" / name


def test_change_new_with_id_and_title(tmp_path: Path) -> None:
    directory = _new(tmp_path)
    assert (directory / "intent.md").is_file()
    result = runner.invoke(
        app, ["change", "new", "Add login MFA", "--root", str(tmp_path), "-r", "high"]
    )
    assert result.exit_code == 0
    created = pkgio.load(tmp_path / "changes" / "CHG-add-login-mfa")
    assert created.intent.title == "Add login MFA"
    assert created.intent.risk_class.value == "high"
    dup = runner.invoke(app, ["change", "new", "CHG-demo", "--root", str(tmp_path)])
    assert dup.exit_code == 2
    assert "already exists" in dup.output


def test_change_validate(tmp_path: Path) -> None:
    directory = _new(tmp_path)
    result = runner.invoke(app, ["change", "validate", str(directory)])
    assert result.exit_code == 0  # warnings only
    assert "INTENT_KERNEL_INCOMPLETE" in result.output
    strict = runner.invoke(app, ["change", "validate", str(directory), "--strict"])
    assert strict.exit_code == 1
    pkg = pkgio.load(directory)
    pkg.requirements = [Requirement(id="REQ-001", text="users can log in")]
    pkg.save()
    as_json = runner.invoke(app, ["change", "validate", str(directory), "--json"])
    assert as_json.exit_code == 1
    payload = json.loads(as_json.output)
    assert payload["change_id"] == "CHG-demo"
    assert {i["code"] for i in payload["issues"]} >= {"REQ_NO_MODAL", "REQ_NO_SCENARIO"}
    missing = runner.invoke(app, ["change", "validate", str(tmp_path)])
    assert missing.exit_code == 2


def test_change_status_and_list(tmp_path: Path) -> None:
    directory = _new(tmp_path)
    pkg = pkgio.load(directory)
    pkg.requirements = [
        Requirement(
            id="REQ-001",
            text="The system SHALL x.",
            scenarios=[Scenario(id="SCN-001-01", when="w", then="t")],
        )
    ]
    pkg.save()
    status = runner.invoke(app, ["change", "status", str(directory)])
    assert status.exit_code == 0
    assert "state: specified" in status.output
    as_json = runner.invoke(app, ["change", "status", str(directory), "--json"])
    payload = json.loads(as_json.output)
    assert payload["requirements"] == 1 and payload["scenarios"] == 1
    assert payload["fingerprint"] == pkg.base_fingerprint

    empty = runner.invoke(app, ["change", "list", "--root", str(tmp_path / "nothing")])
    assert empty.exit_code == 0 and "no change packages" in empty.output
    listing = runner.invoke(app, ["change", "list", "--root", str(tmp_path)])
    assert "CHG-demo" in listing.output and "specified" in listing.output
    (tmp_path / "changes" / "CHG-broken").mkdir()
    (tmp_path / "changes" / "CHG-broken" / "intent.md").write_text("garbage")
    listing_json = runner.invoke(app, ["change", "list", "--root", str(tmp_path), "--json"])
    rows = json.loads(listing_json.output)
    assert {r["change_id"]: r["state"] for r in rows} == {
        "CHG-broken": "invalid",
        "CHG-demo": "specified",
    }
    plain = runner.invoke(app, ["change", "list", "--root", str(tmp_path)])
    assert "invalid" in plain.output


def test_change_fingerprint(tmp_path: Path) -> None:
    directory = _new(tmp_path)
    result = runner.invoke(app, ["change", "fingerprint", str(directory)])
    assert result.exit_code == 0
    value = result.output.strip().splitlines()[0]
    assert len(value) == 64
    (directory / "requirements.md").write_text("---\nrequirements: []\n---\nedited\n")
    stale = runner.invoke(app, ["change", "fingerprint", str(directory)])
    assert stale.exit_code == 0 and "stored .fingerprint differs" in stale.output
    check = runner.invoke(app, ["change", "fingerprint", str(directory), "--check", value])
    assert check.exit_code == 3
    update = runner.invoke(app, ["change", "fingerprint", str(directory), "--update"])
    assert update.exit_code == 0
    new_value = update.output.strip()
    assert (directory / ".fingerprint").read_text().strip() == new_value
    ok = runner.invoke(app, ["change", "fingerprint", str(directory), "--check", new_value])
    assert ok.exit_code == 0
    not_pkg = runner.invoke(app, ["change", "fingerprint", str(tmp_path)])
    assert not_pkg.exit_code == 2


@pytest.fixture
def policy_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    org = tmp_path / "org.yaml"
    org.write_text("name: acme\n")
    good = tmp_path / "good.yaml"
    good.write_text("name: svc\noverrides:\n  cost_limits: {max_agent_turns: 5}\n")
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: svc\noverrides:\n  cost_limits: {max_agent_turns: 500}\n")
    return org, good, bad


def test_policy_show(policy_files: tuple[Path, Path, Path], tmp_path: Path) -> None:
    org, good, _bad = policy_files
    result = runner.invoke(app, ["policy", "show", "--org", str(org), "--project", str(good)])
    assert result.exit_code == 0
    assert "name: acme" in result.output and "name: svc" in result.output
    only_org = runner.invoke(
        app, ["policy", "show", "--org", str(org), "--section", "org", "--root", str(tmp_path)]
    )
    assert "name: acme" in only_org.output and "name: svc" not in only_org.output
    defaults = runner.invoke(app, ["policy", "show", "--root", str(tmp_path)])
    assert defaults.exit_code == 0 and "built-in defaults" in defaults.output
    bad_section = runner.invoke(app, ["policy", "show", "--root", str(tmp_path), "--section", "x"])
    assert bad_section.exit_code == 2


def test_policy_validate_and_effective(
    policy_files: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    org, good, bad = policy_files
    ok = runner.invoke(app, ["policy", "validate", "--org", str(org), "--project", str(good)])
    assert ok.exit_code == 0 and "1 override(s) applied, 0 violation(s)" in ok.output
    fail = runner.invoke(app, ["policy", "validate", "--org", str(org), "--project", str(bad)])
    assert fail.exit_code == 1 and "VIOLATION cost_limits.max_agent_turns" in fail.output

    eff = runner.invoke(
        app, ["policy", "effective", "--org", str(org), "--project", str(good), "--json"]
    )
    assert eff.exit_code == 0
    data = json.loads(eff.output)
    assert data["cost_limits"]["max_agent_turns"] == 5 and data["violations"] == []
    eff_yaml = runner.invoke(app, ["policy", "effective", "--org", str(org), "--project", str(bad)])
    assert eff_yaml.exit_code == 0 and "max_agent_turns: 40" in eff_yaml.output
    strict = runner.invoke(
        app, ["policy", "effective", "--org", str(org), "--project", str(bad), "--strict"]
    )
    assert strict.exit_code == 1

    broken = tmp_path / "broken.yaml"
    broken.write_text("a: [\n")
    err = runner.invoke(app, ["policy", "validate", "--org", str(broken), "--root", str(tmp_path)])
    assert err.exit_code == 2 and "invalid YAML" in err.output


def test_policy_discovers_repo_templates() -> None:
    repo = Path(__file__).resolve().parents[1]
    result = runner.invoke(app, ["policy", "validate", "--root", str(repo)])
    assert result.exit_code == 0
