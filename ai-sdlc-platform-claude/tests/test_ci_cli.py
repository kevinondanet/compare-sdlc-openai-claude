"""Tests for the ``aisdlc ci`` CLI (render, list, verify-pins, collect-security, manifest-drift)."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import Intent, ThreatModel, ToolDataManifest

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
SHA = "c" * 40


def test_render_writes_workflows_and_caller(tmp_path: Path) -> None:
    out = tmp_path / "wf"
    result = runner.invoke(
        app,
        [
            "ci",
            "render",
            "--out",
            str(out),
            "--workflows-ref",
            SHA,
            "--workflows-repo",
            "acme/.github",
            "--matrix",
            "3.12",
            "--matrix",
            "3.13",
        ],
    )
    assert result.exit_code == 0, result.output
    names = sorted(p.name for p in out.iterdir())
    assert "aisdlc-ci.yml" in names and "build-and-test.yml" in names and len(names) == 13
    assert f"@{SHA}" in (out / "aisdlc-ci.yml").read_text()
    build = yaml.safe_load((out / "build-and-test.yml").read_text())
    assert build[True]["workflow_call"]["inputs"]["versions"]["default"] == '["3.12", "3.13"]'
    verify = runner.invoke(app, ["ci", "verify-pins", str(out)])
    assert verify.exit_code == 0, verify.output


def test_render_subset_to_stdout_and_errors(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["ci", "render", "--stdout", "--no-caller", "-w", "secret-scan", "--workflows-ref", SHA],
    )
    assert result.exit_code == 0, result.output
    assert "===== secret-scan.yml =====" in result.output and "gitleaks" in result.output
    bad_ref = runner.invoke(
        app, ["ci", "render", "--out", str(tmp_path), "--workflows-ref", "main"]
    )
    assert bad_ref.exit_code == 2 and "40-hex" in bad_ref.output
    unknown = runner.invoke(
        app, ["ci", "render", "--stdout", "--no-caller", "-w", "nope", "--workflows-ref", SHA]
    )
    assert unknown.exit_code == 2
    project = tmp_path / "project-config.yaml"
    project.write_text("name: cobol-app\nlanguages: [cobol]\n")
    unsupported = runner.invoke(
        app, ["ci", "render", "--stdout", "--project", str(project), "--workflows-ref", SHA]
    )
    assert unsupported.exit_code == 2 and "unsupported language" in unsupported.output
    missing = runner.invoke(app, ["ci", "render", "--project", str(tmp_path / "nope.yaml")])
    assert missing.exit_code == 2


def test_list_command() -> None:
    result = runner.invoke(app, ["ci", "list"])
    assert result.exit_code == 0
    assert "build-and-test" in result.output and "actions/checkout@" in result.output
    as_json = runner.invoke(app, ["ci", "list", "--json"])
    payload = json.loads(as_json.output)
    assert "pins" in payload and payload["languages"] == ["python"]


def test_verify_pins_command(tmp_path: Path) -> None:
    ok = runner.invoke(app, ["ci", "verify-pins"])
    assert ok.exit_code == 0 and "SHA-pinned" in ok.output
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "name: bad\non: push\njobs:\n  j:\n    runs-on: x\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    failed = runner.invoke(app, ["ci", "verify-pins", str(bad)])
    assert failed.exit_code == 1
    assert "not a 40-hex SHA" in failed.output and "NO_TOP_PERMISSIONS" in failed.output
    as_json = runner.invoke(app, ["ci", "verify-pins", str(bad), "--no-lint", "--json"])
    payload = json.loads(as_json.output)
    assert len(payload["pins"]) == 1 and payload["lint"] == []
    missing = runner.invoke(app, ["ci", "verify-pins", str(tmp_path / "nope")])
    assert missing.exit_code == 2


def test_collect_security_command(tmp_path: Path) -> None:
    pkg = pkgio.create(tmp_path, "CHG-sec", Intent(id="CHG-sec", title="sec"))
    assert pkg.root is not None
    out = tmp_path / "security.json"
    result = runner.invoke(
        app,
        [
            "ci",
            "collect-security",
            str(FIXTURES / "supply_chain"),
            "--package",
            str(pkg.root),
            "--commit-sha",
            "abc",
            "--out",
            str(out),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["evidence"]["status"] == "complete"
    assert payload["evidence"]["critical_open"] == 1 and payload["evidence"]["sbom_present"]
    assert payload["inputs"]["provenance"] == "provenance.intoto.json"
    assert json.loads(out.read_text())["commit_sha"] == "abc"
    stored = pkgio.read_evidence(pkg.root, "security")
    assert len(stored) == 1
    empty = tmp_path / "empty"
    empty.mkdir()
    incomplete = runner.invoke(app, ["ci", "collect-security", str(empty)])
    assert incomplete.exit_code == 1 and "status=incomplete" in incomplete.output
    not_pkg = runner.invoke(app, ["ci", "collect-security", str(empty), "-p", str(tmp_path)])
    assert not_pkg.exit_code == 2


def test_manifest_drift_command(tmp_path: Path) -> None:
    pkg = pkgio.create(tmp_path, "CHG-mf", Intent(id="CHG-mf", title="mf"))
    assert pkg.root is not None
    pkg.threat_model = ThreatModel(
        tool_data_manifest=ToolDataManifest(
            tools=["Read", "Write", "mcp__github__*", "WebFetch", "mcp__db__query"],
            network_egress=["api.github.com", "pastebin.com"],
            data_sources=["postgres://orders-db/*"],
        )
    )
    pkg.save()
    clean = runner.invoke(
        app,
        [
            "ci",
            "manifest-drift",
            str(pkg.root),
            "--audit",
            str(FIXTURES / "manifest" / "audit.json"),
        ],
    )
    assert clean.exit_code == 0, clean.output
    assert "manifest drift: no" in clean.output
    no_audit = runner.invoke(app, ["ci", "manifest-drift", str(pkg.root), "--json"])
    assert no_audit.exit_code == 0
    assert any("not found" in n for n in json.loads(no_audit.output)["notes"])
    pkg.threat_model = ThreatModel(tool_data_manifest=ToolDataManifest(tools=["Read"]))
    pkg.save()
    audit_path = pkgio.evidence_path(pkg.root, "audit")
    audit_path.write_text((FIXTURES / "manifest" / "audit.json").read_text())
    drift = runner.invoke(app, ["ci", "manifest-drift", str(pkg.root), "--json"])
    assert drift.exit_code == 1
    report = json.loads(drift.output)
    assert report["drift"] and "WebFetch" in report["undeclared_tools"]
    assert report["undeclared_egress_hosts"] == ["api.github.com", "pastebin.com"]
    bad = runner.invoke(
        app, ["ci", "manifest-drift", str(pkg.root), "--audit", str(tmp_path / "missing.json")]
    )
    assert bad.exit_code == 2


def test_manifest_drift_excludes_platform_actors_by_exact_allowlist(tmp_path: Path) -> None:
    """The orchestrator's own writes (aisdlc.orchestration) are not undeclared agent tools."""
    pkg = pkgio.create(tmp_path, "CHG-pl", Intent(id="CHG-pl", title="pl"))
    assert pkg.root is not None
    pkg.threat_model = ThreatModel(tool_data_manifest=ToolDataManifest(tools=["lookup_order"]))
    pkg.save()
    entries = [
        {
            "event_type": "tool_invocation",
            "action": "write",
            "outcome": "allowed",
            "data": {"tool_name": "aisdlc.orchestration"},
        },
        {
            "event_type": "tool_invocation",
            "action": "modify_shared_state",
            "outcome": "approved",
            "data": {"tool_name": "aisdlc.orchestration"},
        },
        {
            "event_type": "tool_invocation",
            "action": "lookup",
            "outcome": "allowed",
            "data": {"tool_name": "lookup_order"},
        },
    ]
    audit = tmp_path / "audit.json"
    audit.write_text(json.dumps({"entries": entries}))
    base = ["ci", "manifest-drift", str(pkg.root), "--audit", str(audit)]
    clean = runner.invoke(app, [*base, "--json"])
    assert clean.exit_code == 0, clean.output
    report = json.loads(clean.output)
    assert not report["drift"] and report["undeclared_tools"] == []
    assert (
        report["platform_tools"] == {"aisdlc.orchestration": 2} and report["observed_records"] == 1
    )
    text = runner.invoke(app, base)
    assert "platform-internal calls excluded: aisdlc.orchestration (2)" in text.output

    # a real undeclared tool — even one resembling the platform name — is still drift
    entries.append(
        {
            "event_type": "tool_invocation",
            "action": "x",
            "outcome": "allowed",
            "data": {"tool_name": "aisdlc.orchestration.refund"},
        }
    )
    audit.write_text(json.dumps({"entries": entries}))
    drift = runner.invoke(app, [*base, "--json"])
    assert drift.exit_code == 1
    assert json.loads(drift.output)["undeclared_tools"] == ["aisdlc.orchestration.refund"]

    # overrides: disable the allowlist, or extend it
    off = runner.invoke(app, [*base, "--no-platform-allowlist", "--json"])
    assert off.exit_code == 1
    assert "aisdlc.orchestration" in json.loads(off.output)["undeclared_tools"]
    extended = runner.invoke(
        app, [*base, "--platform-tool", "aisdlc.orchestration.refund", "--json"]
    )
    assert extended.exit_code == 0, extended.output
    assert json.loads(extended.output)["platform_tools"]["aisdlc.orchestration.refund"] == 1
