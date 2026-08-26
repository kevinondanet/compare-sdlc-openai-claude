"""Tests for aisdlc.security.manifest (tool/data manifest drift)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisdlc.schema import package as pkgio
from aisdlc.schema.models import Intent, ThreatModel, ToolDataManifest
from aisdlc.security import manifest as mf

FIXTURES = Path(__file__).parent / "fixtures" / "manifest"

DECLARED = ToolDataManifest(
    tools=["Read", "Write", "mcp__github__*"],
    data_sources=["postgres://orders-db/*"],
    network_egress=["api.github.com"],
)


def test_host_of() -> None:
    assert mf.host_of("https://API.GitHub.com/repos") == "api.github.com"
    assert mf.host_of("wss://stream.example.org:443/x") == "stream.example.org"
    assert mf.host_of("git@github.com:org/repo.git") == "github.com"
    assert mf.host_of("src/app/main.py") is None
    assert mf.host_of(None) is None


def test_record_from_platform_audit_entry() -> None:
    entries = mf.load_audit_entries(FIXTURES / "audit.json")
    assert len(entries) == 8
    records = [mf.record_from_audit_entry(e) for e in entries]
    assert records[0] is None and records[7] is None  # session start / approval
    assert records[1] is not None and records[1].tool_name == "Read" and records[1].allowed
    web = records[4]
    assert web is not None and web.egress_host == "pastebin.com"
    blocked = records[5]
    assert blocked is not None and blocked.tool_name == "Bash" and not blocked.allowed
    db = records[6]
    assert db is not None and db.data_sources == ["postgres://orders-db/orders"]


def test_observe_audit_skips_denied_by_default() -> None:
    observed = mf.observe_audit(FIXTURES / "audit.json")
    assert observed.records == 5
    assert set(observed.tools) == {
        "Read",
        "Write",
        "mcp__github__create_pull_request",
        "WebFetch",
        "mcp__db__query",
    }
    assert observed.egress_hosts == {"api.github.com": 1, "pastebin.com": 1}
    assert observed.data_sources == {"postgres://orders-db/orders": 1}
    with_denied = mf.observe_audit(FIXTURES / "audit.json", include_denied=True)
    assert with_denied.records == 6 and "Bash" in with_denied.tools


def test_claude_code_plugin_format() -> None:
    observed = mf.observe_audit(FIXTURES / "claude-code-audit.json")
    assert observed.tools == {"Read": 1, "Write": 1}
    assert (
        "Bash" in mf.observe_audit(FIXTURES / "claude-code-audit.json", include_denied=True).tools
    )


def test_load_audit_entries_formats(tmp_path: Path) -> None:
    lines = tmp_path / "audit.jsonl"
    lines.write_text(
        "\n".join(
            json.dumps(e)
            for e in [
                {"event_type": "tool_invocation", "action": "read", "data": {"tool_name": "Read"}},
                {"event_type": "tool_invocation", "action": "shell", "data": {"tool_name": "Bash"}},
            ]
        )
        + "\n"
    )
    assert len(mf.load_audit_entries(lines)) == 2
    assert mf.load_audit_entries({"entries": [{"a": 1}]}) == [{"a": 1}]
    assert mf.load_audit_entries([{"b": 2}, "junk"]) == [{"b": 2}]
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert mf.load_audit_entries(empty) == []
    bad = tmp_path / "bad.json"
    bad.write_text("[not json")
    with pytest.raises(ValueError, match="invalid JSON"):
        mf.load_audit_entries(bad)
    with pytest.raises(ValueError, match="no 'entries'"):
        mf.load_audit_entries({"foo": 1})


def test_compare_reports_drift() -> None:
    observed = mf.observe_audit(FIXTURES / "audit.json")
    report = mf.compare(DECLARED, observed)
    assert report.drift
    assert report.undeclared_tools == ["WebFetch", "mcp__db__query"]
    assert report.undeclared_egress_hosts == ["pastebin.com"]
    assert report.undeclared_data_sources == []
    assert report.unused_declared == [] and report.unused_declared_egress == []
    assert report.observed_records == 5
    assert "manifest drift: YES" in report.summary_lines()[0]


def test_compare_clean_and_strict_unused() -> None:
    records = [
        mf.ToolCallRecord(tool_name="Read", resource="a.py"),
        mf.ToolCallRecord(tool_name="mcp__github__list_issues", egress_host="api.github.com"),
    ]
    observed = mf.observe(records)
    report = mf.compare(DECLARED, observed)
    assert not report.drift
    assert report.unused_declared == ["Write"]
    assert report.unused_declared_data_sources == ["postgres://orders-db/*"]
    strict = mf.compare(DECLARED, observed, strict_unused=True)
    assert strict.drift and any("strict" in n for n in strict.notes)
    nothing = mf.compare(DECLARED, mf.ObservedBehaviour())
    assert not nothing.drift and any("no tool calls observed" in n for n in nothing.notes)


def test_matches_declared_patterns() -> None:
    assert mf.matches_declared(["*.github.com"], "api.github.com") == "*.github.com"
    assert mf.matches_declared(["API.GITHUB.COM"], "api.github.com") == "API.GITHUB.COM"
    assert mf.matches_declared(["s3://bucket/"], "s3://bucket/key") == "s3://bucket/"
    assert mf.matches_declared(["Read"], "Write") is None


def test_check_drift_accepts_records_entries_and_threat_model() -> None:
    threat_model = ThreatModel(tool_data_manifest=DECLARED)
    records = [mf.ToolCallRecord(tool_name="Evil")]
    assert mf.check_drift(threat_model, records).undeclared_tools == ["Evil"]
    entries = [{"event_type": "tool_invocation", "action": "x", "data": {"tool_name": "Read"}}]
    assert not mf.check_drift(DECLARED, entries).drift
    assert mf.check_drift(DECLARED, FIXTURES / "audit.json").drift
    assert not mf.check_drift(DECLARED, []).drift


def test_drift_for_package(tmp_path: Path) -> None:
    pkg = pkgio.create(tmp_path, "CHG-drift", Intent(id="CHG-drift", title="Drift"))
    root = pkg.root
    assert root is not None
    pkg.threat_model = ThreatModel(tool_data_manifest=DECLARED)
    pkg.save()
    assert mf.load_declared_manifest(root) == DECLARED
    report = mf.drift_for_package(root)
    assert not report.drift and any("not found" in n for n in report.notes)
    audit_path = pkgio.evidence_path(root, "audit")
    audit_path.write_text((FIXTURES / "audit.json").read_text())
    report = mf.drift_for_package(root)
    assert report.drift and report.undeclared_egress_hosts == ["pastebin.com"]
    bare = pkgio.create(tmp_path, "CHG-bare", Intent(id="CHG-bare", title="Bare"))
    assert bare.root is not None
    (bare.root / "architecture" / "threat-model.md").unlink()
    assert mf.load_declared_manifest(bare.root) == ToolDataManifest()


def test_platform_internal_calls_are_excluded_by_exact_allowlist() -> None:
    """The orchestrator's own governed actions never count as drift; look-alikes still do."""
    entries = [
        {
            "event_type": "tool_invocation",
            "action": "write",
            "data": {"tool_name": "aisdlc.orchestration"},
        },
        {
            "event_type": "tool_invocation",
            "action": "git_commit",
            "data": {"tool_name": "aisdlc.orchestration"},
        },
        {
            "event_type": "tool_invocation",
            "action": "http_request",
            "resource": "https://pastebin.com/x",
            "data": {"tool_name": "WebFetch"},
        },
        {
            "event_type": "tool_invocation",
            "action": "x",
            "data": {"tool_name": "aisdlc.orchestration.evil"},
        },
        {
            "event_type": "tool_invocation",
            "action": "x",
            "data": {"tool_name": "AISDLC.ORCHESTRATION"},
        },
    ]
    assert "aisdlc.orchestration" in mf.PLATFORM_TOOLS and mf.is_platform_tool(
        "aisdlc.orchestration"
    )
    assert not mf.is_platform_tool("aisdlc.orchestration.evil")
    assert not mf.is_platform_tool("AISDLC.ORCHESTRATION")

    report = mf.check_drift(DECLARED, entries)
    assert report.drift
    assert report.undeclared_tools == [
        "AISDLC.ORCHESTRATION",
        "WebFetch",
        "aisdlc.orchestration.evil",
    ]
    assert report.undeclared_egress_hosts == ["pastebin.com"]
    assert report.platform_tools == {"aisdlc.orchestration": 2}
    assert report.observed_records == 3
    assert "  platform-internal calls excluded: aisdlc.orchestration (2)" in report.summary_lines()

    # only platform calls: clean, and the note explains why unused-declared is not meaningful
    only_platform = mf.check_drift(DECLARED, entries[:2])
    assert not only_platform.drift and only_platform.observed_records == 0
    assert any("2 platform-internal call(s) excluded" in n for n in only_platform.notes)

    # overrides: an empty allowlist reports the orchestrator; a wider one excludes more
    disabled = mf.check_drift(DECLARED, entries[:2], platform_tools=())
    assert disabled.drift and disabled.undeclared_tools == ["aisdlc.orchestration"]
    wider = mf.check_drift(DECLARED, entries, platform_tools={*mf.PLATFORM_TOOLS, "WebFetch"})
    assert "WebFetch" not in wider.undeclared_tools and wider.platform_tools["WebFetch"] == 1
    assert wider.undeclared_egress_hosts == []  # an excluded call's egress is not the agent's

    # a hand-built ObservedBehaviour is filtered by compare() as well
    observed = mf.ObservedBehaviour(tools={"aisdlc.orchestration": 4, "Read": 1}, records=5)
    by_hand = mf.compare(DECLARED, observed)
    assert not by_hand.drift and by_hand.platform_tools == {"aisdlc.orchestration": 4}
    assert by_hand.observed_records == 1


def test_record_from_audit_entry_keeps_a_null_agent_id_null() -> None:
    entry = {
        "event_type": "tool_invocation",
        "action": "write",
        "agent_id": None,
        "data": {"tool_name": "Write"},
    }
    record = mf.record_from_audit_entry(entry)
    assert record is not None and record.agent_id is None


def test_audit_path_candidates_resolve_relative_paths_against_cwd_then_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    package_dir = repo / "changes" / "CHG-x"
    package_dir.mkdir(parents=True)
    absolute = tmp_path / "abs.jsonl"
    assert mf.audit_path_candidates(absolute, package_dir) == [absolute]

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    candidates = [c.resolve() for c in mf.audit_path_candidates(".aisdlc/audit.jsonl", package_dir)]
    assert candidates == [
        (elsewhere / ".aisdlc/audit.jsonl").resolve(),
        (repo / ".aisdlc/audit.jsonl").resolve(),
    ]
    assert not any(str(c).startswith(str((package_dir / "evidence").resolve())) for c in candidates)

    monkeypatch.chdir(repo)
    same = [c.resolve() for c in mf.audit_path_candidates(".aisdlc/audit.jsonl", package_dir)]
    assert same == [(repo / ".aisdlc/audit.jsonl").resolve()]

    # a package outside a changes/ tree only has the working directory
    lone = tmp_path / "CHG-lone"
    lone.mkdir()
    monkeypatch.chdir(elsewhere)
    only_cwd = [c.resolve() for c in mf.audit_path_candidates("audit.jsonl", lone)]
    assert only_cwd == [(elsewhere / "audit.jsonl").resolve()]


def test_audit_entries_source_follows_a_relative_report_uri(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    pkg = pkgio.create(repo, "CHG-rel", Intent(id="CHG-rel", title="Rel"))
    assert pkg.root is not None
    log = repo / ".aisdlc" / "audit.jsonl"
    log.parent.mkdir()
    lines = [
        {"event_type": "tool_invocation", "action": "read", "data": {"tool_name": "Read"}},
        {"event_type": "tool_invocation", "action": "read", "data": {"tool_name": "Read"}},
    ]
    log.write_text("".join(json.dumps(line) + "\n" for line in lines))
    audit_path = pkgio.evidence_path(pkg.root, "audit")
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps({"id": "EVD-audit-001", "report_uri": ".aisdlc/audit.jsonl"}))
    monkeypatch.chdir(tmp_path)  # not the repo root: resolved through changes/<id>'s repository
    assert mf.audit_entries_source(pkg.root) == log.resolve()
    assert mf.observe_audit(log).tools == {"Read": 2}
