"""Evidence integrity around the gates: package artifacts are tier-3 writes, evidence
counters cannot undercut their scans, safety evidence carries trial counts, and the
signed audit log behind ``evidence/audit.json`` is verified at gate time."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisdlc.gates import gates as g
from aisdlc.governance.claude_code_plugin import classify_claude_tool_call
from aisdlc.governance.tiers import (
    PROTECTED_PACKAGE_ARTIFACT_TIER,
    RiskTier,
    TierConfig,
    classify,
    is_protected_package_artifact,
)
from aisdlc.schema.models import (
    AuditEvidence,
    EvidenceStatus,
    GateId,
    RiskClass,
    SafetySummary,
    ScanResult,
    SecurityEvidence,
)
from aisdlc.security.safety_regression import (
    CaseResult,
    SafetyReport,
    TrialOutcome,
    TrialRecord,
)
from tests.test_gates_fixtures import context, golden_package, policy


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/wt/changes/CHG-x/evidence/tests.json", True),
        ("/wt/changes/CHG-x/evidence/audit-entries.json", True),
        ("changes/CHG-x/approvals.json", True),
        ("changes/CHG-x/final-verdict.json", True),
        ("changes/CHG-x/evidence-bundle.json", True),
        ("changes/CHG-x/.fingerprint", True),
        ("C:\\wt\\changes\\CHG-x\\evidence\\security.json", True),
        ("changes/CHG-x/intent.md", False),
        ("changes/CHG-x/tasks.md", False),
        ("changes/CHG-x/evidence", False),
        ("changes/README.md", False),
        ("src/changes/notes.py", False),
        ("", False),
        (None, False),
    ],
)
def test_protected_package_artifacts(path: str | None, expected: bool) -> None:
    assert is_protected_package_artifact(path) is expected


def test_package_evidence_writes_are_tier_3_even_inside_the_worktree() -> None:
    assert PROTECTED_PACKAGE_ARTIFACT_TIER == RiskTier.APPROVAL
    assert classify("Write", "write", "/wt/changes/CHG-x/evidence/tests.json", True) == 3
    assert classify("Edit", "edit", "/wt/changes/CHG-x/approvals.json", True) == 3
    assert classify("Write", "write", "/wt/changes/CHG-x/intent.md", True) == 1
    lowered = TierConfig(overrides={"tool:Write": 1, "write": 1})
    assert classify("Write", "write", "/wt/changes/CHG-x/final-verdict.json", True, config=lowered)
    assert (
        classify("Write", "write", "/wt/changes/CHG-x/final-verdict.json", True, config=lowered)
        == 3
    )
    cfg = TierConfig(workspace_roots=["/wt/c1"])
    for target in (
        "changes/CHG-x/evidence/tests.json",
        "/wt/c1/changes/CHG-x/approvals.json",
        "/wt/c1/changes/CHG-x/final-verdict.json",
    ):
        action = classify_claude_tool_call("Write", {"file_path": target}, cwd="/wt/c1", config=cfg)
        assert action.tier == RiskTier.APPROVAL, target
    inside = classify_claude_tool_call("Write", {"file_path": "src/x.py"}, cwd="/wt/c1", config=cfg)
    assert inside.tier == RiskTier.AUTOMATIC_AUDIT


def test_security_counters_cannot_undercut_the_scans() -> None:
    record = SecurityEvidence(
        id="EVD-security-001",
        sast=ScanResult(tool="codeql", ran=True, high=7, critical=1),
        sca=ScanResult(tool="dep", ran=True, high=4),
        secrets=ScanResult(tool="gitleaks", ran=False, high=99),
        critical_open=0,
        high_open=0,
    )
    assert record.scan_critical == 1 and record.scan_high == 11
    assert record.critical_open == 1 and record.high_open == 11
    # a higher hand-count (e.g. findings outside the scans) is kept
    record = SecurityEvidence(id="EVD-security-001", sast=ScanResult(ran=True, high=1), high_open=3)
    assert record.high_open == 3


def test_safety_report_evidence_carries_trials_and_undetermined_rate() -> None:
    case = CaseResult(
        case_id="pi",
        category="prompt-injection",
        scheduled_trials=5,
        pass_threshold=0.0,
        trials=[TrialRecord(trial=i, outcome=TrialOutcome.UNDETERMINED) for i in range(5)],
    )
    report = SafetyReport(
        asr_by_category={"prompt-injection": 0.0},
        total_trials=5,
        completed_trials=5,
        complete=True,
        per_case=[case],
    )
    assert report.undetermined_rate == 1.0
    assert report.passed is False
    with pytest.raises(AssertionError, match="undetermined rate"):
        report.assert_passed()
    evidence = report.to_evidence()
    assert evidence["trials"] == 5
    assert evidence["trials_by_category"] == {"prompt-injection": 5}
    assert evidence["undetermined_rate"] == 1.0
    assert evidence["undetermined_by_category"] == {"prompt-injection": 1.0}
    summary = SafetySummary.model_validate(evidence)
    assert summary.trials_for("prompt-injection") == 5

    pkg = golden_package(RiskClass.AI_AGENT)
    assert pkg.evidence.security is not None
    pkg.evidence.security.safety_regression = summary
    result = g.evaluate_gate(GateId.G4, pkg, policy(), context=context())
    assert not result.passed
    assert any("safety undetermined rate 1.000 exceeds" in r for r in result.reasons)


def test_verify_package_audit_follows_the_export_to_the_signed_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("agentmesh.governance")
    from aisdlc.governance.audit import AuditTrail, record_audit_evidence

    monkeypatch.delenv("AISDLC_AUDIT_KEY", raising=False)
    package_dir = tmp_path / "changes" / "CHG-x"
    (package_dir / "evidence").mkdir(parents=True)
    log = package_dir / "evidence" / "audit.jsonl"
    trail = AuditTrail(log, session_id="CHG-x")
    trail.record_event("session_start", agent_id="implementer", action="start", tier=1)
    trail.record_event(
        "tool_call", agent_id="implementer", action="write", resource="src/a.py", tier=1
    )
    record, sidecar = record_audit_evidence(
        package_dir, trail.export_evidence(), commit_sha="abc", environment="local"
    )
    assert record.entries == 2 and record.integrity_ok

    report = g.verify_package_audit(package_dir, record)
    assert report is not None and report.ok and report.entries == 2

    # the signed log itself may be the report_uri
    direct = g.verify_package_audit(package_dir, record.model_copy(update={"report_uri": str(log)}))
    assert direct is not None and direct.ok and direct.entries == 2
    as_uri = g.verify_package_audit(
        package_dir, record.model_copy(update={"report_uri": log.as_uri()})
    )
    assert as_uri is not None and as_uri.ok

    # entry count mismatch between export and log
    inflated = json.loads(sidecar.read_text())
    inflated["entries"].append(dict(inflated["entries"][0]))
    sidecar.write_text(json.dumps(inflated))
    mismatch = g.verify_package_audit(package_dir, record)
    assert mismatch is not None and not mismatch.ok and "holds 2 entries" in (mismatch.error or "")
    sidecar.write_text(json.dumps(trail.export_evidence(), indent=2))

    # tampering with the signed log is detected
    lines = log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["outcome"] = "denied"
    lines[0] = json.dumps(entry, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    tampered = g.verify_package_audit(package_dir, record)
    assert tampered is not None and not tampered.ok

    # a missing log, an export without a log, and no source at all
    log.unlink()
    missing = g.verify_package_audit(package_dir, record)
    assert missing is not None and not missing.ok and "not found" in (missing.error or "")
    export = json.loads(sidecar.read_text())
    export["log_path"] = None
    sidecar.write_text(json.dumps(export))
    unsigned = g.verify_package_audit(package_dir, record)
    assert unsigned is not None and not unsigned.ok and "no signed log" in (unsigned.error or "")
    sidecar.unlink()
    assert (
        g.verify_package_audit(package_dir, record.model_copy(update={"report_uri": None})) is None
    )
    assert g.verify_package_audit(package_dir, None) is None


def test_gate_context_from_disk_verifies_audit_and_reads_portfolio(tmp_path: Path) -> None:
    from aisdlc.schema import package as pkgio
    from aisdlc.testing import portfolio as pf
    from tests.test_gates_fixtures import NOW, portfolio_inputs

    pkg = golden_package()
    created = pkgio.create(tmp_path, pkg.change_id, pkg.intent)
    created.evidence = pkg.evidence
    created.evidence.audit = AuditEvidence(
        id="EVD-audit-001",
        entries=3,
        integrity_ok=True,
        status=EvidenceStatus.COMPLETE,
        report_uri="file:///nowhere/audit.jsonl",
    )
    created.save()
    assert created.root is not None
    ctx = g.GateContext.from_package(created)
    assert ctx.audit_integrity is None and ctx.audit_entries_source is None
    assert ctx.portfolio_inputs is None and ctx.portfolio_inputs_error is None
    assert ctx.manifest_drift is not None and ctx.manifest_drift.drift is False
    deep = g.evaluate_gate(GateId.G6, created, policy(), context=context(audit_integrity=None))
    assert any("signed audit log not found" in r for r in deep.reasons)

    pf.write_portfolio_record(
        created.root,
        pf.PortfolioRecord(
            risk_class=RiskClass.STANDARD,
            inputs=portfolio_inputs(),
            report=pf.evaluate(pf.PortfolioEvidence(), None, RiskClass.STANDARD, now=NOW),
        ),
    )
    ctx = g.GateContext.from_package(created)
    assert ctx.portfolio_inputs is not None and len(ctx.portfolio_inputs.runs) == 1
    pf.portfolio_path(created.root).write_text("{not json")
    ctx = g.GateContext.from_package(created)
    assert ctx.portfolio_inputs is None and ctx.portfolio_inputs_error


def test_verify_package_audit_resolves_a_relative_log_path_against_cwd_and_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--audit-log .aisdlc/audit.jsonl`` is verified where it was written, not under evidence/."""
    pytest.importorskip("agentmesh.governance")
    from aisdlc.governance.audit import AuditTrail, record_audit_evidence

    monkeypatch.delenv("AISDLC_AUDIT_KEY", raising=False)
    repo = tmp_path / "repo"
    package_dir = repo / "changes" / "CHG-x"
    package_dir.mkdir(parents=True)
    monkeypatch.chdir(repo)
    trail = AuditTrail(Path(".aisdlc/audit.jsonl"), session_id="CHG-x")
    trail.record_event(
        "tool_call", agent_id="implementer", action="write", resource="src/a.py", tier=1
    )
    export = trail.export_evidence()
    assert export["log_path"] == ".aisdlc/audit.jsonl"
    record, _sidecar = record_audit_evidence(package_dir, export, commit_sha="abc")
    assert not (package_dir / "evidence" / ".aisdlc").exists()

    # from the repository root (the working directory the log was written from)
    report = g.verify_package_audit(package_dir, record)
    assert report is not None and report.ok and report.entries == 1, report

    # from any other directory: resolved through the repository holding changes/<id>
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    report = g.verify_package_audit(package_dir, record)
    assert report is not None and report.ok and report.entries == 1, report

    # a missing log names the places that were tried — never the evidence directory
    (repo / ".aisdlc" / "audit.jsonl").unlink()
    missing = g.verify_package_audit(package_dir, record)
    assert missing is not None and not missing.ok
    error = missing.error or ""
    assert "not found (looked in" in error
    assert (
        str(elsewhere / ".aisdlc/audit.jsonl") in error
        and str(repo / ".aisdlc/audit.jsonl") in error
    )
    assert "evidence/.aisdlc" not in error
