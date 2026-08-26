"""Cross-module integration: producers write the canonical evidence models.

Covers the reconciliation work: the lazy ``aisdlc.security`` package, the shared
``GateDepthProfile``, and the producer-side helpers that put PyRIT/safety, audit and cost
results into ``evidence/*.json`` in the exact shapes ``schema.package`` loads.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import aisdlc.security as security_pkg
from aisdlc.cli.main import app
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.gates import depth as depthmod
from aisdlc.governance import audit as auditmod
from aisdlc.planning import risk as riskmod
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    AuditEvidence,
    CostEvidence,
    EvidenceKind,
    EvidenceStatus,
    GateDepth,
    GateId,
    Intent,
    PyritSummary,
    RiskClass,
    SecurityEvidence,
    ThreatModel,
    ToolDataManifest,
)
from aisdlc.security import manifest as manifestmod
from aisdlc.security import supply_chain as scmod

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def package(tmp_path: Path) -> Path:
    pkg = pkgio.create(tmp_path, "CHG-evidence", Intent(id="CHG-evidence", title="Evidence"))
    assert pkg.root is not None
    return pkg.root


# --------------------------------------------------------------------------------------
# aisdlc.security lazy package
# --------------------------------------------------------------------------------------


def test_security_package_resolves_every_plane_lazily() -> None:
    for name in security_pkg.__all__:
        if name in ("ci_templates", "supply_chain", "manifest"):
            assert getattr(security_pkg, name) is importlib.import_module(f"aisdlc.security.{name}")
    assert security_pkg.update_security_evidence is scmod.update_security_evidence
    assert security_pkg.drift_for_package is manifestmod.drift_for_package
    assert (
        security_pkg.render_to is importlib.import_module("aisdlc.security.ci_templates").render_to
    )
    assert "update_security_evidence" in dir(security_pkg)
    assert "manifest" in dir(security_pkg)
    with pytest.raises(AttributeError):
        _ = security_pkg.not_a_real_name  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------
# single GateDepthProfile
# --------------------------------------------------------------------------------------


def test_planning_and_gates_share_one_profile_class() -> None:
    assert riskmod.GateDepthProfile is depthmod.GateDepthProfile
    assert riskmod.QualityCheck is depthmod.QualityCheck
    profile = riskmod.gate_depth_profile(RiskClass.AI_AGENT)
    assert profile == depthmod.profile_for(RiskClass.AI_AGENT)
    # planning aliases mirror the gate knobs
    assert profile.pyrit_campaign_required is profile.pyrit_required
    assert profile.pyrit_trials_min == profile.trials
    assert profile.cross_family_review_required is profile.cross_family_required
    assert profile.secret_scan_required is profile.secrets_scan_required
    assert profile.cost_evidence_required is profile.cost_required
    assert profile.performance_evidence_required is profile.performance_required
    assert profile.signed_bundle_required is profile.require_signatures
    assert profile.require_plan_check is profile.require_plan
    assert profile.critical_modules_coverage_min == profile.coverage_critical_modules_min
    assert profile.human_approvals_required == profile.min_approvals == 2
    assert profile.depth_for(GateId.G4) is profile.gate_depth(GateId.G4) is GateDepth.DEEP
    assert profile.applies(GateId.G4) and profile.requires(GateId.G4)
    docs = riskmod.gate_depth_profile(RiskClass.DOCS_ONLY)
    assert docs.human_approvals_required == 0 and not docs.applies(GateId.G6)


# --------------------------------------------------------------------------------------
# security.json merge
# --------------------------------------------------------------------------------------


def test_update_security_evidence_creates_then_merges(package: Path) -> None:
    pyrit = {
        "campaign_id": "c1",
        "asr": 0.0,
        "undetermined_rate": 0.0,
        "complete": True,
        "trials": 9,
    }
    record = scmod.update_security_evidence(
        package, pyrit=pyrit, commit_sha="abc", environment="ci", produced_by="pyrit-runner"
    )
    assert record.status is EvidenceStatus.COMPLETE and record.sast is None
    loaded = pkgio.read_evidence(package, EvidenceKind.SECURITY)
    assert len(loaded) == 1 and isinstance(loaded[0], SecurityEvidence)
    assert loaded[0].pyrit == PyritSummary.model_validate(pyrit)

    # a later safety run keeps the pyrit summary and appends its producer
    safety = {"asr_by_category": {"harm": 0.2}, "complete": False, "threshold_breaches": ["x"]}
    merged = scmod.update_security_evidence(package, safety=safety, produced_by="safety-runner")
    assert merged.pyrit is not None and merged.pyrit.campaign_id == "c1"
    assert merged.safety_regression is not None and not merged.safety_regression.complete
    assert merged.status is EvidenceStatus.INCOMPLETE  # incomplete summary fails closed
    assert merged.produced_by == "pyrit-runner + safety-runner"
    assert merged.commit_sha == "abc" and merged.environment == "ci"

    # supply-chain fields of an existing record survive a plane-3 update
    full = scmod.build_security_evidence(sbom=True, provenance=True, commit_sha="def")
    scmod.write_security_evidence(package, full)
    again = scmod.update_security_evidence(package, pyrit=pyrit, manifest_drift=True)
    assert again.sbom_present and again.provenance_present and again.manifest_drift
    assert again.commit_sha == "def"
    bundle = pkgio.load_evidence_bundle(package)
    assert bundle.security is not None and bundle.security.pyrit is not None


# --------------------------------------------------------------------------------------
# cost.json from the ledger
# --------------------------------------------------------------------------------------


def test_ledger_cost_evidence_and_cli_package_export(package: Path, tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.sqlite"
    with UsageLedger(str(ledger_path)) as ledger:
        empty = ledger.cost_evidence("CHG-evidence", environment="ci")
        assert isinstance(empty, CostEvidence) and empty.status is EvidenceStatus.INCOMPLETE
        ledger.record(
            UsageEvent(
                change_id="CHG-evidence",
                provider="anthropic",
                model="claude-sonnet",
                input_tokens=100,
                output_tokens=50,
                cost_usd=0.25,
            )
        )
        record = ledger.cost_evidence("CHG-evidence", budget_usd=5.0, commit_sha="abc")
    assert record.status is EvidenceStatus.COMPLETE
    assert record.tokens_in == 100 and record.tokens_out == 50 and record.total_cost_usd == 0.25
    assert record.budget_usd == 5.0 and record.report_uri == str(ledger_path)

    result = runner.invoke(
        app,
        [
            "cost",
            "report",
            "--package",
            str(package),
            "--ledger",
            str(ledger_path),
            "--budget",
            "5",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "recorded EVD-cost-001 (complete" in result.output
    loaded = pkgio.load(package)
    assert loaded.evidence.cost is not None and loaded.evidence.cost.total_cost_usd == 0.25
    not_pkg = runner.invoke(
        app, ["cost", "report", "--package", str(tmp_path), "--ledger", str(ledger_path)]
    )
    assert not_pkg.exit_code != 0


# --------------------------------------------------------------------------------------
# audit.json canonical + entries sidecar
# --------------------------------------------------------------------------------------


def _detailed_export() -> dict[str, object]:
    return json.loads((FIXTURES / "manifest" / "audit.json").read_text(encoding="utf-8"))


def test_audit_evidence_from_export_is_canonical() -> None:
    export = _detailed_export()
    record = auditmod.audit_evidence_from_export(export, commit_sha="abc", environment="ci")
    assert isinstance(record, AuditEvidence)
    assert record.entries == len(export["entries"])  # type: ignore[arg-type]
    assert record.privileged_calls == 4 and record.denied_calls == 1 and record.approvals == 0
    assert record.integrity_ok and record.status is EvidenceStatus.COMPLETE
    assert record.started_at is not None and record.finished_at is not None
    tampered = auditmod.audit_evidence_from_export({**export, "integrity_ok": False})
    assert tampered.status is EvidenceStatus.INCOMPLETE
    # AuditTrail.to_audit_evidence goes through the same builder
    trail = auditmod.AuditTrail(None)
    trail.record_event("session_start", agent_id="a", action="session.start", tier=0)
    summary = trail.to_audit_evidence(environment="local")
    assert summary.entries == 1 and summary.integrity_ok


def test_record_audit_evidence_loads_and_feeds_drift(package: Path) -> None:
    export = _detailed_export()
    record, sidecar = auditmod.record_audit_evidence(package, export, commit_sha="abc")
    assert sidecar == pkgio.audit_entries_path(package) and sidecar.is_file()
    assert record.report_uri == str(sidecar)
    loaded = pkgio.load(package)  # canonical audit.json parses with the whole package
    assert loaded.evidence.audit is not None and loaded.evidence.audit.privileged_calls == 4
    pkg = pkgio.load(package)
    pkg.threat_model = ThreatModel(tool_data_manifest=ToolDataManifest(tools=["Read"]))
    pkg.save()
    report = manifestmod.drift_for_package(package)
    assert report.drift and "pastebin.com" in report.undeclared_egress_hosts
    # canonical audit.json alone (sidecar gone) still resolves through report_uri
    sidecar.rename(package / "elsewhere.json")
    auditmod.record_audit_evidence(package, export)
    pkgio.audit_entries_path(package).unlink()
    pkgio.write_evidence(
        package,
        EvidenceKind.AUDIT,
        record.model_copy(update={"report_uri": str(package / "elsewhere.json")}),
    )
    assert manifestmod.audit_entries_source(package) == package / "elsewhere.json"
    pkgio.write_evidence(
        package, EvidenceKind.AUDIT, record.model_copy(update={"report_uri": None})
    )
    assert manifestmod.audit_entries_source(package) is None
    assert any("not found" in n for n in manifestmod.drift_for_package(package).notes)


def test_governance_audit_export_package(package: Path, tmp_path: Path) -> None:
    pytest.importorskip("agentmesh.governance")
    log = tmp_path / "audit.jsonl"
    action = json.dumps({"tool_name": "Write", "action_type": "write", "resource": "/wt/a.py"})
    check = runner.invoke(
        app,
        [
            "governance",
            "policy",
            "check",
            action,
            "--workspace-root",
            "/wt",
            "--audit-log",
            str(log),
        ],
    )
    assert check.exit_code in (0, 1), check.output
    result = runner.invoke(
        app, ["governance", "audit", "export", str(log), "--package", str(package)]
    )
    assert result.exit_code == 0, result.output
    assert "recorded EVD-audit-001" in result.output
    loaded = pkgio.load(package)
    assert loaded.evidence.audit is not None and loaded.evidence.audit.entries >= 1
    assert pkgio.audit_entries_path(package).is_file()
    not_pkg = runner.invoke(
        app, ["governance", "audit", "export", str(log), "--package", str(tmp_path)]
    )
    assert not_pkg.exit_code == 2
