"""Tests for the ``aisdlc gate`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.gates import verdict as v
from aisdlc.schema import fingerprint as fingerprintmod
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import FinalVerdict, GateId, GateResult
from aisdlc.testing import portfolio as pf
from tests.test_gates_fixtures import COMMIT, NOW, golden_package, portfolio_inputs

runner = CliRunner()


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(v.SIGNING_KEY_ENV, "cli-key")
    monkeypatch.delenv(v.ED25519_PRIVATE_KEY_ENV, raising=False)
    monkeypatch.delenv(v.ED25519_PUBLIC_KEY_ENV, raising=False)


@pytest.fixture
def package_dir(tmp_path: Path) -> Path:
    pkg = golden_package()
    created = pkgio.create(tmp_path, pkg.change_id, pkg.intent)
    for name in (
        "requirements",
        "assumptions",
        "decisions",
        "threat_model",
        "plan",
        "tasks",
        "evidence",
    ):
        setattr(created, name, getattr(pkg, name))
    # Audit evidence must point at a verifiable signed log; the on-disk package has none,
    # so a standard-depth package (audit optional) carries no audit record at all.
    created.evidence.audit = None
    created.save()
    assert created.root is not None
    pf.write_portfolio_record(
        created.root,
        pf.PortfolioRecord(
            risk_class=pkg.intent.risk_class,
            inputs=portfolio_inputs(),
            report=pf.evaluate(pf.PortfolioEvidence(), None, pkg.intent.risk_class, now=NOW),
        ),
    )
    return created.root


def test_evaluate_single_gate_and_json(package_dir: Path) -> None:
    result = runner.invoke(app, ["gate", "evaluate", str(package_dir), "--gate", "G0"])
    assert result.exit_code == 0, result.output
    assert "G0 PASS [standard] Intent readiness" in result.output

    as_json = runner.invoke(app, ["gate", "evaluate", str(package_dir), "--json"])
    assert as_json.exit_code == 1, as_json.output  # G6: no human approval yet
    data = json.loads(as_json.output)
    assert data["risk_class"] == "standard" and data["depth"] == "standard"
    by_gate = {r["gate"]: r for r in data["results"]}
    assert by_gate["G0"]["passed"] and not by_gate["G6"]["passed"]
    assert any("approval" in r for r in by_gate["G6"]["reasons"])


def test_evaluate_with_risk_override(package_dir: Path) -> None:
    result = runner.invoke(app, ["gate", "evaluate", str(package_dir), "--risk", "docs_only"])
    assert result.exit_code == 0, result.output
    assert "G4 SKIP [skipped]" in result.output
    assert "G2 PASS [light]" in result.output


def test_evaluate_errors(tmp_path: Path) -> None:
    result = runner.invoke(app, ["gate", "evaluate", str(tmp_path)])
    assert result.exit_code == 2
    bad_policy = tmp_path / "org-policy.yaml"
    bad_policy.write_text("gates: [1, 2]\n")
    pkg = golden_package()
    created = pkgio.create(tmp_path, pkg.change_id, pkg.intent)
    assert created.root is not None
    result = runner.invoke(app, ["gate", "evaluate", str(created.root), "--org", str(bad_policy)])
    assert result.exit_code == 2 and "error" in result.output


def test_full_release_flow(package_dir: Path) -> None:
    approve = runner.invoke(
        app, ["gate", "approve", str(package_dir), "--role", "owner", "--approver", "kevin"]
    )
    assert approve.exit_code == 0, approve.output
    assert "recorded approval by kevin as owner (1 total)" in approve.output

    verdict = runner.invoke(app, ["gate", "verdict", str(package_dir)])
    assert verdict.exit_code == 0, verdict.output
    assert "overall: PASS" in verdict.output
    written = pkgio.read_final_verdict(package_dir)
    assert written is not None and written.overall and written.signatures == []
    assert written.commit_sha == COMMIT

    bundle = runner.invoke(app, ["gate", "bundle", str(package_dir), "--signer", "ci"])
    assert bundle.exit_code == 0, bundle.output
    assert "signed hmac-sha256 by ci" in bundle.output
    signed = pkgio.read_final_verdict(package_dir)
    assert signed is not None and len(signed.signatures) == 1 and signed.bundle_digest

    verify = runner.invoke(
        app, ["gate", "verify-bundle", str(package_dir), "--head", COMMIT, "--json"]
    )
    assert verify.exit_code == 0, verify.output
    data = json.loads(verify.output)
    assert data["ok"] and data["valid_signatures"] == 1 and data["approvals"] == 1

    stale = runner.invoke(app, ["gate", "verify-bundle", str(package_dir), "--head", "deadbeef"])
    assert stale.exit_code == 1
    assert "stale=True" in stale.output

    security_file = package_dir / "evidence" / "security.json"
    data = json.loads(security_file.read_text())
    data["critical_open"] = 0
    data["sbom_present"] = True
    data["produced_by"] = "edited-after-signing"
    security_file.write_text(json.dumps(data))
    tampered = runner.invoke(app, ["gate", "verify-bundle", str(package_dir), "--head", COMMIT])
    assert tampered.exit_code == 1 and "differs from the bundle" in tampered.output


def test_verdict_negative_and_no_write(package_dir: Path) -> None:
    result = runner.invoke(app, ["gate", "verdict", str(package_dir), "--no-write", "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["overall"] is False
    assert not (package_dir / pkgio.FINAL_VERDICT_FILE).is_file()


def test_bundle_evaluates_gates_first_and_requires_key(
    package_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert not (package_dir / pkgio.FINAL_VERDICT_FILE).is_file()
    result = runner.invoke(app, ["gate", "bundle", str(package_dir)])
    assert result.exit_code == 0, result.output
    assert "evaluated gates first" in result.output
    assert (package_dir / pkgio.FINAL_VERDICT_FILE).is_file()
    assert (package_dir / v.BUNDLE_FILE).is_file()
    monkeypatch.delenv(v.SIGNING_KEY_ENV)
    result = runner.invoke(app, ["gate", "bundle", str(package_dir)])
    assert result.exit_code == 2 and "no signing key" in result.output
    not_pkg = runner.invoke(app, ["gate", "bundle", str(package_dir.parent)])
    assert not_pkg.exit_code == 2


def test_bundle_uses_local_signing_key_file(
    package_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(v.SIGNING_KEY_ENV)
    key_file = package_dir.parent.parent / ".aisdlc" / "signing.key"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("ab" * 32 + "\n", encoding="utf-8")
    result = runner.invoke(app, ["gate", "bundle", str(package_dir)])
    assert result.exit_code == 0, result.output
    assert "signed hmac-sha256" in result.output
    verify = runner.invoke(app, ["gate", "verify-bundle", str(package_dir), "--json"])
    data = json.loads(verify.output)
    assert data["valid_signatures"] == 1 and data["invalid_signatures"] == 0


def test_approve_rejects_non_package(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["gate", "approve", str(tmp_path), "--role", "owner", "--approver", "k"]
    )
    assert result.exit_code == 2


def test_bundle_reevaluates_a_stale_or_unstamped_verdict(package_dir: Path) -> None:
    forged = FinalVerdict(
        change_id="CHG-login-mfa",
        overall=True,
        gate_results=[GateResult(gate=gate, passed=True) for gate in GateId],
        commit_sha=COMMIT,
        fingerprint="0" * 64,
    )
    pkgio.write_final_verdict(package_dir, forged)
    result = runner.invoke(app, ["gate", "bundle", str(package_dir)])
    assert result.exit_code == 0, result.output
    assert "package content changed since final-verdict.json was evaluated" in result.output
    assert "evaluated gates first (overall FAIL)" in result.output  # no approvals yet
    written = pkgio.read_final_verdict(package_dir)
    assert written is not None and written.overall is False
    assert written.fingerprint == fingerprintmod.compute_fingerprint(package_dir)
    verify = runner.invoke(app, ["gate", "verify-bundle", str(package_dir), "--head", COMMIT])
    assert verify.exit_code == 1 and "negative" in verify.output

    pkgio.write_final_verdict(package_dir, forged.model_copy(update={"fingerprint": ""}))
    result = runner.invoke(app, ["gate", "bundle", str(package_dir)])
    assert result.exit_code == 0, result.output
    assert "records no package fingerprint" in result.output


def test_evaluate_finds_the_repo_local_signing_key(
    package_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(v.SIGNING_KEY_ENV)
    result = runner.invoke(app, ["gate", "evaluate", str(package_dir), "--gate", "G6"])
    assert "no signing key available" in result.output
    key_file = package_dir.parent.parent / ".aisdlc" / "signing.key"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("ab" * 32 + "\n", encoding="utf-8")
    result = runner.invoke(app, ["gate", "evaluate", str(package_dir), "--gate", "G6"])
    assert "no signing key available" not in result.output
    explicit = runner.invoke(
        app,
        ["gate", "verdict", str(package_dir), "--no-write", "--hmac-key-file", str(key_file)],
    )
    assert "no signing key available" not in explicit.output
