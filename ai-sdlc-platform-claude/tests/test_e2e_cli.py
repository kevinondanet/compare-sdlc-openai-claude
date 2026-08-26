"""End-to-end CLI smoke path from a fresh directory.

Exercises the documented workflow with typer's ``CliRunner`` inside ``tmp_path``:
``init`` -> ``policy show`` -> ``change new`` -> ``intake checklist`` -> ``plan generate`` ->
``plan check`` -> ``run change --runner dry`` -> ``test run-evidence`` -> ``gate evaluate`` ->
``gate bundle`` -> ``cost report`` -> ``governance policy generate`` -> ``adapter emit`` and
(integration, PyRIT) ``security campaign run --package``. A bare demo package cannot pass
the gates, so the assertions are about the artifacts each step must produce — above all a
signed :class:`FinalVerdict` — not about a green verdict.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.gates import verdict as verdictmod
from aisdlc.policy import find_org_policy, find_project_config, load_project_config
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import EvidenceKind, FinalVerdict, GateId, RiskClass, TestEvidence

runner = CliRunner()
REPO = Path(__file__).resolve().parents[1]
CAMPAIGN = REPO / "templates" / "pyrit" / "campaigns" / "agent-baseline.yaml"
CHANGE = "CHG-demo"


def run(args: Sequence[str], ok: Sequence[int] = (0,)) -> str:
    """Invoke ``aisdlc <args>``; fail loudly unless the exit code is in *ok*."""
    result = runner.invoke(app, list(args))
    assert result.exit_code in ok, (
        f"aisdlc {' '.join(args)} exited {result.exit_code}\n{result.output}"
    )
    return result.output


@pytest.fixture
def fresh_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(verdictmod.SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv("AISDLC_LEDGER", raising=False)
    return tmp_path


def test_init_scaffolds_discoverable_config(fresh_dir: Path) -> None:
    out = run(["init", "--name", "demo", "--no-git"])
    assert "aisdlc.yaml" in out and "org-policy.yaml" in out
    assert find_project_config(fresh_dir) == fresh_dir / "aisdlc.yaml"
    assert find_org_policy(fresh_dir) == fresh_dir / "org-policy.yaml"
    assert load_project_config(fresh_dir / "aisdlc.yaml").name == "demo"
    assert (fresh_dir / "changes" / ".gitkeep").is_file()
    assert (fresh_dir / ".aisdlc" / ".gitignore").read_text() == "*\n"
    key = fresh_dir / ".aisdlc" / "signing.key"
    assert len(bytes.fromhex(key.read_text().strip())) == 32
    assert not (fresh_dir / ".git").exists()
    # idempotent: existing files are kept unless --force
    again = json.loads(run(["init", "--no-git", "--json"]))
    assert set(again["files"].values()) == {"exists"}
    forced = json.loads(run(["init", "--no-git", "--force", "--json"]))
    assert set(forced["files"].values()) == {"overwritten"}


def test_init_with_custom_org_policy_and_git(fresh_dir: Path) -> None:
    custom = fresh_dir / "custom-org.yaml"
    custom.write_text("security_baselines:\n  ambiguity_threshold: 0.05\n", encoding="utf-8")
    out = run(["init", "--org-policy", str(custom), "--no-signing-key"])
    assert "ambiguity_threshold: 0.05" in (fresh_dir / "org-policy.yaml").read_text()
    assert not (fresh_dir / ".aisdlc" / "signing.key").exists()
    if shutil.which("git"):
        assert (fresh_dir / ".git").is_dir()
        assert verdictmod.git_head(fresh_dir) is not None, out
        assert json.loads(run(["init", "--json"]))["files"][".git"] == "exists"
    bad = fresh_dir / "bad.yaml"
    bad.write_text("- not a mapping\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "--org-policy", str(bad), "--force"])
    assert result.exit_code == 2


def test_e2e_smoke_path_writes_signed_verdict(fresh_dir: Path) -> None:
    run(["init", "--name", "demo"])
    run(["policy", "show"])
    run(
        [
            "change",
            "new",
            CHANGE,
            "--title",
            "Demo change",
            "--risk",
            "standard",
            "--owner",
            "kevin",
        ]
    )
    pkg_dir = fresh_dir / "changes" / CHANGE
    assert (pkg_dir / pkgio.INTENT_FILE).is_file()
    assert pkgio.load(pkg_dir).intent.risk_class is RiskClass.STANDARD

    run(["intake", "checklist", CHANGE], ok=(0, 1))
    run(["plan", "generate", CHANGE])
    run(["plan", "check", CHANGE], ok=(0, 1))
    if shutil.which("git") and verdictmod.git_head(fresh_dir):
        run(["run", "change", CHANGE, "--runner", "dry", "--yes"], ok=(0, 1, 3, 4))
        assert (pkg_dir / pkgio.HANDOFFS_DIR).is_dir()

    run(["test", "run-evidence", CHANGE, "--command", "true"])
    tests = pkgio.read_evidence(pkg_dir, EvidenceKind.TESTS)
    assert tests and isinstance(tests[0], TestEvidence)
    assert tests[0].exit_code == 0 and tests[0].is_complete

    run(["gate", "evaluate", CHANGE], ok=(0, 1))
    assert not (pkg_dir / pkgio.FINAL_VERDICT_FILE).exists()
    out = run(["gate", "bundle", CHANGE])
    assert "signed hmac-sha256" in out

    verdict = FinalVerdict.model_validate_json(
        (pkg_dir / pkgio.FINAL_VERDICT_FILE).read_text(encoding="utf-8")
    )
    assert [r.gate for r in verdict.gate_results] == list(GateId)
    assert verdict.signatures and verdict.bundle_digest
    manifest = verdictmod.read_bundle(pkg_dir)
    assert manifest is not None and manifest.digest() == verdict.bundle_digest
    verify = json.loads(run(["gate", "verify-bundle", CHANGE, "--json"], ok=(0, 1)))
    assert verify["valid_signatures"] == 1 and not verify["tampered"]

    report = json.loads(run(["cost", "report", "--change", CHANGE, "--json"]))
    assert isinstance(report, list)
    assert "apiVersion: governance.toolkit/v1" in run(["governance", "policy", "generate"])
    run(["adapter", "emit", "claude-code", "--out", "."])
    assert (fresh_dir / ".claude" / "settings.json").is_file()

    # every evidence file the steps produced parses into the canonical bundle
    bundle = pkgio.load_evidence_bundle(pkg_dir)
    assert bundle.tests
    status = json.loads(run(["change", "status", CHANGE, "--json"]))
    assert status["change_id"] == CHANGE


def test_change_refs_resolve_from_subdirectories(fresh_dir: Path) -> None:
    run(["init", "--no-git"])
    run(["change", "new", CHANGE, "--title", "Demo"])
    nested = fresh_dir / "src" / "pkg"
    nested.mkdir(parents=True)
    result = runner.invoke(app, ["change", "status", CHANGE, "--json"])
    assert result.exit_code == 0
    import os

    cwd = os.getcwd()
    os.chdir(nested)
    try:
        nested_result = runner.invoke(app, ["change", "status", CHANGE, "--json"])
        assert nested_result.exit_code == 0, nested_result.output
        by_path = runner.invoke(app, ["change", "status", "../../changes/CHG-demo"])
        assert by_path.exit_code == 0, by_path.output
    finally:
        os.chdir(cwd)
    missing = runner.invoke(app, ["gate", "evaluate", "CHG-nope"])
    assert missing.exit_code == 2 and "CHG-nope" in missing.output


@pytest.mark.integration
def test_e2e_pyrit_campaign_records_security_evidence(fresh_dir: Path) -> None:
    pytest.importorskip("pyrit")
    run(["init", "--no-git"])
    run(["change", "new", CHANGE, "--title", "Agent demo", "--risk", "ai_agent"])
    pkg_dir = fresh_dir / "changes" / CHANGE
    out = run(
        [
            "security",
            "campaign",
            "run",
            str(CAMPAIGN),
            "--target",
            "aisdlc.security.targets:demo_vulnerable_app",
            "--package",
            CHANGE,
            "--trials",
            "1",
        ],
        ok=(0, 1),
    )
    assert "recorded EVD-security-001" in out
    security = pkgio.read_evidence(pkg_dir, EvidenceKind.SECURITY)
    assert len(security) == 1
    record = security[0]
    assert record.kind is EvidenceKind.SECURITY
    pyrit = getattr(record, "pyrit", None)
    assert pyrit is not None and pyrit.complete and pyrit.campaign_id == "agent-baseline"
    evaluation = runner.invoke(app, ["gate", "evaluate", CHANGE, "--gate", "G4", "--json"])
    data = json.loads(evaluation.output)
    reasons = " ".join(data["results"][0]["reasons"])
    assert "attack success rate" in reasons or "PyRIT" in reasons or "SAST" in reasons
