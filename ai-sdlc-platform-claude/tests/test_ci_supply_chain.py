"""Tests for aisdlc.security.supply_chain (SARIF, SCA, secrets, SBOM, provenance, VEX)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aisdlc.schema import package as pkgio
from aisdlc.schema.models import EvidenceStatus, Intent, ScanResult
from aisdlc.security import supply_chain as sc

FIXTURES = Path(__file__).parent / "fixtures" / "supply_chain"


def test_severity_from_score() -> None:
    assert sc.severity_from_score(9.8) is sc.SeverityLevel.CRITICAL
    assert sc.severity_from_score(7.0) is sc.SeverityLevel.HIGH
    assert sc.severity_from_score(5.5) is sc.SeverityLevel.MEDIUM
    assert sc.severity_from_score(0.1) is sc.SeverityLevel.LOW
    assert sc.severity_from_score(0) is sc.SeverityLevel.INFO


def test_parse_codeql_sarif_counts_by_security_severity() -> None:
    report = sc.parse_sarif(FIXTURES / "codeql.sarif")
    assert report.tool == "CodeQL" and report.version == "2.19.3"
    assert len(report.results) == 5 and len(report.active) == 4
    result = report.scan_result(report_uri="codeql.sarif")
    assert (result.critical, result.high, result.medium, result.low) == (1, 1, 1, 1)
    assert result.ran and result.tool == "CodeQL" and result.report_uri == "codeql.sarif"
    first = report.results[0]
    assert first.file == "src/app/db.py" and first.line == 42
    suppressed = [r for r in report.results if r.suppressed]
    assert suppressed and suppressed[0].rule_id == "py/path-injection"


def test_parse_sarif_rejects_other_json() -> None:
    with pytest.raises(ValueError, match="not a SARIF"):
        sc.parse_sarif({"foo": []})
    with pytest.raises(ValueError, match="invalid JSON"):
        sc.parse_sarif("{not json")


def test_parse_dependency_review_and_vex() -> None:
    vulns = sc.parse_dependency_review(FIXTURES / "dependency-review.json")
    assert [v.id for v in vulns] == [
        "GHSA-j8r2-6x86-q33q",
        "GHSA-9wx4-h78v-vm56",
        "GHSA-8q59-q68h-6hv4",
    ]
    assert vulns[0].severity is sc.SeverityLevel.CRITICAL and vulns[0].package == "requests"
    assert vulns[0].fixed_version == "2.31.0" and vulns[0].ecosystem == "pip"
    before = sc.scan_result_for(vulns)
    assert (before.critical, before.high, before.medium) == (1, 1, 1)
    statements = sc.parse_openvex(FIXTURES / "openvex.json")
    assert [s.status for s in statements] == ["not_affected", "under_investigation", "affected"]
    after = sc.apply_vex(vulns, statements)
    assert after[0].suppressed_by == "vex-1" and not after[0].open
    assert after[1].open and after[2].open
    counts = sc.scan_result_for(after)
    assert (counts.critical, counts.high, counts.medium) == (0, 1, 1)


def test_vex_product_matching_rules() -> None:
    vuln = sc.Vulnerability(id="CVE-2024-1", severity="high", package="requests")
    wide = sc.VexStatement(vulnerability="cve-2024-1", status="fixed")
    assert sc.apply_vex([vuln], [wide])[0].suppressed_by == "fixed"
    other = sc.VexStatement(
        vulnerability="CVE-2024-1", status="not_affected", products=["pkg:pypi/urllib3@2"]
    )
    assert sc.apply_vex([vuln], [other])[0].open
    named = sc.VexStatement(
        vulnerability="CVE-2024-1", status="not_affected", products=["requests"]
    )
    assert not sc.apply_vex([vuln], [named])[0].open


def test_parse_dependency_review_shapes() -> None:
    bare = sc.parse_dependency_review([{"id": "CVE-1", "severity": "low", "package": "x"}])
    assert bare[0].id == "CVE-1" and bare[0].severity is sc.SeverityLevel.LOW
    wrapped = sc.parse_dependency_review(
        {"vulnerabilities": [{"ghsa_id": "GHSA-1", "severity": 9.1}]}
    )
    assert wrapped[0].severity is sc.SeverityLevel.CRITICAL
    with pytest.raises(ValueError, match="no changes"):
        sc.parse_dependency_review({"nothing": 1})


def test_parse_gitleaks_json_and_sarif() -> None:
    from_json = sc.parse_gitleaks(FIXTURES / "gitleaks.json")
    assert from_json.tool == "gitleaks" and from_json.high == 3 and from_json.ran
    from_sarif = sc.parse_gitleaks(FIXTURES / "gitleaks.sarif", report_uri="gitleaks.sarif")
    assert from_sarif.high == 2 and from_sarif.report_uri == "gitleaks.sarif"
    assert sc.parse_gitleaks([]).high == 0
    with pytest.raises(ValueError, match="list of findings"):
        sc.parse_gitleaks({"foo": "bar"})


def test_detect_sbom() -> None:
    spdx = sc.detect_sbom(FIXTURES / "sbom.spdx.json")
    assert spdx.present and spdx.format == "spdx" and spdx.components == 3
    assert spdx.spec_version == "SPDX-2.3"
    cdx = sc.detect_sbom(FIXTURES / "bom.cdx.json")
    assert cdx.present and cdx.format == "cyclonedx" and cdx.components == 2
    missing = sc.detect_sbom(None)
    assert not missing.present and missing.problem
    junk = sc.detect_sbom({"hello": "world"})
    assert not junk.present and "unrecognised" in (junk.problem or "")
    assert not sc.detect_sbom(FIXTURES / "does-not-exist.json").present


def test_detect_provenance_formats(tmp_path: Path) -> None:
    statement = sc.detect_provenance(FIXTURES / "provenance.intoto.json")
    assert statement.present and statement.format == "in-toto"
    assert statement.predicate_type == "https://slsa.dev/provenance/v1"
    assert statement.builder_id == "https://github.com/actions/runner/github-hosted"
    assert statement.subjects and statement.subjects[0].startswith("dist/example_app")
    raw = json.loads((FIXTURES / "provenance.intoto.json").read_text())
    payload = base64.b64encode(json.dumps(raw).encode()).decode()
    dsse = {"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": []}
    assert sc.detect_provenance(dsse).format == "dsse"
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle+json", "dsseEnvelope": dsse}
    assert sc.detect_provenance(bundle).format == "sigstore-bundle"
    api = {"attestations": [{"bundle": bundle, "repository_id": 1}]}
    assert sc.detect_provenance(api).format == "github-attestations"
    jsonl = tmp_path / "multiple.intoto.jsonl"
    jsonl.write_text(json.dumps(dsse) + "\n")
    assert sc.detect_provenance(jsonl).present
    not_prov = sc.detect_provenance(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://spdx.dev/Document",
            "subject": [],
        }
    )
    assert not not_prov.present and "not provenance" in (not_prov.problem or "")
    assert not sc.detect_provenance(None).present
    assert not sc.detect_provenance({"foo": 1}).present


def test_build_security_evidence_merges_and_fails_closed() -> None:
    sast = sc.parse_sarif(FIXTURES / "codeql.sarif")
    sca = sc.parse_dependency_review(FIXTURES / "dependency-review.json")
    secrets = sc.parse_gitleaks(FIXTURES / "gitleaks.json")
    vex = sc.parse_openvex(FIXTURES / "openvex.json")
    evidence = sc.build_security_evidence(
        sast=sast,
        sca=sca,
        secrets=secrets,
        sbom=sc.detect_sbom(FIXTURES / "sbom.spdx.json"),
        provenance=sc.detect_provenance(FIXTURES / "provenance.intoto.json"),
        vex=vex,
        pyrit={
            "campaign_id": "c1",
            "asr": 0.02,
            "undetermined_rate": 0.0,
            "complete": True,
            "trials": 20,
        },
        safety={"asr_by_category": {"harm": 0.0}, "complete": True, "threshold_breaches": []},
        commit_sha="abc",
    )
    assert evidence.status is EvidenceStatus.COMPLETE
    assert evidence.critical_open == 1  # CodeQL critical; the SCA critical is VEX-suppressed
    assert evidence.high_open == 1 + 1 + 3  # CodeQL + pyyaml + three secrets
    assert evidence.sbom_present and evidence.provenance_present
    assert evidence.pyrit is not None and evidence.pyrit.campaign_id == "c1"
    assert evidence.safety_regression is not None and evidence.safety_regression.complete
    assert evidence.sca is not None and evidence.sca.critical == 0
    incomplete = sc.build_security_evidence(sast=sast, sca=sca)  # no secrets scan
    assert incomplete.status is EvidenceStatus.INCOMPLETE
    pyrit_incomplete = sc.build_security_evidence(
        sast=sast,
        sca=sca,
        secrets=secrets,
        pyrit={"campaign_id": "c1", "asr": 0.0, "complete": False},
    )
    assert pyrit_incomplete.status is EvidenceStatus.INCOMPLETE
    not_ran = sc.build_security_evidence(
        sast=ScanResult(tool="codeql", ran=False), sca=sca, secrets=secrets
    )
    assert not_ran.status is EvidenceStatus.INCOMPLETE
    relaxed = sc.build_security_evidence(sast=sast, required_scans=["sast"])
    assert relaxed.status is EvidenceStatus.COMPLETE


def test_collect_directory_and_write(tmp_path: Path) -> None:
    evidence, found = sc.collect_directory(FIXTURES, commit_sha="abc")
    assert found.sarif == ["codeql.sarif"]
    assert found.gitleaks == "gitleaks.sarif"  # SARIF wins over the JSON listing (sorted last)
    assert found.dependency_review == "dependency-review.json"
    assert found.sbom == "sbom.spdx.json" and found.provenance == "provenance.intoto.json"
    assert found.vex == "openvex.json"
    assert evidence.status is EvidenceStatus.COMPLETE
    assert evidence.critical_open == 1 and evidence.high_open == 4
    assert evidence.secrets is not None and evidence.secrets.high == 2
    assert evidence.commit_sha == "abc"
    pkg = pkgio.create(tmp_path, "CHG-sc", Intent(id="CHG-sc", title="sc"))
    assert pkg.root is not None
    path = sc.write_security_evidence(pkg.root, evidence)
    assert path.name == "security.json"
    stored = pkgio.read_evidence(pkg.root, "security")
    assert len(stored) == 1 and stored[0].id == evidence.id
    with pytest.raises(FileNotFoundError):
        sc.collect_directory(tmp_path / "nope")


def test_collect_directory_notes_problems(tmp_path: Path) -> None:
    (tmp_path / "broken.sarif").write_text("{")
    (tmp_path / "sbom.json").write_text('{"not": "an sbom"}')
    (tmp_path / "pyrit.json").write_text(
        '{"pyrit": {"campaign_id": "x", "asr": 0.5, "complete": true}}'
    )
    evidence, found = sc.collect_directory(tmp_path)
    assert any("broken.sarif" in n for n in found.notes)
    assert any("sbom.json" in n for n in found.notes)
    assert evidence.pyrit is not None and evidence.pyrit.asr == 0.5
    assert evidence.status is EvidenceStatus.INCOMPLETE
