# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end CLI coverage for governed G0-G6 release issuance."""

from __future__ import annotations

import json

import agent_sre.sdlc.enterprise_gates as enterprise_gates
from agent_sre.cli.main import cli
from agent_sre.sdlc.canonical import canonical_json_bytes
from agent_sre.sdlc.change_contract import RiskClass
from agent_sre.sdlc.development_gates import DevelopmentGatePolicy
from agent_sre.sdlc.enterprise_gates import (
    EnterpriseGatePolicy,
    command_evidence_from_usage_rollup,
    effective_project_policy,
)
from agent_sre.sdlc.review_binding import attach_review_execution_binding
from agent_sre.sdlc.risk import RiskClassification, RiskSignal
from agent_sre.signing import ArtifactSigner

from .test_development_gates import NOW as EVALUATED_AT
from .test_development_gates import complete_standard_evidence
from .test_enterprise_gates import (
    bound_change,
    complete_rollup,
    conventional_security,
    standard_ledger_components,
    successful_execution,
)
from .test_orchestration import make_policy


def _write_model(path, model) -> None:
    path.write_bytes(canonical_json_bytes(model) + b"\n")


def test_sdlc_cli_evaluates_issues_and_verifies_with_pinned_policy_and_key(
    tmp_path,
    capsys,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        enterprise_gates,
        "_utc_now",
        lambda value: EVALUATED_AT if value is None else value,
    )
    change = bound_change(RiskClass.STANDARD, tier=2)
    rollup = complete_rollup(change)
    cost, performance = command_evidence_from_usage_rollup(
        rollup,
        orchestration_rollup=rollup,
        ledger_components=standard_ledger_components(change, rollup),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=EVALUATED_AT,
        report_uri="artifact://ci/usage/rollup.json",
        report_sha256="a" * 64,
    )
    evidence = [
        *complete_standard_evidence(change),
        *conventional_security(change),
        cost,
        performance,
    ]

    change_path = tmp_path / "change.json"
    enterprise_policy_path = tmp_path / "organization-enterprise-policy.json"
    development_policy_path = tmp_path / "organization-development-policy.json"
    orchestration_policy_path = tmp_path / "organization-orchestration-policy.json"
    risk_classification_path = tmp_path / "risk-classification.json"
    readiness_path = tmp_path / "readiness.json"
    manifest_path = tmp_path / "orchestration-manifest.json"
    receipt_path = tmp_path / "execution-receipt.json"
    _write_model(change_path, change)
    manifest, receipt = successful_execution(change)
    review_index = next(index for index, item in enumerate(evidence) if item.kind.value == "review")
    evidence[review_index] = attach_review_execution_binding(
        evidence[review_index],
        manifest=manifest,
        receipt=receipt,
    )
    _write_model(manifest_path, manifest)
    _write_model(receipt_path, receipt)
    risk_signer = ArtifactSigner()
    risk_classification = RiskClassification.create(
        classification_id="RISK-CLI-001",
        classifier_id="central-diff-classifier",
        classifier_version="1",
        change=change,
        changed_paths=("src/change.py",),
        signals=(RiskSignal.SOURCE_CODE,),
        classified_at=EVALUATED_AT,
        expires_at=EVALUATED_AT.replace(day=26),
        signer=risk_signer,
    )
    enterprise_policy = EnterpriseGatePolicy(
        trusted_risk_classifier_public_keys=(risk_signer.public_key_bytes.hex(),)
    )
    development_policy = DevelopmentGatePolicy()
    orchestration_policy = make_policy()
    effective = effective_project_policy(
        organization_enterprise=enterprise_policy,
        project_enterprise=enterprise_policy,
        organization_development=development_policy,
        project_development=development_policy,
        organization_orchestration=orchestration_policy,
        project_orchestration=orchestration_policy,
    )
    _write_model(enterprise_policy_path, enterprise_policy)
    _write_model(development_policy_path, development_policy)
    _write_model(orchestration_policy_path, orchestration_policy)
    _write_model(risk_classification_path, risk_classification)
    evidence_paths = []
    for index, item in enumerate(evidence):
        path = tmp_path / f"evidence-{index:02d}.json"
        _write_model(path, item)
        evidence_paths.extend(("--evidence", str(path)))

    evaluate_args = [
        "sdlc",
        "evaluate",
        "--change",
        str(change_path),
        "--organization-enterprise-policy",
        str(enterprise_policy_path),
        "--organization-development-policy",
        str(development_policy_path),
        "--organization-orchestration-policy",
        str(orchestration_policy_path),
        "--risk-classification",
        str(risk_classification_path),
        "--orchestration-manifest",
        str(manifest_path),
        "--execution-receipt",
        str(receipt_path),
        *evidence_paths,
        "--evaluated-at",
        EVALUATED_AT.isoformat(),
        "--output",
        str(readiness_path),
    ]
    assert cli(evaluate_args) == 0
    evaluated = json.loads(capsys.readouterr().out)
    assert evaluated["status"] == "ready"
    assert [gate["gate_id"] for gate in evaluated["gates"]] == [
        "G0",
        "G1",
        "G2",
        "G3",
        "G4",
        "G5",
        "G6",
    ]

    signer = ArtifactSigner()
    private_key = tmp_path / "release-key.pem"
    private_key.write_bytes(signer.export_private_key_pem())
    issued_path = tmp_path / "issued.json"
    assert (
        cli(
            [
                "sdlc",
                "issue",
                "--readiness",
                str(readiness_path),
                "--change",
                str(change_path),
                "--organization-enterprise-policy",
                str(enterprise_policy_path),
                "--organization-development-policy",
                str(development_policy_path),
                "--organization-orchestration-policy",
                str(orchestration_policy_path),
                "--risk-classification",
                str(risk_classification_path),
                "--orchestration-manifest",
                str(manifest_path),
                "--execution-receipt",
                str(receipt_path),
                "--trusted-change-digest",
                change.digest,
                "--trusted-effective-policy-digest",
                effective.digest,
                *evidence_paths,
                "--output",
                str(issued_path),
                "--signing-key",
                str(private_key),
                "--signer-did",
                "did:web:release.example",
            ]
        )
        == 0
    )
    issuance = json.loads(capsys.readouterr().out)
    signature_path = issuance["signature"]

    assert (
        cli(
            [
                "sdlc",
                "verify",
                "--bundle",
                str(issued_path),
                "--signature",
                signature_path,
                "--expected-change",
                str(change_path),
                "--organization-enterprise-policy",
                str(enterprise_policy_path),
                "--organization-development-policy",
                str(development_policy_path),
                "--organization-orchestration-policy",
                str(orchestration_policy_path),
                "--expected-orchestration-manifest",
                str(manifest_path),
                "--expected-execution-receipt",
                str(receipt_path),
                "--trusted-change-digest",
                change.digest,
                "--trusted-effective-policy-digest",
                effective.digest,
                "--trusted-public-key",
                signer.public_key_bytes.hex(),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"verified": True}

    issued_path.write_bytes(issued_path.read_bytes() + b" ")
    assert (
        cli(
            [
                "sdlc",
                "verify",
                "--bundle",
                str(issued_path),
                "--signature",
                signature_path,
                "--expected-change",
                str(change_path),
                "--organization-enterprise-policy",
                str(enterprise_policy_path),
                "--organization-development-policy",
                str(development_policy_path),
                "--organization-orchestration-policy",
                str(orchestration_policy_path),
                "--expected-orchestration-manifest",
                str(manifest_path),
                "--expected-execution-receipt",
                str(receipt_path),
                "--trusted-change-digest",
                change.digest,
                "--trusted-effective-policy-digest",
                effective.digest,
                "--trusted-public-key",
                signer.public_key_bytes.hex(),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out) == {"verified": False}
