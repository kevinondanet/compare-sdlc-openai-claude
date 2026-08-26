# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for deterministic G0-G3 development gates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agent_sre.sdlc.change_contract import ChangePackage, RiskClass
from agent_sre.sdlc.development_gates import (
    CommandEvidence,
    DevelopmentGateEvaluator,
    EvidenceKind,
    EvidenceStatus,
    GateStatus,
    VerificationLayer,
)

from .test_change_contract import make_change

NOW = datetime(2026, 8, 25, 14, 0, tzinfo=UTC)


def make_evidence(
    *,
    kind: EvidenceKind,
    sequence: int,
    change: ChangePackage,
    status: EvidenceStatus = EvidenceStatus.PASSED,
    exit_code: int | None = 0,
    metrics: dict | None = None,
    generated_at: datetime = NOW,
    test_layers: list[VerificationLayer] | None = None,
    artifacts: dict[str, str] | None = None,
) -> CommandEvidence:
    """Build valid command evidence bound to a test change."""
    requirement_ids = (
        [item.requirement_id for item in change.requirements] if kind is EvidenceKind.TEST else []
    )
    scenario_ids = (
        [item.scenario_id for item in change.scenarios] if kind is EvidenceKind.TEST else []
    )
    task_ids = [item.task_id for item in change.tasks] if kind is EvidenceKind.TEST else []
    return CommandEvidence.create(
        evidence_id=f"EVD-{sequence:03d}",
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        kind=kind,
        status=status,
        generated_at=generated_at,
        producer="ci",
        command=f"run-{kind.value}",
        exit_code=exit_code,
        requirement_ids=requirement_ids,
        scenario_ids=scenario_ids,
        task_ids=task_ids,
        test_layers=test_layers or (_test_layers(change) if kind is EvidenceKind.TEST else []),
        metrics=metrics,
        artifacts=(
            artifacts
            if artifacts is not None
            else {
                "report_uri": f"artifact://ci/{sequence}/{kind.value}",
                "report_sha256": "a" * 64,
            }
        ),
    )


def _test_layers(change: ChangePackage) -> list[VerificationLayer]:
    layers = {
        VerificationLayer.UNIT,
        VerificationLayer.PROPERTY,
        VerificationLayer.INTEGRATION,
        VerificationLayer.CONTRACT,
        VerificationLayer.END_TO_END,
        VerificationLayer.ARCHITECTURE,
    }
    if change.risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}:
        layers.update({VerificationLayer.SECURITY, VerificationLayer.PERFORMANCE})
    if change.risk_class is RiskClass.TOOL_ENABLED_AGENT:
        layers.add(VerificationLayer.AGENT_SAFETY)
    return sorted(layers, key=lambda item: item.value)


def complete_standard_evidence(change: ChangePackage) -> list[CommandEvidence]:
    """Return every deterministic evidence kind required by the standard profile."""
    evidence: list[CommandEvidence] = []
    kinds = [
        EvidenceKind.BUILD,
        EvidenceKind.FORMAT,
        EvidenceKind.LINT,
        EvidenceKind.TYPECHECK,
        EvidenceKind.COMPLEXITY,
        EvidenceKind.DUPLICATION,
        EvidenceKind.CONTRACT,
        EvidenceKind.TEST,
        EvidenceKind.COVERAGE,
        EvidenceKind.ARCHITECTURE,
        EvidenceKind.DRIFT,
    ]
    for index, kind in enumerate(kinds, start=1):
        metrics: dict = {}
        if kind is EvidenceKind.TEST:
            metrics = {"passed": 42, "failed": 0, "skipped": 0, "incomplete": False}
        elif kind is EvidenceKind.COMPLEXITY:
            metrics = {"max_cyclomatic_complexity": 15}
        elif kind is EvidenceKind.DUPLICATION:
            metrics = {"duplication_ratio": "0.03"}
        elif kind is EvidenceKind.CONTRACT:
            metrics = {"unapproved_breaking_changes": 0}
        elif kind is EvidenceKind.COVERAGE:
            metrics = {
                "line_coverage": "0.80",
                "diff_coverage": "0.90",
                "branch_coverage": "0.70",
                "critical_module_coverage": "0.90",
            }
        elif kind is EvidenceKind.DRIFT:
            metrics = {"production_placeholders": 0, "unresolved_ambiguities": 0}
        elif kind is EvidenceKind.ARCHITECTURE:
            metrics = {"boundary_violations": 0}
        evidence.append(make_evidence(kind=kind, sequence=index, change=change, metrics=metrics))

    evidence.append(
        make_evidence(
            kind=EvidenceKind.REVIEW,
            sequence=99,
            change=change,
            metrics={
                "independent": True,
                "whole_change": True,
                "blocking_findings": 0,
                "review_rounds": 1,
                "reviewer_model_family": "family-b",
            },
        )
    )
    return evidence


def test_complete_standard_change_passes_g0_through_g3() -> None:
    change = make_change()
    results = DevelopmentGateEvaluator().evaluate_all(
        change=change,
        evidence=complete_standard_evidence(change),
        evaluated_at=NOW,
    )

    assert {gate_id: result.status for gate_id, result in results.items()} == {
        "G0": GateStatus.PASS,
        "G1": GateStatus.PASS,
        "G2": GateStatus.PASS,
        "G3": GateStatus.PASS,
    }
    assert all(result.blocking_reason_codes == [] for result in results.values())
    assert {item.evidence_id for item in results["G2"].evidence} == {
        item.evidence_id
        for item in complete_standard_evidence(change)
        if item.kind is not EvidenceKind.REVIEW
    }
    assert {item.evidence_id for item in results["G3"].evidence} == {"EVD-099"}


def test_development_gate_result_digest_rejects_tampering() -> None:
    change = make_change()
    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change,
        evidence=complete_standard_evidence(change),
        evaluated_at=NOW,
    )
    payload = result.model_dump(mode="json")
    payload["source_revision"] = "forged"

    with pytest.raises(ValidationError, match="result_digest"):
        type(result).model_validate(payload)


def test_g0_collects_all_intent_failures() -> None:
    payload = make_change().model_dump(mode="json")
    payload["requirements"][0]["statement"] = "TODO decide behavior"
    payload["open_questions"][0]["status"] = "open"
    payload["open_questions"][0]["answer"] = None
    change = ChangePackage.model_validate(payload)

    result = DevelopmentGateEvaluator().evaluate_g0(change=change, evaluated_at=NOW)

    assert result.status is GateStatus.FAIL
    assert set(result.blocking_reason_codes) >= {
        "intent.ambiguity_marker",
        "intent.ambiguity_score",
        "intent.blocking_question_open",
        "intent.requirement_not_normative",
    }


def test_high_risk_g1_fails_closed_on_empty_threat_model() -> None:
    payload = make_change(risk_class=RiskClass.HIGH).model_dump(mode="json")
    payload["architecture"]["threat_model"] = {
        "assets": [],
        "trust_boundaries": [],
        "threats": [],
        "controls": [],
        "residual_risks": [],
        "privileged_tools": [],
        "data_classifications": [],
    }
    change = ChangePackage.model_validate(payload)

    result = DevelopmentGateEvaluator().evaluate_g1(change=change, evaluated_at=NOW)

    assert result.status is GateStatus.FAIL
    assert "security.threat_model_complete" in result.blocking_reason_codes


def test_tool_enabled_agent_g1_requires_privileged_tool_manifest() -> None:
    payload = make_change(risk_class=RiskClass.TOOL_ENABLED_AGENT).model_dump(mode="json")
    payload["architecture"]["threat_model"]["privileged_tools"] = []
    change = ChangePackage.model_validate(payload)

    result = DevelopmentGateEvaluator().evaluate_g1(change=change, evaluated_at=NOW)

    assert result.status is GateStatus.FAIL
    assert "security.agent_tool_manifest_present" in result.blocking_reason_codes


def test_g1_prevents_privileged_tool_risk_downgrade() -> None:
    payload = make_change(risk_class=RiskClass.SIMPLE).model_dump(mode="json")
    payload["architecture"]["threat_model"]["privileged_tools"] = ["send_email"]
    change = ChangePackage.model_validate(payload)

    result = DevelopmentGateEvaluator().evaluate_g1(change=change, evaluated_at=NOW)

    assert result.status is GateStatus.FAIL
    assert "security.privileged_tools_require_agent_risk" in result.blocking_reason_codes


@pytest.mark.parametrize("risk_class", [RiskClass.STANDARD, RiskClass.DOCUMENTATION])
def test_g1_prevents_privileged_task_scope_risk_downgrade(risk_class: RiskClass) -> None:
    payload = make_change(risk_class=risk_class).model_dump(mode="json")
    payload["architecture"]["threat_model"]["privileged_tools"] = []
    payload["tasks"][0]["tool_scopes"] = ["execute", "read"]
    payload["tasks"][0]["risk_tier"] = 2
    change = ChangePackage.model_validate(payload)

    result = DevelopmentGateEvaluator().evaluate_g1(change=change, evaluated_at=NOW)

    assert result.status is GateStatus.FAIL
    assert result.status is not GateStatus.NOT_APPLICABLE
    assert "security.privileged_tools_require_agent_risk" in result.blocking_reason_codes


def test_documentation_change_does_not_require_architecture_gate() -> None:
    result = DevelopmentGateEvaluator().evaluate_g1(
        change=make_change(risk_class=RiskClass.DOCUMENTATION),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.NOT_APPLICABLE


def test_g2_uses_exact_coverage_boundaries() -> None:
    change = make_change()
    evidence = complete_standard_evidence(change)

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )

    assert result.status is GateStatus.PASS


def test_g2_enforces_complexity_duplication_and_contract_metrics() -> None:
    change = make_change()
    evidence = complete_standard_evidence(change)
    replacements = {
        EvidenceKind.COMPLEXITY: {},
        EvidenceKind.DUPLICATION: {"duplication_ratio": "0.031"},
        EvidenceKind.CONTRACT: {"unapproved_breaking_changes": 1},
    }
    evidence = [
        make_evidence(
            kind=item.kind,
            sequence=200 + index,
            change=change,
            metrics=replacements[item.kind],
        )
        if item.kind in replacements
        else item
        for index, item in enumerate(evidence)
    ]

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )

    assert set(result.blocking_reason_codes) >= {
        "quality.cyclomatic_complexity",
        "quality.duplication_ratio",
        "quality.api_schema_compatibility",
    }


def test_evidence_payload_cannot_change_after_its_digest_is_verified() -> None:
    evidence = make_evidence(
        kind=EvidenceKind.TEST,
        sequence=301,
        change=make_change(),
        metrics={"passed": 1, "failed": 0, "incomplete": False},
    )

    with pytest.raises(TypeError, match="immutable"):
        evidence.metrics["passed"] = 2


@pytest.mark.parametrize(
    "update",
    [
        pytest.param({"metrics": {"fabricated": True}}, id="metrics"),
        pytest.param({"status": EvidenceStatus.FAILED}, id="status"),
        pytest.param(
            {
                "artifacts": {
                    "report_uri": "artifact://forged/report.json",
                    "report_sha256": "f" * 64,
                }
            },
            id="artifacts",
        ),
    ],
)
def test_g2_strictly_revalidates_model_copy_updates_at_its_boundary(
    update: dict[str, object],
) -> None:
    change = make_change()
    evidence = complete_standard_evidence(change)
    build_index = next(
        index for index, item in enumerate(evidence) if item.kind is EvidenceKind.BUILD
    )
    evidence[build_index] = evidence[build_index].model_copy(update=update)

    assert evidence[build_index].strict_revalidate() is None

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change,
        evidence=evidence,
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert {"evidence.integrity", "quality.build_evidence"} <= set(result.blocking_reason_codes)


def test_g2_rejects_stale_failed_and_unbound_evidence_together() -> None:
    change = make_change()
    evidence = complete_standard_evidence(change)
    stale_failed = make_evidence(
        kind=EvidenceKind.BUILD,
        sequence=500,
        change=change,
        status=EvidenceStatus.FAILED,
        exit_code=1,
        generated_at=NOW - timedelta(days=2),
    )
    payload = stale_failed.model_dump(mode="json")
    payload["source_revision"] = "wrong-revision"
    payload.pop("evidence_sha256")
    unbound = CommandEvidence.create(
        evidence_id=payload["evidence_id"],
        change_id=payload["change_id"],
        source_revision=payload["source_revision"],
        change_digest=change.digest,
        kind=EvidenceKind.BUILD,
        status=EvidenceStatus.FAILED,
        producer=payload["producer"],
        command=payload["command"],
        exit_code=1,
        generated_at=stale_failed.generated_at,
    )
    evidence.append(unbound)

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )

    assert result.status is GateStatus.FAIL
    assert set(result.blocking_reason_codes) >= {
        "evidence.source_binding",
        "evidence.freshness",
        "evidence.command_succeeded",
    }


def test_g2_requires_content_addressed_report_references() -> None:
    change = make_change()
    evidence = complete_standard_evidence(change)
    evidence.append(
        make_evidence(
            kind=EvidenceKind.BUILD,
            sequence=999,
            change=change,
            artifacts={"report_uri": "artifact://ci/999/build"},
        )
    )

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change,
        evidence=evidence,
        evaluated_at=NOW,
    )

    report_check = next(
        check
        for check in result.checks
        if check.code == "evidence.report_uri" and check.evidence_ids == ("EVD-999",)
    )
    assert not report_check.passed
    assert result.status is GateStatus.FAIL


def test_g2_fails_when_test_traceability_is_incomplete() -> None:
    change = make_change()
    evidence = [
        item for item in complete_standard_evidence(change) if item.kind is not EvidenceKind.TEST
    ]
    evidence.append(
        CommandEvidence.create(
            evidence_id="EVD-777",
            change_id=change.change_id,
            source_revision=change.source_revision,
            change_digest=change.digest,
            kind=EvidenceKind.TEST,
            status=EvidenceStatus.PASSED,
            producer="ci",
            command="pytest one-test.py",
            exit_code=0,
            requirement_ids=["REQ-001"],
            scenario_ids=["SCN-001"],
            task_ids=["TASK-001"],
            test_layers=_test_layers(change),
            metrics={"passed": 1, "failed": 0, "incomplete": False},
            artifacts={
                "report_uri": "artifact://ci/777/test",
                "report_sha256": "a" * 64,
            },
            generated_at=NOW,
        )
    )

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )

    assert result.status is GateStatus.FAIL
    assert set(result.blocking_reason_codes) >= {
        "traceability.requirement_test_coverage",
        "traceability.task_test_coverage",
    }


def test_g2_rejects_same_revision_evidence_replayed_for_a_different_change_digest() -> None:
    original = make_change()
    replayed_payload = original.model_dump(mode="json")
    replayed_payload["intent"]["goal"] = "A materially different implementation intent."
    replayed_change = ChangePackage.model_validate(replayed_payload)

    assert replayed_change.change_id == original.change_id
    assert replayed_change.source_revision == original.source_revision
    assert replayed_change.digest != original.digest

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=replayed_change,
        evidence=complete_standard_evidence(original),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "evidence.source_binding" in result.blocking_reason_codes


def test_g2_requires_every_risk_selected_test_layer() -> None:
    change = make_change()
    evidence = [
        item for item in complete_standard_evidence(change) if item.kind is not EvidenceKind.TEST
    ]
    evidence.append(
        make_evidence(
            kind=EvidenceKind.TEST,
            sequence=778,
            change=change,
            test_layers=[VerificationLayer.INTEGRATION, VerificationLayer.UNIT],
        )
    )

    result = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )

    assert result.status is GateStatus.FAIL
    assert "quality.test_portfolio" in result.blocking_reason_codes


def test_high_risk_g2_requires_mutation_evidence() -> None:
    change = make_change(risk_class=RiskClass.HIGH)
    evidence = complete_standard_evidence(change)

    missing = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )
    assert "quality.mutation_evidence" in missing.blocking_reason_codes

    evidence.append(
        make_evidence(
            kind=EvidenceKind.MUTATION,
            sequence=888,
            change=change,
            metrics={"mutation_score": "0.60"},
        )
    )
    passing = DevelopmentGateEvaluator().evaluate_g2(
        change=change, evidence=evidence, evaluated_at=NOW
    )
    assert passing.status is GateStatus.PASS


def test_g3_requires_independence_whole_change_and_provider_diversity() -> None:
    change = make_change()
    review = make_evidence(
        kind=EvidenceKind.REVIEW,
        sequence=900,
        change=change,
        metrics={
            "independent": False,
            "whole_change": False,
            "blocking_findings": 2,
            "review_rounds": 4,
            "reviewer_model_family": "family-a",
        },
    )

    result = DevelopmentGateEvaluator().evaluate_g3(
        change=change, evidence=[review], evaluated_at=NOW
    )

    assert result.status is GateStatus.FAIL
    assert set(result.blocking_reason_codes) >= {
        "review.role_independence",
        "review.whole_change_reviewed",
        "review.no_blocking_findings",
        "review.bounded_fix_loop",
        "review.provider_diversity",
    }

    unknown_implementation = change.model_copy(update={"implementation_model_family": None})
    otherwise_passing = make_evidence(
        kind=EvidenceKind.REVIEW,
        sequence=901,
        change=unknown_implementation,
        metrics={
            "independent": True,
            "whole_change": True,
            "blocking_findings": 0,
            "review_rounds": 1,
            "reviewer_model_family": "family-b",
        },
    )
    missing_family = DevelopmentGateEvaluator().evaluate_g3(
        change=unknown_implementation,
        evidence=[otherwise_passing],
        evaluated_at=NOW,
    )
    assert missing_family.status is GateStatus.FAIL
    assert "review.provider_diversity" in missing_family.blocking_reason_codes
