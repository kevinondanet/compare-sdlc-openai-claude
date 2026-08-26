# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for exact G3-to-runtime review binding and bounded round history."""

from __future__ import annotations

from agent_sre.sdlc.change_contract import RiskClass
from agent_sre.sdlc.development_gates import EvidenceKind
from agent_sre.sdlc.review_binding import (
    attach_review_execution_binding,
    bind_review_evidence,
)

from .test_enterprise_gates import (
    NOW,
    bound_change,
    command,
    rebuild_execution_receipt,
    successful_execution,
)


def bound_review():
    change = bound_change(RiskClass.STANDARD, tier=2)
    manifest, receipt = successful_execution(change)
    assignment = manifest.review_assignment
    observed = next(
        item for item in receipt.assignments if item.assignment_id == assignment.assignment_id
    )
    evidence = command(
        change,
        EvidenceKind.REVIEW,
        99,
        metrics={
            "independent": True,
            "whole_change": True,
            "blocking_findings": 0,
            "review_rounds": 1,
            "reviewer_model_family": assignment.route.provider_family,
            "orchestration_manifest_digest": manifest.digest,
            "orchestration_run_id": manifest.run_id,
            "review_assignment_id": assignment.assignment_id,
            "review_context_id": assignment.context_id,
            "review_workspace_key": assignment.workspace_key,
            "review_outcome_digest": observed.outcome_digest,
            "review_output_digest": observed.output_digest,
            "review_round_output_digests": [observed.output_digest],
            "fix_round_output_digests": [],
        },
        artifacts={"report_sha256": observed.output_digest},
        generated_at=NOW,
    )
    return manifest, receipt, evidence


def test_review_evidence_binds_exact_runtime_output() -> None:
    manifest, receipt, evidence = bound_review()

    result = bind_review_evidence(evidence, manifest=manifest, receipt=receipt)

    assert result.passed
    assert result.reason_codes == ()


def test_binding_helper_reissues_canonical_command_evidence() -> None:
    manifest, receipt, evidence = bound_review()
    unbound_metrics = {
        key: value
        for key, value in evidence.metrics.items()
        if not key.startswith("orchestration_")
        and not key.startswith("review_assignment")
        and not key.startswith("review_context")
        and not key.startswith("review_workspace")
        and key not in {"review_outcome_digest", "review_output_digest"}
    }
    unbound = command(
        bound_change(RiskClass.STANDARD, tier=2),
        EvidenceKind.REVIEW,
        100,
        metrics=dict(unbound_metrics),
        generated_at=NOW,
    )

    attached = attach_review_execution_binding(unbound, manifest=manifest, receipt=receipt)

    assert attached.evidence_sha256 == attached.computed_digest
    assert bind_review_evidence(attached, manifest=manifest, receipt=receipt).passed


def test_unrelated_clean_review_cannot_satisfy_release_binding() -> None:
    manifest, receipt, evidence = bound_review()
    metrics = dict(evidence.metrics)
    metrics["review_outcome_digest"] = "f" * 64
    forged = evidence.model_copy(update={"metrics": metrics})

    result = bind_review_evidence(forged, manifest=manifest, receipt=receipt)

    assert not result.passed
    assert "review.execution_binding_mismatch" in result.reason_codes


def test_round_and_fix_histories_are_bounded_and_digest_bound() -> None:
    manifest, receipt, evidence = bound_review()
    metrics = dict(evidence.metrics)
    metrics["review_rounds"] = 4
    metrics["review_round_output_digests"] = [
        "1" * 64,
        "2" * 64,
        "3" * 64,
        evidence.metrics["review_output_digest"],
    ]
    metrics["fix_round_output_digests"] = ["4" * 64, "5" * 64, "6" * 64]
    excessive = evidence.model_copy(update={"metrics": metrics})

    result = bind_review_evidence(excessive, manifest=manifest, receipt=receipt)

    assert not result.passed
    assert "review.round_limit_invalid" in result.reason_codes


def test_missing_final_report_digest_fails_closed() -> None:
    manifest, receipt, evidence = bound_review()
    forged = evidence.model_copy(
        update={"artifacts": {**evidence.artifacts, "report_sha256": "e" * 64}}
    )

    result = bind_review_evidence(forged, manifest=manifest, receipt=receipt)

    assert not result.passed
    assert "review.report_digest_mismatch" in result.reason_codes


def test_signed_semantics_cannot_be_replayed_across_same_assignment_requests() -> None:
    manifest, receipt, evidence = bound_review()
    review_id = manifest.review_assignment.assignment_id
    assignments = tuple(
        item.model_copy(update={"request_digest": "f" * 64})
        if item.assignment_id == review_id
        else item
        for item in receipt.assignments
    )
    replayed_receipt = rebuild_execution_receipt(receipt, assignments)

    result = bind_review_evidence(
        evidence,
        manifest=manifest,
        receipt=replayed_receipt,
    )

    assert not result.passed
    assert "review.runtime_semantic_request_mismatch" in result.reason_codes
