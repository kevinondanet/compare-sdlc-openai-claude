# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Exact binding between semantic-review evidence and governed execution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent_sre.sdlc.development_gates import CommandEvidence, EvidenceKind, EvidenceStatus
from agent_sre.sdlc.orchestration import AssignmentRole, OrchestrationManifest
from agent_sre.sdlc.orchestration_runtime import (
    AssignmentExecutionState,
    ExecutionReceipt,
)
from agent_sre.sdlc.review_loop import ReviewVerdict
from agent_sre.sdlc.review_validation import validate_runtime_review_history

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ReviewBindingResult:
    """Stable, presentation-neutral result consumed by the release gate."""

    passed: bool
    reason_codes: tuple[str, ...]
    actual: dict[str, Any]
    expected: dict[str, Any]


def bind_review_evidence(
    evidence: CommandEvidence | None,
    *,
    manifest: OrchestrationManifest,
    receipt: ExecutionReceipt,
) -> ReviewBindingResult:
    """Require the clean G3 report to be the exact runtime review output."""

    runtime_validation = validate_runtime_review_history(
        manifest,
        receipt,
        require_clean=True,
    )
    final_history = runtime_validation.final_review
    review_assignments = {
        item.assignment_id: item
        for item in (
            manifest.review_assignment,
            *(item.review_assignment for item in manifest.conditional_review_rounds),
        )
    }
    review_assignment = (
        None
        if final_history is None
        else review_assignments.get(final_history.review_assignment_id)
    )
    receipt_matches = tuple(
        item
        for item in receipt.assignments
        if review_assignment is not None and item.assignment_id == review_assignment.assignment_id
    )
    receipt_assignment = receipt_matches[0] if len(receipt_matches) == 1 else None
    metrics = evidence.metrics if evidence is not None else {}
    claimed_rounds = _positive_int(metrics.get("review_rounds"))
    claimed_round_digests = _digest_list(metrics.get("review_round_output_digests"))
    claimed_fix_digests = _digest_list(metrics.get("fix_round_output_digests"))
    round_digests = tuple(item.output_digest for item in receipt.review_history)
    fix_digests = tuple(
        item.remediation.output_digest
        for item in receipt.review_history
        if item.remediation is not None
    )
    runtime_rounds = len(receipt.review_history)

    expected = {
        "manifest_digest": manifest.digest,
        "run_id": manifest.run_id,
        "assignment_id": None if review_assignment is None else review_assignment.assignment_id,
        "context_id": None if review_assignment is None else review_assignment.context_id,
        "workspace_key": None if review_assignment is None else review_assignment.workspace_key,
        "reviewer_model_family": (
            None if review_assignment is None else review_assignment.route.provider_family
        ),
        "outcome_digest": (
            None if receipt_assignment is None else receipt_assignment.outcome_digest
        ),
        "output_digest": None if receipt_assignment is None else receipt_assignment.output_digest,
        "maximum_review_rounds": manifest.limits.max_review_rounds,
        "review_rounds": runtime_rounds,
        "review_round_output_digests": round_digests,
        "fix_round_output_digests": fix_digests,
    }
    actual = {
        "manifest_digest": metrics.get("orchestration_manifest_digest"),
        "run_id": metrics.get("orchestration_run_id"),
        "assignment_id": metrics.get("review_assignment_id"),
        "context_id": metrics.get("review_context_id"),
        "workspace_key": metrics.get("review_workspace_key"),
        "reviewer_model_family": metrics.get("reviewer_model_family"),
        "outcome_digest": metrics.get("review_outcome_digest"),
        "output_digest": metrics.get("review_output_digest"),
        "review_rounds": claimed_rounds,
        "review_round_output_digests": claimed_round_digests,
        "fix_round_output_digests": claimed_fix_digests,
        "report_sha256": None if evidence is None else evidence.artifacts.get("report_sha256"),
    }
    reasons: list[str] = []
    if evidence is None:
        reasons.append("review.binding_missing")
    elif (
        evidence.kind is not EvidenceKind.REVIEW
        or evidence.status is not EvidenceStatus.PASSED
        or evidence.exit_code != 0
    ):
        reasons.append("review.binding_not_passing")
    reasons.extend(runtime_validation.reason_codes)
    if receipt_assignment is None:
        reasons.append("review.receipt_assignment_missing")
    elif (
        receipt_assignment.role is not AssignmentRole.INDEPENDENT_REVIEW
        or receipt_assignment.state is not AssignmentExecutionState.SUCCEEDED
        or not receipt_assignment.host_invoked
    ):
        reasons.append("review.receipt_assignment_not_successful")

    exact_fields = {
        "orchestration_manifest_digest": expected["manifest_digest"],
        "orchestration_run_id": expected["run_id"],
        "review_assignment_id": expected["assignment_id"],
        "review_context_id": expected["context_id"],
        "review_workspace_key": expected["workspace_key"],
        "reviewer_model_family": expected["reviewer_model_family"],
        "review_outcome_digest": expected["outcome_digest"],
        "review_output_digest": expected["output_digest"],
    }
    if any(metrics.get(name) != value for name, value in exact_fields.items()):
        reasons.append("review.execution_binding_mismatch")
    if evidence is None or evidence.artifacts.get("report_sha256") != expected["output_digest"]:
        reasons.append("review.report_digest_mismatch")
    if claimed_rounds != runtime_rounds:
        reasons.append("review.round_history_mismatch")
    if claimed_rounds is None or not 1 <= claimed_rounds <= manifest.limits.max_review_rounds:
        reasons.append("review.round_limit_invalid")
    if claimed_round_digests != round_digests:
        reasons.append("review.round_output_history_mismatch")
    if claimed_fix_digests != fix_digests:
        reasons.append("review.fix_output_history_mismatch")
    if (
        metrics.get("independent") is not True
        or metrics.get("whole_change") is not True
        or metrics.get("blocking_findings")
        != (
            None
            if final_history is None
            else len(final_history.semantic_outcome.finding_set.findings)
        )
        or final_history is None
        or final_history.semantic_outcome.verdict is not ReviewVerdict.CLEAN
    ):
        reasons.append("review.semantic_verdict_invalid")
    return ReviewBindingResult(
        passed=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
        actual=actual,
        expected=expected,
    )


def attach_review_execution_binding(
    evidence: CommandEvidence,
    *,
    manifest: OrchestrationManifest,
    receipt: ExecutionReceipt,
    review_round_output_digests: tuple[str, ...] | None = None,
    fix_round_output_digests: tuple[str, ...] = (),
) -> CommandEvidence:
    """Reissue a review record with exact, digest-authenticated runtime facts."""

    if evidence.kind is not EvidenceKind.REVIEW:
        raise ValueError("execution binding may only be attached to review evidence")
    runtime_validation = validate_runtime_review_history(
        manifest,
        receipt,
        require_clean=True,
    )
    if not runtime_validation.passed or runtime_validation.final_review is None:
        raise ValueError(
            "receipt does not contain a valid final clean review: "
            + ", ".join(runtime_validation.reason_codes)
        )
    final_history = runtime_validation.final_review
    assignment = next(
        item
        for item in (
            manifest.review_assignment,
            *(round_plan.review_assignment for round_plan in manifest.conditional_review_rounds),
        )
        if item.assignment_id == final_history.review_assignment_id
    )
    matches = tuple(
        item for item in receipt.assignments if item.assignment_id == assignment.assignment_id
    )
    if len(matches) != 1:
        raise ValueError("receipt must contain the manifest review assignment exactly once")
    observed = matches[0]
    if observed.outcome_digest is None or observed.output_digest is None:
        raise ValueError("review assignment must contain observed outcome and output digests")
    rounds = tuple(item.output_digest for item in receipt.review_history)
    fixes = tuple(
        item.remediation.output_digest
        for item in receipt.review_history
        if item.remediation is not None
    )
    if review_round_output_digests is not None and review_round_output_digests != rounds:
        raise ValueError("caller review round history disagrees with the runtime receipt")
    if fix_round_output_digests and fix_round_output_digests != fixes:
        raise ValueError("caller fix history disagrees with the runtime receipt")
    metrics = {
        **dict(evidence.metrics),
        "orchestration_manifest_digest": manifest.digest,
        "orchestration_run_id": manifest.run_id,
        "review_assignment_id": assignment.assignment_id,
        "review_context_id": assignment.context_id,
        "review_workspace_key": assignment.workspace_key,
        "review_outcome_digest": observed.outcome_digest,
        "review_output_digest": observed.output_digest,
        "review_rounds": len(rounds),
        "review_round_output_digests": list(rounds),
        "fix_round_output_digests": list(fixes),
        "reviewer_model_family": assignment.route.provider_family,
        "independent": True,
        "whole_change": True,
        "blocking_findings": 0,
    }
    artifacts = {**dict(evidence.artifacts), "report_sha256": observed.output_digest}
    return CommandEvidence.create(
        evidence_id=evidence.evidence_id,
        change_id=evidence.change_id,
        source_revision=evidence.source_revision,
        change_digest=evidence.change_digest,
        kind=evidence.kind,
        status=evidence.status,
        producer=evidence.producer,
        command=evidence.command,
        exit_code=evidence.exit_code,
        environment=evidence.environment,
        requirement_ids=list(evidence.requirement_ids),
        scenario_ids=list(evidence.scenario_ids),
        task_ids=list(evidence.task_ids),
        test_layers=list(evidence.test_layers),
        metrics=metrics,
        artifacts=artifacts,
        generated_at=evidence.generated_at,
    )


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _digest_list(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list | tuple) or any(
        not isinstance(item, str) or _SHA256.fullmatch(item) is None for item in value
    ):
        return None
    result = tuple(value)
    if len(set(result)) != len(result):
        return None
    return result
