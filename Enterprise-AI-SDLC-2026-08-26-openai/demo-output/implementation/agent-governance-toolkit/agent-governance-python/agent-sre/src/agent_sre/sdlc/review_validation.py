# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Independent validation of raw runtime review/remediation history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from agent_sre.sdlc.orchestration import AssignmentRole, OrchestrationManifest, WorkAssignment
from agent_sre.sdlc.orchestration_runtime import (
    AssignmentExecutionState,
    ExecutionReceipt,
    ExecutionStatus,
)
from agent_sre.sdlc.review_loop import ReviewRoundHistory, ReviewVerdict


@dataclass(frozen=True, slots=True)
class RuntimeReviewValidation:
    """Stable validation result for gate and evidence-binding consumers."""

    passed: bool
    reason_codes: tuple[str, ...]
    final_review: ReviewRoundHistory | None


def _review_assignments(manifest: OrchestrationManifest) -> tuple[WorkAssignment, ...]:
    return (
        manifest.review_assignment,
        *(item.review_assignment for item in manifest.conditional_review_rounds),
    )


def validate_runtime_review_history(
    manifest: OrchestrationManifest,
    receipt: ExecutionReceipt,
    *,
    require_clean: bool = True,
    evaluated_at: datetime | None = None,
) -> RuntimeReviewValidation:
    """Validate history solely from the canonical manifest and runtime receipt."""

    reasons: list[str] = []
    if evaluated_at is not None:
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            reasons.append("review.runtime_evaluation_time_invalid")
            evaluation_time = None
        else:
            evaluation_time = evaluated_at.astimezone(UTC)
    else:
        evaluation_time = None
    if (
        receipt.manifest_id != manifest.manifest_id
        or receipt.manifest_digest != manifest.digest
        or receipt.run_id != manifest.run_id
        or receipt.change_id != manifest.change_id
        or receipt.change_digest != manifest.change_digest
        or receipt.policy_digest != manifest.policy_digest
    ):
        reasons.append("review.runtime_subject_mismatch")

    history = receipt.review_history
    if not 1 <= len(history) <= manifest.limits.max_review_rounds:
        reasons.append("review.runtime_round_count_invalid")
    planned_reviews = _review_assignments(manifest)
    receipts = {item.assignment_id: item for item in receipt.assignments}
    if len(receipts) != len(receipt.assignments):
        reasons.append("review.runtime_assignment_duplicate")

    for index, item in enumerate(history):
        if index >= len(planned_reviews):
            reasons.append("review.runtime_unplanned_round")
            continue
        planned = planned_reviews[index]
        observed = receipts.get(planned.assignment_id)
        if (
            item.round_number != index + 1
            or item.review_assignment_id != planned.assignment_id
            or item.context_id != planned.context_id
            or item.workspace_key != planned.workspace_key
            or item.reviewer_model_family != planned.route.provider_family
            or item.output_digest != item.semantic_outcome.report_digest
        ):
            reasons.append("review.runtime_round_binding_mismatch")
        if not item.semantic_outcome.verify_attestation(manifest.trusted_review_attesters):
            reasons.append("review.runtime_semantic_attestation_untrusted")
        semantics = item.semantic_outcome
        if (
            semantics.manifest_id != manifest.manifest_id
            or semantics.manifest_digest != manifest.digest
            or semantics.run_id != manifest.run_id
            or semantics.change_digest != manifest.change_digest
            or semantics.policy_digest != manifest.policy_digest
            or semantics.review_assignment_id != planned.assignment_id
            or semantics.context_id != planned.context_id
            or semantics.workspace_key != planned.workspace_key
            or semantics.reviewer_model_id != planned.route.identity.canonical_id
            or semantics.reviewer_model_family != planned.route.provider_family
            or semantics.review_round_number != index + 1
        ):
            reasons.append("review.runtime_semantic_subject_mismatch")
        if (
            observed is None
            or observed.request_digest != semantics.request_digest
            or observed.requested_at is None
            or observed.finished_at is None
        ):
            reasons.append("review.runtime_semantic_request_mismatch")
        elif not (
            observed.requested_at
            <= semantics.issued_at
            <= observed.finished_at
            < semantics.expires_at
            and receipt.evaluated_at < semantics.expires_at
        ):
            reasons.append("review.runtime_semantic_time_invalid")
        if semantics.expires_at > semantics.issued_at + timedelta(
            seconds=manifest.review_attestation_ttl_seconds
        ):
            reasons.append("review.runtime_semantic_ttl_exceeded")
        if evaluation_time is not None and evaluation_time >= semantics.expires_at:
            reasons.append("review.runtime_semantic_attestation_expired")
        if (
            observed is None
            or observed.role is not AssignmentRole.INDEPENDENT_REVIEW
            or observed.state is not AssignmentExecutionState.SUCCEEDED
            or not observed.host_invoked
            or observed.outcome_digest != item.outcome_digest
            or observed.output_digest != item.output_digest
        ):
            reasons.append("review.runtime_review_receipt_mismatch")

        if item.semantic_outcome.verdict is ReviewVerdict.BLOCKING:
            if index < len(history) - 1:
                if index >= len(manifest.conditional_review_rounds):
                    reasons.append("review.runtime_unplanned_remediation")
                    continue
                remediation = item.remediation
                planned_fix = manifest.conditional_review_rounds[index].remediation_assignment
                fix_receipt = receipts.get(planned_fix.assignment_id)
                if (
                    remediation is None
                    or remediation.assignment_id != planned_fix.assignment_id
                    or remediation.context_id != planned_fix.context_id
                    or remediation.workspace_key != planned_fix.workspace_key
                    or remediation.binding.prior_review_assignment_id != item.review_assignment_id
                    or remediation.binding.prior_review_outcome_digest != item.outcome_digest
                    or remediation.binding.finding_set != item.semantic_outcome.finding_set
                ):
                    reasons.append("review.runtime_remediation_binding_mismatch")
                elif (
                    fix_receipt is None
                    or fix_receipt.role is not AssignmentRole.REMEDIATION
                    or fix_receipt.state is not AssignmentExecutionState.SUCCEEDED
                    or not fix_receipt.host_invoked
                    or fix_receipt.outcome_digest != remediation.outcome_digest
                    or fix_receipt.output_digest != remediation.output_digest
                ):
                    reasons.append("review.runtime_remediation_receipt_mismatch")
            elif item.remediation is not None:
                reasons.append("review.runtime_orphaned_remediation")
        elif item.remediation is not None:
            reasons.append("review.runtime_clean_round_has_remediation")

    final = history[-1] if history else None
    if require_clean and (
        final is None or final.semantic_outcome.verdict is not ReviewVerdict.CLEAN
    ):
        reasons.append("review.runtime_final_verdict_not_clean")
    if final is not None and final.semantic_outcome.verdict is ReviewVerdict.CLEAN:
        if receipt.status is not ExecutionStatus.SUCCEEDED:
            reasons.append("review.runtime_clean_receipt_not_successful")
        for planned in planned_reviews[len(history) :]:
            observed = receipts.get(planned.assignment_id)
            if observed is None or observed.state is not AssignmentExecutionState.SKIPPED:
                reasons.append("review.runtime_future_review_not_skipped")
        for plan in manifest.conditional_review_rounds[len(history) - 1 :]:
            for planned in (plan.remediation_assignment, plan.review_assignment):
                observed = receipts.get(planned.assignment_id)
                if observed is None or observed.state is not AssignmentExecutionState.SKIPPED:
                    reasons.append("review.runtime_future_work_not_skipped")
    elif final is not None and len(history) == manifest.limits.max_review_rounds:
        if (
            receipt.status is not ExecutionStatus.FAILED
            or "review.round_limit_exhausted" not in receipt.reason_codes
        ):
            reasons.append("review.runtime_exhaustion_not_terminal")

    return RuntimeReviewValidation(
        passed=not reasons,
        reason_codes=tuple(sorted(set(reasons))),
        final_review=final,
    )


__all__ = ["RuntimeReviewValidation", "validate_runtime_review_history"]
