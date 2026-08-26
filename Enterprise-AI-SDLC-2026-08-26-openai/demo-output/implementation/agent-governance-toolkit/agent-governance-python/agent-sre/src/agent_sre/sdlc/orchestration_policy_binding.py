# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Bind an execution manifest to the protected effective orchestration policy."""

from __future__ import annotations

from datetime import datetime, timedelta

from agent_sre.sdlc.orchestration import (
    AssignmentRole,
    CheckpointPhase,
    OrchestrationManifest,
    OrchestrationPolicy,
    RouteProfile,
    WorkAssignment,
)


def orchestration_policy_violations(
    policy: OrchestrationPolicy,
    manifest: OrchestrationManifest,
) -> tuple[str, ...]:
    """Return stable codes for every manifest fact that weakens *policy*.

    The manifest's own ``policy_digest`` is only a claim.  Release evaluation
    calls this function with an organization-protected effective policy and
    independently verifies both the digest and every policy projection that is
    materialized in the execution plan.
    """

    violations: list[str] = []
    if manifest.policy_id != policy.policy_id:
        violations.append("orchestration.policy_id_mismatch")
    if manifest.policy_digest != policy.digest:
        violations.append("orchestration.policy_digest_mismatch")
    if manifest.limits != policy.limits:
        violations.append("orchestration.policy_limits_mismatch")
    if manifest.allowed_tool_scopes != policy.allowed_tool_scopes:
        violations.append("orchestration.policy_tool_scopes_mismatch")
    if manifest.tool_governance != policy.tool_governance:
        violations.append("orchestration.policy_tool_governance_mismatch")
    if manifest.implementation_route != policy.implementation_route:
        violations.append("orchestration.policy_implementation_route_mismatch")
    if manifest.review_route != policy.review_route:
        violations.append("orchestration.policy_review_route_mismatch")
    if manifest.checkpoint_tool_scopes != policy.checkpoint_tool_scopes:
        violations.append("orchestration.policy_checkpoint_scopes_mismatch")
    if manifest.checkpoint_min_risk_tier != policy.checkpoint_min_risk_tier:
        violations.append("orchestration.policy_checkpoint_tier_mismatch")
    if manifest.reservation_ttl_seconds != policy.reservation_ttl_seconds:
        violations.append("orchestration.policy_reservation_ttl_mismatch")
    if manifest.review_attestation_ttl_seconds != policy.review_attestation_ttl_seconds:
        violations.append("orchestration.policy_review_attestation_ttl_mismatch")
    if manifest.remediation_path_scopes != policy.remediation_path_scopes:
        violations.append("orchestration.policy_remediation_paths_mismatch")
    if manifest.trusted_review_attesters != policy.trusted_review_attesters:
        violations.append("orchestration.policy_review_attesters_mismatch")
    if len(manifest.conditional_review_rounds) != policy.limits.max_review_rounds - 1:
        violations.append("orchestration.policy_review_round_plan_mismatch")

    implementations = tuple(
        assignment for wave in manifest.execution_waves for assignment in wave.assignments
    )
    for assignment in implementations:
        violations.extend(
            _route_violations(
                assignment,
                policy.implementation_route,
                expected_use_case="implementation",
                planned_at=manifest.planned_at,
            )
        )
    violations.extend(
        _route_violations(
            manifest.review_assignment,
            policy.review_route,
            expected_use_case="independent_review",
            planned_at=manifest.planned_at,
        )
    )
    for conditional in manifest.conditional_review_rounds:
        violations.extend(
            _route_violations(
                conditional.remediation_assignment,
                policy.implementation_route,
                expected_use_case="implementation",
                planned_at=manifest.planned_at,
            )
        )
        violations.extend(
            _route_violations(
                conditional.review_assignment,
                policy.review_route,
                expected_use_case="independent_review",
                planned_at=manifest.planned_at,
            )
        )

    before_assignment = tuple(
        checkpoint
        for checkpoint in manifest.human_checkpoints
        if checkpoint.phase is CheckpointPhase.BEFORE_ASSIGNMENT
    )
    if any(
        checkpoint.approver_role != policy.execution_approver_role
        for checkpoint in before_assignment
    ):
        violations.append("orchestration.policy_execution_approver_mismatch")
    release = tuple(
        checkpoint
        for checkpoint in manifest.human_checkpoints
        if checkpoint.phase is CheckpointPhase.BEFORE_RELEASE
    )
    if len(release) != 1 or release[0].approver_role != policy.release_approver_role:
        violations.append("orchestration.policy_release_approver_mismatch")
    return tuple(sorted(set(violations)))


def _route_violations(
    assignment: WorkAssignment,
    profile: RouteProfile,
    *,
    expected_use_case: str,
    planned_at: datetime,
) -> list[str]:
    prefix = (
        "orchestration.review_route"
        if assignment.role is AssignmentRole.INDEPENDENT_REVIEW
        else "orchestration.implementation_route"
    )
    route = assignment.route
    registry = route.registry_record
    violations: list[str] = []
    if profile.use_case != expected_use_case:
        violations.append(f"{prefix}.policy_use_case_invalid")
    if route.model_tier > profile.max_tier:
        violations.append(f"{prefix}.model_tier_exceeded")
    if route.benchmark_quality < profile.min_quality:
        violations.append(f"{prefix}.quality_below_policy")
    if planned_at - route.benchmark_measured_at > timedelta(
        seconds=profile.max_benchmark_age_seconds
    ):
        violations.append(f"{prefix}.benchmark_too_old")
    if profile.max_latency_ms is not None and route.benchmark_latency_ms > profile.max_latency_ms:
        violations.append(f"{prefix}.latency_above_policy")
    if not set(profile.required_capabilities) <= set(registry.capabilities):
        violations.append(f"{prefix}.capability_missing")
    if profile.context_tokens > registry.max_context_tokens:
        violations.append(f"{prefix}.context_limit_exceeded")
    if expected_use_case not in registry.allowed_use_cases:
        violations.append(f"{prefix}.use_case_not_registered")
    if not set(assignment.tool_scopes) <= set(registry.allowed_tools):
        violations.append(f"{prefix}.tool_not_registered")
    try:
        expected_cost = route.price_record.calculate(profile.estimated_usage.to_usage())
    except ValueError:
        violations.append(f"{prefix}.estimated_cost_unverifiable")
    else:
        if route.estimated_cost_usd != expected_cost:
            violations.append(f"{prefix}.estimated_cost_mismatch")
    return violations
