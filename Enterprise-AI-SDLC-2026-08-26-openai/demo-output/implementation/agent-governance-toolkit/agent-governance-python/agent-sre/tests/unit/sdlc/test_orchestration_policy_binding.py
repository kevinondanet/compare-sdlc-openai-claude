# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for protected orchestration-policy to manifest binding."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from agent_sre.sdlc.orchestration_policy_binding import orchestration_policy_violations

from .test_orchestration import NOW, make_change, make_planner, make_policy


def test_planner_manifest_exactly_matches_protected_policy() -> None:
    policy = make_policy()
    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-policy-binding",
        planned_at=NOW,
    )

    assert orchestration_policy_violations(policy, manifest) == ()


def test_self_claimed_policy_digest_does_not_hide_weaker_limits_or_scopes() -> None:
    policy = make_policy()
    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-policy-weakened",
        planned_at=NOW,
    )
    weakened_limits = manifest.limits.model_copy(update={"max_total_cost_usd": Decimal("99")})
    forged = manifest.model_copy(
        update={
            "limits": weakened_limits,
            "allowed_tool_scopes": (*manifest.allowed_tool_scopes, "forged"),
        }
    )

    assert set(orchestration_policy_violations(policy, forged)) >= {
        "orchestration.policy_limits_mismatch",
        "orchestration.policy_tool_scopes_mismatch",
    }


def test_route_and_checkpoint_projections_are_independently_checked() -> None:
    policy = make_policy()
    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-policy-route",
        planned_at=NOW,
    )
    review = manifest.review_assignment
    weak_route = review.route.model_copy(update={"benchmark_quality": Decimal("0.01")})
    weak_review = review.model_copy(update={"route": weak_route})
    checkpoints = list(manifest.human_checkpoints)
    release_index = next(
        index for index, item in enumerate(checkpoints) if item.phase.value == "before_release"
    )
    checkpoints[release_index] = checkpoints[release_index].model_copy(
        update={"approver_role": "project-self-approver"}
    )
    forged = manifest.model_copy(
        update={"review_assignment": weak_review, "human_checkpoints": tuple(checkpoints)}
    )

    assert set(orchestration_policy_violations(policy, forged)) >= {
        "orchestration.policy_release_approver_mismatch",
        "orchestration.review_route.quality_below_policy",
    }


def test_review_attester_and_conditional_routes_are_exact_policy_projections() -> None:
    base = make_policy()
    policy = make_policy(
        remediation_path_scopes=("src",),
        limits=base.limits.model_copy(update={"max_review_rounds": 2}),
    )
    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-policy-review-loop-binding",
        planned_at=NOW,
    )
    conditional = manifest.conditional_review_rounds[0]
    forged = manifest.model_copy(
        update={
            "trusted_review_attesters": (),
            "remediation_path_scopes": (".",),
            "conditional_review_rounds": (
                conditional.model_copy(
                    update={
                        "review_assignment": conditional.review_assignment.model_copy(
                            update={
                                "route": conditional.review_assignment.route.model_copy(
                                    update={"benchmark_quality": Decimal("0.01")}
                                )
                            }
                        )
                    }
                ),
            ),
        }
    )

    assert set(orchestration_policy_violations(policy, forged)) >= {
        "orchestration.policy_remediation_paths_mismatch",
        "orchestration.policy_review_attesters_mismatch",
        "orchestration.review_route.quality_below_policy",
    }


def test_route_freshness_and_estimated_cost_are_recomputed_from_protected_policy() -> None:
    policy = make_policy()
    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-policy-route-reseal",
        planned_at=NOW,
    )
    first_wave = manifest.execution_waves[0]
    first = first_wave.assignments[0]
    stale_route = first.route.model_copy(
        update={
            "benchmark_measured_at": NOW
            - timedelta(seconds=policy.implementation_route.max_benchmark_age_seconds + 1),
            "benchmark_valid_until": None,
            "estimated_cost_usd": Decimal("0"),
        }
    )
    forged_first = first.model_copy(update={"route": stale_route})
    forged_wave = first_wave.model_copy(
        update={"assignments": (forged_first, *first_wave.assignments[1:])}
    )
    forged = manifest.model_copy(
        update={"execution_waves": (forged_wave, *manifest.execution_waves[1:])}
    )

    assert set(orchestration_policy_violations(policy, forged)) >= {
        "orchestration.implementation_route.benchmark_too_old",
        "orchestration.implementation_route.estimated_cost_mismatch",
    }
