# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Tests for deterministic, privacy-safe scenario evidence production."""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from pyrit.analytics.scenario_evidence import (
    build_security_evidence,
    canonical_security_evidence_bytes,
    compute_security_evidence_baseline_digest,
    verify_security_evidence_digest,
)
from pyrit.common.utils import to_sha256
from pyrit.models import (
    AttackOutcome,
    AttackResult,
    ComponentIdentifier,
    ConversationReference,
    ConversationType,
    MessagePiece,
    ScenarioRunState,
)
from pyrit.models.catalog.security_evidence import (
    EvidenceCachedTrial,
    EvidenceCompletenessStatus,
    EvidenceCoverage,
    EvidenceTrialIdentity,
    SecurityEvidenceSubject,
    SecurityEvidenceTrialPlan,
)
from pyrit.models.results.scenario_result import (
    SECURITY_EVIDENCE_SUBJECT_METADATA_KEY,
    SECURITY_EVIDENCE_TRIAL_PLAN_METADATA_KEY,
    ScenarioResult,
)
from unit.mocks import make_scenario_result

_NOW = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
_SECRET = "sentinel-secret-that-must-never-serialize"


def _identifier(name: str, *, secret: bool = False) -> ComponentIdentifier:
    params = {"endpoint": f"https://{_SECRET}.example", "api_key": _SECRET} if secret else {}
    return ComponentIdentifier(class_name=name, class_module="tests.evidence", params=params)


def _attack(
    *,
    conversation_id: str,
    outcome: AttackOutcome,
    latency: int,
    objective: str = _SECRET,
) -> AttackResult:
    return AttackResult(
        conversation_id=conversation_id,
        objective=objective,
        attack_result_id=str(uuid.uuid5(uuid.NAMESPACE_URL, conversation_id)),
        outcome=outcome,
        execution_time_ms=latency,
        error_message=_SECRET,
        error_traceback=_SECRET,
        metadata={"private": _SECRET},
        labels={"private": _SECRET},
        timestamp=_NOW,
    )


def _result(
    *,
    target_name: str | None = "Target",
    outcomes: list[AttackOutcome] | None = None,
    scenario_version: int = 3,
    pyrit_version: str | None = None,
):
    selected = outcomes or [
        AttackOutcome.SUCCESS,
        AttackOutcome.FAILURE,
        AttackOutcome.ERROR,
        AttackOutcome.UNDETERMINED,
    ]
    attacks = [
        _attack(
            conversation_id=f"conv-{index}",
            outcome=outcome,
            latency=index * 10,
            objective=f"{_SECRET}-{index}",
        )
        for index, outcome in enumerate(selected, start=1)
    ]
    result = make_scenario_result(
        id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        scenario_name="EvidenceScenario",
        scenario_version=scenario_version,
        pyrit_version=pyrit_version,
        objective_target_identifier=(_identifier(target_name, secret=True) if target_name is not None else None),
        objective_scorer_identifier=_identifier("Judge", secret=True),
        techniques=["zeta", "alpha", "alpha"],
        datasets=["dataset-b", "dataset-a"],
        params={"private": _SECRET},
        scenario_description=_SECRET,
        attack_results={"attack-z": attacks[:2], "attack-a": attacks[2:]},
        display_group_map={"attack-z": "group-z", "attack-a": "group-a"},
        scenario_run_state=ScenarioRunState.COMPLETED,
        creation_time=_NOW,
        completion_time=_NOW,
        number_tries=1,
        labels={"private": _SECRET},
        metadata={
            "private": _SECRET,
            SECURITY_EVIDENCE_SUBJECT_METADATA_KEY: SecurityEvidenceSubject(
                application="app",
                change="CHG-1",
                commit_sha="abcdef1",
            ).model_dump(mode="json"),
        },
    )
    for attack_results in result.attack_results.values():
        for attack_result in attack_results:
            attack_result.attribution_parent_id = str(result.id)
    _bind_trial_plan(result=result)
    return result


def _bind_trial_plan(
    *,
    result: ScenarioResult,
    expected_trials: tuple[EvidenceTrialIdentity, ...] | None = None,
    cached_trials: tuple[EvidenceCachedTrial, ...] = (),
) -> None:
    if expected_trials is None:
        expected_trials = tuple(
            EvidenceTrialIdentity(
                atomic_attack_name=atomic_attack_name,
                display_group=result.display_group_map.get(atomic_attack_name, atomic_attack_name),
                objective_sha256=to_sha256(attack_result.objective),
            )
            for atomic_attack_name, attack_results in result.attack_results.items()
            for attack_result in attack_results
        )
    plan = SecurityEvidenceTrialPlan.create(
        expected_trials=expected_trials,
        cached_trials=cached_trials,
    )
    result.metadata[SECURITY_EVIDENCE_TRIAL_PLAN_METADATA_KEY] = plan.model_dump(mode="json")


def test_builder_derives_counts_groups_hashes_and_private_allowlist() -> None:
    result = _result()
    subject = SecurityEvidenceSubject(application="app", change="CHG-1", commit_sha="abcdef1")

    first = build_security_evidence(scenario_result=result, subject=subject)
    second = build_security_evidence(scenario_result=result, subject=subject)

    assert first == second
    assert verify_security_evidence_digest(first)
    assert first.configuration.benchmark_fingerprint == second.configuration.benchmark_fingerprint
    assert first.configuration.pyrit_version == first.run.pyrit_version
    assert first.configuration.techniques == ("alpha", "zeta")
    assert first.configuration.datasets == ("dataset-a", "dataset-b")
    assert len(first.configuration.objective_hashes) == 4
    assert first.configuration.scenario.content_hash != first.configuration.scenario.eval_hash
    assert first.configuration.target is not None
    assert first.configuration.scorer is not None

    overall = first.metrics.overall
    assert (overall.trials, overall.determinate_trials) == (4, 2)
    assert (overall.successes, overall.failures, overall.errors, overall.undetermined) == (1, 1, 1, 1)
    assert overall.attack_success_rate == 0.5
    assert overall.error_rate == 0.25
    assert overall.undetermined_rate == 0.25
    assert overall.latency.total_ms == 100
    assert overall.latency.mean_ms == 25
    assert overall.latency.p95_ms == 40
    assert [group.name for group in first.metrics.groups] == ["group-a", "group-z"]
    assert first.metrics.groups[0].atomic_attack_names == ("attack-a",)
    assert first.completeness.status is EvidenceCompletenessStatus.COMPLETE
    assert "run.has_errors" not in first.completeness.reasons
    assert "run.has_undetermined" not in first.completeness.reasons

    serialized = canonical_security_evidence_bytes(first).decode("utf-8")
    assert _SECRET not in serialized
    for forbidden in ("objective", "response", "error_message", "error_traceback", "endpoint", "api_key"):
        assert f'"{forbidden}"' not in serialized


def test_zero_trial_atomic_attacks_do_not_count_as_group_coverage() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    result.attack_results["empty-attack"] = []
    result.display_group_map["empty-attack"] = "group-z"

    evidence = build_security_evidence(scenario_result=result)

    assert evidence.metrics.overall.trials == 1
    assert [group.name for group in evidence.metrics.groups] == ["group-z"]
    assert evidence.metrics.groups[0].atomic_attack_names == ("attack-z",)


def test_builder_marks_clean_completed_outcomes_complete_even_when_usage_unknown() -> None:
    evidence = build_security_evidence(scenario_result=_result(outcomes=[AttackOutcome.FAILURE, AttackOutcome.FAILURE]))

    assert evidence.completeness.status is EvidenceCompletenessStatus.COMPLETE
    assert evidence.completeness.reasons == ("cost.unavailable", "usage.unavailable")
    assert evidence.is_exportable()


def test_unbound_legacy_run_is_diagnostic_only() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    result.metadata.pop(SECURITY_EVIDENCE_SUBJECT_METADATA_KEY)

    evidence = build_security_evidence(scenario_result=result)

    assert evidence.subject is None
    assert evidence.completeness.status is EvidenceCompletenessStatus.INCOMPLETE
    assert "subject.unbound" in evidence.completeness.reasons
    assert not evidence.is_exportable()


def test_legacy_run_without_trial_inventory_is_diagnostic_only() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    result.metadata.pop(SECURITY_EVIDENCE_TRIAL_PLAN_METADATA_KEY)

    evidence = build_security_evidence(scenario_result=result)

    assert evidence.run.expected_trial_inventory is None
    assert evidence.completeness.status is EvidenceCompletenessStatus.INCOMPLETE
    assert "run.trial_inventory_unbound" in evidence.completeness.reasons


def test_export_subject_is_only_an_assertion_and_cannot_relabel_commit() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])

    with pytest.raises(ValueError, match="immutable stored binding"):
        build_security_evidence(
            scenario_result=result,
            subject=SecurityEvidenceSubject(
                application="app",
                change="CHG-1",
                commit_sha="bbbbbbb",
            ),
        )


def test_reused_old_trial_is_incomplete_and_anchors_evidence_freshness() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE, AttackOutcome.FAILURE])
    current, reused = result.attack_results["attack-z"]
    current.attribution_parent_id = str(result.id)
    reused.attribution_parent_id = "22222222-2222-2222-2222-222222222222"
    reused.timestamp = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    evidence = build_security_evidence(scenario_result=result)

    assert evidence.generated_at == reused.timestamp
    assert evidence.run.current_run_trial_count == 1
    assert evidence.run.reused_trial_count == 1
    assert evidence.run.origin_scenario_result_ids == (
        str(result.id),
        "22222222-2222-2222-2222-222222222222",
    )
    assert evidence.completeness.status is EvidenceCompletenessStatus.INCOMPLETE
    assert "run.reused_trials" in evidence.completeness.reasons
    assert not evidence.is_exportable()


def test_cached_trial_omitted_by_db_reload_is_still_incomplete_and_oldest() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    current = result.attack_results["attack-z"][0]
    old_time = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    cached_identity = EvidenceTrialIdentity(
        atomic_attack_name="attack-cached",
        display_group="group-cached",
        objective_sha256=to_sha256("cached objective"),
    )
    current_identity = EvidenceTrialIdentity(
        atomic_attack_name="attack-z",
        display_group="group-z",
        objective_sha256=to_sha256(current.objective),
    )
    cached = EvidenceCachedTrial(
        identity=cached_identity,
        attack_result_id="33333333-3333-3333-3333-333333333333",
        origin_scenario_result_id="22222222-2222-2222-2222-222222222222",
        observed_at=old_time,
    )
    _bind_trial_plan(
        result=result,
        expected_trials=(current_identity, cached_identity),
        cached_trials=(cached,),
    )

    evidence = build_security_evidence(scenario_result=result)

    assert evidence.generated_at == old_time
    assert evidence.run.oldest_trial_at == old_time
    assert evidence.run.reused_trial_count == 1
    assert evidence.run.omitted_reused_trial_count == 1
    assert evidence.metrics.overall.trials == 1
    assert "run.reused_trials" in evidence.completeness.reasons
    assert "run.trial_inventory_mismatch" in evidence.completeness.reasons
    assert evidence.completeness.status is EvidenceCompletenessStatus.INCOMPLETE


def test_builder_rejects_terminal_result_without_completion_timestamp() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    result.completion_time = None

    with pytest.raises(ValueError, match="terminal runs must include completed_at"):
        build_security_evidence(scenario_result=result)


def test_completed_run_with_error_and_undetermined_counts_remains_policy_evaluable() -> None:
    evidence = build_security_evidence(
        scenario_result=_result(outcomes=[AttackOutcome.FAILURE, AttackOutcome.ERROR, AttackOutcome.UNDETERMINED])
    )

    assert evidence.completeness.status is EvidenceCompletenessStatus.COMPLETE
    assert evidence.metrics.overall.errors == 1
    assert evidence.metrics.overall.undetermined == 1
    assert evidence.metrics.overall.error_rate == pytest.approx(1 / 3)
    assert evidence.metrics.overall.undetermined_rate == pytest.approx(1 / 3)
    assert evidence.is_exportable()


def test_usage_aggregates_unique_linked_responses_and_preserves_partial_unknowns() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    only_attack = result.attack_results["attack-z"][0]
    only_attack.related_conversations.add(
        ConversationReference(conversation_id="related", conversation_type=ConversationType.ADVERSARIAL)
    )
    only_attack.related_conversations.add(
        ConversationReference(conversation_id="conv-1", conversation_type=ConversationType.PRUNED)
    )

    pieces = {
        "conv-1": [
            MessagePiece(
                role="assistant",
                conversation_id="conv-1",
                sequence=1,
                original_value="private response",
                prompt_metadata={
                    "token_usage_input_tokens": 10,
                    "token_usage_output_tokens": 5,
                    "token_usage_total_tokens": 15,
                    "token_usage_cached_tokens": 2,
                    "token_usage_cost": "0.0012",
                },
            ),
            MessagePiece(
                role="assistant",
                conversation_id="conv-1",
                sequence=2,
                original_value="unmetered response",
            ),
            MessagePiece(role="user", conversation_id="conv-1", sequence=3, original_value="ignored"),
        ],
        "related": [
            MessagePiece(
                role="assistant",
                conversation_id="related",
                sequence=1,
                original_value="private attacker response",
                prompt_metadata={
                    "token_usage_input_tokens": 3,
                    "token_usage_output_tokens": 4,
                    "token_usage_reasoning_tokens": 1,
                    "token_usage_cost": "0.0008",
                },
            )
        ],
    }
    memory = MagicMock()
    memory.get_message_pieces.side_effect = lambda *, conversation_id: pieces[conversation_id]

    usage = build_security_evidence(scenario_result=result, memory=memory).usage

    assert usage.conversation_count == 2
    assert usage.observed_response_count == 3
    assert usage.calls_with_token_usage == 2
    assert usage.calls_with_cost == 2
    assert usage.input_tokens == 13
    assert usage.output_tokens == 9
    assert usage.total_tokens == 22
    assert usage.reasoning_tokens == 1
    assert usage.cached_tokens == 2
    assert usage.cost is not None and usage.cost.amount == "0.0020"
    assert usage.token_coverage is EvidenceCoverage.PARTIAL
    assert usage.cost_coverage is EvidenceCoverage.PARTIAL
    assert memory.get_message_pieces.call_count == 2


def test_usage_marks_partial_provider_core_counts_partial_without_inventing_totals() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    memory = MagicMock()
    memory.get_message_pieces.return_value = [
        MessagePiece(
            role="assistant",
            conversation_id="conv-1",
            sequence=1,
            original_value="private response",
            prompt_metadata={
                "token_usage_input_tokens": 11,
                "token_usage_cached_tokens": 4,
            },
        )
    ]

    usage = build_security_evidence(scenario_result=result, memory=memory).usage

    assert usage.calls_with_token_usage == 1
    assert usage.token_coverage is EvidenceCoverage.PARTIAL
    assert usage.input_tokens == 11
    assert usage.output_tokens is None
    assert usage.total_tokens is None
    assert usage.cached_tokens == 4


@pytest.mark.parametrize("bad_cost", ["NaN", "Infinity", "-0.01", "not-money", True])
def test_usage_rejects_invalid_cost_records(bad_cost: object) -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    memory = MagicMock()
    memory.get_message_pieces.return_value = [
        MessagePiece(
            role="assistant",
            conversation_id="conv-1",
            sequence=1,
            original_value="response",
            prompt_metadata={"token_usage_cost": bad_cost},
        )
    ]

    with pytest.raises(ValueError, match="token_usage_cost"):
        build_security_evidence(scenario_result=result, memory=memory)


def test_baseline_summary_only_emits_deltas_for_compatible_configuration() -> None:
    current = _result(outcomes=[AttackOutcome.SUCCESS, AttackOutcome.FAILURE])
    baseline = _result(outcomes=[AttackOutcome.FAILURE, AttackOutcome.FAILURE])
    baseline.id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    for attack_results in baseline.attack_results.values():
        for attack_result in attack_results:
            attack_result.attribution_parent_id = str(baseline.id)

    evidence = build_security_evidence(scenario_result=current, baseline_result=baseline)
    compatible = evidence.baseline
    assert compatible is not None and compatible.compatible
    assert compatible.generated_at == _NOW
    assert compatible.state is ScenarioRunState.COMPLETED
    assert compatible.pyrit_version == baseline.pyrit_version
    assert compatible.baseline_digest == compute_security_evidence_baseline_digest(compatible)
    assert compatible.delta_attack_success_rate == 0.5
    assert compatible.incompatibility_reasons == ()
    assert _SECRET not in canonical_security_evidence_bytes(evidence).decode("utf-8")

    incompatible_result = _result(target_name="OtherTarget", outcomes=[AttackOutcome.FAILURE])
    incompatible = build_security_evidence(
        scenario_result=current,
        baseline_result=incompatible_result,
    ).baseline
    assert incompatible is not None and not incompatible.compatible
    assert "baseline.benchmark_fingerprint_mismatch" in incompatible.incompatibility_reasons
    assert incompatible.delta_attack_success_rate is None


def test_baseline_rejects_foreign_trial_provenance() -> None:
    current = _result(outcomes=[AttackOutcome.FAILURE])
    baseline = _result(outcomes=[AttackOutcome.FAILURE])
    baseline.attack_results["attack-z"][0].attribution_parent_id = "22222222-2222-2222-2222-222222222222"

    with pytest.raises(ValueError, match="foreign or missing trial provenance"):
        build_security_evidence(scenario_result=current, baseline_result=baseline)


def test_baseline_rejects_scenario_version_mismatch() -> None:
    current = _result(outcomes=[AttackOutcome.FAILURE])
    baseline = _result(outcomes=[AttackOutcome.FAILURE], scenario_version=current.scenario_version + 1)

    comparison = build_security_evidence(scenario_result=current, baseline_result=baseline).baseline

    assert comparison is not None and not comparison.compatible
    assert "baseline.benchmark_fingerprint_mismatch" in comparison.incompatibility_reasons
    assert comparison.delta_attack_success_rate is None


def test_baseline_rejects_pyrit_version_mismatch() -> None:
    current = _result(outcomes=[AttackOutcome.FAILURE], pyrit_version="2.0.0")
    baseline = _result(outcomes=[AttackOutcome.FAILURE], pyrit_version="1.0.0")

    comparison = build_security_evidence(scenario_result=current, baseline_result=baseline).baseline

    assert comparison is not None and not comparison.compatible
    assert "baseline.pyrit_version_mismatch" in comparison.incompatibility_reasons
    assert comparison.delta_attack_success_rate is None


def test_baseline_rejects_noncompleted_run_even_when_configuration_matches() -> None:
    current = _result(outcomes=[AttackOutcome.FAILURE])
    baseline = _result(outcomes=[AttackOutcome.FAILURE])
    baseline.scenario_run_state = ScenarioRunState.FAILED

    comparison = build_security_evidence(scenario_result=current, baseline_result=baseline).baseline

    assert comparison is not None and not comparison.compatible
    assert "baseline.run_not_completed" in comparison.incompatibility_reasons
    assert comparison.delta_attack_success_rate is None


def test_target_missing_baseline_remains_exportable_as_incompatible_diagnostic() -> None:
    current = _result(target_name=None, outcomes=[AttackOutcome.FAILURE])
    baseline = _result(target_name=None, outcomes=[AttackOutcome.FAILURE])

    evidence = build_security_evidence(
        scenario_result=current,
        baseline_result=baseline,
    )

    assert evidence.configuration.target is None
    assert evidence.completeness.status is EvidenceCompletenessStatus.INCOMPLETE
    assert evidence.baseline is not None
    assert not evidence.baseline.compatible
    assert "baseline.target_missing" in evidence.baseline.incompatibility_reasons
    assert evidence.baseline.delta_attack_success_rate is None


def test_caller_metadata_cannot_forge_objective_hashes() -> None:
    result = _result(outcomes=[AttackOutcome.FAILURE])
    result.metadata["objective_hashes"] = ["0" * 64]

    evidence = build_security_evidence(scenario_result=result)

    assert evidence.configuration.objective_hashes == (to_sha256(f"{_SECRET}-1"),)
    assert "0" * 64 not in evidence.configuration.objective_hashes
