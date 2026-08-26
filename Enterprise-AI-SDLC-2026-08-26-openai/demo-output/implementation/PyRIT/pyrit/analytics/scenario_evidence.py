# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Build deterministic, privacy-safe security evidence from persisted scenario results."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from pyrit.common.utils import to_sha256
from pyrit.models.catalog.security_evidence import (
    EvidenceCompletenessStatus,
    EvidenceComponentIdentity,
    EvidenceCoverage,
    EvidenceGroupSummary,
    EvidenceLatencySummary,
    EvidenceMetricSummary,
    EvidenceMoney,
    EvidenceObservedTrial,
    EvidenceTrialIdentity,
    SecurityEvidence,
    SecurityEvidenceBaseline,
    SecurityEvidenceCompleteness,
    SecurityEvidenceConfiguration,
    SecurityEvidenceMetrics,
    SecurityEvidenceRun,
    SecurityEvidenceSubject,
    SecurityEvidenceTrialPlan,
    SecurityEvidenceUsage,
)
from pyrit.models.identifiers.evaluation_identifier import (
    ObjectiveTargetEvaluationIdentifier,
    ScenarioEvaluationIdentifier,
    ScorerEvaluationIdentifier,
)
from pyrit.models.results.attack_result import AttackOutcome, AttackResult
from pyrit.models.results.scenario_result import (
    SECURITY_EVIDENCE_SUBJECT_METADATA_KEY,
    SECURITY_EVIDENCE_TRIAL_PLAN_METADATA_KEY,
    ScenarioResult,
    ScenarioRunState,
)
from pyrit.models.target.token_usage import TokenUsage

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from pyrit.memory.memory_interface import MemoryInterface
    from pyrit.models.identifiers.component_identifier import ComponentIdentifier
    from pyrit.models.messages.message_piece import MessagePiece


_BENCHMARK_SCHEMA = "pyrit.security-evidence/benchmark/v1"
_TERMINAL_STATES = frozenset(
    {
        ScenarioRunState.COMPLETED,
        ScenarioRunState.FAILED,
        ScenarioRunState.CANCELLED,
    }
)
_ZERO_DIGEST = "0" * 64


def canonical_json_bytes(value: Any) -> bytes:
    """
    Serialize a JSON-native value using the evidence canonicalization rules.

    Returns:
        Canonical UTF-8 JSON bytes.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_security_evidence_bytes(evidence: SecurityEvidence) -> bytes:
    """Return the complete evidence envelope as canonical UTF-8 JSON."""
    return canonical_json_bytes(evidence.model_dump(mode="json"))


def compute_security_evidence_digest(evidence: SecurityEvidence) -> str:
    """
    Compute the envelope digest, excluding the digest field itself.

    Returns:
        Lowercase SHA-256 hex digest.
    """
    return evidence.computed_digest


def compute_security_evidence_baseline_digest(baseline: SecurityEvidenceBaseline) -> str:
    """Return the canonical digest of a baseline's persisted producer facts."""
    return baseline.computed_digest


def verify_security_evidence_digest(evidence: SecurityEvidence) -> bool:
    """Return whether an envelope carries the digest of its canonical facts."""
    return evidence.evidence_digest == compute_security_evidence_digest(evidence)


def build_security_evidence(
    *,
    scenario_result: ScenarioResult,
    memory: MemoryInterface | None = None,
    subject: SecurityEvidenceSubject | None = None,
    baseline_result: ScenarioResult | None = None,
) -> SecurityEvidence:
    """
    Build a ``pyrit.security-evidence/v1`` envelope from real PyRIT result objects.

    The output is an allowlist projection. It never serializes prompt/objective/response
    text, arbitrary labels or metadata, error messages or tracebacks, component params,
    target endpoints, or credentials. When memory is supplied, usage is read only from
    provider-owned ``token_usage_*`` response metadata in conversations linked by the
    attack results.

    Args:
        scenario_result: Persisted scenario aggregate to summarize.
        memory: Optional memory interface used to aggregate linked conversation usage.
        subject: Optional assertion of the subject already persisted with the run.
            It can verify a stored binding but can never create or replace one.
        baseline_result: Optional prior scenario result for a factual compatibility summary.

    Returns:
        A strict evidence envelope carrying a verified canonical SHA-256 digest.

    Raises:
        ValueError: If a persisted subject, trial plan, baseline, or provider fact
            is malformed, unsafe, or inconsistent with the requested assertion.
    """
    persisted_subject = get_persisted_security_evidence_subject(scenario_result=scenario_result)
    if subject is not None and subject != persisted_subject:
        raise ValueError("requested evidence subject does not match the run's immutable stored binding")
    subject = persisted_subject

    trial_plan = get_persisted_security_evidence_trial_plan(scenario_result=scenario_result)
    attack_results = _flatten_attack_results(scenario_result=scenario_result)
    scenario_result_id = str(scenario_result.id)
    observed_trials = _build_observed_trial_provenance(
        scenario_result=scenario_result,
        scenario_result_id=scenario_result_id,
    )
    planned_cached_trials = trial_plan.cached_trials if trial_plan is not None else ()
    observed_ids = {trial.attack_result_id for trial in observed_trials}
    planned_ids = {trial.attack_result_id for trial in planned_cached_trials}
    current_run_trial_count = sum(trial.origin_scenario_result_id == scenario_result_id for trial in observed_trials)
    reused_trial_count = len({trial.attack_result_id for trial in observed_trials if trial.cached} | planned_ids)
    omitted_reused_trial_count = len(planned_ids - observed_ids)
    missing_provenance_trial_count = sum(trial.origin_scenario_result_id is None for trial in observed_trials)
    origin_ids = tuple(
        sorted(
            {
                trial.origin_scenario_result_id
                for trial in observed_trials
                if trial.origin_scenario_result_id is not None
            }
            | {trial.origin_scenario_result_id for trial in planned_cached_trials}
        )
    )
    trial_times = [trial.observed_at for trial in observed_trials] + [
        trial.observed_at for trial in planned_cached_trials
    ]
    oldest_trial_at = min(trial_times) if trial_times else None
    expected_trial_inventory = trial_plan.expected_trials if trial_plan is not None else None
    configuration = _build_configuration(
        scenario_result=scenario_result,
        attack_results=attack_results,
        expected_trial_inventory=expected_trial_inventory,
    )
    metrics = _build_metrics(scenario_result=scenario_result, attack_results=attack_results)
    usage = _build_usage(attack_results=attack_results, memory=memory)
    terminal = scenario_result.scenario_run_state in _TERMINAL_STATES
    completed_at = _as_utc(scenario_result.completion_time) if terminal and scenario_result.completion_time else None
    created_at = _as_utc(scenario_result.creation_time)
    run = SecurityEvidenceRun(
        scenario_result_id=scenario_result_id,
        state=scenario_result.scenario_run_state,
        created_at=created_at,
        completed_at=completed_at,
        number_tries=scenario_result.number_tries,
        pyrit_version=scenario_result.pyrit_version,
        trial_plan_digest=trial_plan.plan_digest if trial_plan is not None else None,
        expected_trial_inventory=expected_trial_inventory,
        planned_cached_trials=planned_cached_trials,
        observed_trials=observed_trials,
        oldest_trial_at=oldest_trial_at,
        current_run_trial_count=current_run_trial_count,
        reused_trial_count=reused_trial_count,
        omitted_reused_trial_count=omitted_reused_trial_count,
        missing_provenance_trial_count=missing_provenance_trial_count,
        origin_scenario_result_ids=origin_ids,
    )
    completeness = _build_completeness(
        scenario_result=scenario_result,
        run=run,
        metrics=metrics.overall,
        usage=usage,
        target_available=configuration.target is not None,
        subject_bound=subject is not None,
    )
    baseline = (
        _build_baseline_summary(
            current_configuration=configuration,
            current_metrics=metrics.overall,
            baseline_result=baseline_result,
        )
        if baseline_result is not None
        else None
    )

    generated_at = oldest_trial_at or completed_at or created_at

    payload: dict[str, Any] = {
        "generated_at": generated_at,
        "subject": subject,
        "run": run,
        "configuration": configuration,
        "metrics": metrics,
        "usage": usage,
        "baseline": baseline,
        "completeness": completeness,
    }
    provisional = SecurityEvidence.model_construct(**payload, evidence_digest=_ZERO_DIGEST)
    return SecurityEvidence.model_validate(
        {**payload, "evidence_digest": compute_security_evidence_digest(provisional)}
    )


def _as_utc(value: datetime) -> datetime:
    """
    Normalize persisted timestamps to aware UTC values.

    Returns:
        An aware UTC datetime.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def get_persisted_security_evidence_subject(*, scenario_result: ScenarioResult) -> SecurityEvidenceSubject | None:
    """
    Load the protected release subject stored on a scenario result.

    Returns:
        The validated immutable subject, or ``None`` for an unbound legacy run.

    Raises:
        ValueError: If the stored subject payload is malformed.
    """
    payload = scenario_result.metadata.get(SECURITY_EVIDENCE_SUBJECT_METADATA_KEY)
    if payload is None:
        return None
    try:
        return SecurityEvidenceSubject.model_validate(payload)
    except ValueError as exc:
        raise ValueError("persisted security-evidence subject is malformed") from exc


def get_persisted_security_evidence_trial_plan(*, scenario_result: ScenarioResult) -> SecurityEvidenceTrialPlan | None:
    """
    Load and verify the producer-owned trial plan stored at run creation.

    Returns:
        The digest-verified plan, or ``None`` for a legacy run without one.

    Raises:
        ValueError: If the stored plan is malformed or its digest is invalid.
    """
    payload = scenario_result.metadata.get(SECURITY_EVIDENCE_TRIAL_PLAN_METADATA_KEY)
    if payload is None:
        return None
    try:
        return SecurityEvidenceTrialPlan.model_validate(payload)
    except ValueError as exc:
        raise ValueError("persisted security-evidence trial plan is malformed") from exc


def _build_observed_trial_provenance(
    *,
    scenario_result: ScenarioResult,
    scenario_result_id: str,
) -> tuple[EvidenceObservedTrial, ...]:
    observed = [
        EvidenceObservedTrial(
            identity=EvidenceTrialIdentity(
                atomic_attack_name=atomic_attack_name,
                display_group=scenario_result.display_group_map.get(atomic_attack_name, atomic_attack_name),
                objective_sha256=to_sha256(attack_result.objective),
            ),
            attack_result_id=attack_result.attack_result_id,
            origin_scenario_result_id=attack_result.attribution_parent_id,
            observed_at=_as_utc(attack_result.timestamp),
            cached=(
                attack_result.attribution_parent_id is not None
                and attack_result.attribution_parent_id != scenario_result_id
            ),
            outcome=attack_result.outcome,
            execution_time_ms=attack_result.execution_time_ms,
        )
        for atomic_attack_name, attack_results in scenario_result.attack_results.items()
        for attack_result in attack_results
    ]
    return tuple(sorted(observed, key=lambda trial: trial.sort_key))


def _flatten_attack_results(*, scenario_result: ScenarioResult) -> list[AttackResult]:
    return [result for results in scenario_result.attack_results.values() for result in results]


def _component_identity(
    *,
    identifier: ComponentIdentifier,
    eval_hash: str,
) -> EvidenceComponentIdentity:
    return EvidenceComponentIdentity(
        class_name=identifier.class_name,
        content_hash=identifier.hash,
        eval_hash=eval_hash,
    )


def _build_configuration(
    *,
    scenario_result: ScenarioResult,
    attack_results: Sequence[AttackResult],
    expected_trial_inventory: Sequence[EvidenceTrialIdentity] | None = None,
) -> SecurityEvidenceConfiguration:
    scenario_identifier = scenario_result.scenario_identifier
    scenario_identity = _component_identity(
        identifier=scenario_identifier,
        eval_hash=ScenarioEvaluationIdentifier(scenario_identifier).eval_hash,
    )

    target_identifier = scenario_result.objective_target_identifier
    target_identity = (
        _component_identity(
            identifier=target_identifier,
            eval_hash=ObjectiveTargetEvaluationIdentifier(target_identifier).eval_hash,
        )
        if target_identifier is not None
        else None
    )

    scorer_identifier = scenario_result.objective_scorer_identifier
    scorer_identity = (
        _component_identity(
            identifier=scorer_identifier,
            eval_hash=ScorerEvaluationIdentifier(scorer_identifier).eval_hash,
        )
        if scorer_identifier is not None
        else None
    )

    objective_hashes = (
        sorted({trial.objective_sha256 for trial in expected_trial_inventory})
        if expected_trial_inventory is not None
        else _objective_hashes(scenario_result=scenario_result, attack_results=attack_results)
    )
    techniques = sorted(set(scenario_identifier.techniques or []))
    datasets = sorted(set(scenario_identifier.datasets or []))
    fingerprint_payload = {
        "schema": _BENCHMARK_SCHEMA,
        "scenario": scenario_identity.model_dump(mode="json"),
        "target": target_identity.model_dump(mode="json") if target_identity else None,
        "scorer": scorer_identity.model_dump(mode="json") if scorer_identity else None,
        "scenario_version": scenario_result.scenario_version,
        "pyrit_version": scenario_result.pyrit_version,
        "techniques": techniques,
        "datasets": datasets,
        "objective_hashes": objective_hashes,
    }
    benchmark_fingerprint = hashlib.sha256(canonical_json_bytes(fingerprint_payload)).hexdigest()

    return SecurityEvidenceConfiguration(
        scenario=scenario_identity,
        target=target_identity,
        scorer=scorer_identity,
        scenario_version=scenario_result.scenario_version,
        pyrit_version=scenario_result.pyrit_version,
        techniques=techniques,
        datasets=datasets,
        objective_hashes=objective_hashes,
        benchmark_fingerprint=benchmark_fingerprint,
    )


def _objective_hashes(
    *,
    scenario_result: ScenarioResult,
    attack_results: Sequence[AttackResult],
) -> list[str]:
    # ScenarioResult metadata is caller-controlled and therefore cannot establish
    # benchmark identity. Attack objectives are persisted producer facts; only
    # their digests leave this privacy boundary.
    return sorted({to_sha256(result.objective) for result in attack_results})


def _build_metrics(
    *,
    scenario_result: ScenarioResult,
    attack_results: Sequence[AttackResult],
) -> SecurityEvidenceMetrics:
    overall = _summarize_attacks(attack_results)
    grouped_results: dict[str, list[AttackResult]] = defaultdict(list)
    group_attack_names: dict[str, set[str]] = defaultdict(set)
    for atomic_attack_name, results in scenario_result.attack_results.items():
        if not results:
            continue
        group_name = scenario_result.display_group_map.get(atomic_attack_name, atomic_attack_name)
        group_attack_names[group_name].add(atomic_attack_name)
        grouped_results[group_name].extend(results)

    groups = [
        EvidenceGroupSummary(
            name=group_name,
            atomic_attack_names=sorted(group_attack_names[group_name]),
            metrics=_summarize_attacks(grouped_results[group_name]),
        )
        for group_name in sorted(grouped_results)
    ]
    return SecurityEvidenceMetrics(overall=overall, groups=groups)


def _summarize_attacks(results: Iterable[AttackResult]) -> EvidenceMetricSummary:
    result_list = list(results)
    successes = sum(result.outcome is AttackOutcome.SUCCESS for result in result_list)
    failures = sum(result.outcome is AttackOutcome.FAILURE for result in result_list)
    errors = sum(result.outcome is AttackOutcome.ERROR for result in result_list)
    undetermined = sum(result.outcome is AttackOutcome.UNDETERMINED for result in result_list)
    trials = len(result_list)
    determinate = successes + failures
    latencies = [result.execution_time_ms for result in result_list]

    if latencies:
        ordered = sorted(latencies)
        p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
        total_ms = sum(ordered)
        latency = EvidenceLatencySummary(
            samples=len(ordered),
            total_ms=total_ms,
            mean_ms=total_ms / len(ordered),
            p95_ms=ordered[p95_index],
            max_ms=ordered[-1],
        )
    else:
        latency = EvidenceLatencySummary(samples=0)

    return EvidenceMetricSummary(
        trials=trials,
        determinate_trials=determinate,
        successes=successes,
        failures=failures,
        errors=errors,
        undetermined=undetermined,
        attack_success_rate=successes / determinate if determinate else None,
        error_rate=errors / trials if trials else None,
        undetermined_rate=undetermined / trials if trials else None,
        latency=latency,
    )


def _build_usage(
    *,
    attack_results: Sequence[AttackResult],
    memory: MemoryInterface | None,
) -> SecurityEvidenceUsage:
    conversation_ids = sorted(
        {conversation_id for result in attack_results for conversation_id in result.get_all_conversation_ids()}
    )
    if memory is None:
        return SecurityEvidenceUsage(
            conversation_count=len(conversation_ids),
            observed_response_count=0,
            calls_with_token_usage=0,
            calls_with_cost=0,
            token_coverage=EvidenceCoverage.UNAVAILABLE,
            cost_coverage=EvidenceCoverage.UNAVAILABLE,
        )

    response_groups: dict[tuple[str, str], list[MessagePiece]] = defaultdict(list)
    for conversation_id in conversation_ids:
        for piece in memory.get_message_pieces(conversation_id=conversation_id):
            if piece.api_role != "assistant":
                continue
            call_key = str(piece.sequence) if piece.sequence >= 0 else f"piece:{piece.original_prompt_id or piece.id}"
            response_groups[(conversation_id, call_key)].append(piece)

    token_sums: dict[str, int] = defaultdict(int)
    token_reports: dict[str, int] = defaultdict(int)
    calls_with_token_usage = 0
    calls_with_complete_core_usage = 0
    calls_with_cost = 0
    total_cost = Decimal(0)

    for pieces in response_groups.values():
        usage = _usage_for_response(pieces=pieces)
        if usage is not None:
            input_tokens = usage.input_tokens
            output_tokens = usage.output_tokens
            total_tokens = usage.total_tokens
            if total_tokens is None and input_tokens is not None and output_tokens is not None:
                total_tokens = input_tokens + output_tokens
            if (
                input_tokens is not None
                and output_tokens is not None
                and total_tokens is not None
                and total_tokens != input_tokens + output_tokens
            ):
                raise ValueError("Provider token total does not equal input plus output tokens")

            calls_with_token_usage += 1
            if input_tokens is not None and output_tokens is not None and total_tokens is not None:
                calls_with_complete_core_usage += 1
            values = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": usage.reasoning_tokens,
                "cached_tokens": usage.cached_tokens,
                "total_tokens": total_tokens,
            }
            for name, value in values.items():
                if value is not None:
                    token_sums[name] += value
                    token_reports[name] += 1

        cost = _cost_for_response(pieces=pieces)
        if cost is not None:
            calls_with_cost += 1
            total_cost += cost

    observed = len(response_groups)
    token_coverage = _token_coverage(
        observed=observed,
        reported=calls_with_token_usage,
        core_complete=calls_with_complete_core_usage,
    )
    cost_coverage = _coverage(observed=observed, reported=calls_with_cost)
    aggregate_cost = EvidenceMoney(amount=format(total_cost, "f")) if calls_with_cost else None

    return SecurityEvidenceUsage(
        conversation_count=len(conversation_ids),
        observed_response_count=observed,
        calls_with_token_usage=calls_with_token_usage,
        calls_with_cost=calls_with_cost,
        input_tokens=(
            token_sums["input_tokens"]
            if calls_with_token_usage and token_reports["input_tokens"] == calls_with_token_usage
            else None
        ),
        output_tokens=(
            token_sums["output_tokens"]
            if calls_with_token_usage and token_reports["output_tokens"] == calls_with_token_usage
            else None
        ),
        reasoning_tokens=token_sums["reasoning_tokens"] if token_reports["reasoning_tokens"] else None,
        cached_tokens=token_sums["cached_tokens"] if token_reports["cached_tokens"] else None,
        total_tokens=(
            token_sums["total_tokens"]
            if calls_with_token_usage and token_reports["total_tokens"] == calls_with_token_usage
            else None
        ),
        cost=aggregate_cost,
        token_coverage=token_coverage,
        cost_coverage=cost_coverage,
    )


def _usage_for_response(*, pieces: Sequence[MessagePiece]) -> TokenUsage | None:
    usages: list[TokenUsage] = []
    for piece in pieces:
        usage = TokenUsage.from_metadata(piece.prompt_metadata)
        if usage is None:
            continue
        if any(value is not None for value in (usage.input_tokens, usage.output_tokens, usage.total_tokens)):
            usages.append(usage)
    if not usages:
        return None
    if len(usages) > 1 and any(usage != usages[0] for usage in usages[1:]):
        raise ValueError("Conflicting token usage was recorded for one model response")
    return usages[0]


def _cost_for_response(*, pieces: Sequence[MessagePiece]) -> Decimal | None:
    costs: list[Decimal] = []
    for piece in pieces:
        raw = piece.prompt_metadata.get("token_usage_cost")
        if raw is None:
            continue
        if isinstance(raw, bool):
            raise ValueError("token_usage_cost must be a finite, non-negative decimal")
        try:
            amount = Decimal(str(raw))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("token_usage_cost must be a finite, non-negative decimal") from exc
        if not amount.is_finite() or amount < 0:
            raise ValueError("token_usage_cost must be a finite, non-negative decimal")
        costs.append(amount)
    if not costs:
        return None
    if any(cost != costs[0] for cost in costs[1:]):
        raise ValueError("Conflicting token costs were recorded for one model response")
    return costs[0]


def _coverage(*, observed: int, reported: int) -> EvidenceCoverage:
    if observed == 0 or reported == 0:
        return EvidenceCoverage.UNAVAILABLE
    if reported == observed:
        return EvidenceCoverage.COMPLETE
    return EvidenceCoverage.PARTIAL


def _token_coverage(*, observed: int, reported: int, core_complete: int) -> EvidenceCoverage:
    """
    Classify core token accounting without treating auxiliary counts as totals.

    Returns:
        Coverage of usable input/output/total token facts.
    """
    if observed == 0 or reported == 0:
        return EvidenceCoverage.UNAVAILABLE
    if core_complete == observed:
        return EvidenceCoverage.COMPLETE
    return EvidenceCoverage.PARTIAL


def _build_completeness(
    *,
    scenario_result: ScenarioResult,
    run: SecurityEvidenceRun,
    metrics: EvidenceMetricSummary,
    usage: SecurityEvidenceUsage,
    target_available: bool,
    subject_bound: bool,
) -> SecurityEvidenceCompleteness:
    state = scenario_result.scenario_run_state
    terminal = state in _TERMINAL_STATES
    outcome_reasons: list[str] = []
    if state is not ScenarioRunState.COMPLETED:
        outcome_reasons.append("run.not_completed")
    if metrics.trials == 0:
        outcome_reasons.append("run.no_trials")
    if not target_available:
        outcome_reasons.append("configuration.target_missing")
    if not subject_bound:
        outcome_reasons.append("subject.unbound")
    if run.expected_trial_inventory is None:
        outcome_reasons.append("run.trial_inventory_unbound")
    elif not run.current_inventory_is_exact:
        outcome_reasons.append("run.trial_inventory_mismatch")
    if run.reused_trial_count:
        outcome_reasons.append("run.reused_trials")
    if run.missing_provenance_trial_count:
        outcome_reasons.append("run.trial_provenance_missing")

    observations: list[str] = []
    if usage.token_coverage is EvidenceCoverage.UNAVAILABLE:
        observations.append("usage.unavailable")
    elif usage.token_coverage is EvidenceCoverage.PARTIAL:
        observations.append("usage.partial")
    if usage.cost_coverage is EvidenceCoverage.UNAVAILABLE:
        observations.append("cost.unavailable")
    elif usage.cost_coverage is EvidenceCoverage.PARTIAL:
        observations.append("cost.partial")

    if not terminal:
        status = EvidenceCompletenessStatus.UNAVAILABLE
    elif outcome_reasons:
        status = EvidenceCompletenessStatus.INCOMPLETE
    else:
        status = EvidenceCompletenessStatus.COMPLETE

    return SecurityEvidenceCompleteness(
        status=status,
        reasons=sorted(set(outcome_reasons + observations)),
        terminal=terminal,
        has_trials=metrics.trials > 0,
    )


def _build_baseline_summary(
    *,
    current_configuration: SecurityEvidenceConfiguration,
    current_metrics: EvidenceMetricSummary,
    baseline_result: ScenarioResult,
) -> SecurityEvidenceBaseline:
    baseline_trial_plan = get_persisted_security_evidence_trial_plan(scenario_result=baseline_result)
    if baseline_trial_plan is None:
        raise ValueError("baseline scenario run has no immutable trial inventory")
    if baseline_trial_plan.cached_trials:
        raise ValueError("baseline scenario run reused cached trials")
    baseline_attacks = _flatten_attack_results(scenario_result=baseline_result)
    baseline_id = str(baseline_result.id)
    baseline_observed = _build_observed_trial_provenance(
        scenario_result=baseline_result,
        scenario_result_id=baseline_id,
    )
    if any(trial.origin_scenario_result_id != baseline_id for trial in baseline_observed):
        raise ValueError("baseline scenario run contains foreign or missing trial provenance")
    if Counter(trial.sort_key for trial in baseline_trial_plan.expected_trials) != Counter(
        trial.identity.sort_key for trial in baseline_observed
    ):
        raise ValueError("baseline scenario run does not match its immutable trial inventory")
    baseline_configuration = _build_configuration(
        scenario_result=baseline_result,
        attack_results=baseline_attacks,
        expected_trial_inventory=baseline_trial_plan.expected_trials,
    )
    baseline_metrics = _summarize_attacks(baseline_attacks)
    reasons: list[str] = []
    if baseline_configuration.benchmark_fingerprint != current_configuration.benchmark_fingerprint:
        reasons.append("baseline.benchmark_fingerprint_mismatch")
    if baseline_configuration.pyrit_version != current_configuration.pyrit_version:
        reasons.append("baseline.pyrit_version_mismatch")
    if baseline_result.scenario_run_state is not ScenarioRunState.COMPLETED:
        reasons.append("baseline.run_not_completed")
    if not baseline_attacks:
        reasons.append("baseline.no_trials")
    if current_configuration.target is None:
        reasons.append("baseline.target_missing")
    reasons = sorted(set(reasons))
    compatible = not reasons

    generated_at = (
        min(trial.observed_at for trial in baseline_observed)
        if baseline_observed
        else _as_utc(baseline_result.completion_time or baseline_result.creation_time)
    )
    payload: dict[str, Any] = {
        "scenario_result_id": str(baseline_result.id),
        "generated_at": generated_at,
        "state": baseline_result.scenario_run_state,
        "pyrit_version": baseline_result.pyrit_version,
        "benchmark_fingerprint": baseline_configuration.benchmark_fingerprint,
        "compatible": compatible,
        "incompatibility_reasons": reasons,
        "metrics": baseline_metrics,
        "delta_attack_success_rate": (
            _delta(current_metrics.attack_success_rate, baseline_metrics.attack_success_rate) if compatible else None
        ),
        "delta_error_rate": _delta(current_metrics.error_rate, baseline_metrics.error_rate) if compatible else None,
        "delta_undetermined_rate": (
            _delta(current_metrics.undetermined_rate, baseline_metrics.undetermined_rate) if compatible else None
        ),
    }
    provisional = SecurityEvidenceBaseline.model_construct(**payload, baseline_digest=_ZERO_DIGEST)
    return SecurityEvidenceBaseline.model_validate({**payload, "baseline_digest": provisional.computed_digest})


def _delta(current: float | None, baseline: float | None) -> float | None:
    if current is None or baseline is None:
        return None
    return current - baseline


__all__ = [
    "build_security_evidence",
    "canonical_json_bytes",
    "canonical_security_evidence_bytes",
    "compute_security_evidence_baseline_digest",
    "compute_security_evidence_digest",
    "verify_security_evidence_digest",
]
