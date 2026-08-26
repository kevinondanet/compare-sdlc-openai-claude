# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail-closed evaluation of PyRIT evidence against release policy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path  # noqa: TC003 -- public loader annotation
from typing import TYPE_CHECKING, Any

from agent_sre.sdlc.canonical import (
    canonical_json_bytes,
    load_json_file_strict,
    load_json_strict,
    with_digest,
)
from agent_sre.sdlc.models import (
    ReasonCode,
    ReleaseCheck,
    ReleasePolicy,
    ReleaseVerdict,
    VerdictStatus,
    validate_contract_json,
)
from agent_sre.sdlc.pyrit import (
    CompletenessStatus,
    Coverage,
    PyRITRunState,
    PyRITSecurityEvidence,
)

if TYPE_CHECKING:
    from agent_sre.sdlc.ledger import SQLiteEvaluationLedger


def parse_release_policy(data: str | bytes) -> ReleasePolicy:
    """Strictly parse an ``agt.release-policy/v1`` JSON document."""

    payload = load_json_strict(data)
    if not isinstance(payload, dict):
        raise ValueError("release policy must be a JSON object")
    thresholds = payload.get("thresholds")
    max_cost = thresholds.get("max_cost_usd") if isinstance(thresholds, dict) else None
    if not isinstance(max_cost, str):
        raise ValueError("thresholds.max_cost_usd must be a decimal JSON string")
    result = validate_contract_json(ReleasePolicy, payload)
    assert isinstance(result, ReleasePolicy)
    return result


def load_release_policy(path: str | Path) -> ReleasePolicy:
    """Load a bounded release-policy JSON file."""

    payload = load_json_file_strict(path)
    if not isinstance(payload, dict):
        raise ValueError("release policy must be a JSON object")
    import json

    return parse_release_policy(json.dumps(payload, ensure_ascii=False, allow_nan=False))


def parse_release_verdict(data: str | bytes) -> ReleaseVerdict:
    """Strictly parse and integrity-check an ``agt.release-verdict/v1`` document."""

    payload = load_json_strict(data)
    if not isinstance(payload, dict):
        raise ValueError("release verdict must be a JSON object")
    result = validate_contract_json(ReleaseVerdict, payload)
    assert isinstance(result, ReleaseVerdict)
    return result


def _display(value: object) -> str:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, float):
        return format(value, ".12g")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, set | frozenset | tuple | list):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def _freshness_state(
    policy: ReleasePolicy,
    evidence: PyRITSecurityEvidence,
    *,
    at: datetime,
) -> str:
    """Classify the only policy checks whose outcome changes with wall time."""
    future_limit = at + timedelta(seconds=policy.freshness.max_future_skew_seconds)
    if evidence.generated_at > future_limit:
        evidence_state = "future"
    else:
        oldest = at - timedelta(seconds=policy.freshness.max_age_seconds)
        evidence_state = "stale" if evidence.generated_at < oldest else "fresh"

    baseline = evidence.baseline
    if baseline is None:
        baseline_state = "missing"
    elif baseline.generated_at > future_limit:
        baseline_state = "future"
    else:
        oldest_baseline = at - timedelta(seconds=policy.baseline.max_age_seconds)
        baseline_state = "stale" if baseline.generated_at < oldest_baseline else "fresh"
    return f"evidence={evidence_state};baseline={baseline_state}"


class ReleaseEvaluator:
    """Evaluate one immutable evidence document and optionally persist its verdict."""

    def __init__(self, ledger: SQLiteEvaluationLedger | None = None) -> None:
        self._ledger = ledger

    def evaluate(
        self,
        policy: ReleasePolicy,
        evidence: PyRITSecurityEvidence,
        *,
        evaluated_at: datetime | None = None,
    ) -> ReleaseVerdict:
        """Return a deterministic verdict while collecting every applicable failure."""

        try:
            policy = ReleasePolicy.model_validate_json(
                canonical_json_bytes(policy.model_dump(mode="json", warnings="error")),
                strict=True,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("release policy failed strict canonical revalidation") from exc
        try:
            evidence = PyRITSecurityEvidence.model_validate_json(
                canonical_json_bytes(evidence.model_dump(mode="json", warnings="error")),
                strict=True,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("PyRIT evidence failed strict canonical revalidation") from exc

        now = evaluated_at or datetime.now(UTC)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware UTC")
        if now.utcoffset() != timedelta(0):
            raise ValueError("evaluated_at must be UTC")

        if self._ledger is not None:
            existing = self._ledger.get(evidence.evidence_digest)
            if existing is not None:
                if existing.policy_digest != policy.policy_digest:
                    from agent_sre.sdlc.ledger import EvaluationConflictError

                    raise EvaluationConflictError(
                        "evidence digest has already been evaluated under a different policy"
                    )
                if _freshness_state(policy, evidence, at=existing.evaluated_at) == _freshness_state(
                    policy, evidence, at=now
                ):
                    return existing

        checks: dict[ReasonCode, ReleaseCheck] = {}

        def check(
            code: ReasonCode,
            passed: bool,
            *,
            actual: object | None = None,
            expected: object | None = None,
        ) -> None:
            checks[code] = ReleaseCheck(
                code=code,
                passed=passed,
                actual=None if actual is None else _display(actual),
                expected=None if expected is None else _display(expected),
            )

        subject = evidence.subject
        check(
            ReasonCode.SUBJECT_MISSING,
            subject is not None,
            actual="missing" if subject is None else "present",
            expected="present",
        )
        if subject is not None:
            check(
                ReasonCode.APPLICATION_MISMATCH,
                subject.application == policy.subject.application,
                actual=subject.application,
                expected=policy.subject.application,
            )
            check(
                ReasonCode.CHANGE_MISMATCH,
                subject.change == policy.subject.change,
                actual=subject.change,
                expected=policy.subject.change,
            )
            check(
                ReasonCode.COMMIT_MISMATCH,
                subject.commit_sha == policy.subject.commit_sha,
                actual=subject.commit_sha,
                expected=policy.subject.commit_sha,
            )

        check(
            ReasonCode.RUN_NOT_COMPLETED,
            evidence.run.state is PyRITRunState.COMPLETED,
            actual=evidence.run.state.value,
            expected=PyRITRunState.COMPLETED.value,
        )
        check(
            ReasonCode.EVIDENCE_NOT_TERMINAL,
            evidence.completeness.terminal,
            actual=evidence.completeness.terminal,
            expected=True,
        )
        check(
            ReasonCode.EVIDENCE_NO_TRIALS,
            evidence.completeness.has_trials,
            actual=evidence.metrics.overall.trials,
            expected=">=1",
        )
        check(
            ReasonCode.EVIDENCE_INCOMPLETE,
            evidence.completeness.status is CompletenessStatus.COMPLETE,
            actual=evidence.completeness.status.value,
            expected=CompletenessStatus.COMPLETE.value,
        )
        check(
            ReasonCode.CONFIGURATION_TARGET_MISSING,
            evidence.configuration.target is not None,
            actual="missing" if evidence.configuration.target is None else "present",
            expected="present",
        )
        check(
            ReasonCode.BENCHMARK_NOT_ALLOWED,
            evidence.configuration.benchmark_fingerprint
            in policy.requirements.allowed_benchmark_fingerprints,
            actual=evidence.configuration.benchmark_fingerprint,
            expected=policy.requirements.allowed_benchmark_fingerprints,
        )

        future_limit = now + timedelta(seconds=policy.freshness.max_future_skew_seconds)
        oldest = now - timedelta(seconds=policy.freshness.max_age_seconds)
        check(
            ReasonCode.EVIDENCE_FROM_FUTURE,
            evidence.generated_at <= future_limit,
            actual=evidence.generated_at,
            expected=f"<={future_limit.isoformat()}",
        )
        check(
            ReasonCode.EVIDENCE_STALE,
            evidence.generated_at >= oldest,
            actual=evidence.generated_at,
            expected=f">={oldest.isoformat()}",
        )

        groups = {group.name: group for group in evidence.metrics.groups}
        observed_scenarios = {
            name for group in evidence.metrics.groups for name in group.atomic_attack_names
        }
        missing_scenarios = sorted(set(policy.requirements.required_scenarios) - observed_scenarios)
        check(
            ReasonCode.MISSING_REQUIRED_SCENARIO,
            not missing_scenarios,
            actual=missing_scenarios,
            expected="none",
        )
        missing_groups = sorted(set(policy.requirements.required_groups) - set(groups))
        check(
            ReasonCode.MISSING_REQUIRED_GROUP,
            not missing_groups,
            actual=missing_groups,
            expected="none",
        )
        check(
            ReasonCode.INSUFFICIENT_TRIALS,
            evidence.metrics.overall.trials >= policy.requirements.minimum_trials,
            actual=evidence.metrics.overall.trials,
            expected=f">={policy.requirements.minimum_trials}",
        )
        insufficient_groups = sorted(
            name
            for name in policy.requirements.required_groups
            if name in groups
            and groups[name].metrics.trials < policy.requirements.minimum_trials_per_group
        )
        check(
            ReasonCode.INSUFFICIENT_GROUP_TRIALS,
            not insufficient_groups,
            actual=insufficient_groups,
            expected=f">={policy.requirements.minimum_trials_per_group} trials per group",
        )

        overall = evidence.metrics.overall
        if overall.attack_success_rate is None:
            check(
                ReasonCode.ASR_UNAVAILABLE,
                False,
                actual="unavailable",
                expected="available",
            )
        else:
            check(
                ReasonCode.ASR_EXCEEDED,
                overall.attack_success_rate <= policy.thresholds.max_attack_success_rate,
                actual=overall.attack_success_rate,
                expected=f"<={_display(policy.thresholds.max_attack_success_rate)}",
            )
        if overall.undetermined_rate is None:
            check(
                ReasonCode.UNDETERMINED_RATE_UNAVAILABLE,
                False,
                actual="unavailable",
                expected="available",
            )
        else:
            check(
                ReasonCode.UNDETERMINED_RATE_EXCEEDED,
                overall.undetermined_rate <= policy.thresholds.max_undetermined_rate,
                actual=overall.undetermined_rate,
                expected=f"<={_display(policy.thresholds.max_undetermined_rate)}",
            )
        if overall.error_rate is None:
            check(
                ReasonCode.ERROR_RATE_UNAVAILABLE,
                False,
                actual="unavailable",
                expected="available",
            )
        else:
            check(
                ReasonCode.ERROR_RATE_EXCEEDED,
                overall.error_rate <= policy.thresholds.max_error_rate,
                actual=overall.error_rate,
                expected=f"<={_display(policy.thresholds.max_error_rate)}",
            )
        if overall.latency.p95_ms is None:
            check(
                ReasonCode.LATENCY_UNAVAILABLE,
                False,
                actual="unavailable",
                expected="available",
            )
        else:
            check(
                ReasonCode.LATENCY_EXCEEDED,
                overall.latency.p95_ms <= policy.thresholds.max_p95_latency_ms,
                actual=overall.latency.p95_ms,
                expected=f"<={_display(policy.thresholds.max_p95_latency_ms)}",
            )

        usage = evidence.usage
        if policy.requirements.require_usage_complete:
            has_accountable_tokens = (
                usage.input_tokens is not None
                and usage.output_tokens is not None
                and usage.total_tokens is not None
            )
            check(
                ReasonCode.USAGE_INCOMPLETE,
                usage.token_coverage is Coverage.COMPLETE and has_accountable_tokens,
                actual=(
                    f"{usage.token_coverage.value};accountable_totals={has_accountable_tokens}"
                ),
                expected="complete;accountable_totals=True",
            )
        if policy.requirements.require_cost_complete:
            check(
                ReasonCode.COST_INCOMPLETE,
                usage.cost_coverage is Coverage.COMPLETE,
                actual=usage.cost_coverage.value,
                expected=Coverage.COMPLETE.value,
            )
        if usage.cost is None:
            check(
                ReasonCode.COST_UNAVAILABLE,
                False,
                actual="unavailable",
                expected="available",
            )
        else:
            check(
                ReasonCode.COST_EXCEEDED,
                usage.cost.decimal_amount <= policy.thresholds.max_cost_usd,
                actual=usage.cost.decimal_amount,
                expected=f"<={_display(policy.thresholds.max_cost_usd)} USD",
            )

        baseline = evidence.baseline
        if baseline is None:
            if policy.baseline.required:
                check(
                    ReasonCode.BASELINE_REQUIRED,
                    False,
                    actual="missing",
                    expected="present",
                )
        else:
            check(
                ReasonCode.BASELINE_NOT_ALLOWED,
                baseline.baseline_digest in policy.baseline.allowed_evidence_digests,
                actual=baseline.baseline_digest,
                expected=policy.baseline.allowed_evidence_digests,
            )
            baseline_future_limit = now + timedelta(
                seconds=policy.freshness.max_future_skew_seconds
            )
            baseline_oldest = now - timedelta(seconds=policy.baseline.max_age_seconds)
            check(
                ReasonCode.BASELINE_FROM_FUTURE,
                baseline.generated_at <= baseline_future_limit,
                actual=baseline.generated_at,
                expected=f"<={baseline_future_limit.isoformat()}",
            )
            check(
                ReasonCode.BASELINE_STALE,
                baseline.generated_at >= baseline_oldest,
                actual=baseline.generated_at,
                expected=f">={baseline_oldest.isoformat()}",
            )
            if policy.baseline.require_compatible:
                check(
                    ReasonCode.BASELINE_INCOMPATIBLE,
                    baseline.compatible,
                    actual=baseline.compatible,
                    expected=True,
                )
            if baseline.compatible:
                self._regression_check(
                    checks,
                    ReasonCode.BASELINE_ASR_DELTA_UNAVAILABLE,
                    ReasonCode.BASELINE_ASR_REGRESSION,
                    baseline.delta_attack_success_rate,
                    policy.baseline.max_attack_success_rate_increase,
                )
                self._regression_check(
                    checks,
                    ReasonCode.BASELINE_ERROR_DELTA_UNAVAILABLE,
                    ReasonCode.BASELINE_ERROR_REGRESSION,
                    baseline.delta_error_rate,
                    policy.baseline.max_error_rate_increase,
                )
                self._regression_check(
                    checks,
                    ReasonCode.BASELINE_UNDETERMINED_DELTA_UNAVAILABLE,
                    ReasonCode.BASELINE_UNDETERMINED_REGRESSION,
                    baseline.delta_undetermined_rate,
                    policy.baseline.max_undetermined_rate_increase,
                )

        ordered_checks = tuple(checks[code] for code in sorted(checks, key=lambda item: item.value))
        reasons = tuple(check.code for check in ordered_checks if not check.passed)
        payload: dict[str, Any] = {
            "schema": "agt.release-verdict/v1",
            "status": VerdictStatus.PASS.value if not reasons else VerdictStatus.FAIL.value,
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_digest": policy.policy_digest,
            "evidence_digest": evidence.evidence_digest,
            "subject": None if subject is None else subject.model_dump(mode="json"),
            "evaluated_at": now.isoformat().replace("+00:00", "Z"),
            "checks": [item.model_dump(mode="json") for item in ordered_checks],
            "reason_codes": [reason.value for reason in reasons],
        }
        verdict_payload = with_digest(payload, field="verdict_digest")
        verdict = validate_contract_json(ReleaseVerdict, verdict_payload)
        assert isinstance(verdict, ReleaseVerdict)
        if self._ledger is not None:
            return self._ledger.record(verdict)
        return verdict

    @staticmethod
    def _regression_check(
        checks: dict[ReasonCode, ReleaseCheck],
        unavailable_code: ReasonCode,
        exceeded_code: ReasonCode,
        delta: float | None,
        maximum: float,
    ) -> None:
        if delta is None:
            checks[unavailable_code] = ReleaseCheck(
                code=unavailable_code,
                passed=False,
                actual="unavailable",
                expected="available",
            )
            return
        checks[exceeded_code] = ReleaseCheck(
            code=exceeded_code,
            passed=delta <= maximum,
            actual=_display(delta),
            expected=f"<={_display(maximum)}",
        )
