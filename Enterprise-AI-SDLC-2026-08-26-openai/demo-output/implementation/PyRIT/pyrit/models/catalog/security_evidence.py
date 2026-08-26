# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Versioned, privacy-safe wire models for scenario security evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections import Counter
from datetime import datetime  # noqa: TC003 - runtime-required by Pydantic validators
from enum import Enum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from pyrit.models.results.attack_result import AttackOutcome  # noqa: TC001 - runtime-required by Pydantic
from pyrit.models.results.scenario_result import ScenarioRunState  # noqa: TC001 - runtime-required by Pydantic

SECURITY_EVIDENCE_SCHEMA = "pyrit.security-evidence/v1"
"""Current security-evidence wire schema identifier."""

SECURITY_EVIDENCE_BASELINE_SCHEMA = "pyrit.security-evidence/baseline/v1"
"""Canonical schema identifier used to digest baseline producer facts."""

SECURITY_EVIDENCE_TRIAL_PLAN_SCHEMA = "pyrit.security-evidence/trial-plan/v1"
"""Canonical schema for the producer-owned expected/cached trial plan."""

_SHA256_PATTERN = r"^[0-9a-f]{64}$"

BaselineIncompatibilityReason = Literal[
    "baseline.benchmark_fingerprint_mismatch",
    "baseline.no_trials",
    "baseline.pyrit_version_mismatch",
    "baseline.run_not_completed",
    "baseline.target_missing",
]
"""Stable baseline diagnostics derivable from the evidence envelope itself."""


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class _StrictEvidenceModel(BaseModel):
    """Common strict configuration for every security-evidence object."""

    model_config = ConfigDict(extra="forbid", frozen=True, serialize_by_alias=True)


class EvidenceCoverage(str, Enum):
    """How much of a usage dimension was reported by model providers."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class EvidenceCompletenessStatus(str, Enum):
    """Whether a scenario run contains complete, gateable attack outcomes."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class SecurityEvidenceSubject(_StrictEvidenceModel):
    """Release subject immutably attached to a scenario run before execution."""

    application: str = Field(..., min_length=1)
    change: str = Field(..., min_length=1)
    commit_sha: str = Field(..., pattern=r"^[0-9a-f]{7,64}$")


class EvidenceTrialIdentity(_StrictEvidenceModel):
    """Privacy-safe identity of one planned atomic-attack objective."""

    atomic_attack_name: str = Field(..., min_length=1)
    display_group: str = Field(..., min_length=1)
    objective_sha256: str = Field(..., pattern=_SHA256_PATTERN)

    @property
    def sort_key(self) -> tuple[str, str, str]:
        """Canonical inventory ordering key."""
        return (self.atomic_attack_name, self.display_group, self.objective_sha256)


class EvidenceCachedTrial(_StrictEvidenceModel):
    """Immutable provenance for a prior-run trial selected by scenario caching."""

    identity: EvidenceTrialIdentity
    attack_result_id: str = Field(..., min_length=1)
    origin_scenario_result_id: str = Field(..., min_length=1)
    observed_at: AwareDatetime
    cached: Literal[True] = True

    @field_validator("observed_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if offset is not None and offset.total_seconds() != 0:
            raise ValueError("cached trial timestamps must be UTC")
        return value

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        """Canonical cached-trial ordering key."""
        return (*self.identity.sort_key, self.attack_result_id)


class EvidenceObservedTrial(_StrictEvidenceModel):
    """Safe provenance for a trial present in the exported result aggregate."""

    identity: EvidenceTrialIdentity
    attack_result_id: str = Field(..., min_length=1)
    origin_scenario_result_id: str | None = None
    observed_at: AwareDatetime
    cached: bool
    outcome: AttackOutcome
    execution_time_ms: int = Field(..., ge=0)

    @field_validator("observed_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if offset is not None and offset.total_seconds() != 0:
            raise ValueError("observed trial timestamps must be UTC")
        return value

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        """Canonical observed-trial ordering key."""
        return (*self.identity.sort_key, self.attack_result_id)


class SecurityEvidenceTrialPlan(_StrictEvidenceModel):
    """Digest-bound expected inventory and prior-run trials fixed at creation."""

    schema_name: Literal["pyrit.security-evidence/trial-plan/v1"] = Field(
        default=SECURITY_EVIDENCE_TRIAL_PLAN_SCHEMA,
        alias="schema",
    )
    expected_trials: tuple[EvidenceTrialIdentity, ...]
    cached_trials: tuple[EvidenceCachedTrial, ...] = ()
    plan_digest: str = Field(..., pattern=_SHA256_PATTERN)

    @classmethod
    def create(
        cls,
        *,
        expected_trials: tuple[EvidenceTrialIdentity, ...],
        cached_trials: tuple[EvidenceCachedTrial, ...] = (),
    ) -> SecurityEvidenceTrialPlan:
        """
        Create a canonically ordered, self-verifying producer trial plan.

        Returns:
            A strict plan carrying the digest of its canonical producer facts.
        """
        expected_trials = tuple(sorted(expected_trials, key=lambda item: item.sort_key))
        cached_trials = tuple(sorted(cached_trials, key=lambda item: item.sort_key))
        payload = {
            "expected_trials": expected_trials,
            "cached_trials": cached_trials,
        }
        provisional = cls.model_construct(
            expected_trials=expected_trials,
            cached_trials=cached_trials,
            plan_digest="0" * 64,
        )
        return cls.model_validate({**payload, "plan_digest": provisional.computed_digest})

    @property
    def computed_digest(self) -> str:
        """Digest of the complete plan except its digest field."""
        return _canonical_sha256(self.model_dump(mode="json", exclude={"plan_digest"}))

    @model_validator(mode="after")
    def _validate_plan(self) -> SecurityEvidenceTrialPlan:
        if self.expected_trials != tuple(sorted(self.expected_trials, key=lambda item: item.sort_key)):
            raise ValueError("expected_trials must be canonically sorted")
        expected_keys = [trial.sort_key for trial in self.expected_trials]
        if len(expected_keys) != len(set(expected_keys)):
            raise ValueError("expected_trials must be unique")
        display_groups_by_atomic: dict[str, set[str]] = {}
        for trial in self.expected_trials:
            display_groups_by_atomic.setdefault(trial.atomic_attack_name, set()).add(trial.display_group)
        if any(len(groups) != 1 for groups in display_groups_by_atomic.values()):
            raise ValueError("each atomic attack must belong to exactly one display group")
        if self.cached_trials != tuple(sorted(self.cached_trials, key=lambda item: item.sort_key)):
            raise ValueError("cached_trials must be canonically sorted")
        cached_ids = [trial.attack_result_id for trial in self.cached_trials]
        if len(cached_ids) != len(set(cached_ids)):
            raise ValueError("cached trial attack_result_id values must be unique")
        expected = set(expected_keys)
        if any(trial.identity.sort_key not in expected for trial in self.cached_trials):
            raise ValueError("cached trials must belong to the expected inventory")
        if not hmac.compare_digest(self.plan_digest, self.computed_digest):
            raise ValueError("plan_digest does not match the canonical trial plan")
        return self


class SecurityEvidenceRun(_StrictEvidenceModel):
    """Safe lifecycle facts for the scenario execution that produced evidence."""

    scenario_result_id: str = Field(..., min_length=1)
    state: ScenarioRunState
    created_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    number_tries: int = Field(..., ge=0)
    pyrit_version: str = Field(..., min_length=1)
    trial_plan_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    expected_trial_inventory: tuple[EvidenceTrialIdentity, ...] | None = None
    planned_cached_trials: tuple[EvidenceCachedTrial, ...] = ()
    observed_trials: tuple[EvidenceObservedTrial, ...] = ()
    oldest_trial_at: AwareDatetime | None = None
    current_run_trial_count: int = Field(..., ge=0)
    reused_trial_count: int = Field(..., ge=0)
    omitted_reused_trial_count: int = Field(..., ge=0)
    missing_provenance_trial_count: int = Field(..., ge=0)
    origin_scenario_result_ids: tuple[str, ...] = ()

    @field_validator("created_at", "completed_at", "oldest_trial_at")
    @classmethod
    def _require_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            offset = value.utcoffset()
            if offset is not None and offset.total_seconds() != 0:
                raise ValueError("evidence timestamps must be UTC")
        return value

    @model_validator(mode="after")
    def _validate_lifecycle(self) -> SecurityEvidenceRun:
        terminal = self.state in {
            ScenarioRunState.COMPLETED,
            ScenarioRunState.FAILED,
            ScenarioRunState.CANCELLED,
        }
        if not terminal and self.completed_at is not None:
            raise ValueError("non-terminal runs must not include completed_at")
        if terminal and self.completed_at is None:
            raise ValueError("terminal runs must include completed_at")
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValueError("completed_at must not precede created_at")
        origin_ids = self.origin_scenario_result_ids
        if origin_ids != tuple(sorted(set(origin_ids))) or any(not item for item in origin_ids):
            raise ValueError("origin_scenario_result_ids must be sorted, unique, and non-empty")

        plan_parts = (self.trial_plan_digest, self.expected_trial_inventory)
        if any(part is None for part in plan_parts) and not all(part is None for part in plan_parts):
            raise ValueError("trial plan digest and expected inventory must appear together")
        if self.expected_trial_inventory is None:
            if self.planned_cached_trials:
                raise ValueError("planned cached trials require a bound trial plan")
        else:
            SecurityEvidenceTrialPlan.model_validate(
                {
                    "expected_trials": self.expected_trial_inventory,
                    "cached_trials": self.planned_cached_trials,
                    "plan_digest": self.trial_plan_digest,
                }
            )

        if self.observed_trials != tuple(sorted(self.observed_trials, key=lambda item: item.sort_key)):
            raise ValueError("observed_trials must be canonically sorted")
        observed_ids = [trial.attack_result_id for trial in self.observed_trials]
        if len(observed_ids) != len(set(observed_ids)):
            raise ValueError("observed trial attack_result_id values must be unique")
        for trial in self.observed_trials:
            expected_cached = (
                trial.origin_scenario_result_id is not None
                and trial.origin_scenario_result_id != self.scenario_result_id
            )
            if trial.cached is not expected_cached:
                raise ValueError("observed trial cached flag does not match its origin run")
        for trial in self.planned_cached_trials:
            if trial.origin_scenario_result_id == self.scenario_result_id:
                raise ValueError("a planned cached trial cannot originate from the current run")

        observed_by_id = {trial.attack_result_id: trial for trial in self.observed_trials}
        planned_by_id = {trial.attack_result_id: trial for trial in self.planned_cached_trials}
        for attack_result_id in observed_by_id.keys() & planned_by_id.keys():
            observed = observed_by_id[attack_result_id]
            planned = planned_by_id[attack_result_id]
            if (
                observed.identity != planned.identity
                or observed.origin_scenario_result_id != planned.origin_scenario_result_id
                or observed.observed_at != planned.observed_at
                or not observed.cached
            ):
                raise ValueError("observed cached trial does not match its immutable plan record")

        actual_current_count = sum(
            trial.origin_scenario_result_id == self.scenario_result_id for trial in self.observed_trials
        )
        actual_missing_count = sum(trial.origin_scenario_result_id is None for trial in self.observed_trials)
        reused_ids = {trial.attack_result_id for trial in self.observed_trials if trial.cached} | set(planned_by_id)
        omitted_ids = set(planned_by_id) - set(observed_by_id)
        if self.current_run_trial_count != actual_current_count:
            raise ValueError("current_run_trial_count does not match observed trial origins")
        if self.missing_provenance_trial_count != actual_missing_count:
            raise ValueError("missing_provenance_trial_count does not match observed trials")
        if self.reused_trial_count != len(reused_ids):
            raise ValueError("reused_trial_count does not match cached trial provenance")
        if self.omitted_reused_trial_count != len(omitted_ids):
            raise ValueError("omitted_reused_trial_count does not match the persisted cache plan")

        actual_origins = {
            trial.origin_scenario_result_id
            for trial in self.observed_trials
            if trial.origin_scenario_result_id is not None
        } | {trial.origin_scenario_result_id for trial in self.planned_cached_trials}
        if origin_ids != tuple(sorted(actual_origins)):
            raise ValueError("origin_scenario_result_ids does not match trial provenance")
        all_trial_times = [trial.observed_at for trial in self.observed_trials] + [
            trial.observed_at for trial in self.planned_cached_trials
        ]
        actual_oldest = min(all_trial_times) if all_trial_times else None
        if self.oldest_trial_at != actual_oldest:
            raise ValueError("oldest_trial_at does not match the complete trial provenance")

        observed_count = (
            self.current_run_trial_count
            + self.reused_trial_count
            - self.omitted_reused_trial_count
            + self.missing_provenance_trial_count
        )
        if observed_count != len(self.observed_trials):
            raise ValueError("trial provenance counts do not match observed_trials")
        if not self.observed_trials and not self.planned_cached_trials:
            if self.oldest_trial_at is not None or origin_ids:
                raise ValueError("a run without trials cannot carry trial provenance")
            return self
        if self.oldest_trial_at is None:
            raise ValueError("a run with trials must include oldest_trial_at")
        if self.completed_at is not None and self.oldest_trial_at > self.completed_at:
            raise ValueError("oldest_trial_at must not follow completed_at")
        if (
            self.reused_trial_count == 0
            and self.missing_provenance_trial_count == 0
            and self.oldest_trial_at < self.created_at
        ):
            raise ValueError("current-run trials must not predate run creation")
        return self

    @property
    def current_inventory_is_exact(self) -> bool:
        """Whether current-run trials exactly partition the bound plan."""
        if self.expected_trial_inventory is None:
            return False
        expected = Counter(trial.sort_key for trial in self.expected_trial_inventory)
        current = Counter(
            trial.identity.sort_key
            for trial in self.observed_trials
            if trial.origin_scenario_result_id == self.scenario_result_id
        )
        return current == expected


class EvidenceComponentIdentity(_StrictEvidenceModel):
    """Allowlisted component identity without parameters, endpoints, or secrets."""

    class_name: str = Field(..., min_length=1)
    content_hash: str = Field(..., pattern=_SHA256_PATTERN)
    eval_hash: str = Field(..., pattern=_SHA256_PATTERN)


class SecurityEvidenceConfiguration(_StrictEvidenceModel):
    """Resolved behavioral configuration and its deterministic benchmark key."""

    scenario: EvidenceComponentIdentity
    target: EvidenceComponentIdentity | None = None
    scorer: EvidenceComponentIdentity | None = None
    scenario_version: int = Field(..., ge=0)
    pyrit_version: str = Field(..., min_length=1)
    techniques: tuple[str, ...] = Field(default_factory=tuple)
    datasets: tuple[str, ...] = Field(default_factory=tuple)
    objective_hashes: tuple[str, ...] = Field(default_factory=tuple)
    benchmark_fingerprint: str = Field(..., pattern=_SHA256_PATTERN)

    @field_validator("techniques", "datasets")
    @classmethod
    def _require_sorted_unique_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item for item in value):
            raise ValueError("configuration names must not be empty")
        if value != tuple(sorted(set(value))):
            raise ValueError("configuration names must be sorted and unique")
        return value

    @field_validator("objective_hashes")
    @classmethod
    def _require_sorted_unique_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("objective_hashes must be sorted and unique")
        for item in value:
            if len(item) != 64 or any(char not in "0123456789abcdef" for char in item):
                raise ValueError("objective_hashes must contain lowercase SHA-256 values")
        return value

    @model_validator(mode="after")
    def _validate_benchmark_fingerprint(self) -> SecurityEvidenceConfiguration:
        payload = {
            "schema": "pyrit.security-evidence/benchmark/v1",
            "scenario": self.scenario.model_dump(mode="json"),
            "target": None if self.target is None else self.target.model_dump(mode="json"),
            "scorer": None if self.scorer is None else self.scorer.model_dump(mode="json"),
            "scenario_version": self.scenario_version,
            "pyrit_version": self.pyrit_version,
            "techniques": list(self.techniques),
            "datasets": list(self.datasets),
            "objective_hashes": list(self.objective_hashes),
        }
        if not hmac.compare_digest(self.benchmark_fingerprint, _canonical_sha256(payload)):
            raise ValueError("benchmark_fingerprint does not match configuration facts")
        return self


class EvidenceLatencySummary(_StrictEvidenceModel):
    """Deterministic latency facts derived from attack-result execution times."""

    samples: int = Field(..., ge=0)
    total_ms: int | None = Field(default=None, ge=0)
    mean_ms: float | None = Field(default=None, ge=0)
    p95_ms: int | None = Field(default=None, ge=0)
    max_ms: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_empty_shape(self) -> EvidenceLatencySummary:
        values = (self.total_ms, self.mean_ms, self.p95_ms, self.max_ms)
        if self.samples == 0 and any(value is not None for value in values):
            raise ValueError("latency values must be null when samples is zero")
        if self.samples > 0 and any(value is None for value in values):
            raise ValueError("latency values are required when samples is nonzero")
        if self.mean_ms is not None and not math.isfinite(self.mean_ms):
            raise ValueError("mean_ms must be finite")
        if self.samples > 0:
            assert self.total_ms is not None
            assert self.mean_ms is not None
            assert self.p95_ms is not None
            assert self.max_ms is not None
            if self.mean_ms > self.max_ms or self.p95_ms > self.max_ms:
                raise ValueError("latency mean and p95 must not exceed max")
            if not math.isclose(
                self.mean_ms * self.samples,
                self.total_ms,
                rel_tol=1e-9,
                abs_tol=1e-6,
            ):
                raise ValueError("latency mean is inconsistent with samples and total_ms")
        return self


class EvidenceMetricSummary(_StrictEvidenceModel):
    """Outcome counts and rates for a scenario or display group."""

    trials: int = Field(..., ge=0)
    determinate_trials: int = Field(..., ge=0)
    successes: int = Field(..., ge=0)
    failures: int = Field(..., ge=0)
    errors: int = Field(..., ge=0)
    undetermined: int = Field(..., ge=0)
    attack_success_rate: float | None = Field(default=None, ge=0, le=1)
    error_rate: float | None = Field(default=None, ge=0, le=1)
    undetermined_rate: float | None = Field(default=None, ge=0, le=1)
    latency: EvidenceLatencySummary

    @model_validator(mode="after")
    def _validate_derived_facts(self) -> EvidenceMetricSummary:
        if self.trials != self.successes + self.failures + self.errors + self.undetermined:
            raise ValueError("trials must equal the sum of every outcome count")
        if self.determinate_trials != self.successes + self.failures:
            raise ValueError("determinate_trials must equal successes plus failures")
        if self.latency.samples != self.trials:
            raise ValueError("latency samples must equal trials")

        expected_asr = self.successes / self.determinate_trials if self.determinate_trials else None
        expected_error_rate = self.errors / self.trials if self.trials else None
        expected_undetermined_rate = self.undetermined / self.trials if self.trials else None
        for name, actual, expected in (
            ("attack_success_rate", self.attack_success_rate, expected_asr),
            ("error_rate", self.error_rate, expected_error_rate),
            ("undetermined_rate", self.undetermined_rate, expected_undetermined_rate),
        ):
            if actual is None and expected is None:
                continue
            if actual is None or expected is None or not math.isclose(actual, expected, rel_tol=0, abs_tol=1e-12):
                raise ValueError(f"{name} does not match the outcome counts")
        return self


class EvidenceGroupSummary(_StrictEvidenceModel):
    """Observed display-group coverage and metrics."""

    name: str = Field(..., min_length=1)
    atomic_attack_names: tuple[str, ...] = Field(default_factory=tuple)
    metrics: EvidenceMetricSummary

    @field_validator("atomic_attack_names")
    @classmethod
    def _require_sorted_unique_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item for item in value):
            raise ValueError("atomic_attack_names must not contain empty values")
        if value != tuple(sorted(set(value))):
            raise ValueError("atomic_attack_names must be sorted and unique")
        return value


class SecurityEvidenceMetrics(_StrictEvidenceModel):
    """Overall campaign metrics and deterministic per-group summaries."""

    overall: EvidenceMetricSummary
    groups: tuple[EvidenceGroupSummary, ...] = Field(default_factory=tuple)

    @field_validator("groups")
    @classmethod
    def _require_sorted_unique_groups(cls, value: tuple[EvidenceGroupSummary, ...]) -> tuple[EvidenceGroupSummary, ...]:
        names = [group.name for group in value]
        if names != sorted(set(names)):
            raise ValueError("groups must be sorted by unique name")
        atomic_names = [name for group in value for name in group.atomic_attack_names]
        if len(atomic_names) != len(set(atomic_names)):
            raise ValueError("atomic attack names must belong to only one group")
        return value

    @model_validator(mode="after")
    def _validate_group_partition(self) -> SecurityEvidenceMetrics:
        if not self.groups:
            if self.overall.trials:
                raise ValueError("overall trials require at least one group")
            return self
        if any(group.metrics.trials and not group.atomic_attack_names for group in self.groups):
            raise ValueError("a group with trials must identify its atomic attacks")
        for field_name in (
            "trials",
            "determinate_trials",
            "successes",
            "failures",
            "errors",
            "undetermined",
        ):
            grouped = sum(getattr(group.metrics, field_name) for group in self.groups)
            if grouped != getattr(self.overall, field_name):
                raise ValueError(f"group {field_name} does not sum to overall metrics")
        grouped_latency_total = sum(group.metrics.latency.total_ms or 0 for group in self.groups)
        if grouped_latency_total != (self.overall.latency.total_ms or 0):
            raise ValueError("group latency total does not sum to overall metrics")
        return self


class EvidenceMoney(_StrictEvidenceModel):
    """An exact non-negative decimal currency amount."""

    currency: Literal["USD"] = "USD"
    amount: str

    @field_validator("amount")
    @classmethod
    def _validate_decimal_amount(cls, value: str) -> str:
        from decimal import Decimal, InvalidOperation

        try:
            amount = Decimal(value)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("amount must be a decimal string") from exc
        if not amount.is_finite() or amount < 0:
            raise ValueError("amount must be finite and non-negative")
        return value


class SecurityEvidenceUsage(_StrictEvidenceModel):
    """Provider-reported usage with explicit availability and coverage."""

    scope: Literal["linked_conversations"] = "linked_conversations"
    conversation_count: int = Field(..., ge=0)
    observed_response_count: int = Field(..., ge=0)
    calls_with_token_usage: int = Field(..., ge=0)
    calls_with_cost: int = Field(..., ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    cached_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    cost: EvidenceMoney | None = None
    token_coverage: EvidenceCoverage
    cost_coverage: EvidenceCoverage

    @model_validator(mode="after")
    def _validate_coverage(self) -> SecurityEvidenceUsage:
        if self.calls_with_token_usage > self.observed_response_count:
            raise ValueError("calls_with_token_usage cannot exceed observed responses")
        if self.calls_with_cost > self.observed_response_count:
            raise ValueError("calls_with_cost cannot exceed observed responses")

        core_token_values = (
            self.input_tokens,
            self.output_tokens,
            self.total_tokens,
        )
        token_values = (*core_token_values, self.reasoning_tokens, self.cached_tokens)
        if self.calls_with_token_usage == 0:
            if any(value is not None for value in token_values):
                raise ValueError("token totals require at least one usage-bearing call")
            if self.token_coverage is not EvidenceCoverage.UNAVAILABLE:
                raise ValueError("zero token records require unavailable token coverage")
        else:
            if self.token_coverage is EvidenceCoverage.UNAVAILABLE:
                raise ValueError("usage-bearing calls cannot have unavailable token coverage")
            if not any(value is not None for value in core_token_values):
                raise ValueError("token coverage requires an input, output, or total token fact")
            if self.token_coverage is EvidenceCoverage.COMPLETE:
                if self.calls_with_token_usage != self.observed_response_count:
                    raise ValueError("complete token coverage must cover every observed response")
                if any(value is None for value in core_token_values):
                    raise ValueError("complete token coverage requires input, output, and total tokens")
            elif self.calls_with_token_usage == self.observed_response_count and all(
                value is not None for value in core_token_values
            ):
                raise ValueError("fully reported core token usage requires complete coverage")
            if (
                self.input_tokens is not None
                and self.output_tokens is not None
                and self.total_tokens is not None
                and self.total_tokens != self.input_tokens + self.output_tokens
            ):
                raise ValueError("total_tokens must equal input_tokens plus output_tokens")
        if self.calls_with_cost == 0:
            if self.cost is not None:
                raise ValueError("cost requires at least one priced call")
            if self.cost_coverage is not EvidenceCoverage.UNAVAILABLE:
                raise ValueError("zero cost records require unavailable cost coverage")
        else:
            if self.cost is None:
                raise ValueError("priced calls require an aggregate cost")
            if self.cost_coverage is EvidenceCoverage.UNAVAILABLE:
                raise ValueError("priced calls cannot have unavailable cost coverage")
            if self.cost_coverage is EvidenceCoverage.COMPLETE and self.calls_with_cost != self.observed_response_count:
                raise ValueError("complete cost coverage must cover every observed response")
            if self.cost_coverage is EvidenceCoverage.PARTIAL and self.calls_with_cost == self.observed_response_count:
                raise ValueError("partial cost coverage must omit at least one observed response")
        return self


class SecurityEvidenceCompleteness(_StrictEvidenceModel):
    """Fail-closed availability facts independent of organization policy."""

    status: EvidenceCompletenessStatus
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    terminal: bool
    has_trials: bool

    @field_validator("reasons")
    @classmethod
    def _require_sorted_unique_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("completeness reasons must be sorted and unique")
        return value


class SecurityEvidenceBaseline(_StrictEvidenceModel):
    """Factual comparison against an explicitly supplied prior run."""

    scenario_result_id: str = Field(..., min_length=1)
    generated_at: AwareDatetime
    state: ScenarioRunState
    pyrit_version: str = Field(..., min_length=1)
    benchmark_fingerprint: str = Field(..., pattern=_SHA256_PATTERN)
    compatible: bool
    incompatibility_reasons: tuple[BaselineIncompatibilityReason, ...] = Field(default_factory=tuple)
    metrics: EvidenceMetricSummary
    delta_attack_success_rate: float | None = Field(default=None, ge=-1, le=1)
    delta_error_rate: float | None = Field(default=None, ge=-1, le=1)
    delta_undetermined_rate: float | None = Field(default=None, ge=-1, le=1)
    baseline_digest: str = Field(..., pattern=_SHA256_PATTERN)

    @field_validator("generated_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if offset is not None and offset.total_seconds() != 0:
            raise ValueError("baseline timestamps must be UTC")
        return value

    @field_validator("incompatibility_reasons")
    @classmethod
    def _require_sorted_unique_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("baseline reasons must be sorted and unique")
        return value

    @model_validator(mode="after")
    def _validate_compatibility_shape(self) -> SecurityEvidenceBaseline:
        deltas = (
            self.delta_attack_success_rate,
            self.delta_error_rate,
            self.delta_undetermined_rate,
        )
        if self.compatible and self.incompatibility_reasons:
            raise ValueError("compatible baselines cannot have incompatibility reasons")
        if not self.compatible:
            if not self.incompatibility_reasons:
                raise ValueError("incompatible baselines require at least one reason")
            if any(delta is not None for delta in deltas):
                raise ValueError("incompatible baselines cannot have metric deltas")
        if not hmac.compare_digest(self.baseline_digest, self.computed_digest):
            raise ValueError("baseline_digest does not match the canonical baseline facts")
        return self

    @property
    def computed_digest(self) -> str:
        """Canonical digest of the persisted producer facts used as a baseline."""
        facts = self.model_dump(
            mode="json",
            include={
                "scenario_result_id",
                "generated_at",
                "state",
                "pyrit_version",
                "benchmark_fingerprint",
                "metrics",
            },
        )
        return _canonical_sha256({"schema": SECURITY_EVIDENCE_BASELINE_SCHEMA, **facts})


class SecurityEvidence(_StrictEvidenceModel):
    """Complete ``pyrit.security-evidence/v1`` producer envelope."""

    schema_name: Literal["pyrit.security-evidence/v1"] = Field(
        default=SECURITY_EVIDENCE_SCHEMA,
        alias="schema",
    )
    generated_at: AwareDatetime
    subject: SecurityEvidenceSubject | None = None
    run: SecurityEvidenceRun
    configuration: SecurityEvidenceConfiguration
    metrics: SecurityEvidenceMetrics
    usage: SecurityEvidenceUsage
    baseline: SecurityEvidenceBaseline | None = None
    completeness: SecurityEvidenceCompleteness
    evidence_digest: str = Field(..., pattern=_SHA256_PATTERN)

    @field_validator("generated_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if offset is not None and offset.total_seconds() != 0:
            raise ValueError("evidence timestamps must be UTC")
        return value

    @property
    def computed_digest(self) -> str:
        """Canonical digest of every fact except ``evidence_digest``."""
        return _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_digest"}))

    @model_validator(mode="after")
    def _validate_envelope(self) -> SecurityEvidence:
        expected_generated_at = self.run.oldest_trial_at or self.run.completed_at or self.run.created_at
        if self.generated_at != expected_generated_at:
            raise ValueError("generated_at must match the oldest included trial or run lifecycle timestamp")
        if self.configuration.pyrit_version != self.run.pyrit_version:
            raise ValueError("configuration.pyrit_version must match run.pyrit_version")
        if self.baseline is not None:
            baseline = self.baseline
            expected_incompatibility_reasons: set[BaselineIncompatibilityReason] = set()
            if baseline.state is not ScenarioRunState.COMPLETED:
                expected_incompatibility_reasons.add("baseline.run_not_completed")
            if baseline.metrics.trials == 0:
                expected_incompatibility_reasons.add("baseline.no_trials")
            if self.configuration.target is None:
                expected_incompatibility_reasons.add("baseline.target_missing")
            if baseline.pyrit_version != self.configuration.pyrit_version:
                expected_incompatibility_reasons.add("baseline.pyrit_version_mismatch")
            if baseline.benchmark_fingerprint != self.configuration.benchmark_fingerprint:
                expected_incompatibility_reasons.add("baseline.benchmark_fingerprint_mismatch")
            expected_reasons = tuple(sorted(expected_incompatibility_reasons))
            if baseline.incompatibility_reasons != expected_reasons:
                raise ValueError(
                    "baseline incompatibility reasons do not match persisted lifecycle and configuration facts"
                )
            derived_compatible = not expected_reasons
            if baseline.compatible is not derived_compatible:
                raise ValueError("baseline compatible flag does not match persisted lifecycle and configuration facts")
            if baseline.compatible:
                self._validate_delta(
                    "delta_attack_success_rate",
                    self.metrics.overall.attack_success_rate,
                    baseline.metrics.attack_success_rate,
                    baseline.delta_attack_success_rate,
                )
                self._validate_delta(
                    "delta_error_rate",
                    self.metrics.overall.error_rate,
                    baseline.metrics.error_rate,
                    baseline.delta_error_rate,
                )
                self._validate_delta(
                    "delta_undetermined_rate",
                    self.metrics.overall.undetermined_rate,
                    baseline.metrics.undetermined_rate,
                    baseline.delta_undetermined_rate,
                )
        terminal = self.run.state in {
            ScenarioRunState.COMPLETED,
            ScenarioRunState.FAILED,
            ScenarioRunState.CANCELLED,
        }
        has_trials = self.metrics.overall.trials > 0
        provenance_trials = (
            self.run.current_run_trial_count
            + self.run.reused_trial_count
            - self.run.omitted_reused_trial_count
            + self.run.missing_provenance_trial_count
        )
        if provenance_trials != self.metrics.overall.trials:
            raise ValueError("run trial provenance counts must equal metrics.overall.trials")
        if len(self.run.observed_trials) != self.metrics.overall.trials:
            raise ValueError("observed_trials must exactly account for metrics.overall.trials")
        observed_by_atomic = Counter(trial.identity.atomic_attack_name for trial in self.run.observed_trials)
        observed_display_groups: dict[str, set[str]] = {}
        for trial in self.run.observed_trials:
            observed_display_groups.setdefault(trial.identity.atomic_attack_name, set()).add(
                trial.identity.display_group
            )
        if any(len(groups) != 1 for groups in observed_display_groups.values()):
            raise ValueError("observed trials assign an atomic attack to multiple display groups")
        exported_group_by_atomic = {
            atomic_attack_name: group.name
            for group in self.metrics.groups
            for atomic_attack_name in group.atomic_attack_names
        }
        if set(exported_group_by_atomic) != set(observed_by_atomic):
            raise ValueError("group atomic attacks must exactly match observed trial identities")
        for atomic_attack_name, display_groups in observed_display_groups.items():
            if exported_group_by_atomic[atomic_attack_name] != next(iter(display_groups)):
                raise ValueError("group names must match observed trial display-group identities")
        for group in self.metrics.groups:
            observed_group_trials = [
                trial
                for trial in self.run.observed_trials
                if trial.identity.atomic_attack_name in group.atomic_attack_names
            ]
            if group.metrics.trials != len(observed_group_trials):
                raise ValueError("group trial counts must match observed trial identities")
            expected_outcomes = Counter(trial.outcome for trial in observed_group_trials)
            expected_counts = {
                "determinate_trials": expected_outcomes[AttackOutcome.SUCCESS]
                + expected_outcomes[AttackOutcome.FAILURE],
                "successes": expected_outcomes[AttackOutcome.SUCCESS],
                "failures": expected_outcomes[AttackOutcome.FAILURE],
                "errors": expected_outcomes[AttackOutcome.ERROR],
                "undetermined": expected_outcomes[AttackOutcome.UNDETERMINED],
            }
            for field_name, expected in expected_counts.items():
                if getattr(group.metrics, field_name) != expected:
                    raise ValueError("group outcome counts must match observed trial identities")
            latencies = sorted(trial.execution_time_ms for trial in observed_group_trials)
            expected_total: int | None
            expected_mean: float | None
            if latencies:
                expected_total = sum(latencies)
                expected_mean = expected_total / len(latencies)
            else:
                expected_total = None
                expected_mean = None
            expected_p95 = latencies[max(0, math.ceil(0.95 * len(latencies)) - 1)] if latencies else None
            expected_max = latencies[-1] if latencies else None
            latency = group.metrics.latency
            if (
                latency.samples != len(latencies)
                or latency.total_ms != expected_total
                or latency.p95_ms != expected_p95
                or latency.max_ms != expected_max
                or (
                    expected_mean is not None
                    and (
                        latency.mean_ms is None
                        or not math.isclose(
                            latency.mean_ms,
                            expected_mean,
                            rel_tol=1e-12,
                            abs_tol=1e-12,
                        )
                    )
                )
                or (expected_mean is None and latency.mean_ms is not None)
            ):
                raise ValueError("group latency metrics must match observed trial execution times")
        all_latencies = sorted(trial.execution_time_ms for trial in self.run.observed_trials)
        expected_overall_total: int | None
        expected_overall_mean: float | None
        if all_latencies:
            expected_overall_total = sum(all_latencies)
            expected_overall_mean = expected_overall_total / len(all_latencies)
        else:
            expected_overall_total = None
            expected_overall_mean = None
        expected_overall_p95 = (
            all_latencies[max(0, math.ceil(0.95 * len(all_latencies)) - 1)] if all_latencies else None
        )
        expected_overall_max = all_latencies[-1] if all_latencies else None
        overall_latency = self.metrics.overall.latency
        if (
            overall_latency.samples != len(all_latencies)
            or overall_latency.total_ms != expected_overall_total
            or overall_latency.p95_ms != expected_overall_p95
            or overall_latency.max_ms != expected_overall_max
            or (
                expected_overall_mean is not None
                and (
                    overall_latency.mean_ms is None
                    or not math.isclose(
                        overall_latency.mean_ms,
                        expected_overall_mean,
                        rel_tol=1e-12,
                        abs_tol=1e-12,
                    )
                )
            )
            or (expected_overall_mean is None and overall_latency.mean_ms is not None)
        ):
            raise ValueError("overall latency metrics must match observed trial execution times")
        if self.run.expected_trial_inventory is not None:
            expected_objective_hashes = tuple(
                sorted({trial.objective_sha256 for trial in self.run.expected_trial_inventory})
            )
            if self.configuration.objective_hashes != expected_objective_hashes:
                raise ValueError("configuration objective hashes must match the bound trial inventory")
        if self.completeness.terminal is not terminal:
            raise ValueError("completeness.terminal does not match run state")
        if self.completeness.has_trials is not has_trials:
            raise ValueError("completeness.has_trials does not match metrics")

        reasons: set[str] = set()
        if self.run.state is not ScenarioRunState.COMPLETED:
            reasons.add("run.not_completed")
        if not has_trials:
            reasons.add("run.no_trials")
        if self.configuration.target is None:
            reasons.add("configuration.target_missing")
        if self.subject is None:
            reasons.add("subject.unbound")
        if self.run.expected_trial_inventory is None:
            reasons.add("run.trial_inventory_unbound")
        elif not self.run.current_inventory_is_exact:
            reasons.add("run.trial_inventory_mismatch")
        if self.run.reused_trial_count:
            reasons.add("run.reused_trials")
        if self.run.missing_provenance_trial_count:
            reasons.add("run.trial_provenance_missing")
        if self.usage.token_coverage is EvidenceCoverage.UNAVAILABLE:
            reasons.add("usage.unavailable")
        elif self.usage.token_coverage is EvidenceCoverage.PARTIAL:
            reasons.add("usage.partial")
        if self.usage.cost_coverage is EvidenceCoverage.UNAVAILABLE:
            reasons.add("cost.unavailable")
        elif self.usage.cost_coverage is EvidenceCoverage.PARTIAL:
            reasons.add("cost.partial")
        if self.completeness.reasons != tuple(sorted(reasons)):
            raise ValueError("completeness reasons do not match exported facts")

        expected_status = (
            EvidenceCompletenessStatus.UNAVAILABLE
            if not terminal
            else EvidenceCompletenessStatus.COMPLETE
            if (
                self.run.state is ScenarioRunState.COMPLETED
                and has_trials
                and self.configuration.target is not None
                and self.subject is not None
                and self.run.expected_trial_inventory is not None
                and self.run.current_inventory_is_exact
                and self.run.reused_trial_count == 0
                and self.run.missing_provenance_trial_count == 0
            )
            else EvidenceCompletenessStatus.INCOMPLETE
        )
        if self.completeness.status is not expected_status:
            raise ValueError("completeness.status does not match exported facts")
        if not hmac.compare_digest(self.evidence_digest, self.computed_digest):
            raise ValueError("evidence_digest does not match the canonical evidence facts")
        return self

    @staticmethod
    def _validate_delta(
        label: str,
        current: float | None,
        baseline: float | None,
        delta: float | None,
    ) -> None:
        expected = current - baseline if current is not None and baseline is not None else None
        if delta is None or expected is None:
            if delta is not expected:
                raise ValueError(f"{label} availability is inconsistent with compared rates")
        elif not math.isclose(delta, expected, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError(f"{label} is inconsistent with compared rates")

    def is_exportable(self) -> bool:
        """Return whether this evidence has complete, gateable attack outcomes."""
        return self.completeness.status is EvidenceCompletenessStatus.COMPLETE


__all__ = [
    "EvidenceCachedTrial",
    "EvidenceComponentIdentity",
    "EvidenceCompletenessStatus",
    "EvidenceCoverage",
    "EvidenceGroupSummary",
    "EvidenceLatencySummary",
    "EvidenceMetricSummary",
    "EvidenceMoney",
    "EvidenceObservedTrial",
    "EvidenceTrialIdentity",
    "SECURITY_EVIDENCE_BASELINE_SCHEMA",
    "SECURITY_EVIDENCE_SCHEMA",
    "SECURITY_EVIDENCE_TRIAL_PLAN_SCHEMA",
    "SecurityEvidence",
    "SecurityEvidenceBaseline",
    "SecurityEvidenceCompleteness",
    "SecurityEvidenceConfiguration",
    "SecurityEvidenceMetrics",
    "SecurityEvidenceRun",
    "SecurityEvidenceSubject",
    "SecurityEvidenceTrialPlan",
    "SecurityEvidenceUsage",
]
