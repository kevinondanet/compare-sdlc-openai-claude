# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Defensive adapter for ``pyrit.security-evidence/v1`` documents."""

from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime  # noqa: TC003 -- Pydantic resolves this annotation at runtime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path  # noqa: TC003 -- public loader annotation
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from agent_sre.sdlc.canonical import (
    canonical_sha256,
    digest_without,
    load_json_file_strict,
    load_json_strict,
)
from agent_sre.sdlc.models import (
    EvidenceSubject,
    Identifier,
    Rate,
    Sha256,
    StrictContractModel,
    _require_sorted_unique,
    _require_utc,
    validate_contract_json,
)


class PyRITRunState(StrEnum):
    """Persisted PyRIT scenario lifecycle state."""

    CREATED = "CREATED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Coverage(StrEnum):
    """How completely a usage fact was observed."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class CompletenessStatus(StrEnum):
    """Factual completeness of the security run itself."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class PyRITAttackOutcome(StrEnum):
    """Outcome carried by one observed PyRIT trial."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    UNDETERMINED = "undetermined"


BaselineIncompatibilityReason = Literal[
    "baseline.benchmark_fingerprint_mismatch",
    "baseline.no_trials",
    "baseline.pyrit_version_mismatch",
    "baseline.run_not_completed",
    "baseline.target_missing",
]


class TrialIdentity(StrictContractModel):
    """Privacy-safe identity of one planned atomic-attack objective."""

    atomic_attack_name: Identifier
    display_group: Identifier
    objective_sha256: Sha256

    @property
    def sort_key(self) -> tuple[str, str, str]:
        """Canonical trial inventory ordering key."""

        return (
            self.atomic_attack_name,
            self.display_group,
            self.objective_sha256,
        )


class CachedTrial(StrictContractModel):
    """Immutable provenance for a prior-run trial selected by caching."""

    identity: TrialIdentity
    attack_result_id: Identifier
    origin_scenario_result_id: Identifier
    observed_at: datetime
    cached: Literal[True]

    _utc_observed = field_validator("observed_at")(_require_utc)

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        """Canonical cached-trial ordering key."""

        return (*self.identity.sort_key, self.attack_result_id)


class ObservedTrial(StrictContractModel):
    """Privacy-safe provenance and measurements for one exported trial."""

    identity: TrialIdentity
    attack_result_id: Identifier
    origin_scenario_result_id: Identifier | None
    observed_at: datetime
    cached: bool
    outcome: PyRITAttackOutcome
    execution_time_ms: Annotated[int, Field(ge=0)]

    _utc_observed = field_validator("observed_at")(_require_utc)

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        """Canonical observed-trial ordering key."""

        return (*self.identity.sort_key, self.attack_result_id)


class PyRITRun(StrictContractModel):
    """Identity and lifecycle of the exported scenario result."""

    scenario_result_id: Identifier
    state: PyRITRunState
    created_at: datetime
    completed_at: datetime | None
    number_tries: Annotated[int, Field(ge=0)]
    pyrit_version: Identifier
    trial_plan_digest: Sha256 | None
    expected_trial_inventory: tuple[TrialIdentity, ...] | None
    planned_cached_trials: tuple[CachedTrial, ...]
    observed_trials: tuple[ObservedTrial, ...]
    oldest_trial_at: datetime | None
    current_run_trial_count: Annotated[int, Field(ge=0)]
    reused_trial_count: Annotated[int, Field(ge=0)]
    omitted_reused_trial_count: Annotated[int, Field(ge=0)]
    missing_provenance_trial_count: Annotated[int, Field(ge=0)]
    origin_scenario_result_ids: tuple[Identifier, ...]

    _utc_created = field_validator("created_at")(_require_utc)
    _utc_completed = field_validator("completed_at")(
        lambda value, info: value if value is None else _require_utc(value, info)
    )
    _utc_oldest = field_validator("oldest_trial_at")(
        lambda value, info: value if value is None else _require_utc(value, info)
    )
    _sorted_origins = field_validator("origin_scenario_result_ids")(_require_sorted_unique)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> PyRITRun:
        terminal = self.state in {
            PyRITRunState.COMPLETED,
            PyRITRunState.FAILED,
            PyRITRunState.CANCELLED,
        }
        if not terminal and self.completed_at is not None:
            raise ValueError("non-terminal run must not include completed_at")
        if terminal and self.completed_at is None:
            raise ValueError("terminal run must include completed_at")
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValueError("completed_at must not precede created_at")

        plan_parts = (self.trial_plan_digest, self.expected_trial_inventory)
        if any(part is None for part in plan_parts) and not all(
            part is None for part in plan_parts
        ):
            raise ValueError("trial plan digest and expected inventory must appear together")
        if self.expected_trial_inventory is None:
            if self.planned_cached_trials:
                raise ValueError("planned cached trials require a bound trial plan")
        else:
            expected = tuple(
                sorted(self.expected_trial_inventory, key=lambda trial: trial.sort_key)
            )
            if self.expected_trial_inventory != expected:
                raise ValueError("expected_trial_inventory must be canonically sorted")
            expected_keys = tuple(trial.sort_key for trial in expected)
            if len(expected_keys) != len(set(expected_keys)):
                raise ValueError("expected_trial_inventory must be unique")
            display_groups_by_atomic: dict[str, set[str]] = {}
            for expected_trial in expected:
                display_groups_by_atomic.setdefault(expected_trial.atomic_attack_name, set()).add(
                    expected_trial.display_group
                )
            if any(len(groups) != 1 for groups in display_groups_by_atomic.values()):
                raise ValueError("each atomic attack must belong to exactly one display group")

            planned = tuple(sorted(self.planned_cached_trials, key=lambda trial: trial.sort_key))
            if self.planned_cached_trials != planned:
                raise ValueError("planned_cached_trials must be canonically sorted")
            planned_ids = tuple(trial.attack_result_id for trial in planned)
            if len(planned_ids) != len(set(planned_ids)):
                raise ValueError("planned cached trial attack_result_id values must be unique")
            expected_identity_keys = set(expected_keys)
            if any(
                planned_trial.identity.sort_key not in expected_identity_keys
                for planned_trial in planned
            ):
                raise ValueError("planned cached trials must belong to the expected inventory")
            plan_payload = {
                "schema": "pyrit.security-evidence/trial-plan/v1",
                "expected_trials": [
                    expected_trial.model_dump(mode="json") for expected_trial in expected
                ],
                "cached_trials": [
                    planned_trial.model_dump(mode="json") for planned_trial in planned
                ],
            }
            expected_plan_digest = canonical_sha256(plan_payload)
            if self.trial_plan_digest != expected_plan_digest:
                raise ValueError("trial_plan_digest does not match the canonical trial plan")

        observed = tuple(sorted(self.observed_trials, key=lambda trial: trial.sort_key))
        if self.observed_trials != observed:
            raise ValueError("observed_trials must be canonically sorted")
        observed_ids = tuple(trial.attack_result_id for trial in observed)
        if len(observed_ids) != len(set(observed_ids)):
            raise ValueError("observed trial attack_result_id values must be unique")
        for observed_trial in observed:
            expected_cached = (
                observed_trial.origin_scenario_result_id is not None
                and observed_trial.origin_scenario_result_id != self.scenario_result_id
            )
            if observed_trial.cached is not expected_cached:
                raise ValueError("observed trial cached flag does not match its origin run")
        for cached_trial in self.planned_cached_trials:
            if cached_trial.origin_scenario_result_id == self.scenario_result_id:
                raise ValueError("a planned cached trial cannot originate from the current run")

        observed_by_id = {trial.attack_result_id: trial for trial in observed}
        planned_by_id = {trial.attack_result_id: trial for trial in self.planned_cached_trials}
        for attack_result_id in observed_by_id.keys() & planned_by_id.keys():
            observed_trial = observed_by_id[attack_result_id]
            planned_trial = planned_by_id[attack_result_id]
            if (
                observed_trial.identity != planned_trial.identity
                or observed_trial.origin_scenario_result_id
                != planned_trial.origin_scenario_result_id
                or observed_trial.observed_at != planned_trial.observed_at
                or not observed_trial.cached
            ):
                raise ValueError("observed cached trial does not match its immutable plan record")

        current_count = sum(
            trial.origin_scenario_result_id == self.scenario_result_id for trial in observed
        )
        missing_count = sum(trial.origin_scenario_result_id is None for trial in observed)
        reused_ids = {trial.attack_result_id for trial in observed if trial.cached} | set(
            planned_by_id
        )
        omitted_ids = set(planned_by_id) - set(observed_by_id)
        if self.current_run_trial_count != current_count:
            raise ValueError("current_run_trial_count does not match observed trial origins")
        if self.missing_provenance_trial_count != missing_count:
            raise ValueError("missing_provenance_trial_count does not match observed trials")
        if self.reused_trial_count != len(reused_ids):
            raise ValueError("reused_trial_count does not match cached trial provenance")
        if self.omitted_reused_trial_count != len(omitted_ids):
            raise ValueError("omitted_reused_trial_count does not match the persisted cache plan")

        actual_origins = {
            trial.origin_scenario_result_id
            for trial in observed
            if trial.origin_scenario_result_id is not None
        } | {trial.origin_scenario_result_id for trial in self.planned_cached_trials}
        if self.origin_scenario_result_ids != tuple(sorted(actual_origins)):
            raise ValueError("origin_scenario_result_ids does not match trial provenance")
        trial_times = [trial.observed_at for trial in observed] + [
            trial.observed_at for trial in self.planned_cached_trials
        ]
        actual_oldest = min(trial_times) if trial_times else None
        if self.oldest_trial_at != actual_oldest:
            raise ValueError("oldest_trial_at does not match the complete trial provenance")
        provenance_count = (
            self.current_run_trial_count
            + self.reused_trial_count
            - self.omitted_reused_trial_count
            + self.missing_provenance_trial_count
        )
        if provenance_count != len(observed):
            raise ValueError("trial provenance counts do not match observed_trials")
        if not observed and not self.planned_cached_trials:
            if self.oldest_trial_at is not None or self.origin_scenario_result_ids:
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


class ConfigurationIdentity(StrictContractModel):
    """Privacy-safe identity of one PyRIT component configuration."""

    class_name: Identifier
    content_hash: Sha256
    eval_hash: Sha256


class PyRITConfiguration(StrictContractModel):
    """Configuration used to derive the compatibility fingerprint."""

    pyrit_version: Identifier
    scenario: ConfigurationIdentity
    target: ConfigurationIdentity | None
    scorer: ConfigurationIdentity | None
    scenario_version: Annotated[int, Field(ge=0)]
    techniques: tuple[Identifier, ...]
    datasets: tuple[Identifier, ...]
    objective_hashes: tuple[Sha256, ...]
    benchmark_fingerprint: Sha256

    _sorted_techniques = field_validator("techniques")(_require_sorted_unique)
    _sorted_datasets = field_validator("datasets")(_require_sorted_unique)
    _sorted_objectives = field_validator("objective_hashes")(_require_sorted_unique)


class LatencySummary(StrictContractModel):
    """Aggregate wall-clock trial latency."""

    samples: Annotated[int, Field(ge=0)]
    total_ms: Annotated[int, Field(ge=0)] | None
    mean_ms: Annotated[float, Field(ge=0.0)] | None
    p95_ms: Annotated[int, Field(ge=0)] | None
    max_ms: Annotated[int, Field(ge=0)] | None

    @model_validator(mode="after")
    def validate_latency(self) -> LatencySummary:
        aggregates = (self.mean_ms, self.p95_ms, self.max_ms)
        if self.samples == 0:
            if self.total_ms is not None or any(value is not None for value in aggregates):
                raise ValueError("empty latency summary must contain null latency values")
            return self
        if self.total_ms is None or any(value is None for value in aggregates):
            raise ValueError("latency aggregates are required when samples are present")
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


class MetricSummary(StrictContractModel):
    """Counts and rates for all trials in a scope."""

    trials: Annotated[int, Field(ge=0)]
    determinate_trials: Annotated[int, Field(ge=0)]
    successes: Annotated[int, Field(ge=0)]
    failures: Annotated[int, Field(ge=0)]
    errors: Annotated[int, Field(ge=0)]
    undetermined: Annotated[int, Field(ge=0)]
    attack_success_rate: Rate | None
    error_rate: Rate | None
    undetermined_rate: Rate | None
    latency: LatencySummary

    @model_validator(mode="after")
    def validate_counts_and_rates(self) -> MetricSummary:
        if self.determinate_trials != self.successes + self.failures:
            raise ValueError("determinate_trials must equal successes plus failures")
        if self.trials != self.determinate_trials + self.errors + self.undetermined:
            raise ValueError("trials must equal determinate, error, and undetermined outcomes")
        if self.latency.samples != self.trials:
            raise ValueError("latency samples must equal trial count")

        expected_asr = self.successes / self.determinate_trials if self.determinate_trials else None
        expected_error = self.errors / self.trials if self.trials else None
        expected_undetermined = self.undetermined / self.trials if self.trials else None
        for label, actual, expected in (
            ("attack_success_rate", self.attack_success_rate, expected_asr),
            ("error_rate", self.error_rate, expected_error),
            ("undetermined_rate", self.undetermined_rate, expected_undetermined),
        ):
            if actual is None or expected is None:
                if actual is not expected:
                    raise ValueError(f"{label} availability is inconsistent with its denominator")
            elif not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12):
                raise ValueError(f"{label} is inconsistent with outcome counts")
        return self


class GroupSummary(StrictContractModel):
    """Metrics for one named scenario group."""

    name: Identifier
    atomic_attack_names: tuple[Identifier, ...]
    metrics: MetricSummary

    _sorted_attacks = field_validator("atomic_attack_names")(_require_sorted_unique)


class PyRITMetrics(StrictContractModel):
    """Overall and grouped security measurements."""

    overall: MetricSummary
    groups: tuple[GroupSummary, ...]

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, value: tuple[GroupSummary, ...]) -> tuple[GroupSummary, ...]:
        names = tuple(group.name for group in value)
        if names != tuple(sorted(set(names))):
            raise ValueError("groups must be sorted by name and contain no duplicates")
        atomic_names = [name for group in value for name in group.atomic_attack_names]
        if len(atomic_names) != len(set(atomic_names)):
            raise ValueError("atomic attack names must belong to only one group")
        return value

    @model_validator(mode="after")
    def validate_group_totals(self) -> PyRITMetrics:
        if not self.groups:
            if self.overall.trials:
                raise ValueError("overall trials require at least one group")
            return self
        if any(group.metrics.trials and not group.atomic_attack_names for group in self.groups):
            raise ValueError("a group with trials must identify its atomic attacks")
        count_fields = (
            "trials",
            "determinate_trials",
            "successes",
            "failures",
            "errors",
            "undetermined",
        )
        for field_name in count_fields:
            grouped = sum(getattr(group.metrics, field_name) for group in self.groups)
            if grouped != getattr(self.overall, field_name):
                raise ValueError(f"group {field_name} does not sum to overall metrics")
        grouped_samples = sum(group.metrics.latency.samples for group in self.groups)
        if grouped_samples != self.overall.latency.samples:
            raise ValueError("group latency samples do not sum to overall metrics")
        grouped_total = sum(group.metrics.latency.total_ms or 0 for group in self.groups)
        if grouped_total != (self.overall.latency.total_ms or 0):
            raise ValueError("group latency total does not sum to overall metrics")
        return self


class CostAmount(StrictContractModel):
    """Exact monetary amount reported by the producer."""

    currency: Literal["USD"]
    amount: Annotated[str, Field(min_length=1, max_length=256)]

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, value: str) -> str:
        try:
            amount = Decimal(value)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("cost amount must be a decimal string") from exc
        if not amount.is_finite() or amount < 0:
            raise ValueError("cost amount must be finite and non-negative")
        return value

    @property
    def decimal_amount(self) -> Decimal:
        """Return the exact value for policy comparison without changing wire form."""

        return Decimal(self.amount)


class UsageSummary(StrictContractModel):
    """Privacy-safe aggregate model usage for linked conversations."""

    scope: Literal["linked_conversations"]
    conversation_count: Annotated[int, Field(ge=0)]
    observed_response_count: Annotated[int, Field(ge=0)]
    calls_with_token_usage: Annotated[int, Field(ge=0)]
    calls_with_cost: Annotated[int, Field(ge=0)]
    input_tokens: Annotated[int, Field(ge=0)] | None
    output_tokens: Annotated[int, Field(ge=0)] | None
    reasoning_tokens: Annotated[int, Field(ge=0)] | None
    cached_tokens: Annotated[int, Field(ge=0)] | None
    total_tokens: Annotated[int, Field(ge=0)] | None
    cost: CostAmount | None
    token_coverage: Coverage
    cost_coverage: Coverage

    @model_validator(mode="after")
    def validate_coverage(self) -> UsageSummary:
        if self.calls_with_token_usage > self.observed_response_count:
            raise ValueError("calls_with_token_usage exceeds observed_response_count")
        if self.calls_with_cost > self.observed_response_count:
            raise ValueError("calls_with_cost exceeds observed_response_count")

        token_values = (
            self.input_tokens,
            self.output_tokens,
            self.reasoning_tokens,
            self.cached_tokens,
            self.total_tokens,
        )
        if self.token_coverage is Coverage.UNAVAILABLE:
            if self.calls_with_token_usage != 0 or any(value is not None for value in token_values):
                raise ValueError("unavailable token coverage must not report token usage")
        else:
            if self.calls_with_token_usage == 0:
                raise ValueError(
                    "available token coverage requires at least one usage-bearing call"
                )
            if not any(value is not None for value in token_values):
                raise ValueError("available token coverage requires at least one token fact")
            if (
                self.input_tokens is not None
                and self.output_tokens is not None
                and self.total_tokens is not None
                and self.total_tokens != self.input_tokens + self.output_tokens
            ):
                raise ValueError("total_tokens must equal input_tokens plus output_tokens")
            if self.token_coverage is Coverage.COMPLETE and (
                self.calls_with_token_usage != self.observed_response_count
                or self.input_tokens is None
                or self.output_tokens is None
                or self.total_tokens is None
            ):
                raise ValueError(
                    "complete token coverage requires core totals for every observed response"
                )
            if (
                self.token_coverage is Coverage.PARTIAL
                and self.calls_with_token_usage == self.observed_response_count
                and self.input_tokens is not None
                and self.output_tokens is not None
                and self.total_tokens is not None
            ):
                raise ValueError("fully reported core token usage requires complete coverage")

        if self.cost_coverage is Coverage.UNAVAILABLE:
            if self.calls_with_cost != 0 or self.cost is not None:
                raise ValueError("unavailable cost coverage must not report cost")
        else:
            if self.calls_with_cost == 0 or self.cost is None:
                raise ValueError("available cost coverage requires observed cost")
            if (
                self.cost_coverage is Coverage.COMPLETE
                and self.calls_with_cost != self.observed_response_count
            ):
                raise ValueError("complete cost coverage must cover every observed response")
            if (
                self.cost_coverage is Coverage.PARTIAL
                and self.calls_with_cost == self.observed_response_count
            ):
                raise ValueError("partial cost coverage must omit an observed response")
        return self


class BaselineSummary(StrictContractModel):
    """Producer comparison with a configuration-compatible prior run."""

    scenario_result_id: Identifier
    generated_at: datetime
    state: PyRITRunState
    pyrit_version: Identifier
    benchmark_fingerprint: Sha256
    compatible: bool
    incompatibility_reasons: tuple[BaselineIncompatibilityReason, ...]
    metrics: MetricSummary
    delta_attack_success_rate: float | None
    delta_error_rate: float | None
    delta_undetermined_rate: float | None
    baseline_digest: Sha256

    _sorted_reasons = field_validator("incompatibility_reasons")(_require_sorted_unique)
    _utc_generated = field_validator("generated_at")(_require_utc)

    @model_validator(mode="after")
    def validate_compatibility_shape(self) -> BaselineSummary:
        deltas = (
            self.delta_attack_success_rate,
            self.delta_error_rate,
            self.delta_undetermined_rate,
        )
        if self.compatible and self.incompatibility_reasons:
            raise ValueError("compatible baseline must not include incompatibility reasons")
        if not self.compatible:
            if not self.incompatibility_reasons:
                raise ValueError("incompatible baseline must explain why it is incompatible")
            if any(delta is not None for delta in deltas):
                raise ValueError("incompatible baseline must not report regression deltas")

        serialized = self.model_dump(mode="json")
        digest_payload = {
            "schema": "pyrit.security-evidence/baseline/v1",
            "scenario_result_id": serialized["scenario_result_id"],
            "generated_at": serialized["generated_at"],
            "state": serialized["state"],
            "pyrit_version": serialized["pyrit_version"],
            "benchmark_fingerprint": serialized["benchmark_fingerprint"],
            "metrics": serialized["metrics"],
        }
        expected_digest = canonical_sha256(digest_payload)
        if self.baseline_digest != expected_digest:
            raise ValueError(
                f"baseline_digest mismatch: expected {expected_digest}, got {self.baseline_digest}"
            )
        return self


class EvidenceCompleteness(StrictContractModel):
    """Factual producer completeness with stable reason codes."""

    status: CompletenessStatus
    reasons: tuple[Identifier, ...]
    terminal: bool
    has_trials: bool

    _sorted_reasons = field_validator("reasons")(_require_sorted_unique)


class PyRITSecurityEvidence(StrictContractModel):
    """Strict privacy-safe PyRIT security evidence envelope."""

    schema_: Literal["pyrit.security-evidence/v1"] = Field(alias="schema")
    generated_at: datetime
    subject: EvidenceSubject | None
    run: PyRITRun
    configuration: PyRITConfiguration
    metrics: PyRITMetrics
    usage: UsageSummary
    baseline: BaselineSummary | None
    completeness: EvidenceCompleteness
    evidence_digest: Sha256

    _utc_generated = field_validator("generated_at")(_require_utc)

    @model_validator(mode="after")
    def validate_envelope(self) -> PyRITSecurityEvidence:
        if self.run.pyrit_version != self.configuration.pyrit_version:
            raise ValueError("run and configuration pyrit_version must match")

        terminal = self.run.state in {
            PyRITRunState.COMPLETED,
            PyRITRunState.FAILED,
            PyRITRunState.CANCELLED,
        }
        if self.completeness.terminal != terminal:
            raise ValueError("completeness.terminal does not match run state")
        has_trials = self.metrics.overall.trials > 0
        if self.completeness.has_trials != has_trials:
            raise ValueError("completeness.has_trials does not match overall metrics")

        expected_generated = (
            self.run.oldest_trial_at or self.run.completed_at or self.run.created_at
        )
        if self.generated_at != expected_generated:
            raise ValueError(
                "generated_at must match the oldest included trial or run lifecycle timestamp"
            )

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

        observed_by_atomic = Counter(
            trial.identity.atomic_attack_name for trial in self.run.observed_trials
        )
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
                "determinate_trials": expected_outcomes[PyRITAttackOutcome.SUCCESS]
                + expected_outcomes[PyRITAttackOutcome.FAILURE],
                "successes": expected_outcomes[PyRITAttackOutcome.SUCCESS],
                "failures": expected_outcomes[PyRITAttackOutcome.FAILURE],
                "errors": expected_outcomes[PyRITAttackOutcome.ERROR],
                "undetermined": expected_outcomes[PyRITAttackOutcome.UNDETERMINED],
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
            expected_p95 = (
                latencies[max(0, math.ceil(0.95 * len(latencies)) - 1)] if latencies else None
            )
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
            all_latencies[max(0, math.ceil(0.95 * len(all_latencies)) - 1)]
            if all_latencies
            else None
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
                raise ValueError(
                    "configuration objective hashes must match the bound trial inventory"
                )

        expected_reasons: set[str] = set()
        if self.run.state is not PyRITRunState.COMPLETED:
            expected_reasons.add("run.not_completed")
        if not has_trials:
            expected_reasons.add("run.no_trials")
        if self.configuration.target is None:
            expected_reasons.add("configuration.target_missing")
        if self.subject is None:
            expected_reasons.add("subject.unbound")
        if self.run.expected_trial_inventory is None:
            expected_reasons.add("run.trial_inventory_unbound")
        elif not self.run.current_inventory_is_exact:
            expected_reasons.add("run.trial_inventory_mismatch")
        if self.run.reused_trial_count:
            expected_reasons.add("run.reused_trials")
        if self.run.missing_provenance_trial_count:
            expected_reasons.add("run.trial_provenance_missing")
        if self.usage.token_coverage is Coverage.UNAVAILABLE:
            expected_reasons.add("usage.unavailable")
        elif self.usage.token_coverage is Coverage.PARTIAL:
            expected_reasons.add("usage.partial")
        if self.usage.cost_coverage is Coverage.UNAVAILABLE:
            expected_reasons.add("cost.unavailable")
        elif self.usage.cost_coverage is Coverage.PARTIAL:
            expected_reasons.add("cost.partial")
        if tuple(sorted(expected_reasons)) != self.completeness.reasons:
            raise ValueError("completeness reasons do not match the exported facts")

        run_complete = (
            self.run.state is PyRITRunState.COMPLETED
            and has_trials
            and self.configuration.target is not None
            and self.subject is not None
            and self.run.expected_trial_inventory is not None
            and self.run.current_inventory_is_exact
            and self.run.reused_trial_count == 0
            and self.run.missing_provenance_trial_count == 0
        )
        expected_status = (
            CompletenessStatus.UNAVAILABLE
            if not terminal
            else CompletenessStatus.COMPLETE
            if run_complete
            else CompletenessStatus.INCOMPLETE
        )
        if self.completeness.status is not expected_status:
            raise ValueError("completeness.status does not match run outcome facts")

        if self.baseline is not None:
            baseline = self.baseline
            expected_incompatibility_reasons: set[BaselineIncompatibilityReason] = set()
            if baseline.state is not PyRITRunState.COMPLETED:
                expected_incompatibility_reasons.add("baseline.run_not_completed")
            if baseline.metrics.trials == 0:
                expected_incompatibility_reasons.add("baseline.no_trials")
            if self.configuration.target is None:
                expected_incompatibility_reasons.add("baseline.target_missing")
            if baseline.pyrit_version != self.configuration.pyrit_version:
                expected_incompatibility_reasons.add("baseline.pyrit_version_mismatch")
            if baseline.benchmark_fingerprint != self.configuration.benchmark_fingerprint:
                expected_incompatibility_reasons.add("baseline.benchmark_fingerprint_mismatch")
            expected_baseline_reasons = tuple(sorted(expected_incompatibility_reasons))
            if baseline.incompatibility_reasons != expected_baseline_reasons:
                raise ValueError(
                    "baseline incompatibility reasons do not match persisted "
                    "lifecycle and configuration facts"
                )
            derived_compatible = not expected_baseline_reasons
            if baseline.compatible is not derived_compatible:
                raise ValueError(
                    "baseline compatible flag does not match persisted lifecycle and "
                    "configuration facts"
                )
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

        fingerprint_payload = {
            "schema": "pyrit.security-evidence/benchmark/v1",
            "pyrit_version": self.configuration.pyrit_version,
            "scenario": self.configuration.scenario.model_dump(mode="json"),
            "target": (
                None
                if self.configuration.target is None
                else self.configuration.target.model_dump(mode="json")
            ),
            "scorer": (
                None
                if self.configuration.scorer is None
                else self.configuration.scorer.model_dump(mode="json")
            ),
            "scenario_version": self.configuration.scenario_version,
            "techniques": list(self.configuration.techniques),
            "datasets": list(self.configuration.datasets),
            "objective_hashes": list(self.configuration.objective_hashes),
        }
        expected_fingerprint = canonical_sha256(fingerprint_payload)
        if self.configuration.benchmark_fingerprint != expected_fingerprint:
            raise ValueError(
                "configuration.benchmark_fingerprint does not match configuration facts"
            )

        expected_digest = digest_without(self, "evidence_digest")
        if self.evidence_digest != expected_digest:
            raise ValueError(
                f"evidence_digest mismatch: expected {expected_digest}, got {self.evidence_digest}"
            )
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


def parse_pyrit_security_evidence(data: str | bytes) -> PyRITSecurityEvidence:
    """Strictly parse and integrity-check a PyRIT evidence document."""

    payload = load_json_strict(data)
    if not isinstance(payload, dict):
        raise ValueError("security evidence must be a JSON object")
    usage = payload.get("usage")
    if isinstance(usage, dict):
        cost = usage.get("cost")
        if cost is not None and (
            not isinstance(cost, dict) or not isinstance(cost.get("amount"), str)
        ):
            raise ValueError("usage.cost.amount must be a decimal JSON string")
    result = validate_contract_json(PyRITSecurityEvidence, payload)
    assert isinstance(result, PyRITSecurityEvidence)
    return result


def load_pyrit_security_evidence(path: str | Path) -> PyRITSecurityEvidence:
    """Load a bounded evidence file through the defensive adapter."""

    payload = load_json_file_strict(path)
    if not isinstance(payload, dict):
        raise ValueError("security evidence must be a JSON object")
    return parse_pyrit_security_evidence(json.dumps(payload, ensure_ascii=False, allow_nan=False))
