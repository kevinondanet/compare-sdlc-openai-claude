# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Strict release-policy and release-verdict contracts."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- Pydantic resolves this annotation at runtime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from agent_sre.sdlc.canonical import digest_without

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, StringConstraints(min_length=1, max_length=256, strip_whitespace=True)]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{7,64}$")]
Money = Annotated[Decimal, Field(ge=Decimal("0"), max_digits=30, decimal_places=12)]
Rate = Annotated[float, Field(ge=0.0, le=1.0)]


class StrictContractModel(BaseModel):
    """Base class shared by versioned external release contracts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        allow_inf_nan=False,
    )

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Serialize external contracts by their wire aliases on every Pydantic 2.x release."""

        kwargs.setdefault("by_alias", True)
        return super().model_dump(*args, **kwargs)

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        """Serialize JSON using wire aliases on every Pydantic 2.x release."""

        kwargs.setdefault("by_alias", True)
        return super().model_dump_json(*args, **kwargs)


def _require_sorted_unique(values: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{info.field_name} must be sorted and contain no duplicates")
    return values


def _require_utc(value: datetime, info: ValidationInfo) -> datetime:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise ValueError(f"{info.field_name} must include a UTC offset")
    if offset.total_seconds() != 0:
        raise ValueError(f"{info.field_name} must be UTC")
    return value


class EvidenceSubject(StrictContractModel):
    """Immutable release subject binding carried by policy and evidence."""

    application: Identifier
    change: Identifier
    commit_sha: CommitSha


class ReleaseRequirements(StrictContractModel):
    """Coverage and accounting requirements for security evidence."""

    allowed_benchmark_fingerprints: Annotated[tuple[Sha256, ...], Field(min_length=1)]
    required_scenarios: tuple[Identifier, ...]
    required_groups: tuple[Identifier, ...]
    minimum_trials: Annotated[int, Field(ge=1)]
    minimum_trials_per_group: Annotated[int, Field(ge=1)]
    require_usage_complete: bool
    require_cost_complete: bool

    _sorted_benchmark_fingerprints = field_validator("allowed_benchmark_fingerprints")(
        _require_sorted_unique
    )
    _sorted_scenarios = field_validator("required_scenarios")(_require_sorted_unique)
    _sorted_groups = field_validator("required_groups")(_require_sorted_unique)


class ReleaseThresholds(StrictContractModel):
    """Maximum permitted security, cost, and latency measurements."""

    max_attack_success_rate: Rate
    max_undetermined_rate: Rate
    max_error_rate: Rate
    max_cost_usd: Money
    max_p95_latency_ms: Annotated[float, Field(ge=0.0)]


class EvidenceFreshnessPolicy(StrictContractModel):
    """Time bounds applied at release evaluation."""

    max_age_seconds: Annotated[int, Field(ge=0)]
    max_future_skew_seconds: Annotated[int, Field(ge=0)]


class BaselinePolicy(StrictContractModel):
    """Compatibility and absolute regression limits for a baseline run."""

    required: bool
    require_compatible: bool
    allowed_evidence_digests: tuple[Sha256, ...]
    max_age_seconds: Annotated[int, Field(ge=0)]
    max_attack_success_rate_increase: Rate
    max_error_rate_increase: Rate
    max_undetermined_rate_increase: Rate

    _sorted_evidence_digests = field_validator("allowed_evidence_digests")(_require_sorted_unique)

    @model_validator(mode="after")
    def validate_required_pins(self) -> BaselinePolicy:
        if self.required and not self.allowed_evidence_digests:
            raise ValueError("required baseline policy must pin at least one evidence digest")
        return self


class ReleasePolicy(StrictContractModel):
    """Canonical ``agt.release-policy/v1`` policy document."""

    schema_: Literal["agt.release-policy/v1"] = Field(alias="schema")
    policy_id: Identifier
    policy_version: Identifier
    subject: EvidenceSubject
    requirements: ReleaseRequirements
    thresholds: ReleaseThresholds
    freshness: EvidenceFreshnessPolicy
    baseline: BaselinePolicy
    policy_digest: Sha256

    @model_validator(mode="after")
    def validate_digest(self) -> ReleasePolicy:
        expected = digest_without(self, "policy_digest")
        if self.policy_digest != expected:
            raise ValueError(
                f"policy_digest mismatch: expected {expected}, got {self.policy_digest}"
            )
        return self


class VerdictStatus(StrEnum):
    """Fail-closed release outcome."""

    PASS = "pass"
    FAIL = "fail"


class ReasonCode(StrEnum):
    """Stable machine-readable failure reasons for release automation."""

    APPLICATION_MISMATCH = "binding.application_mismatch"
    CHANGE_MISMATCH = "binding.change_mismatch"
    COMMIT_MISMATCH = "binding.commit_mismatch"
    SUBJECT_MISSING = "binding.subject_missing"
    BENCHMARK_NOT_ALLOWED = "configuration.benchmark_not_allowed"
    CONFIGURATION_TARGET_MISSING = "configuration.target_missing"
    BASELINE_ASR_DELTA_UNAVAILABLE = "baseline.attack_success_delta_unavailable"
    BASELINE_ASR_REGRESSION = "baseline.attack_success_regression"
    BASELINE_ERROR_DELTA_UNAVAILABLE = "baseline.error_delta_unavailable"
    BASELINE_ERROR_REGRESSION = "baseline.error_regression"
    BASELINE_FROM_FUTURE = "baseline.from_future"
    BASELINE_INCOMPATIBLE = "baseline.incompatible"
    BASELINE_NOT_ALLOWED = "baseline.not_allowed"
    BASELINE_REQUIRED = "baseline.required"
    BASELINE_STALE = "baseline.stale"
    BASELINE_UNDETERMINED_DELTA_UNAVAILABLE = "baseline.undetermined_delta_unavailable"
    BASELINE_UNDETERMINED_REGRESSION = "baseline.undetermined_regression"
    COST_EXCEEDED = "cost.exceeded"
    COST_INCOMPLETE = "cost.incomplete"
    COST_UNAVAILABLE = "cost.unavailable"
    EVIDENCE_FROM_FUTURE = "evidence.from_future"
    EVIDENCE_INCOMPLETE = "evidence.incomplete"
    EVIDENCE_NO_TRIALS = "evidence.no_trials"
    EVIDENCE_NOT_TERMINAL = "evidence.not_terminal"
    EVIDENCE_STALE = "evidence.stale"
    MISSING_REQUIRED_GROUP = "requirements.group_missing"
    MISSING_REQUIRED_SCENARIO = "requirements.scenario_missing"
    INSUFFICIENT_GROUP_TRIALS = "requirements.group_trials_insufficient"
    INSUFFICIENT_TRIALS = "requirements.trials_insufficient"
    RUN_NOT_COMPLETED = "run.not_completed"
    ASR_EXCEEDED = "threshold.attack_success_rate_exceeded"
    ASR_UNAVAILABLE = "threshold.attack_success_rate_unavailable"
    ERROR_RATE_EXCEEDED = "threshold.error_rate_exceeded"
    ERROR_RATE_UNAVAILABLE = "threshold.error_rate_unavailable"
    LATENCY_EXCEEDED = "threshold.p95_latency_exceeded"
    LATENCY_UNAVAILABLE = "threshold.p95_latency_unavailable"
    UNDETERMINED_RATE_EXCEEDED = "threshold.undetermined_rate_exceeded"
    UNDETERMINED_RATE_UNAVAILABLE = "threshold.undetermined_rate_unavailable"
    USAGE_INCOMPLETE = "usage.incomplete"


class ReleaseCheck(StrictContractModel):
    """One deterministic policy check included in a verdict."""

    code: ReasonCode
    passed: bool
    actual: str | None
    expected: str | None


class ReleaseVerdict(StrictContractModel):
    """Canonical ``agt.release-verdict/v1`` evaluation result."""

    schema_: Literal["agt.release-verdict/v1"] = Field(alias="schema")
    status: VerdictStatus
    policy_id: Identifier
    policy_version: Identifier
    policy_digest: Sha256
    evidence_digest: Sha256
    subject: EvidenceSubject | None
    evaluated_at: datetime
    checks: tuple[ReleaseCheck, ...]
    reason_codes: tuple[ReasonCode, ...]
    verdict_digest: Sha256

    _utc_evaluated_at = field_validator("evaluated_at")(_require_utc)

    @model_validator(mode="after")
    def validate_invariants(self) -> ReleaseVerdict:
        check_codes = tuple(check.code.value for check in self.checks)
        if check_codes != tuple(sorted(set(check_codes))):
            raise ValueError("checks must be sorted by code and contain no duplicates")

        reasons = tuple(reason.value for reason in self.reason_codes)
        if reasons != tuple(sorted(set(reasons))):
            raise ValueError("reason_codes must be sorted and contain no duplicates")

        failed = tuple(check.code.value for check in self.checks if not check.passed)
        if reasons != failed:
            raise ValueError("reason_codes must exactly match failed checks")
        expected_status = VerdictStatus.PASS if not reasons else VerdictStatus.FAIL
        if self.status is not expected_status:
            raise ValueError("status does not match failed checks")

        expected_digest = digest_without(self, "verdict_digest")
        if self.verdict_digest != expected_digest:
            raise ValueError(
                f"verdict_digest mismatch: expected {expected_digest}, got {self.verdict_digest}"
            )
        return self


def validate_contract_json(model: type[StrictContractModel], payload: Any) -> StrictContractModel:
    """Validate an already duplicate-checked JSON value with JSON strictness."""

    from agent_sre.sdlc.canonical import canonical_json_bytes

    return model.model_validate_json(canonical_json_bytes(payload), strict=True)
