# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Strict, source-bound adapter for native RAMPART JSON reports.

RAMPART's ``JsonFileReportSink`` emits raw ``TestRunReport`` JSON. This
module validates that upstream shape, recomputes its aggregates from the raw
results, and binds it to an immutable change subject. G4 therefore consumes
RAMPART outcomes rather than caller-written summary metrics.

The upstream report does not expose model cost. Cost is carried separately
as a source-digested external usage observation so G5 can fail closed without
pretending that a RAMPART safety count is a billing record.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime  # noqa: TC003 -- Pydantic resolves at runtime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path, PurePosixPath  # noqa: TC003 -- public loader annotation
from typing import Annotated, Any, Literal, Self

from pydantic import Field, JsonValue, field_validator, model_validator

from agent_sre.sdlc.canonical import (
    canonical_json_bytes,
    canonical_sha256,
    digest_without,
    load_json_file_strict,
    load_json_strict,
)
from agent_sre.sdlc.development_gates import (
    CommandEvidence,
    EvidenceKind,
    EvidenceStatus,
)
from agent_sre.sdlc.models import (
    Identifier,
    Money,
    Sha256,
    StrictContractModel,
    _require_utc,
    validate_contract_json,
)
from agent_sre.signing import ArtifactSigner

RAMPART_NATIVE_REPORT_SCHEMA_VERSION: Literal["rampart.test-run-report/v1"] = (
    "rampart.test-run-report/v1"
)
RAMPART_REPORT_SCHEMA_VERSION: Literal["agt.rampart-safety-report/v1"] = (
    "agt.rampart-safety-report/v1"
)
RAMPART_CAMPAIGN_SCHEMA_VERSION: Literal["agt.rampart-campaign/v1"] = "agt.rampart-campaign/v1"
RAMPART_RUN_ATTESTATION_SCHEMA_VERSION: Literal["agt.rampart-run-attestation/v1"] = (
    "agt.rampart-run-attestation/v1"
)


class RampartTrialOutcome(StrEnum):
    """Native RAMPART ``SafetyStatus`` values."""

    SAFE = "safe"
    POLICY_BYPASS = "unsafe"
    ERROR = "error"
    UNDETERMINED = "undetermined"


class RampartObservabilityLevel(StrEnum):
    """Native RAMPART agent-adapter observability declarations."""

    RESPONSE_ONLY = "response_only"
    TOOL_ONLY = "tool_only"
    TOOL_AND_SIDE_EFFECTS = "tool_and_side_effects"


_OBSERVABILITY_RANK = {
    RampartObservabilityLevel.RESPONSE_ONLY: 0,
    RampartObservabilityLevel.TOOL_ONLY: 1,
    RampartObservabilityLevel.TOOL_AND_SIDE_EFFECTS: 2,
}


class RampartDefinitionArtifact(StrictContractModel):
    """One policy-pinned test, evaluator, payload, driver, or adapter artifact."""

    path: Annotated[str, Field(min_length=1, max_length=2048)]
    sha256: Sha256

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("definition artifact paths must use POSIX separators")
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or value in {".", ".."} or ".." in candidate.parts:
            raise ValueError("definition artifact paths must be canonical relative paths")
        normalized = candidate.as_posix()
        if normalized != value or normalized.startswith("./"):
            raise ValueError("definition artifact paths must be canonical relative paths")
        return value


class RampartCampaignCase(StrictContractModel):
    """One exact native RAMPART execution and its protected definition files."""

    scenario_id: Identifier
    pytest_nodeid: Annotated[str, Field(min_length=1, max_length=4096)]
    rampart_result_index: Annotated[int, Field(ge=0)]
    definition_artifacts: Annotated[tuple[RampartDefinitionArtifact, ...], Field(min_length=1)]
    harm_category: Identifier
    strategy: Identifier
    required_observability_level: RampartObservabilityLevel

    @model_validator(mode="after")
    def validate_case(self) -> RampartCampaignCase:
        artifacts = tuple(artifact.path for artifact in self.definition_artifacts)
        if artifacts != tuple(sorted(set(artifacts))):
            raise ValueError("definition_artifacts must be sorted with unique canonical paths")
        source_path = self.pytest_nodeid.split("::", 1)[0]
        if source_path not in artifacts:
            raise ValueError("definition_artifacts must include the source path from pytest_nodeid")
        return self


class RampartCampaignInventory(StrictContractModel):
    """Canonical inventory that turns native RAMPART output into coverage evidence."""

    schema_version: Literal["agt.rampart-campaign/v1"] = RAMPART_CAMPAIGN_SCHEMA_VERSION
    campaign_id: Identifier
    campaign_version: Identifier
    rampart_version: Identifier
    cases: Annotated[tuple[RampartCampaignCase, ...], Field(min_length=1)]
    campaign_digest: Sha256

    @model_validator(mode="after")
    def validate_inventory(self) -> RampartCampaignInventory:
        scenario_ids = tuple(case.scenario_id for case in self.cases)
        if scenario_ids != tuple(sorted(set(scenario_ids))):
            raise ValueError("campaign cases must be sorted with unique scenario_id values")
        execution_keys = tuple(
            (case.pytest_nodeid, case.rampart_result_index) for case in self.cases
        )
        if len(set(execution_keys)) != len(execution_keys):
            raise ValueError("campaign cases must have unique native execution identities")
        expected = digest_without(self, "campaign_digest")
        if self.campaign_digest != expected:
            raise ValueError(
                "campaign_digest mismatch: " f"expected {expected}, got {self.campaign_digest}"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        campaign_id: str,
        campaign_version: str,
        rampart_version: str,
        cases: tuple[RampartCampaignCase, ...],
    ) -> RampartCampaignInventory:
        """Create a deterministically ordered, self-digested campaign inventory."""

        ordered = tuple(sorted(cases, key=lambda case: case.scenario_id))
        payload: dict[str, Any] = {
            "schema_version": RAMPART_CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "campaign_version": campaign_version,
            "rampart_version": rampart_version,
            "cases": ordered,
        }
        provisional = cls.model_construct(**payload, campaign_digest="0" * 64)
        payload["campaign_digest"] = digest_without(provisional, "campaign_digest")
        return cls.model_validate(payload)

    @property
    def dimensions(self) -> tuple[str, ...]:
        """Return the exact harm-category inventory covered by the campaign."""

        return tuple(sorted({case.harm_category for case in self.cases}))

    @property
    def cases_per_dimension(self) -> dict[str, int]:
        """Return deterministic expected-case counts by harm category."""

        return {
            dimension: sum(case.harm_category == dimension for case in self.cases)
            for dimension in self.dimensions
        }

    def verify_definition_artifacts(
        self,
        root: str | Path,
        *,
        max_artifact_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        """Recompute every policy-pinned definition hash inside a protected root."""

        root_path = Path(root).resolve(strict=True)
        if not root_path.is_dir():
            raise ValueError("campaign definition root must be a directory")
        expected = {
            artifact.path: artifact.sha256
            for case in self.cases
            for artifact in case.definition_artifacts
        }
        if any(
            artifact.sha256 != expected[artifact.path]
            for case in self.cases
            for artifact in case.definition_artifacts
        ):
            raise ValueError("campaign definition path has conflicting pinned digests")
        for relative_path, expected_digest in sorted(expected.items()):
            candidate = (root_path / relative_path).resolve(strict=True)
            if not candidate.is_relative_to(root_path) or not candidate.is_file():
                raise ValueError("campaign definition artifact escapes the protected root")
            if candidate.stat().st_size > max_artifact_bytes:
                raise ValueError("campaign definition artifact exceeds the size limit")
            actual_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if actual_digest != expected_digest:
                raise ValueError(f"campaign definition artifact digest mismatch: {relative_path}")


class RampartIssuerTrust(StrictContractModel):
    """Policy-pinned RAMPART producer identity and allowed execution contexts."""

    issuer_id: Identifier
    public_key: Sha256
    allowed_producers: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    allowed_environments: Annotated[tuple[Identifier, ...], Field(min_length=1)]

    @field_validator("allowed_producers", "allowed_environments")
    @classmethod
    def validate_ordered_sets(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError(f"{info.field_name} must be sorted and unique")
        return value


class RampartNativeToolCall(StrictContractModel):
    """One tool call retained in a native RAMPART turn."""

    name: Identifier
    arguments: dict[str, JsonValue]
    result: JsonValue = None


class RampartNativeSideEffect(StrictContractModel):
    """One side effect retained in a native RAMPART turn."""

    kind: Identifier
    details: dict[str, JsonValue]


class RampartNativeTurn(StrictContractModel):
    """Public turn projection emitted by ``JsonFileReportSink``."""

    turn_number: Annotated[int, Field(ge=0)]
    prompt: str
    response_text: str
    response_metadata: dict[str, JsonValue]
    tool_calls: tuple[RampartNativeToolCall, ...] = ()
    side_effects: tuple[RampartNativeSideEffect, ...] = ()
    eval_outcome: Literal["detected", "not_detected", "undetermined"] | None = None
    eval_confidence: Annotated[float, Field(ge=0, le=1)] | None = None
    eval_rationale: str | None = None
    eval_undetermined_operands: tuple[str, ...] = ()
    driver_reasoning: str | None = None


class RampartNativeResult(StrictContractModel):
    """One raw ``Result`` projection from a RAMPART JSON report."""

    safe: bool
    status: RampartTrialOutcome
    summary: str
    harm_category: Identifier | None
    strategy: str
    observability_level: RampartObservabilityLevel
    duration_seconds: Annotated[float, Field(ge=0)]
    metadata: dict[str, JsonValue]
    turns: tuple[RampartNativeTurn, ...]

    @model_validator(mode="after")
    def validate_safe_flag(self) -> RampartNativeResult:
        if self.safe != (self.status is RampartTrialOutcome.SAFE):
            raise ValueError("native result safe flag does not match status")
        turn_numbers = tuple(turn.turn_number for turn in self.turns)
        if turn_numbers != tuple(sorted(set(turn_numbers))):
            raise ValueError("native result turns must have unique increasing numbers")
        return self


class RampartNativePopulationSummary(StrictContractModel):
    """Native RAMPART population statistics, checked against raw results."""

    total_runs: Annotated[int, Field(ge=0)]
    safe_count: Annotated[int, Field(ge=0)]
    unsafe_count: Annotated[int, Field(ge=0)]
    undetermined_count: Annotated[int, Field(ge=0)]
    error_count: Annotated[int, Field(ge=0)]
    attack_success_rate: Annotated[float, Field(ge=0, le=1)]
    safety_pass_rate: Annotated[float, Field(ge=0, le=1)]


class RampartNativeReport(StrictContractModel):
    """Exact public JSON shape emitted by RAMPART's file report sink."""

    total_runs: Annotated[int, Field(ge=0)]
    passed: Annotated[int, Field(ge=0)]
    failed: Annotated[int, Field(ge=0)]
    undetermined: Annotated[int, Field(ge=0)]
    errors: Annotated[int, Field(ge=0)]
    duration_seconds: Annotated[float, Field(ge=0)]
    metadata: dict[str, JsonValue]
    population_summary: RampartNativePopulationSummary
    by_harm_category: dict[Identifier, tuple[RampartNativeResult, ...]]

    @model_validator(mode="after")
    def validate_native_aggregates(self) -> RampartNativeReport:
        results = tuple(
            result
            for category_results in self.by_harm_category.values()
            for result in category_results
        )
        safe = sum(result.status is RampartTrialOutcome.SAFE for result in results)
        unsafe = sum(result.status is RampartTrialOutcome.POLICY_BYPASS for result in results)
        undetermined = sum(result.status is RampartTrialOutcome.UNDETERMINED for result in results)
        errors = sum(result.status is RampartTrialOutcome.ERROR for result in results)
        expected_counts = (len(results), safe, unsafe, undetermined, errors)
        if (
            self.total_runs,
            self.passed,
            self.failed,
            self.undetermined,
            self.errors,
        ) != expected_counts:
            raise ValueError("native RAMPART counts do not match retained results")

        for category, category_results in self.by_harm_category.items():
            if not category_results:
                raise ValueError("native RAMPART harm-category buckets must not be empty")
            if any(
                (result.harm_category or "uncategorized") != category for result in category_results
            ):
                raise ValueError("native result is filed under the wrong harm category")

        diagnostic_total = len(results) - errors
        attack_success_rate = unsafe / diagnostic_total if diagnostic_total else 0.0
        safety_pass_rate = safe / diagnostic_total if diagnostic_total else 0.0
        expected_summary = RampartNativePopulationSummary(
            total_runs=len(results),
            safe_count=safe,
            unsafe_count=unsafe,
            undetermined_count=undetermined,
            error_count=errors,
            attack_success_rate=attack_success_rate,
            safety_pass_rate=safety_pass_rate,
        )
        if self.population_summary != expected_summary:
            raise ValueError("native population summary does not match retained results")

        incomplete = self.metadata.get("incomplete", False)
        reasons = self.metadata.get("incomplete_reasons", [])
        if not isinstance(incomplete, bool):
            raise ValueError("native incomplete metadata must be a boolean")
        if not isinstance(reasons, list) or any(
            not isinstance(reason, str) or not reason.strip() for reason in reasons
        ):
            raise ValueError("native incomplete_reasons must be non-empty strings")
        if incomplete != bool(reasons):
            raise ValueError("native incomplete metadata and reasons must agree")
        return self

    @property
    def incomplete(self) -> bool:
        """Whether RAMPART marked a worker/run transport incomplete."""

        return self.metadata.get("incomplete") is True

    @property
    def observability_gap_count(self) -> int:
        """Count evaluator operands that the native adapter could not observe."""

        return sum(
            len(turn.eval_undetermined_operands)
            for results in self.by_harm_category.values()
            for result in results
            for turn in result.turns
        )


class RampartSubject(StrictContractModel):
    """Canonical change and source binding for a RAMPART report."""

    application: Identifier
    repository: Identifier
    change_id: Identifier
    source_revision: Identifier
    change_digest: Sha256


class RampartUsage(StrictContractModel):
    """External usage observation for RAMPART model calls."""

    source: Literal["external_usage_ledger"] = "external_usage_ledger"
    source_digest: Sha256
    observed_calls: Annotated[int, Field(ge=0)]
    calls_with_cost: Annotated[int, Field(ge=0)]
    total_cost_usd: Money | None
    cost_complete: bool

    @model_validator(mode="after")
    def validate_cost_coverage(self) -> RampartUsage:
        if self.calls_with_cost > self.observed_calls:
            raise ValueError("calls_with_cost must not exceed observed_calls")
        complete = self.calls_with_cost == self.observed_calls and self.total_cost_usd is not None
        if self.cost_complete != complete:
            raise ValueError("cost_complete does not match observed RAMPART usage")
        if self.observed_calls == 0 and self.total_cost_usd not in {None, Decimal("0")}:
            raise ValueError("a run without model calls cannot report non-zero cost")
        return self


class RampartRunAttestation(StrictContractModel):
    """Trusted producer signature over one exact native RAMPART execution."""

    schema_version: Literal["agt.rampart-run-attestation/v1"] = (
        RAMPART_RUN_ATTESTATION_SCHEMA_VERSION
    )
    attestation_id: Identifier
    report_id: Identifier
    subject: RampartSubject
    run_id: Identifier
    started_at: datetime
    generated_at: datetime
    attested_at: datetime
    expires_at: datetime
    rampart_version: Identifier
    producer: Identifier
    environment: Identifier
    command: Identifier
    campaign_digest: Sha256
    native_report_digest: Sha256
    usage_digest: Sha256
    issuer_id: Identifier
    issuer_public_key: Sha256
    attestation_signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
    attestation_digest: Sha256

    _utc_started = field_validator("started_at")(_require_utc)
    _utc_generated = field_validator("generated_at")(_require_utc)
    _utc_attested = field_validator("attested_at")(_require_utc)
    _utc_expires = field_validator("expires_at")(_require_utc)

    @staticmethod
    def _signature_payload(
        *,
        attestation_id: str,
        report_id: str,
        subject: RampartSubject,
        run_id: str,
        started_at: datetime,
        generated_at: datetime,
        attested_at: datetime,
        expires_at: datetime,
        rampart_version: str,
        producer: str,
        environment: str,
        command: str,
        campaign_digest: str,
        native_report_digest: str,
        usage_digest: str,
        issuer_id: str,
        issuer_public_key: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": RAMPART_RUN_ATTESTATION_SCHEMA_VERSION,
                "attestation_id": attestation_id,
                "report_id": report_id,
                "subject": subject,
                "run_id": run_id,
                "started_at": started_at,
                "generated_at": generated_at,
                "attested_at": attested_at,
                "expires_at": expires_at,
                "rampart_version": rampart_version,
                "producer": producer,
                "environment": environment,
                "command": command,
                "campaign_digest": campaign_digest,
                "native_report_digest": native_report_digest,
                "usage_digest": usage_digest,
                "issuer_id": issuer_id,
                "issuer_public_key": issuer_public_key,
            }
        )

    def signature_payload(self) -> bytes:
        """Return the exact run claims authenticated by the trusted producer."""

        return self._signature_payload(
            attestation_id=self.attestation_id,
            report_id=self.report_id,
            subject=self.subject,
            run_id=self.run_id,
            started_at=self.started_at,
            generated_at=self.generated_at,
            attested_at=self.attested_at,
            expires_at=self.expires_at,
            rampart_version=self.rampart_version,
            producer=self.producer,
            environment=self.environment,
            command=self.command,
            campaign_digest=self.campaign_digest,
            native_report_digest=self.native_report_digest,
            usage_digest=self.usage_digest,
            issuer_id=self.issuer_id,
            issuer_public_key=self.issuer_public_key,
        )

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.generated_at < self.started_at:
            raise ValueError("generated_at must not precede started_at")
        if self.attested_at < self.generated_at:
            raise ValueError("attested_at must not precede generated_at")
        if self.expires_at <= self.attested_at:
            raise ValueError("expires_at must follow attested_at")
        try:
            valid_signature = ArtifactSigner.verify_payload(
                self.signature_payload(),
                bytes.fromhex(self.attestation_signature),
                bytes.fromhex(self.issuer_public_key),
            )
        except (ImportError, TypeError, ValueError):
            valid_signature = False
        if not valid_signature:
            raise ValueError("RAMPART run attestation signature is invalid")
        expected = digest_without(self, "attestation_digest")
        if not hmac.compare_digest(self.attestation_digest, expected):
            raise ValueError("attestation_digest does not match the signed run attestation")
        return self

    def verify_issuer(self, trusted_issuers: tuple[RampartIssuerTrust, ...]) -> bool:
        """Return whether policy trusts this issuer, key, producer, and environment."""

        return any(
            hmac.compare_digest(trust.issuer_id, self.issuer_id)
            and hmac.compare_digest(trust.public_key, self.issuer_public_key)
            and self.producer in trust.allowed_producers
            and self.environment in trust.allowed_environments
            for trust in trusted_issuers
        )

    @classmethod
    def create(
        cls,
        *,
        attestation_id: str,
        report_id: str,
        subject: RampartSubject,
        run_id: str,
        started_at: datetime,
        generated_at: datetime,
        attested_at: datetime,
        expires_at: datetime,
        rampart_version: str,
        producer: str,
        environment: str,
        command: str,
        campaign: RampartCampaignInventory,
        native_report: RampartNativeReport,
        usage: RampartUsage,
        issuer_id: str,
        signer: ArtifactSigner,
    ) -> RampartRunAttestation:
        """Sign immutable run identity after the protected producer finishes."""

        public_key = signer.public_key_bytes.hex()
        payload: dict[str, Any] = {
            "schema_version": RAMPART_RUN_ATTESTATION_SCHEMA_VERSION,
            "attestation_id": attestation_id,
            "report_id": report_id,
            "subject": subject,
            "run_id": run_id,
            "started_at": started_at,
            "generated_at": generated_at,
            "attested_at": attested_at,
            "expires_at": expires_at,
            "rampart_version": rampart_version,
            "producer": producer,
            "environment": environment,
            "command": command,
            "campaign_digest": campaign.campaign_digest,
            "native_report_digest": canonical_sha256(native_report),
            "usage_digest": canonical_sha256(usage),
            "issuer_id": issuer_id,
            "issuer_public_key": public_key,
        }
        payload["attestation_signature"] = signer.sign_payload(
            cls._signature_payload(
                attestation_id=attestation_id,
                report_id=report_id,
                subject=subject,
                run_id=run_id,
                started_at=started_at,
                generated_at=generated_at,
                attested_at=attested_at,
                expires_at=expires_at,
                rampart_version=rampart_version,
                producer=producer,
                environment=environment,
                command=command,
                campaign_digest=campaign.campaign_digest,
                native_report_digest=canonical_sha256(native_report),
                usage_digest=canonical_sha256(usage),
                issuer_id=issuer_id,
                issuer_public_key=public_key,
            )
        ).hex()
        provisional = cls.model_construct(**payload, attestation_digest="0" * 64)
        payload["attestation_digest"] = digest_without(provisional, "attestation_digest")
        return cls.model_validate(payload)


def _validate_campaign_results(
    native_report: RampartNativeReport,
    campaign: RampartCampaignInventory,
) -> None:
    """Require an exact match between policy inventory and native RAMPART identities."""

    expected = {(case.pytest_nodeid, case.rampart_result_index): case for case in campaign.cases}
    observed: dict[tuple[str, int], tuple[str, RampartNativeResult]] = {}
    for category, results in native_report.by_harm_category.items():
        for result in results:
            nodeid = result.metadata.get("_pytest_nodeid")
            result_index = result.metadata.get("_rampart_result_index")
            if not isinstance(nodeid, str) or not nodeid.strip():
                raise ValueError("every native result must retain metadata._pytest_nodeid")
            if isinstance(result_index, bool) or not isinstance(result_index, int):
                raise ValueError(
                    "every native result must retain integer metadata._rampart_result_index"
                )
            key = (nodeid, result_index)
            if key in observed:
                raise ValueError("native results contain a duplicate execution identity")
            observed[key] = (category, result)

    if set(observed) != set(expected):
        raise ValueError("native execution identities do not exactly match the campaign")
    if set(native_report.by_harm_category) != set(campaign.dimensions):
        raise ValueError("native harm-category buckets do not exactly match the campaign")
    for key, case in expected.items():
        category, result = observed[key]
        if category != case.harm_category:
            raise ValueError("native result harm category does not match its campaign case")
        if result.strategy != case.strategy:
            raise ValueError("native result strategy does not match its campaign case")
        if (
            _OBSERVABILITY_RANK[result.observability_level]
            < _OBSERVABILITY_RANK[case.required_observability_level]
        ):
            raise ValueError("native result observability is weaker than its campaign requirement")
        if (
            result.status
            in {
                RampartTrialOutcome.SAFE,
                RampartTrialOutcome.POLICY_BYPASS,
            }
            and not result.turns
        ):
            raise ValueError("completed native campaign results must retain at least one turn")


class RampartSafetyReport(StrictContractModel):
    """Source-bound enterprise envelope around one native RAMPART report."""

    schema_version: Literal["agt.rampart-safety-report/v1"] = RAMPART_REPORT_SCHEMA_VERSION
    native_schema_version: Literal["rampart.test-run-report/v1"] = (
        RAMPART_NATIVE_REPORT_SCHEMA_VERSION
    )
    report_id: Identifier
    subject: RampartSubject
    run_id: Identifier
    started_at: datetime
    generated_at: datetime
    rampart_version: Identifier
    producer: Identifier
    environment: Identifier
    command: Identifier
    run_attestation: RampartRunAttestation
    campaign: RampartCampaignInventory
    campaign_digest: Sha256
    native_report: RampartNativeReport
    native_report_digest: Sha256
    usage: RampartUsage
    report_digest: Sha256

    _utc_started = field_validator("started_at")(_require_utc)
    _utc_generated = field_validator("generated_at")(_require_utc)

    @model_validator(mode="after")
    def validate_report(self) -> RampartSafetyReport:
        if self.generated_at < self.started_at:
            raise ValueError("generated_at must not precede started_at")
        attestation = self.run_attestation
        if (
            self.report_id != attestation.report_id
            or self.subject != attestation.subject
            or self.run_id != attestation.run_id
            or self.started_at != attestation.started_at
            or self.generated_at != attestation.generated_at
            or self.rampart_version != attestation.rampart_version
            or self.producer != attestation.producer
            or self.environment != attestation.environment
            or self.command != attestation.command
            or self.campaign_digest != attestation.campaign_digest
            or self.native_report_digest != attestation.native_report_digest
            or canonical_sha256(self.usage) != attestation.usage_digest
        ):
            raise ValueError("RAMPART wrapper does not match its signed run attestation")
        if self.campaign_digest != self.campaign.campaign_digest:
            raise ValueError("campaign_digest does not match the campaign inventory")
        if self.rampart_version != self.campaign.rampart_version:
            raise ValueError("report rampart_version does not match the campaign inventory")
        _validate_campaign_results(self.native_report, self.campaign)
        if self.usage.observed_calls < self.native_report.total_runs:
            raise ValueError("RAMPART usage must observe at least one model call per trial")
        expected_native_digest = canonical_sha256(self.native_report)
        if self.native_report_digest != expected_native_digest:
            raise ValueError(
                "native_report_digest mismatch: "
                f"expected {expected_native_digest}, got {self.native_report_digest}"
            )
        expected_digest = digest_without(self, "report_digest")
        if self.report_digest != expected_digest:
            raise ValueError(
                f"report_digest mismatch: expected {expected_digest}, got {self.report_digest}"
            )
        return self

    @property
    def dimensions(self) -> tuple[str, ...]:
        return self.campaign.dimensions

    @property
    def cases_per_dimension(self) -> dict[str, int]:
        """Return exact campaign case counts by safety dimension."""

        return self.campaign.cases_per_dimension

    @property
    def tested_cases(self) -> int:
        return self.native_report.total_runs

    @property
    def blocking_findings(self) -> int:
        return self.native_report.failed

    @property
    def policy_bypass_rate(self) -> Decimal:
        diagnostic_total = self.tested_cases - self.error_count
        return (
            Decimal("0")
            if diagnostic_total == 0
            else Decimal(self.blocking_findings) / Decimal(diagnostic_total)
        )

    @property
    def error_count(self) -> int:
        return self.native_report.errors

    @property
    def undetermined_count(self) -> int:
        return self.native_report.undetermined

    @property
    def complete(self) -> bool:
        return (
            self.tested_cases > 0
            and not self.native_report.incomplete
            and self.error_count == 0
            and self.undetermined_count == 0
            and self.native_report.observability_gap_count == 0
        )

    @property
    def artifact_sha256(self) -> str:
        """Hash the exact canonical bytes that must be retained as the wrapper file."""

        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


def parse_rampart_native_report(data: str | bytes) -> RampartNativeReport:
    """Strictly parse raw JSON emitted by RAMPART's ``JsonFileReportSink``."""

    payload = load_json_strict(data)
    if not isinstance(payload, dict):
        raise ValueError("native RAMPART report must be a JSON object")
    result = validate_contract_json(RampartNativeReport, payload)
    assert isinstance(result, RampartNativeReport)
    return result


def load_rampart_native_report(path: str | Path) -> RampartNativeReport:
    """Load a bounded native RAMPART JSON report."""

    payload = load_json_file_strict(path)
    if not isinstance(payload, dict):
        raise ValueError("native RAMPART report must be a JSON object")
    return parse_rampart_native_report(json.dumps(payload, ensure_ascii=False, allow_nan=False))


def rampart_safety_report_from_native(
    native_report: RampartNativeReport,
    *,
    campaign: RampartCampaignInventory,
    campaign_root: str | Path,
    run_attestation: RampartRunAttestation,
    usage: RampartUsage,
) -> RampartSafetyReport:
    """Bind native output exclusively from signed, source-rehashed run claims."""

    native_report = RampartNativeReport.model_validate_json(
        canonical_json_bytes(native_report.model_dump(mode="json")),
        strict=True,
    )
    campaign = RampartCampaignInventory.model_validate_json(
        canonical_json_bytes(campaign.model_dump(mode="json")),
        strict=True,
    )
    run_attestation = RampartRunAttestation.model_validate_json(
        canonical_json_bytes(run_attestation.model_dump(mode="json")),
        strict=True,
    )
    usage = RampartUsage.model_validate_json(
        canonical_json_bytes(usage.model_dump(mode="json")),
        strict=True,
    )
    campaign.verify_definition_artifacts(campaign_root)
    if run_attestation.campaign_digest != campaign.campaign_digest:
        raise ValueError("run attestation does not bind the supplied campaign")
    if run_attestation.native_report_digest != canonical_sha256(native_report):
        raise ValueError("run attestation does not bind the supplied native report")
    if run_attestation.usage_digest != canonical_sha256(usage):
        raise ValueError("run attestation does not bind the supplied usage observation")
    payload: dict[str, Any] = {
        "schema_version": RAMPART_REPORT_SCHEMA_VERSION,
        "native_schema_version": RAMPART_NATIVE_REPORT_SCHEMA_VERSION,
        "report_id": run_attestation.report_id,
        "subject": run_attestation.subject,
        "run_id": run_attestation.run_id,
        "started_at": run_attestation.started_at,
        "generated_at": run_attestation.generated_at,
        "rampart_version": run_attestation.rampart_version,
        "producer": run_attestation.producer,
        "environment": run_attestation.environment,
        "command": run_attestation.command,
        "run_attestation": run_attestation,
        "campaign": campaign,
        "campaign_digest": campaign.campaign_digest,
        "native_report": native_report,
        "native_report_digest": canonical_sha256(native_report),
        "usage": usage,
    }
    provisional = RampartSafetyReport.model_construct(**payload, report_digest="0" * 64)
    payload["report_digest"] = digest_without(provisional, "report_digest")
    return RampartSafetyReport.model_validate(payload)


def parse_rampart_safety_report(data: str | bytes) -> RampartSafetyReport:
    """Strictly parse and integrity-check a source-bound RAMPART envelope."""

    payload = load_json_strict(data)
    if not isinstance(payload, dict):
        raise ValueError("RAMPART safety report must be a JSON object")
    result = validate_contract_json(RampartSafetyReport, payload)
    assert isinstance(result, RampartSafetyReport)
    return result


def load_rampart_safety_report(path: str | Path) -> RampartSafetyReport:
    """Load a bounded source-bound RAMPART envelope."""

    payload = load_json_file_strict(path)
    if not isinstance(payload, dict):
        raise ValueError("RAMPART safety report must be a JSON object")
    return parse_rampart_safety_report(json.dumps(payload, ensure_ascii=False, allow_nan=False))


def command_evidence_from_rampart_report(
    report: RampartSafetyReport,
    *,
    report_uri: str,
    native_report_uri: str,
    campaign_uri: str,
    run_attestation_uri: str,
    evidence_id: str = "EVD-RAMPART-SAFETY",
) -> CommandEvidence:
    """Embed a strictly revalidated native RAMPART report in command evidence."""

    if not isinstance(report, RampartSafetyReport):
        raise ValueError("report must be a RampartSafetyReport")
    report = RampartSafetyReport.model_validate_json(
        canonical_json_bytes(report.model_dump(mode="json")),
        strict=True,
    )
    if any(
        not uri.strip()
        for uri in (
            report_uri,
            native_report_uri,
            campaign_uri,
            run_attestation_uri,
        )
    ):
        raise ValueError("RAMPART artifact URIs must be non-empty")
    status = (
        EvidenceStatus.PASSED
        if report.complete and report.blocking_findings == 0
        else EvidenceStatus.FAILED
        if report.complete
        else EvidenceStatus.INCOMPLETE
    )
    return CommandEvidence.create(
        evidence_id=evidence_id,
        change_id=report.subject.change_id,
        source_revision=report.subject.source_revision,
        change_digest=report.subject.change_digest,
        kind=EvidenceKind.AGENT_SAFETY,
        status=status,
        producer=report.producer,
        environment=report.environment,
        command=report.command,
        exit_code=0 if status is EvidenceStatus.PASSED else 1,
        generated_at=report.generated_at,
        metrics={"rampart_report": report.model_dump(mode="json")},
        artifacts={
            "report_uri": report_uri,
            "report_sha256": report.artifact_sha256,
            "native_report_uri": native_report_uri,
            "native_report_sha256": canonical_sha256(report.native_report),
            "campaign_uri": campaign_uri,
            "campaign_sha256": canonical_sha256(report.campaign),
            "run_attestation_uri": run_attestation_uri,
            "run_attestation_sha256": canonical_sha256(report.run_attestation),
        },
    )


__all__ = [
    "RAMPART_CAMPAIGN_SCHEMA_VERSION",
    "RAMPART_NATIVE_REPORT_SCHEMA_VERSION",
    "RAMPART_REPORT_SCHEMA_VERSION",
    "RAMPART_RUN_ATTESTATION_SCHEMA_VERSION",
    "RampartCampaignCase",
    "RampartCampaignInventory",
    "RampartDefinitionArtifact",
    "RampartIssuerTrust",
    "RampartNativePopulationSummary",
    "RampartNativeReport",
    "RampartNativeResult",
    "RampartNativeSideEffect",
    "RampartNativeToolCall",
    "RampartNativeTurn",
    "RampartObservabilityLevel",
    "RampartSafetyReport",
    "RampartRunAttestation",
    "RampartSubject",
    "RampartTrialOutcome",
    "RampartUsage",
    "command_evidence_from_rampart_report",
    "load_rampart_native_report",
    "load_rampart_safety_report",
    "parse_rampart_native_report",
    "parse_rampart_safety_report",
    "rampart_safety_report_from_native",
]
