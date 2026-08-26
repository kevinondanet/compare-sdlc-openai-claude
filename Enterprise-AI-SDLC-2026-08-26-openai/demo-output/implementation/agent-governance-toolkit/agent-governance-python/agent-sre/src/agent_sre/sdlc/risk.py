# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Signed, source-bound risk classification for enterprise SDLC depth selection.

The canonical change contract contains the risk class requested by a project.  It
is intentionally not treated as a trust anchor by itself: an organization-owned
classifier must inspect the source revision and sign the minimum required depth.
This prevents a project from avoiding security and safety gates by omitting tool,
authentication, or private-data declarations from its own change description.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.canonical import canonical_json_bytes, canonical_sha256
from agent_sre.sdlc.change_contract import ChangePackage, RiskClass
from agent_sre.signing import ArtifactSigner

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RiskSignal(StrEnum):
    """Organization-classified source surfaces that determine minimum depth."""

    DOCUMENTATION_ONLY = "documentation_only"
    LOW_RISK_CODE = "low_risk_code"
    SOURCE_CODE = "source_code"
    AUTHENTICATION_AUTHORIZATION = "authentication_authorization"
    PRIVATE_RESTRICTED_DATA = "private_restricted_data"
    SECURITY_BOUNDARY = "security_boundary"
    AI_AGENT = "ai_agent"
    TOOL_EXECUTION = "tool_execution"
    NETWORK_EGRESS = "network_egress"
    ADMINISTRATIVE_CONTROL = "administrative_control"


_RISK_RANK = {
    RiskClass.DOCUMENTATION: 0,
    RiskClass.SIMPLE: 1,
    RiskClass.STANDARD: 2,
    RiskClass.HIGH: 3,
    RiskClass.TOOL_ENABLED_AGENT: 4,
}
_HIGH_SIGNALS = frozenset(
    {
        RiskSignal.AUTHENTICATION_AUTHORIZATION,
        RiskSignal.PRIVATE_RESTRICTED_DATA,
        RiskSignal.SECURITY_BOUNDARY,
    }
)
_TOOL_SIGNALS = frozenset(
    {
        RiskSignal.AI_AGENT,
        RiskSignal.TOOL_EXECUTION,
        RiskSignal.NETWORK_EGRESS,
        RiskSignal.ADMINISTRATIVE_CONTROL,
    }
)


class RiskClassification(BaseModel):
    """Immutable classifier result signed by an organization trust anchor."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        str_strip_whitespace=True,
    )

    schema_version: Literal["agt.risk-classification/v1"] = "agt.risk-classification/v1"
    classification_id: Annotated[str, Field(min_length=1, max_length=128)]
    classifier_id: Annotated[str, Field(min_length=1, max_length=128)]
    classifier_version: Annotated[str, Field(min_length=1, max_length=64)]
    change_id: str
    source_revision: Annotated[str, Field(min_length=1)]
    change_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    changed_paths: tuple[str, ...] = Field(min_length=1)
    signals: tuple[RiskSignal, ...] = Field(min_length=1)
    declared_risk_class: RiskClass
    required_risk_class: RiskClass
    classified_at: datetime
    expires_at: datetime
    public_key: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    assessment_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]

    @field_validator("classification_id", "classifier_id")
    @classmethod
    def _safe_ids(cls, value: str, info: Any) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator("classified_at", "expires_at")
    @classmethod
    def _utc_times(cls, value: datetime, info: Any) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{info.field_name} must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("changed_paths")
    @classmethod
    def _canonical_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("changed_paths must be sorted and unique")
        for path in value:
            candidate = PurePosixPath(path)
            if (
                not path
                or path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in candidate.parts)
            ):
                raise ValueError("changed_paths must be canonical repository-relative paths")
        return value

    @field_validator("signals")
    @classmethod
    def _canonical_signals(cls, value: tuple[RiskSignal, ...]) -> tuple[RiskSignal, ...]:
        expected = tuple(sorted(set(value), key=lambda item: item.value))
        if value != expected:
            raise ValueError("signals must be sorted and unique")
        if RiskSignal.DOCUMENTATION_ONLY in value and len(value) != 1:
            raise ValueError("documentation_only cannot be combined with another risk signal")
        if RiskSignal.LOW_RISK_CODE in value and RiskSignal.SOURCE_CODE in value:
            raise ValueError("low_risk_code and source_code are mutually exclusive")
        return value

    @model_validator(mode="after")
    def _validate_claims(self) -> Self:
        if self.expires_at <= self.classified_at:
            raise ValueError("expires_at must follow classified_at")
        expected_risk = minimum_risk_for_signals(self.signals)
        if self.required_risk_class is not expected_risk:
            raise ValueError("required_risk_class does not match classified source signals")
        if self.assessment_digest != canonical_sha256(self._claims_payload()):
            raise ValueError("assessment_digest does not match classification claims")
        return self

    def _claims_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "classification_id": self.classification_id,
            "classifier_id": self.classifier_id,
            "classifier_version": self.classifier_version,
            "change_id": self.change_id,
            "source_revision": self.source_revision,
            "change_digest": self.change_digest,
            "changed_paths": self.changed_paths,
            "signals": self.signals,
            "declared_risk_class": self.declared_risk_class,
            "required_risk_class": self.required_risk_class,
            "classified_at": self.classified_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
        }

    def signature_payload(self) -> bytes:
        """Return the domain-separated bytes authenticated by the classifier."""

        return canonical_json_bytes(
            {
                "schema_version": "agt.risk-classification-signature-payload/v1",
                "assessment_digest": self.assessment_digest,
                "claims": self._claims_payload(),
            }
        )

    def verify(
        self,
        *,
        trusted_public_keys: tuple[str, ...],
        change: ChangePackage,
        evaluated_at: datetime,
        maximum_age_seconds: int,
        future_clock_skew_seconds: int,
    ) -> tuple[bool, tuple[str, ...]]:
        """Verify signature, subject, freshness, and non-underclassification."""

        reasons: list[str] = []
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        now = evaluated_at.astimezone(UTC)
        if self.public_key not in trusted_public_keys:
            reasons.append("risk.untrusted_classifier")
        try:
            signature_valid = ArtifactSigner.verify_payload(
                self.signature_payload(),
                bytes.fromhex(self.signature),
                bytes.fromhex(self.public_key),
            )
        except (ImportError, TypeError, ValueError):
            signature_valid = False
        if not signature_valid:
            reasons.append("risk.invalid_signature")
        if (
            self.change_id != change.change_id
            or self.source_revision != change.source_revision
            or self.change_digest != change.digest
            or self.declared_risk_class is not change.risk_class
        ):
            reasons.append("risk.subject_mismatch")
        age_floor = now.timestamp() - maximum_age_seconds
        future_ceiling = now.timestamp() + future_clock_skew_seconds
        if not age_floor <= self.classified_at.timestamp() <= future_ceiling:
            reasons.append("risk.stale_classification")
        if now >= self.expires_at:
            reasons.append("risk.expired_classification")
        if _RISK_RANK[change.risk_class] < _RISK_RANK[self.required_risk_class]:
            reasons.append("risk.underclassified")
        return not reasons, tuple(sorted(reasons))

    @classmethod
    def create(
        cls,
        *,
        classification_id: str,
        classifier_id: str,
        classifier_version: str,
        change: ChangePackage,
        changed_paths: tuple[str, ...],
        signals: tuple[RiskSignal, ...],
        classified_at: datetime,
        expires_at: datetime,
        signer: ArtifactSigner,
    ) -> RiskClassification:
        """Classify and sign the exact canonical change/source revision."""

        public_key = signer.public_key_bytes.hex()
        claims: dict[str, Any] = {
            "schema_version": "agt.risk-classification/v1",
            "classification_id": classification_id,
            "classifier_id": classifier_id,
            "classifier_version": classifier_version,
            "change_id": change.change_id,
            "source_revision": change.source_revision,
            "change_digest": change.digest,
            "changed_paths": tuple(sorted(changed_paths)),
            "signals": tuple(sorted(signals, key=lambda item: item.value)),
            "declared_risk_class": change.risk_class,
            "required_risk_class": minimum_risk_for_signals(signals),
            "classified_at": classified_at,
            "expires_at": expires_at,
            "public_key": public_key,
        }
        assessment_digest = canonical_sha256(claims)
        provisional = cls.model_construct(
            **claims,
            assessment_digest=assessment_digest,
            signature="0" * 128,
        )
        signature = signer.sign_payload(provisional.signature_payload()).hex()
        return cls.model_validate(
            {**claims, "assessment_digest": assessment_digest, "signature": signature}
        )


def minimum_risk_for_signals(signals: tuple[RiskSignal, ...]) -> RiskClass:
    """Return the fail-closed minimum gate depth for classifier signals."""

    signal_set = set(signals)
    if not signal_set:
        raise ValueError("at least one risk signal is required")
    if signal_set & _TOOL_SIGNALS:
        return RiskClass.TOOL_ENABLED_AGENT
    if signal_set & _HIGH_SIGNALS:
        return RiskClass.HIGH
    if signal_set == {RiskSignal.DOCUMENTATION_ONLY}:
        return RiskClass.DOCUMENTATION
    if signal_set == {RiskSignal.LOW_RISK_CODE}:
        return RiskClass.SIMPLE
    return RiskClass.STANDARD
