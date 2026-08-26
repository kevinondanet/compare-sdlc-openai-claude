# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cryptographically authenticated human approvals for enterprise release gates."""

from __future__ import annotations

import hmac
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.canonical import canonical_json_bytes, digest_without
from agent_sre.signing import ArtifactSigner

if TYPE_CHECKING:
    from agent_sre.sdlc.change_contract import ChangePackage

HUMAN_APPROVAL_SCHEMA_VERSION: Literal["agt.human-approval/v1"] = "agt.human-approval/v1"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ED25519_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")


class ApprovalModel(BaseModel):
    """Strict immutable base for approval trust-boundary records."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        str_strip_whitespace=False,
    )


def _safe_identifier(value: str, *, field_name: str) -> str:
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{field_name} contains unsupported characters")
    return value


class ApprovalDecision(StrEnum):
    """Human disposition of a high-impact change."""

    APPROVE = "approve"
    REJECT = "reject"


class ApprovalIssuerTrust(ApprovalModel):
    """Policy-pinned approval issuer, key, and roles it may attest."""

    issuer_id: str = Field(min_length=1, max_length=256)
    public_key: str
    allowed_roles: tuple[str, ...] = Field(min_length=1)

    @field_validator("issuer_id")
    @classmethod
    def _issuer_id(cls, value: str) -> str:
        return _safe_identifier(value, field_name="issuer_id")

    @field_validator("public_key")
    @classmethod
    def _public_key(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("public_key must be a canonical Ed25519 public key")
        return value

    @field_validator("allowed_roles")
    @classmethod
    def _roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("allowed_roles must be sorted and unique")
        return tuple(_safe_identifier(item, field_name="allowed role") for item in value)


class HumanApproval(ApprovalModel):
    """Signed, policy- and source-bound approval for a tier-3 or tier-4 change."""

    schema_version: Literal["agt.human-approval/v1"] = HUMAN_APPROVAL_SCHEMA_VERSION
    approval_id: str = Field(pattern=r"^APR-[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
    change_id: str = Field(min_length=1, max_length=256)
    source_revision: str = Field(min_length=1, max_length=256)
    change_digest: str
    enterprise_policy_digest: str
    risk_tier: int = Field(ge=3, le=4)
    approver: str = Field(min_length=1, max_length=256)
    role: str = Field(min_length=1, max_length=256)
    decision: ApprovalDecision
    approved_at: datetime
    expires_at: datetime
    issuer_id: str = Field(min_length=1, max_length=256)
    issuer_public_key: str
    approval_signature: str
    approval_digest: str

    @field_validator("change_id", "source_revision", "approver", "role", "issuer_id")
    @classmethod
    def _safe_ids(cls, value: str, info: Any) -> str:
        return _safe_identifier(value, field_name=info.field_name)

    @field_validator(
        "change_digest", "enterprise_policy_digest", "issuer_public_key", "approval_digest"
    )
    @classmethod
    def _digests_and_key(cls, value: str, info: Any) -> str:
        if _SHA256.fullmatch(value) is None:
            label = (
                "a canonical Ed25519 public key"
                if info.field_name == "issuer_public_key"
                else "a lowercase SHA-256 digest"
            )
            raise ValueError(f"{info.field_name} must be {label}")
        return value

    @field_validator("approval_signature")
    @classmethod
    def _signature(cls, value: str) -> str:
        if _ED25519_SIGNATURE.fullmatch(value) is None:
            raise ValueError("approval_signature must be a canonical Ed25519 signature")
        return value

    @field_validator("approved_at", "expires_at")
    @classmethod
    def _times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @staticmethod
    def _signature_payload(
        *,
        approval_id: str,
        change_id: str,
        source_revision: str,
        change_digest: str,
        enterprise_policy_digest: str,
        risk_tier: int,
        approver: str,
        role: str,
        decision: ApprovalDecision,
        approved_at: datetime,
        expires_at: datetime,
        issuer_id: str,
        issuer_public_key: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": HUMAN_APPROVAL_SCHEMA_VERSION,
                "approval_id": approval_id,
                "change_id": change_id,
                "source_revision": source_revision,
                "change_digest": change_digest,
                "enterprise_policy_digest": enterprise_policy_digest,
                "risk_tier": risk_tier,
                "approver": approver,
                "role": role,
                "decision": decision.value,
                "approved_at": approved_at.astimezone(UTC),
                "expires_at": expires_at.astimezone(UTC),
                "issuer_id": issuer_id,
                "issuer_public_key": issuer_public_key,
            }
        )

    def signature_payload(self) -> bytes:
        """Return the exact domain-separated identity, policy, and release facts."""

        return self._signature_payload(
            approval_id=self.approval_id,
            change_id=self.change_id,
            source_revision=self.source_revision,
            change_digest=self.change_digest,
            enterprise_policy_digest=self.enterprise_policy_digest,
            risk_tier=self.risk_tier,
            approver=self.approver,
            role=self.role,
            decision=self.decision,
            approved_at=self.approved_at,
            expires_at=self.expires_at,
            issuer_id=self.issuer_id,
            issuer_public_key=self.issuer_public_key,
        )

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise ValueError("expires_at must follow approved_at")
        if not ArtifactSigner.verify_payload(
            self.signature_payload(),
            bytes.fromhex(self.approval_signature),
            bytes.fromhex(self.issuer_public_key),
        ):
            raise ValueError("human approval signature is invalid")
        expected = digest_without(self, "approval_digest")
        if not hmac.compare_digest(self.approval_digest, expected):
            raise ValueError("approval_digest does not match the signed approval")
        return self

    def verify_issuer(self, trusted_issuers: tuple[ApprovalIssuerTrust, ...]) -> bool:
        """Return whether protected policy authorizes this exact issuer, key, and role."""

        return any(
            hmac.compare_digest(trust.issuer_id, self.issuer_id)
            and hmac.compare_digest(trust.public_key, self.issuer_public_key)
            and self.role in trust.allowed_roles
            for trust in trusted_issuers
        )

    def strict_revalidate(self) -> HumanApproval | None:
        """Re-run canonical schema, signature, and digest checks at a trust boundary."""

        try:
            canonical = canonical_json_bytes(self.model_dump(mode="json", warnings="error"))
            return HumanApproval.model_validate_json(canonical, strict=True)
        except (TypeError, ValueError):
            return None

    @classmethod
    def create(
        cls,
        *,
        approval_id: str,
        change: ChangePackage,
        enterprise_policy_digest: str,
        risk_tier: Literal[3, 4],
        approver: str,
        role: str,
        decision: ApprovalDecision,
        approved_at: datetime,
        expires_at: datetime,
        issuer_id: str,
        signer: ArtifactSigner,
    ) -> HumanApproval:
        """Sign one exact approval using a policy-pinned identity-provider key."""

        approved_at = approved_at.astimezone(UTC)
        expires_at = expires_at.astimezone(UTC)
        public_key = signer.public_key_bytes.hex()
        payload: dict[str, Any] = {
            "schema_version": HUMAN_APPROVAL_SCHEMA_VERSION,
            "approval_id": approval_id,
            "change_id": change.change_id,
            "source_revision": change.source_revision,
            "change_digest": change.digest,
            "enterprise_policy_digest": enterprise_policy_digest,
            "risk_tier": risk_tier,
            "approver": approver,
            "role": role,
            "decision": decision,
            "approved_at": approved_at,
            "expires_at": expires_at,
            "issuer_id": issuer_id,
            "issuer_public_key": public_key,
        }
        payload["approval_signature"] = signer.sign_payload(
            cls._signature_payload(
                approval_id=approval_id,
                change_id=change.change_id,
                source_revision=change.source_revision,
                change_digest=change.digest,
                enterprise_policy_digest=enterprise_policy_digest,
                risk_tier=risk_tier,
                approver=approver,
                role=role,
                decision=decision,
                approved_at=approved_at,
                expires_at=expires_at,
                issuer_id=issuer_id,
                issuer_public_key=public_key,
            )
        ).hex()
        provisional = cls.model_construct(**payload, approval_digest="0" * 64)
        payload["approval_digest"] = digest_without(provisional, "approval_digest")
        return cls.model_validate(payload)


__all__ = [
    "ApprovalDecision",
    "ApprovalIssuerTrust",
    "HUMAN_APPROVAL_SCHEMA_VERSION",
    "HumanApproval",
]
