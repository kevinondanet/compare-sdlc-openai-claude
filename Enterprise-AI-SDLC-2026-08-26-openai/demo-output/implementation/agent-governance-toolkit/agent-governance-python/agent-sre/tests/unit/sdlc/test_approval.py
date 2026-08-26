# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Adversarial tests for signed, policy-bound human approvals."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agent_sre.sdlc.approval import (
    ApprovalDecision,
    ApprovalIssuerTrust,
    HumanApproval,
)
from agent_sre.signing import ArtifactSigner

from .test_change_contract import make_change

NOW = datetime(2026, 8, 25, 12, 30, tzinfo=UTC)


def _approval(*, signer: ArtifactSigner | None = None) -> HumanApproval:
    return HumanApproval.create(
        approval_id="APR-security-1",
        change=make_change(),
        enterprise_policy_digest="f" * 64,
        risk_tier=4,
        approver="person-1",
        role="security",
        decision=ApprovalDecision.APPROVE,
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        issuer_id="enterprise-idp",
        signer=signer or ArtifactSigner(),
    )


def test_signed_approval_binds_identity_role_decision_subject_policy_and_expiry() -> None:
    approval = _approval()

    reparsed = HumanApproval.model_validate_json(approval.model_dump_json())

    assert reparsed == approval
    for field_name, replacement in (
        ("approver", "attacker"),
        ("role", "release-owner"),
        ("decision", "reject"),
        ("change_digest", "0" * 64),
        ("enterprise_policy_digest", "0" * 64),
        ("expires_at", (NOW + timedelta(hours=2)).isoformat()),
    ):
        payload = approval.model_dump(mode="json")
        payload[field_name] = replacement
        with pytest.raises(ValidationError, match="signature"):
            HumanApproval.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("change_id", "CHG-REPLAY"),
        ("source_revision", "fedcba654321"),
        ("change_digest", "0" * 64),
        ("enterprise_policy_digest", "0" * 64),
        ("risk_tier", 3),
        ("approver", "attacker"),
        ("role", "release-owner"),
        ("decision", ApprovalDecision.REJECT),
        ("approved_at", NOW + timedelta(minutes=1)),
        ("expires_at", NOW + timedelta(hours=2)),
        ("issuer_id", "other-idp"),
        ("issuer_public_key", "0" * 64),
    ),
)
def test_strict_revalidation_rejects_in_memory_signed_field_mutation(
    field_name: str,
    replacement: object,
) -> None:
    forged = _approval().model_copy(update={field_name: replacement})

    assert forged.strict_revalidate() is None


def test_approval_requires_exact_policy_pinned_issuer_key_and_role() -> None:
    signer = ArtifactSigner()
    approval = _approval(signer=signer)
    trusted = ApprovalIssuerTrust(
        issuer_id="enterprise-idp",
        public_key=signer.public_key_bytes.hex(),
        allowed_roles=("release-owner", "security"),
    )

    assert approval.verify_issuer((trusted,))
    assert not approval.verify_issuer(
        (
            ApprovalIssuerTrust(
                issuer_id="other-idp",
                public_key=signer.public_key_bytes.hex(),
                allowed_roles=("security",),
            ),
        )
    )
    assert not approval.verify_issuer(
        (
            ApprovalIssuerTrust(
                issuer_id="enterprise-idp",
                public_key=ArtifactSigner().public_key_bytes.hex(),
                allowed_roles=("security",),
            ),
        )
    )
    assert not approval.verify_issuer(
        (
            ApprovalIssuerTrust(
                issuer_id="enterprise-idp",
                public_key=signer.public_key_bytes.hex(),
                allowed_roles=("release-owner",),
            ),
        )
    )


def test_approval_rejects_invalid_signature_expiry_and_unsorted_role_authority() -> None:
    approval = _approval()
    payload = approval.model_dump(mode="json")
    payload["approval_signature"] = "0" * 128
    with pytest.raises(ValidationError, match="signature"):
        HumanApproval.model_validate_json(json.dumps(payload))

    with pytest.raises(ValidationError, match="expires_at must follow"):
        HumanApproval.create(
            approval_id="APR-expired",
            change=make_change(),
            enterprise_policy_digest="f" * 64,
            risk_tier=3,
            approver="person-2",
            role="release-owner",
            decision=ApprovalDecision.APPROVE,
            approved_at=NOW,
            expires_at=NOW,
            issuer_id="enterprise-idp",
            signer=ArtifactSigner(),
        )

    with pytest.raises(ValidationError, match="sorted and unique"):
        ApprovalIssuerTrust(
            issuer_id="enterprise-idp",
            public_key=ArtifactSigner().public_key_bytes.hex(),
            allowed_roles=("security", "release-owner"),
        )
