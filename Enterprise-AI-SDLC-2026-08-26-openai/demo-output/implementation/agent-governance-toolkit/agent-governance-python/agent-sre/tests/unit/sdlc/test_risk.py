# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for signed organization-owned source risk classification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from agent_sre.sdlc.change_contract import RiskClass
from agent_sre.sdlc.risk import RiskClassification, RiskSignal, minimum_risk_for_signals
from agent_sre.signing import ArtifactSigner

from .test_change_contract import make_change

NOW = datetime(2026, 8, 25, 12, 30, tzinfo=UTC)


def classification(
    *,
    risk_class: RiskClass = RiskClass.HIGH,
    signals: tuple[RiskSignal, ...] = (RiskSignal.AUTHENTICATION_AUTHORIZATION,),
    signer: ArtifactSigner | None = None,
) -> tuple[RiskClassification, ArtifactSigner]:
    actual_signer = signer or ArtifactSigner()
    result = RiskClassification.create(
        classification_id="RISK-CHG-001",
        classifier_id="central-diff-classifier",
        classifier_version="2026.08.25",
        change=make_change(risk_class=risk_class),
        changed_paths=("src/auth/policy.py", "tests/test_auth_policy.py"),
        signals=signals,
        classified_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        signer=actual_signer,
    )
    return result, actual_signer


def test_signal_depth_is_fail_closed_for_sensitive_and_agent_surfaces() -> None:
    assert minimum_risk_for_signals((RiskSignal.DOCUMENTATION_ONLY,)) is RiskClass.DOCUMENTATION
    assert minimum_risk_for_signals((RiskSignal.LOW_RISK_CODE,)) is RiskClass.SIMPLE
    assert minimum_risk_for_signals((RiskSignal.SOURCE_CODE,)) is RiskClass.STANDARD
    assert minimum_risk_for_signals((RiskSignal.PRIVATE_RESTRICTED_DATA,)) is RiskClass.HIGH
    assert minimum_risk_for_signals((RiskSignal.TOOL_EXECUTION,)) is RiskClass.TOOL_ENABLED_AGENT


def test_signed_classification_verifies_exact_subject_and_trusted_key() -> None:
    result, signer = classification()

    valid, reasons = result.verify(
        trusted_public_keys=(signer.public_key_bytes.hex(),),
        change=make_change(risk_class=RiskClass.HIGH),
        evaluated_at=NOW + timedelta(minutes=5),
        maximum_age_seconds=3600,
        future_clock_skew_seconds=60,
    )

    assert valid
    assert reasons == ()


def test_underclassification_untrusted_key_and_expiry_fail_closed() -> None:
    result, _signer = classification(risk_class=RiskClass.STANDARD)
    valid, reasons = result.verify(
        trusted_public_keys=(ArtifactSigner().public_key_bytes.hex(),),
        change=make_change(risk_class=RiskClass.STANDARD),
        evaluated_at=NOW + timedelta(hours=2),
        maximum_age_seconds=3600,
        future_clock_skew_seconds=60,
    )

    assert not valid
    assert set(reasons) == {
        "risk.expired_classification",
        "risk.stale_classification",
        "risk.underclassified",
        "risk.untrusted_classifier",
    }


def test_tampered_claim_or_signature_cannot_revalidate() -> None:
    result, signer = classification()
    payload = result.model_dump(mode="python")
    payload["changed_paths"] = ("src/billing.py",)
    try:
        RiskClassification.model_validate(payload)
    except ValidationError as exc:
        assert "assessment_digest" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("tampered classification was accepted")

    forged = result.model_copy(update={"signature": "0" * 128})
    valid, reasons = forged.verify(
        trusted_public_keys=(signer.public_key_bytes.hex(),),
        change=make_change(risk_class=RiskClass.HIGH),
        evaluated_at=NOW,
        maximum_age_seconds=3600,
        future_clock_skew_seconds=60,
    )
    assert not valid
    assert reasons == ("risk.invalid_signature",)


def test_paths_and_signal_sets_must_be_canonical() -> None:
    result, _signer = classification()
    payload = result.model_dump(mode="python")
    payload["changed_paths"] = ("../outside",)
    try:
        RiskClassification.model_validate(payload)
    except ValidationError as exc:
        assert "repository-relative" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("path traversal was accepted")

    payload = result.model_dump(mode="python")
    payload["signals"] = (
        RiskSignal.DOCUMENTATION_ONLY,
        RiskSignal.SOURCE_CODE,
    )
    try:
        RiskClassification.model_validate(payload)
    except ValidationError as exc:
        assert "documentation_only" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("conflicting signals were accepted")
