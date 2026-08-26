# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the strict native RAMPART report adapter."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from agent_sre.sdlc.canonical import canonical_json_bytes, canonical_sha256, digest_without
from agent_sre.sdlc.development_gates import EvidenceStatus
from agent_sre.sdlc.rampart import (
    RampartCampaignCase,
    RampartCampaignInventory,
    RampartDefinitionArtifact,
    RampartIssuerTrust,
    RampartNativeReport,
    RampartObservabilityLevel,
    RampartRunAttestation,
    RampartSafetyReport,
    RampartSubject,
    RampartUsage,
    command_evidence_from_rampart_report,
    parse_rampart_native_report,
    parse_rampart_safety_report,
    rampart_safety_report_from_native,
)
from agent_sre.signing import ArtifactSigner

from .test_change_contract import make_change

if TYPE_CHECKING:
    from agent_sre.sdlc.change_contract import ChangePackage

NOW = datetime(2026, 8, 25, 12, 30, tzinfo=UTC)
RAMPART_ATTESTER_SIGNER = ArtifactSigner()
RAMPART_ATTESTATION_EXPIRES_AT = NOW + timedelta(hours=1)
RAMPART_ISSUER_TRUST = RampartIssuerTrust(
    issuer_id="enterprise-rampart-ci",
    public_key=RAMPART_ATTESTER_SIGNER.public_key_bytes.hex(),
    allowed_producers=("rampart-adapter",),
    allowed_environments=("ci",),
)
CAMPAIGN_ROOT = Path(__file__).resolve().parents[3]
CAMPAIGN_SOURCE = "tests/unit/sdlc/test_rampart.py"
DIMENSIONS = (
    "authorization",
    "data_exfiltration",
    "prompt_injection",
    "tool_misuse",
)


def make_rampart_campaign(*, trial_count: int = 25) -> RampartCampaignInventory:
    """Create the policy-curated inventory used by the native test report."""

    if trial_count < len(DIMENSIONS):
        raise ValueError("test campaign requires at least one trial per dimension")
    source_digest = hashlib.sha256((CAMPAIGN_ROOT / CAMPAIGN_SOURCE).read_bytes()).hexdigest()
    return RampartCampaignInventory.create(
        campaign_id="enterprise-agent-safety-v1",
        campaign_version="1.0.0",
        rampart_version="0.2.0",
        cases=tuple(
            RampartCampaignCase(
                scenario_id=f"SCENARIO-{dimension}-{index:04d}",
                pytest_nodeid=(f"{CAMPAIGN_SOURCE}::enterprise_{dimension}[trial-{index:04d}]"),
                rampart_result_index=0,
                definition_artifacts=(
                    RampartDefinitionArtifact(
                        path=CAMPAIGN_SOURCE,
                        sha256=source_digest,
                    ),
                ),
                harm_category=dimension,
                strategy="xpia",
                required_observability_level=(RampartObservabilityLevel.TOOL_AND_SIDE_EFFECTS),
            )
            for index in range(1, trial_count + 1)
            for dimension in (DIMENSIONS[(index - 1) % len(DIMENSIONS)],)
        ),
    )


DEFAULT_RAMPART_CAMPAIGN_DIGEST = make_rampart_campaign().campaign_digest


def make_native_rampart_report(
    *,
    trial_count: int = 25,
    incomplete: bool = False,
) -> RampartNativeReport:
    """Create the exact JSON projection emitted by RAMPART's file sink."""

    campaign = make_rampart_campaign(trial_count=trial_count)
    grouped: dict[str, list[dict]] = {dimension: [] for dimension in campaign.dimensions}
    for index in range(1, trial_count + 1):
        dimension = DIMENSIONS[(index - 1) % len(DIMENSIONS)]
        case = next(
            item
            for item in campaign.cases
            if item.scenario_id == f"SCENARIO-{dimension}-{index:04d}"
        )
        grouped[dimension].append(
            {
                "safe": True,
                "status": "safe",
                "summary": "No attack objective detected",
                "harm_category": dimension,
                "strategy": "xpia",
                "observability_level": "tool_and_side_effects",
                "duration_seconds": 0.1,
                "metadata": {
                    "_pytest_nodeid": case.pytest_nodeid,
                    "_rampart_result_index": case.rampart_result_index,
                },
                "turns": [
                    {
                        "turn_number": 0,
                        "prompt": "attempt the declared attack objective",
                        "response_text": "request rejected",
                        "response_metadata": {},
                        "tool_calls": [],
                        "side_effects": [],
                        "eval_outcome": "not_detected",
                        "eval_confidence": 1.0,
                        "eval_rationale": "No attack objective detected",
                        "eval_undetermined_operands": [],
                        "driver_reasoning": None,
                    }
                ],
            }
        )
    metadata = {
        "xdist_active": True,
        "worker_count": 2,
        "dist_mode": "load",
    }
    if incomplete:
        metadata.update(
            {
                "incomplete": True,
                "incomplete_reasons": ["worker gw1 missing RAMPART output"],
            }
        )
    payload = {
        "total_runs": trial_count,
        "passed": trial_count,
        "failed": 0,
        "undetermined": 0,
        "errors": 0,
        "duration_seconds": 2.5,
        "metadata": metadata,
        "population_summary": {
            "total_runs": trial_count,
            "safe_count": trial_count,
            "unsafe_count": 0,
            "undetermined_count": 0,
            "error_count": 0,
            "attack_success_rate": 0.0,
            "safety_pass_rate": 1.0,
        },
        "by_harm_category": grouped,
    }
    return parse_rampart_native_report(canonical_json_bytes(payload))


def make_rampart_report(
    change: ChangePackage,
    *,
    trial_count: int = 25,
    total_cost_usd: Decimal | None = Decimal("1.25"),
    complete: bool = True,
    run_id: str = "RAMPART-RUN-001",
    attested_at: datetime = NOW,
    expires_at: datetime = RAMPART_ATTESTATION_EXPIRES_AT,
    producer: str = "rampart-adapter",
    environment: str = "ci",
) -> RampartSafetyReport:
    """Bind a real native RAMPART report projection to a change."""

    return bind_native_report(
        make_native_rampart_report(trial_count=trial_count, incomplete=not complete),
        change=change,
        campaign=make_rampart_campaign(trial_count=trial_count),
        run_id=run_id,
        total_cost_usd=total_cost_usd,
        attested_at=attested_at,
        expires_at=expires_at,
        producer=producer,
        environment=environment,
    )


def make_unsafe_rampart_report(
    change: ChangePackage,
    *,
    run_id: str = "RAMPART-RUN-UNSAFE",
) -> RampartSafetyReport:
    """Create one complete, signed report with a retained policy bypass."""

    payload = make_native_rampart_report().model_dump(mode="json")
    result = payload["by_harm_category"]["authorization"][0]
    result["safe"] = False
    result["status"] = "unsafe"
    result["summary"] = "attack objective detected"
    payload["passed"] = 24
    payload["failed"] = 1
    payload["population_summary"] = {
        "total_runs": 25,
        "safe_count": 24,
        "unsafe_count": 1,
        "undetermined_count": 0,
        "error_count": 0,
        "attack_success_rate": 1 / 25,
        "safety_pass_rate": 24 / 25,
    }
    native = RampartNativeReport.model_validate_json(
        canonical_json_bytes(payload),
        strict=True,
    )
    return bind_native_report(native, change=change, run_id=run_id)


def bind_native_report(
    native: RampartNativeReport,
    *,
    change: ChangePackage | None = None,
    campaign: RampartCampaignInventory | None = None,
    campaign_root: Path = CAMPAIGN_ROOT,
    run_id: str = "RAMPART-RUN-001",
    total_cost_usd: Decimal | None = Decimal("1.25"),
    observed_calls: int | None = None,
    signer: ArtifactSigner = RAMPART_ATTESTER_SIGNER,
    issuer_id: str = "enterprise-rampart-ci",
    subject: RampartSubject | None = None,
    attested_at: datetime = NOW,
    expires_at: datetime = RAMPART_ATTESTATION_EXPIRES_AT,
    producer: str = "rampart-adapter",
    environment: str = "ci",
) -> RampartSafetyReport:
    """Bind native output with the protected test campaign and source tree."""

    bound_change = change or make_change()
    bound_campaign = campaign or make_rampart_campaign(trial_count=native.total_runs)
    calls = native.total_runs if observed_calls is None else observed_calls
    usage = RampartUsage(
        source_digest="e" * 64,
        observed_calls=calls,
        calls_with_cost=calls if total_cost_usd is not None else 0,
        total_cost_usd=total_cost_usd,
        cost_complete=total_cost_usd is not None,
    )
    bound_subject = subject or RampartSubject(
        application=bound_change.application,
        repository=bound_change.repository,
        change_id=bound_change.change_id,
        source_revision=bound_change.source_revision,
        change_digest=bound_change.digest,
    )
    run_attestation = RampartRunAttestation.create(
        attestation_id=f"RAMPART-ATTESTATION-{run_id}",
        report_id=f"RAMPART-REPORT-{run_id}",
        subject=bound_subject,
        run_id=run_id,
        started_at=NOW,
        generated_at=NOW,
        attested_at=attested_at,
        expires_at=expires_at,
        rampart_version=bound_campaign.rampart_version,
        producer=producer,
        environment=environment,
        command="pytest tests/agent-safety",
        campaign=bound_campaign,
        native_report=native,
        usage=usage,
        issuer_id=issuer_id,
        signer=signer,
    )
    return rampart_safety_report_from_native(
        native,
        campaign=bound_campaign,
        campaign_root=campaign_root,
        run_attestation=run_attestation,
        usage=usage,
    )


def test_native_report_round_trips_and_adapter_embeds_raw_results() -> None:
    native = make_native_rampart_report()
    report = make_rampart_report(make_change())
    evidence = command_evidence_from_rampart_report(
        report,
        report_uri="artifact://rampart/report.json",
        native_report_uri="artifact://rampart/native-report.json",
        campaign_uri="artifact://rampart/campaign.json",
        run_attestation_uri="artifact://rampart/run-attestation.json",
    )

    assert parse_rampart_native_report(native.model_dump_json()) == native
    assert parse_rampart_safety_report(report.model_dump_json()) == report
    assert report.tested_cases == 25
    assert report.blocking_findings == 0
    assert report.policy_bypass_rate == Decimal("0")
    assert report.dimensions == DIMENSIONS
    assert report.campaign_digest == DEFAULT_RAMPART_CAMPAIGN_DIGEST
    assert sum(report.cases_per_dimension.values()) == 25
    assert evidence.status is EvidenceStatus.PASSED
    raw = evidence.metrics["rampart_report"]["native_report"]
    assert sum(len(results) for results in raw["by_harm_category"].values()) == 25
    assert evidence.artifacts["report_sha256"] == report.artifact_sha256
    assert evidence.artifacts["native_report_sha256"] == report.native_report_digest
    assert evidence.artifacts["campaign_sha256"] == canonical_sha256(report.campaign)
    assert evidence.artifacts["run_attestation_sha256"] == canonical_sha256(report.run_attestation)


def test_native_report_rejects_forged_aggregates() -> None:
    payload = make_native_rampart_report().model_dump(mode="json")
    payload["failed"] = 1

    with pytest.raises(ValidationError, match="counts do not match retained results"):
        RampartNativeReport.model_validate_json(canonical_json_bytes(payload), strict=True)


def test_signed_run_attestation_round_trips_and_trusts_exact_context() -> None:
    report = make_rampart_report(make_change())
    attestation = RampartRunAttestation.model_validate_json(
        canonical_json_bytes(report.run_attestation),
        strict=True,
    )

    assert attestation == report.run_attestation
    assert attestation.verify_issuer((RAMPART_ISSUER_TRUST,))
    assert not attestation.verify_issuer(
        (RAMPART_ISSUER_TRUST.model_copy(update={"allowed_environments": ("developer",)}),)
    )


def test_signed_run_attestation_rejects_signature_mutation() -> None:
    payload = make_rampart_report(make_change()).run_attestation.model_dump(mode="json")
    payload["attestation_signature"] = (
        "0" if payload["attestation_signature"][0] != "0" else "1"
    ) + payload["attestation_signature"][1:]
    payload["attestation_digest"] = digest_without(payload, "attestation_digest")

    with pytest.raises(ValidationError, match="signature is invalid"):
        RampartRunAttestation.model_validate_json(canonical_json_bytes(payload), strict=True)


def test_signed_run_attestation_prevents_wrapper_subject_relabeling() -> None:
    payload = make_rampart_report(make_change()).model_dump(mode="json")
    payload["subject"] = {
        "application": "other-agent",
        "repository": "contoso/other-agent",
        "change_id": "CHG-REPLAY",
        "source_revision": "fedcba654321",
        "change_digest": "f" * 64,
    }
    payload["report_digest"] = digest_without(payload, "report_digest")

    with pytest.raises(ValidationError, match="signed run attestation"):
        RampartSafetyReport.model_validate_json(canonical_json_bytes(payload), strict=True)


def test_source_bound_report_rejects_native_result_tampering_and_duplicate_keys() -> None:
    report = make_rampart_report(make_change())
    payload = report.model_dump(mode="json")
    payload["native_report"]["by_harm_category"]["authorization"][0]["summary"] = "tampered"

    with pytest.raises(ValidationError, match="native_report_digest mismatch"):
        RampartSafetyReport.model_validate_json(canonical_json_bytes(payload), strict=True)

    raw = report.model_dump_json()
    with pytest.raises(ValueError, match="duplicate JSON key"):
        parse_rampart_safety_report(
            raw.replace(
                '"report_id":"RAMPART-REPORT-RAMPART-RUN-001"',
                ('"report_id":"RAMPART-REPORT-RAMPART-RUN-001",' '"report_id":"forged"'),
                1,
            )
        )


def test_incomplete_distributed_run_fails_closed() -> None:
    report = make_rampart_report(make_change(), complete=False)

    evidence = command_evidence_from_rampart_report(
        report,
        report_uri="artifact://rampart/incomplete.json",
        native_report_uri="artifact://rampart/native-incomplete.json",
        campaign_uri="artifact://rampart/campaign.json",
        run_attestation_uri="artifact://rampart/run-attestation.json",
    )

    assert report.native_report.incomplete
    assert evidence.status is EvidenceStatus.INCOMPLETE
    assert evidence.exit_code == 1


def test_complete_unsafe_run_is_failed_command_evidence() -> None:
    report = make_unsafe_rampart_report(make_change())
    evidence = command_evidence_from_rampart_report(
        report,
        report_uri="artifact://rampart/unsafe.json",
        native_report_uri="artifact://rampart/native-unsafe.json",
        campaign_uri="artifact://rampart/campaign.json",
        run_attestation_uri="artifact://rampart/run-attestation.json",
    )

    assert report.complete
    assert report.blocking_findings == 1
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.exit_code == 1


def test_campaign_rejects_duplicate_native_execution_identity() -> None:
    payload = make_native_rampart_report().model_dump(mode="json")
    results = payload["by_harm_category"]["authorization"]
    results[0]["metadata"] = results[1]["metadata"]
    native = RampartNativeReport.model_validate_json(
        canonical_json_bytes(payload),
        strict=True,
    )

    with pytest.raises(ValidationError, match="duplicate execution identity"):
        bind_native_report(native, campaign=make_rampart_campaign())


def test_campaign_rejects_missing_identity_and_weaker_observability() -> None:
    missing_payload = make_native_rampart_report().model_dump(mode="json")
    missing_payload["by_harm_category"]["authorization"][0]["metadata"].pop("_pytest_nodeid")
    missing = RampartNativeReport.model_validate_json(
        canonical_json_bytes(missing_payload),
        strict=True,
    )
    with pytest.raises(ValidationError, match="must retain metadata._pytest_nodeid"):
        bind_native_report(missing, campaign=make_rampart_campaign())

    weak_payload = make_native_rampart_report().model_dump(mode="json")
    weak_payload["by_harm_category"]["authorization"][0]["observability_level"] = "response_only"
    weak = RampartNativeReport.model_validate_json(
        canonical_json_bytes(weak_payload),
        strict=True,
    )
    with pytest.raises(ValidationError, match="observability is weaker"):
        bind_native_report(weak, campaign=make_rampart_campaign())


def test_campaign_rejects_missing_trial_even_when_native_run_claims_complete() -> None:
    native = make_native_rampart_report(trial_count=24)

    assert not native.incomplete
    with pytest.raises(ValidationError, match="do not exactly match the campaign"):
        bind_native_report(native, campaign=make_rampart_campaign(trial_count=25))


def test_native_report_rejects_empty_non_native_harm_bucket() -> None:
    payload = make_native_rampart_report().model_dump(mode="json")
    payload["by_harm_category"]["empty-spoofed-dimension"] = []

    with pytest.raises(ValidationError, match="buckets must not be empty"):
        RampartNativeReport.model_validate_json(canonical_json_bytes(payload), strict=True)


def test_source_bound_report_requires_separate_campaign_inventory() -> None:
    report_payload = make_rampart_report(make_change()).model_dump(mode="json")
    report_payload.pop("campaign")
    report_payload.pop("campaign_digest")

    with pytest.raises(ValidationError, match="campaign"):
        RampartSafetyReport.model_validate_json(
            canonical_json_bytes(report_payload),
            strict=True,
        )


def test_builder_rehashes_campaign_definition_files(tmp_path: Path) -> None:
    source = tmp_path / CAMPAIGN_SOURCE
    source.parent.mkdir(parents=True)
    source.write_text("def weakened_test():\n    assert True\n", encoding="utf-8")

    with pytest.raises(ValueError, match="definition artifact digest mismatch"):
        bind_native_report(
            make_native_rampart_report(),
            campaign=make_rampart_campaign(),
            campaign_root=tmp_path,
        )


def test_report_rejects_usage_without_one_observed_call_per_trial() -> None:
    with pytest.raises(ValidationError, match="at least one model call per trial"):
        bind_native_report(
            make_native_rampart_report(),
            campaign=make_rampart_campaign(),
            observed_calls=0,
            total_cost_usd=Decimal("0"),
        )


def test_campaign_rejects_strategy_substitution() -> None:
    payload = make_native_rampart_report().model_dump(mode="json")
    payload["by_harm_category"]["authorization"][0]["strategy"] = "no-op"
    native = RampartNativeReport.model_validate_json(
        canonical_json_bytes(payload),
        strict=True,
    )

    with pytest.raises(ValidationError, match="strategy does not match"):
        bind_native_report(native, campaign=make_rampart_campaign())


def test_observability_gap_makes_enterprise_report_incomplete() -> None:
    native_payload = make_native_rampart_report().model_dump(mode="json")
    native_payload["by_harm_category"]["authorization"][0]["turns"] = [
        {
            "turn_number": 0,
            "prompt": "attack",
            "response_text": "safe",
            "response_metadata": {},
            "tool_calls": [],
            "side_effects": [],
            "eval_outcome": "not_detected",
            "eval_confidence": 1.0,
            "eval_rationale": "one operand was not observable",
            "eval_undetermined_operands": ["side_effect:mail"],
            "driver_reasoning": None,
        }
    ]
    native = RampartNativeReport.model_validate_json(
        canonical_json_bytes(native_payload),
        strict=True,
    )
    report = bind_native_report(
        native,
        campaign=make_rampart_campaign(),
        run_id="RAMPART-RUN-GAP",
    )

    assert report.native_report.observability_gap_count == 1
    assert not report.complete
