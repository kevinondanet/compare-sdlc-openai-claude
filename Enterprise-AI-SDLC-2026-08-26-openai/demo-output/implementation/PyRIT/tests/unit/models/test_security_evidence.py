# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Contract tests for the strict security-evidence wire models."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from pyrit.models import ScenarioRunState
from pyrit.models.catalog.security_evidence import (
    SECURITY_EVIDENCE_BASELINE_SCHEMA,
    EvidenceCompletenessStatus,
    EvidenceCoverage,
    EvidenceGroupSummary,
    EvidenceLatencySummary,
    EvidenceMetricSummary,
    SecurityEvidence,
    SecurityEvidenceBaseline,
    SecurityEvidenceMetrics,
    SecurityEvidenceUsage,
)

_FIXTURE = Path(__file__).with_name("fixtures") / "security_evidence_v1.json"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _refresh_benchmark_fingerprint(payload: dict) -> None:
    configuration = dict(payload["configuration"])
    configuration.pop("benchmark_fingerprint")
    payload["configuration"]["benchmark_fingerprint"] = _canonical_sha256(
        {"schema": "pyrit.security-evidence/benchmark/v1", **configuration}
    )


def _refresh_evidence_digest(payload: dict) -> None:
    digest_payload = dict(payload)
    digest_payload.pop("evidence_digest")
    payload["evidence_digest"] = _canonical_sha256(digest_payload)


def _refresh_baseline_digest(payload: dict) -> None:
    digest_facts = {
        key: payload[key]
        for key in (
            "scenario_result_id",
            "generated_at",
            "state",
            "pyrit_version",
            "benchmark_fingerprint",
            "metrics",
        )
    }
    payload["baseline_digest"] = _canonical_sha256({"schema": SECURITY_EVIDENCE_BASELINE_SCHEMA, **digest_facts})


def _evidence_payload() -> dict:
    timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    identity = {"class_name": "Example", "content_hash": "a" * 64, "eval_hash": "b" * 64}
    empty_metrics = {
        "trials": 0,
        "determinate_trials": 0,
        "successes": 0,
        "failures": 0,
        "errors": 0,
        "undetermined": 0,
        "attack_success_rate": None,
        "error_rate": None,
        "undetermined_rate": None,
        "latency": {"samples": 0, "total_ms": None, "mean_ms": None, "p95_ms": None, "max_ms": None},
    }
    payload = {
        "schema": "pyrit.security-evidence/v1",
        "generated_at": timestamp,
        "subject": None,
        "run": {
            "scenario_result_id": "run-1",
            "state": "CREATED",
            "created_at": timestamp,
            "completed_at": None,
            "number_tries": 0,
            "pyrit_version": "1.0.0",
            "trial_plan_digest": None,
            "expected_trial_inventory": None,
            "planned_cached_trials": [],
            "observed_trials": [],
            "oldest_trial_at": None,
            "current_run_trial_count": 0,
            "reused_trial_count": 0,
            "omitted_reused_trial_count": 0,
            "missing_provenance_trial_count": 0,
            "origin_scenario_result_ids": [],
        },
        "configuration": {
            "scenario": identity,
            "target": None,
            "scorer": None,
            "scenario_version": 1,
            "pyrit_version": "1.0.0",
            "techniques": [],
            "datasets": [],
            "objective_hashes": [],
            "benchmark_fingerprint": "0" * 64,
        },
        "metrics": {"overall": empty_metrics, "groups": []},
        "usage": {
            "scope": "linked_conversations",
            "conversation_count": 0,
            "observed_response_count": 0,
            "calls_with_token_usage": 0,
            "calls_with_cost": 0,
            "input_tokens": None,
            "output_tokens": None,
            "reasoning_tokens": None,
            "cached_tokens": None,
            "total_tokens": None,
            "cost": None,
            "token_coverage": "unavailable",
            "cost_coverage": "unavailable",
        },
        "baseline": None,
        "completeness": {
            "status": "unavailable",
            "reasons": [
                "configuration.target_missing",
                "cost.unavailable",
                "run.no_trials",
                "run.not_completed",
                "run.trial_inventory_unbound",
                "subject.unbound",
                "usage.unavailable",
            ],
            "terminal": False,
            "has_trials": False,
        },
        "evidence_digest": "0" * 64,
    }
    _refresh_benchmark_fingerprint(payload)
    _refresh_evidence_digest(payload)
    return payload


def _baseline_payload(*, benchmark_fingerprint: str) -> dict:
    timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "scenario_result_id": "baseline-1",
        "generated_at": timestamp,
        "state": "COMPLETED",
        "pyrit_version": "1.0.0",
        "benchmark_fingerprint": benchmark_fingerprint,
        "compatible": True,
        "incompatibility_reasons": [],
        "metrics": _evidence_payload()["metrics"]["overall"],
        "delta_attack_success_rate": None,
        "delta_error_rate": None,
        "delta_undetermined_rate": None,
        "baseline_digest": "0" * 64,
    }
    _refresh_baseline_digest(payload)
    return payload


def test_security_evidence_rejects_unknown_schema_and_fields() -> None:
    payload = _evidence_payload()
    payload["schema"] = "pyrit.security-evidence/v2"
    with pytest.raises(ValidationError):
        SecurityEvidence.model_validate(payload)


def test_terminal_run_requires_a_completion_timestamp() -> None:
    payload = _evidence_payload()
    payload["run"]["state"] = "COMPLETED"

    with pytest.raises(ValidationError, match="terminal runs must include completed_at"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_rejects_tampered_digest_and_benchmark_fingerprint() -> None:
    payload = _evidence_payload()
    payload["evidence_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="evidence_digest"):
        SecurityEvidence.model_validate(payload)

    payload = _evidence_payload()
    payload["configuration"]["benchmark_fingerprint"] = "f" * 64
    with pytest.raises(ValidationError, match="benchmark_fingerprint"):
        SecurityEvidence.model_validate(payload)

    payload = _evidence_payload()
    payload["secret"] = "must not be accepted"
    with pytest.raises(ValidationError):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_requires_configuration_and_run_pyrit_versions_to_match() -> None:
    payload = _evidence_payload()
    payload["configuration"]["pyrit_version"] = "forged"
    _refresh_benchmark_fingerprint(payload)
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="configuration.pyrit_version"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_rejects_trial_provenance_count_mismatch() -> None:
    payload = _evidence_payload()
    payload["run"]["oldest_trial_at"] = payload["run"]["created_at"]
    payload["run"]["missing_provenance_trial_count"] = 1
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="missing_provenance_trial_count"):
        SecurityEvidence.model_validate(payload)


def test_usage_rejects_partial_when_core_token_coverage_is_complete() -> None:
    with pytest.raises(ValidationError, match="requires complete coverage"):
        SecurityEvidenceUsage(
            conversation_count=1,
            observed_response_count=1,
            calls_with_token_usage=1,
            calls_with_cost=0,
            input_tokens=3,
            output_tokens=2,
            total_tokens=5,
            token_coverage=EvidenceCoverage.PARTIAL,
            cost_coverage=EvidenceCoverage.UNAVAILABLE,
        )


def test_security_evidence_rejects_group_atomic_relabel_after_rehash() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    payload["metrics"]["groups"][0]["atomic_attack_names"] = ["forged-attack"]
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="exactly match observed trial identities"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_rejects_group_name_relabel_after_rehash() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    payload["metrics"]["groups"][0]["name"] = "group-b"
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="display-group identities"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_rejects_group_metric_reallocation_after_rehash() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    first, second = payload["metrics"]["groups"]
    first["metrics"], second["metrics"] = second["metrics"], first["metrics"]
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="group trial counts"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_rejects_group_outcome_relabel_after_rehash() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    group_metrics = payload["metrics"]["groups"][0]["metrics"]
    group_metrics.update(
        successes=1,
        failures=0,
        attack_success_rate=1.0,
    )
    overall = payload["metrics"]["overall"]
    overall.update(
        successes=1,
        failures=2,
        attack_success_rate=1 / 3,
    )
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="group outcome counts"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_rejects_lowered_overall_p95_after_rehash() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    payload["metrics"]["overall"]["latency"].update(p95_ms=20, max_ms=20)
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="overall latency metrics"):
        SecurityEvidence.model_validate(payload)


def test_security_evidence_baseline_digest_and_utc_timestamp_are_validated() -> None:
    baseline_payload = _baseline_payload(benchmark_fingerprint="a" * 64)
    baseline = SecurityEvidenceBaseline.model_validate(baseline_payload)
    assert baseline.baseline_digest == baseline.computed_digest

    baseline_payload["scenario_result_id"] = "forged"
    with pytest.raises(ValidationError, match="baseline_digest"):
        SecurityEvidenceBaseline.model_validate(baseline_payload)

    baseline_payload = _baseline_payload(benchmark_fingerprint="a" * 64)
    baseline_payload["generated_at"] = "2025-01-01T00:00:00-06:00"
    with pytest.raises(ValidationError, match="baseline timestamps must be UTC"):
        SecurityEvidenceBaseline.model_validate(baseline_payload)


def test_compatible_baseline_must_match_current_benchmark_fingerprint() -> None:
    payload = _evidence_payload()
    payload["baseline"] = _baseline_payload(benchmark_fingerprint="f" * 64)
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="incompatibility reasons"):
        SecurityEvidence.model_validate(payload)


def test_incompatible_baseline_rejects_arbitrary_resealed_reason() -> None:
    payload = _evidence_payload()
    baseline = _baseline_payload(benchmark_fingerprint="f" * 64)
    baseline["compatible"] = False
    baseline["incompatibility_reasons"] = ["baseline.arbitrary_reason"]
    _refresh_baseline_digest(baseline)
    payload["baseline"] = baseline
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="Input should be"):
        SecurityEvidence.model_validate(payload)


def test_compatible_baseline_flag_is_derived_from_persisted_facts() -> None:
    payload = _evidence_payload()
    payload["configuration"]["target"] = payload["configuration"]["scenario"].copy()
    _refresh_benchmark_fingerprint(payload)
    baseline = _baseline_payload(benchmark_fingerprint=payload["configuration"]["benchmark_fingerprint"])
    baseline["metrics"] = {
        "trials": 1,
        "determinate_trials": 1,
        "successes": 0,
        "failures": 1,
        "errors": 0,
        "undetermined": 0,
        "attack_success_rate": 0.0,
        "error_rate": 0.0,
        "undetermined_rate": 0.0,
        "latency": {"samples": 1, "total_ms": 1, "mean_ms": 1.0, "p95_ms": 1, "max_ms": 1},
    }
    baseline["compatible"] = False
    baseline["incompatibility_reasons"] = ["baseline.benchmark_fingerprint_mismatch"]
    _refresh_baseline_digest(baseline)
    payload["baseline"] = baseline
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="incompatibility reasons"):
        SecurityEvidence.model_validate(payload)


def test_compatible_baseline_deltas_are_recomputed_from_current_and_prior_rates() -> None:
    payload = _evidence_payload()
    payload["configuration"]["target"] = payload["configuration"]["scenario"].copy()
    _refresh_benchmark_fingerprint(payload)
    baseline = _baseline_payload(benchmark_fingerprint=payload["configuration"]["benchmark_fingerprint"])
    baseline["metrics"] = {
        "trials": 1,
        "determinate_trials": 1,
        "successes": 0,
        "failures": 1,
        "errors": 0,
        "undetermined": 0,
        "attack_success_rate": 0.0,
        "error_rate": 0.0,
        "undetermined_rate": 0.0,
        "latency": {"samples": 1, "total_ms": 1, "mean_ms": 1.0, "p95_ms": 1, "max_ms": 1},
    }
    baseline["delta_attack_success_rate"] = 0.25
    _refresh_baseline_digest(baseline)
    payload["baseline"] = baseline
    _refresh_evidence_digest(payload)

    with pytest.raises(ValidationError, match="delta_attack_success_rate availability"):
        SecurityEvidence.model_validate(payload)


def test_nested_models_are_strict() -> None:
    payload = _evidence_payload()
    payload["configuration"]["scenario"]["endpoint"] = "https://secret.example"
    with pytest.raises(ValidationError):
        SecurityEvidence.model_validate(payload)


def test_metric_summary_validates_derived_counts_and_rates() -> None:
    latency = EvidenceLatencySummary(samples=2, total_ms=30, mean_ms=15, p95_ms=20, max_ms=20)
    metric = EvidenceMetricSummary(
        trials=2,
        determinate_trials=2,
        successes=1,
        failures=1,
        errors=0,
        undetermined=0,
        attack_success_rate=0.5,
        error_rate=0,
        undetermined_rate=0,
        latency=latency,
    )
    assert metric.attack_success_rate == 0.5

    with pytest.raises(ValidationError, match="trials must equal"):
        EvidenceMetricSummary(
            trials=3,
            determinate_trials=2,
            successes=1,
            failures=1,
            errors=0,
            undetermined=0,
            attack_success_rate=0.5,
            error_rate=0,
            undetermined_rate=0,
            latency=EvidenceLatencySummary(samples=3, total_ms=30, mean_ms=10, p95_ms=20, max_ms=20),
        )

    with pytest.raises(ValidationError, match="latency mean is inconsistent"):
        EvidenceLatencySummary(samples=2, total_ms=30, mean_ms=10, p95_ms=20, max_ms=20)


def test_group_metrics_must_be_a_disjoint_partition_of_overall_counts() -> None:
    latency = EvidenceLatencySummary(samples=1, total_ms=10, mean_ms=10, p95_ms=10, max_ms=10)
    metric = EvidenceMetricSummary(
        trials=1,
        determinate_trials=1,
        successes=0,
        failures=1,
        errors=0,
        undetermined=0,
        attack_success_rate=0,
        error_rate=0,
        undetermined_rate=0,
        latency=latency,
    )
    with pytest.raises(ValidationError, match="group trials does not sum"):
        SecurityEvidenceMetrics(
            overall=metric,
            groups=(
                EvidenceGroupSummary(
                    name="group-a",
                    atomic_attack_names=("attack-a",),
                    metrics=EvidenceMetricSummary(
                        trials=0,
                        determinate_trials=0,
                        successes=0,
                        failures=0,
                        errors=0,
                        undetermined=0,
                        attack_success_rate=None,
                        error_rate=None,
                        undetermined_rate=None,
                        latency=EvidenceLatencySummary(samples=0),
                    ),
                ),
            ),
        )

    with pytest.raises(ValidationError, match="atomic attack names"):
        SecurityEvidenceMetrics(
            overall=EvidenceMetricSummary(
                trials=2,
                determinate_trials=2,
                successes=0,
                failures=2,
                errors=0,
                undetermined=0,
                attack_success_rate=0,
                error_rate=0,
                undetermined_rate=0,
                latency=EvidenceLatencySummary(
                    samples=2,
                    total_ms=20,
                    mean_ms=10,
                    p95_ms=10,
                    max_ms=10,
                ),
            ),
            groups=(
                EvidenceGroupSummary(name="group-a", atomic_attack_names=("attack-a",), metrics=metric),
                EvidenceGroupSummary(name="group-b", atomic_attack_names=("attack-a",), metrics=metric),
            ),
        )


def test_wire_enums_round_trip() -> None:
    evidence = SecurityEvidence.model_validate(_evidence_payload())
    assert evidence.run.state is ScenarioRunState.CREATED
    assert evidence.completeness.status is EvidenceCompletenessStatus.UNAVAILABLE
    assert evidence.usage.token_coverage is EvidenceCoverage.UNAVAILABLE
    assert evidence.model_dump(mode="json")["schema"] == "pyrit.security-evidence/v1"


def test_security_evidence_v1_golden_fixture_is_canonical_and_digest_valid() -> None:
    from pyrit.analytics.scenario_evidence import (
        canonical_security_evidence_bytes,
        verify_security_evidence_digest,
    )

    raw = _FIXTURE.read_bytes().rstrip(b"\n")
    evidence = SecurityEvidence.model_validate_json(raw)

    assert evidence.evidence_digest == "90966a7d8e2f7f43b82a4360f88a936934fdedb5bb94611fa31f2d6abf4abe2b"
    assert verify_security_evidence_digest(evidence)
    assert canonical_security_evidence_bytes(evidence) == raw


def test_verified_envelope_collections_cannot_be_mutated() -> None:
    from pyrit.analytics.scenario_evidence import (
        canonical_security_evidence_bytes,
        verify_security_evidence_digest,
    )

    evidence = SecurityEvidence.model_validate_json(_FIXTURE.read_bytes())
    before = canonical_security_evidence_bytes(evidence)
    techniques: Any = evidence.configuration.techniques
    completeness: Any = evidence.completeness

    with pytest.raises(TypeError):
        techniques[0] = "forged"
    with pytest.raises(ValidationError, match="frozen"):
        completeness.reasons = ("forged",)

    assert canonical_security_evidence_bytes(evidence) == before
    assert verify_security_evidence_digest(evidence)
