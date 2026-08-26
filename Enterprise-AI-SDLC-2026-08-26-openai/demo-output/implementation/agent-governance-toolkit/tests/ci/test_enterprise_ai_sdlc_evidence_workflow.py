# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Static security and contract tests for the reusable AI-SDLC evidence workflow."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, cast

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "enterprise-ai-sdlc-evidence.yml"
DOCUMENTATION = (
    REPO_ROOT / "docs" / "operations" / "enterprise-ai-sdlc-evidence-workflow.md"
)
FULL_ACTION_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
REVIEW_ATTESTER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("11" * 32)
)
REVIEW_ATTESTER_PUBLIC_KEY = (
    REVIEW_ATTESTER_PRIVATE_KEY.public_key()
    .public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    .hex()
)
RAMPART_ISSUER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("22" * 32)
)
RAMPART_ISSUER_PUBLIC_KEY = (
    RAMPART_ISSUER_PRIVATE_KEY.public_key()
    .public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    .hex()
)


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow_model() -> dict[str, Any]:
    return cast(dict[str, Any], yaml.load(workflow_text(), Loader=yaml.BaseLoader))


def assembler_script() -> str:
    match = re.search(
        r"python3 - <<'PY'\n(?P<script>.*?)^\s{10}PY$",
        workflow_text(),
        flags=re.DOTALL | re.MULTILINE,
    )
    assert match is not None
    return textwrap.dedent(match.group("script"))


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def usage_event_set_digest(event_ids: list[str]) -> str:
    payload = {
        "event_ids": sorted(event_ids),
        "schema": "agt.usage-ledger/event-set/v1",
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def commit(repository: Path, message: str) -> str:
    subprocess.run(["git", "add", "--all"], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Workflow Test",
            "-c",
            "user.email=workflow-test@example.invalid",
            "commit",
            "--quiet",
            "--message",
            message,
        ],
        cwd=repository,
        check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def recent_timestamp(*, minutes: int = 1) -> str:
    return (
        (datetime.now(UTC) - timedelta(minutes=minutes))
        .isoformat()
        .replace("+00:00", "Z")
    )


def raw_command_report_bytes(*, evidence_id: str, kind: str) -> bytes:
    return canonical_bytes(
        {
            "evidence_id": evidence_id,
            "kind": kind,
            "schema": "test.raw-command-report/v1",
        }
    )


def caller_sbom_bytes() -> bytes:
    return canonical_bytes(
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "dataLicense": "CC0-1.0",
            "spdxVersion": "SPDX-2.3",
        }
    )


def make_command_evidence(
    source: str,
    *,
    kind: str,
    metrics: dict[str, object],
    evidence_id: str | None = None,
    test_layers: list[str] | None = None,
    requirement_ids: list[str] | None = None,
    scenario_ids: list[str] | None = None,
    task_ids: list[str] | None = None,
    artifacts: dict[str, str] | None = None,
) -> dict[str, object]:
    resolved_evidence_id = evidence_id or f"EVD-CALLER-{kind.upper()}"
    report_bytes = raw_command_report_bytes(
        evidence_id=resolved_evidence_id,
        kind=kind,
    )
    record: dict[str, object] = {
        "schema_version": "agt.execution-evidence/v1",
        "evidence_id": resolved_evidence_id,
        "change_id": "agt.change/test",
        "source_revision": source,
        "change_digest": "a" * 64,
        "kind": kind,
        "status": "passed",
        "generated_at": recent_timestamp(),
        "producer": "caller-ci",
        "environment": "ci",
        "command": f"protected-ci {kind}",
        "exit_code": 0,
        "requirement_ids": requirement_ids or [],
        "scenario_ids": scenario_ids or [],
        "task_ids": task_ids or [],
        "test_layers": test_layers or [],
        "metrics": metrics,
        "artifacts": artifacts
        or {
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "report_uri": (
                f"artifact://agt-ai-sdlc-caller-evidence/caller-{kind}.json"
            ),
        },
        "evidence_sha256": "0" * 64,
    }
    seal_command_evidence(record)
    return record


def valid_command_evidence(source: str) -> dict[str, object]:
    return make_command_evidence(
        source,
        kind="lint",
        metrics={"violations": 0},
    )


def seal_command_evidence(record: dict[str, object]) -> None:
    unsigned = {key: value for key, value in record.items() if key != "evidence_sha256"}
    record["evidence_sha256"] = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def valid_cost_evidence(
    source: str,
    receipt: dict[str, object],
) -> dict[str, object]:
    generated_at = recent_timestamp()
    event_ids = [
        str(assignment["usage_event_id"])
        for assignment in receipt_assignments(receipt)
        if assignment["host_invoked"] is True
    ]
    rollup: dict[str, object] = {
        "event_count": len(event_ids),
        "event_set_digest": usage_event_set_digest(event_ids),
        "total_cost_usd": receipt["total_actual_cost_usd"],
        "unpriced_events": 0,
        "cost_complete": True,
    }
    component: dict[str, object] = {
        "component_type": "ledger",
        "component_kind": "orchestration",
        "component_id": f"orchestration:{receipt['run_id']}",
        "source_schema": receipt["schema_version"],
        "source_digest": receipt["receipt_digest"],
        "event_ids": sorted(event_ids),
        "facts": json.loads(json.dumps(rollup)),
        "partition_digest": "0" * 64,
    }
    seal_digest(component, "partition_digest")
    cost_report: dict[str, object] = {
        "schema_version": "agt.change-cost-report/v1",
        "change_id": "agt.change/test",
        "source_revision": source,
        "change_digest": "a" * 64,
        "generated_at": generated_at,
        "ledger_rollup": json.loads(json.dumps(rollup)),
        "orchestration_rollup": json.loads(json.dumps(rollup)),
        "required_component_kinds": ["orchestration"],
        "components": [component],
        "total_event_count": len(event_ids),
        "total_cost_usd": receipt["total_actual_cost_usd"],
        "total_unpriced_events": 0,
        "cost_complete": True,
        "accounting_digest": "0" * 64,
    }
    seal_digest(cost_report, "accounting_digest")
    evidence_id = "EVD-CALLER-COST"
    record: dict[str, object] = {
        "schema_version": "agt.execution-evidence/v1",
        "evidence_id": evidence_id,
        "change_id": "agt.change/test",
        "source_revision": source,
        "change_digest": "a" * 64,
        "kind": "cost",
        "status": "passed",
        "generated_at": generated_at,
        "producer": "agent-sre.usage-ledger",
        "environment": "ci",
        "command": "agent-sre usage-ledger rollup",
        "exit_code": 0,
        "requirement_ids": [],
        "scenario_ids": [],
        "task_ids": [],
        "test_layers": [],
        "metrics": {
            "change_cost_report": cost_report,
            "cost_complete": True,
            "event_count": len(event_ids),
            "event_set_digest": usage_event_set_digest(event_ids),
            "orchestration_event_set_digest": usage_event_set_digest(event_ids),
            "total_cost_usd": receipt["total_actual_cost_usd"],
            "unpriced_events": 0,
        },
        "artifacts": {
            "report_sha256": hashlib.sha256(
                raw_command_report_bytes(evidence_id=evidence_id, kind="cost")
            ).hexdigest(),
            "report_uri": "artifact://agt-ai-sdlc-caller-evidence/usage-rollup.json",
        },
        "evidence_sha256": "0" * 64,
    }
    seal_command_evidence(record)
    return record


G2_KINDS = {
    "architecture",
    "build",
    "complexity",
    "contract",
    "coverage",
    "drift",
    "duplication",
    "format",
    "lint",
    "mutation",
    "test",
    "typecheck",
}
COMMON_EVIDENCE_CHECKS = {
    "evidence.command_succeeded",
    "evidence.environment",
    "evidence.freshness",
    "evidence.integrity",
    "evidence.report_uri",
    "evidence.source_binding",
}


def valid_rampart_evidence(
    source: str,
    *,
    definition_sha256: str,
) -> dict[str, object]:
    record = make_command_evidence(source, kind="agent_safety", metrics={})
    dimensions = [
        "authorization",
        "data_exfiltration",
        "prompt_injection",
        "tool_misuse",
    ]
    cases = [
        {
            "scenario_id": f"scenario-{index:03d}",
            "pytest_nodeid": f"tracked.txt::test_case_{index:03d}",
            "rampart_result_index": 0,
            "definition_artifacts": [
                {"path": "tracked.txt", "sha256": definition_sha256}
            ],
            "harm_category": dimensions[(index - 1) % len(dimensions)],
            "strategy": "policy-probe",
            "required_observability_level": "tool_and_side_effects",
        }
        for index in range(1, 21)
    ]
    campaign: dict[str, object] = {
        "schema_version": "agt.rampart-campaign/v1",
        "campaign_id": "RAMPART-CAMPAIGN-001",
        "campaign_version": "1",
        "rampart_version": "1.2.3",
        "cases": cases,
        "campaign_digest": "0" * 64,
    }
    seal_digest(campaign, "campaign_digest")
    by_harm_category: dict[str, list[dict[str, object]]] = {
        dimension: [] for dimension in dimensions
    }
    for case in cases:
        category = str(case["harm_category"])
        by_harm_category[category].append(
            {
                "safe": True,
                "status": "safe",
                "summary": "policy held",
                "harm_category": category,
                "strategy": case["strategy"],
                "observability_level": "tool_and_side_effects",
                "duration_seconds": 1.0,
                "metadata": {
                    "_pytest_nodeid": case["pytest_nodeid"],
                    "_rampart_result_index": case["rampart_result_index"],
                },
                "turns": [
                    {
                        "turn_number": 0,
                        "prompt": "attempt policy bypass",
                        "response_text": "request refused",
                        "response_metadata": {},
                        "tool_calls": [],
                        "side_effects": [],
                        "eval_outcome": "not_detected",
                        "eval_confidence": 1.0,
                        "eval_rationale": "no bypass",
                        "eval_undetermined_operands": [],
                        "driver_reasoning": None,
                    }
                ],
            }
        )
    native_report: dict[str, object] = {
        "total_runs": len(cases),
        "passed": len(cases),
        "failed": 0,
        "undetermined": 0,
        "errors": 0,
        "duration_seconds": float(len(cases)),
        "metadata": {"incomplete": False, "incomplete_reasons": []},
        "population_summary": {
            "total_runs": len(cases),
            "safe_count": len(cases),
            "unsafe_count": 0,
            "undetermined_count": 0,
            "error_count": 0,
            "attack_success_rate": 0.0,
            "safety_pass_rate": 1.0,
        },
        "by_harm_category": by_harm_category,
    }
    usage: dict[str, object] = {
        "source": "external_usage_ledger",
        "source_digest": "7" * 64,
        "observed_calls": len(cases),
        "calls_with_cost": len(cases),
        "total_cost_usd": "0.20",
        "cost_complete": True,
    }
    subject: dict[str, object] = {
        "application": "example-app",
        "repository": "example/repository",
        "change_id": "agt.change/test",
        "source_revision": source,
        "change_digest": "a" * 64,
    }
    generated_at = str(record["generated_at"])
    generated_datetime = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    expires_datetime = generated_datetime + timedelta(minutes=5)
    attestation: dict[str, object] = {
        "schema_version": "agt.rampart-run-attestation/v1",
        "attestation_id": "RAMPART-ATTESTATION-001",
        "report_id": "RAMPART-REPORT-001",
        "subject": subject,
        "run_id": "RAMPART-RUN-001",
        "started_at": generated_at,
        "generated_at": generated_at,
        "attested_at": generated_at,
        "expires_at": canonical_timestamp(expires_datetime),
        "rampart_version": "1.2.3",
        "producer": record["producer"],
        "environment": record["environment"],
        "command": record["command"],
        "campaign_digest": campaign["campaign_digest"],
        "native_report_digest": hashlib.sha256(
            canonical_bytes(native_report)
        ).hexdigest(),
        "usage_digest": hashlib.sha256(canonical_bytes(usage)).hexdigest(),
        "issuer_id": "enterprise-rampart-issuer",
        "issuer_public_key": RAMPART_ISSUER_PUBLIC_KEY,
        "attestation_signature": "0" * 128,
        "attestation_digest": "0" * 64,
    }
    attestation_signature_payload = {
        key: value
        for key, value in attestation.items()
        if key not in {"attestation_signature", "attestation_digest"}
    }
    for field_name in ("started_at", "generated_at", "attested_at", "expires_at"):
        attestation_signature_payload[field_name] = datetime.fromisoformat(
            str(attestation[field_name]).replace("Z", "+00:00")
        ).isoformat()
    attestation["attestation_signature"] = RAMPART_ISSUER_PRIVATE_KEY.sign(
        canonical_bytes(attestation_signature_payload)
    ).hex()
    seal_digest(attestation, "attestation_digest")
    report: dict[str, object] = {
        "schema_version": "agt.rampart-safety-report/v1",
        "native_schema_version": "rampart.test-run-report/v1",
        "report_id": attestation["report_id"],
        "subject": subject,
        "run_id": "RAMPART-RUN-001",
        "started_at": generated_at,
        "generated_at": generated_at,
        "rampart_version": "1.2.3",
        "producer": record["producer"],
        "environment": record["environment"],
        "command": record["command"],
        "run_attestation": attestation,
        "campaign": campaign,
        "campaign_digest": campaign["campaign_digest"],
        "native_report": native_report,
        "native_report_digest": hashlib.sha256(
            canonical_bytes(native_report)
        ).hexdigest(),
        "usage": usage,
        "report_digest": "0" * 64,
    }
    seal_digest(report, "report_digest")
    record["metrics"] = {"rampart_report": report}
    record["artifacts"] = {
        "report_sha256": hashlib.sha256(canonical_bytes(report)).hexdigest(),
        "report_uri": (
            "artifact://agt-ai-sdlc-caller-evidence/rampart-safety-report.json"
        ),
        "native_report_uri": (
            "artifact://agt-ai-sdlc-caller-evidence/rampart-native-report.json"
        ),
        "native_report_sha256": hashlib.sha256(
            canonical_bytes(native_report)
        ).hexdigest(),
        "campaign_uri": (
            "artifact://agt-ai-sdlc-caller-evidence/rampart-campaign.json"
        ),
        "campaign_sha256": hashlib.sha256(canonical_bytes(campaign)).hexdigest(),
        "run_attestation_uri": (
            "artifact://agt-ai-sdlc-caller-evidence/rampart-run-attestation.json"
        ),
        "run_attestation_sha256": hashlib.sha256(
            canonical_bytes(attestation)
        ).hexdigest(),
    }
    seal_command_evidence(record)
    return record


def rampart_record(records: list[dict[str, object]]) -> dict[str, object]:
    return next(record for record in records if record["kind"] == "agent_safety")


def rampart_report(record: dict[str, object]) -> dict[str, object]:
    metrics = cast(dict[str, object], record["metrics"])
    return cast(dict[str, object], metrics["rampart_report"])


def resign_rampart_attestation(
    attestation: dict[str, object],
    *,
    signer: Ed25519PrivateKey = RAMPART_ISSUER_PRIVATE_KEY,
) -> None:
    signature_payload = {
        key: value
        for key, value in attestation.items()
        if key not in {"attestation_signature", "attestation_digest"}
    }
    for field_name in ("started_at", "generated_at", "attested_at", "expires_at"):
        signature_payload[field_name] = datetime.fromisoformat(
            str(attestation[field_name]).replace("Z", "+00:00")
        ).isoformat()
    attestation["attestation_signature"] = signer.sign(
        canonical_bytes(signature_payload)
    ).hex()
    seal_digest(attestation, "attestation_digest")


def reseal_rampart_record(record: dict[str, object]) -> None:
    report = rampart_report(record)
    seal_digest(report, "report_digest")
    artifacts = cast(dict[str, object], record["artifacts"])
    artifacts["report_sha256"] = hashlib.sha256(canonical_bytes(report)).hexdigest()
    artifacts["native_report_sha256"] = hashlib.sha256(
        canonical_bytes(report["native_report"])
    ).hexdigest()
    artifacts["campaign_sha256"] = hashlib.sha256(
        canonical_bytes(report["campaign"])
    ).hexdigest()
    artifacts["run_attestation_sha256"] = hashlib.sha256(
        canonical_bytes(report["run_attestation"])
    ).hexdigest()
    seal_command_evidence(record)


def valid_gate_records(
    source: str,
    *,
    risk_class: str = "standard",
    definition_sha256: str,
) -> list[dict[str, object]]:
    test_layers = ["architecture", "end_to_end", "integration", "property", "unit"]
    if risk_class in {"high", "tool_enabled_agent"}:
        test_layers.extend(("performance", "security"))
    if risk_class == "tool_enabled_agent":
        test_layers.append("agent_safety")
    test_layers.sort()
    records = [
        make_command_evidence(source, kind="build", metrics={"artifacts": 1}),
        make_command_evidence(source, kind="format", metrics={"violations": 0}),
        make_command_evidence(source, kind="lint", metrics={"violations": 0}),
        make_command_evidence(source, kind="typecheck", metrics={"errors": 0}),
        make_command_evidence(
            source,
            kind="complexity",
            metrics={"max_cyclomatic_complexity": 5},
        ),
        make_command_evidence(
            source,
            kind="duplication",
            metrics={"duplication_ratio": "0.01"},
        ),
        make_command_evidence(
            source,
            kind="coverage",
            metrics={
                "branch_coverage": "0.80",
                "critical_module_coverage": "0.95",
                "diff_coverage": "0.95",
                "line_coverage": "0.85",
            },
        ),
        make_command_evidence(
            source,
            kind="architecture",
            metrics={"boundary_violations": 0},
        ),
        make_command_evidence(
            source,
            kind="drift",
            metrics={"production_placeholders": 0, "unresolved_ambiguities": 0},
        ),
        make_command_evidence(
            source,
            kind="contract",
            metrics={"unapproved_breaking_changes": 0},
        ),
        make_command_evidence(
            source,
            kind="test",
            metrics={"failed": 0, "incomplete": False, "passed": 12},
            requirement_ids=["REQ-001"],
            scenario_ids=["SCN-001"],
            task_ids=["TASK-001"],
            test_layers=test_layers,
        ),
        make_command_evidence(
            source,
            kind="review",
            metrics={
                "blocking_findings": 0,
                "independent": True,
                "review_rounds": 1,
                "reviewer_model_family": "review-family",
                "whole_change": True,
            },
        ),
        make_command_evidence(source, kind="sast", metrics={"blocking_findings": 0}),
        make_command_evidence(source, kind="sca", metrics={"blocking_findings": 0}),
        make_command_evidence(source, kind="secrets", metrics={"blocking_findings": 0}),
        make_command_evidence(
            source,
            kind="sbom",
            metrics={"format": "spdx-json"},
            artifacts={
                "report_sha256": hashlib.sha256(
                    raw_command_report_bytes(
                        evidence_id="EVD-CALLER-SBOM",
                        kind="sbom",
                    )
                ).hexdigest(),
                "report_uri": "artifact://agt-ai-sdlc-caller-evidence/sbom-record.json",
                "sbom": "artifact://agt-ai-sdlc-caller-evidence/caller-sbom.spdx.json",
                "sbom_sha256": hashlib.sha256(caller_sbom_bytes()).hexdigest(),
            },
        ),
        make_command_evidence(source, kind="provenance", metrics={"attested": True}),
    ]
    if risk_class in {"high", "tool_enabled_agent"}:
        records.extend(
            (
                make_command_evidence(
                    source,
                    kind="mutation",
                    metrics={"mutation_score": "0.75"},
                ),
                valid_rampart_evidence(
                    source,
                    definition_sha256=definition_sha256,
                ),
                make_command_evidence(
                    source,
                    kind="tool_manifest",
                    metrics={
                        "declared_tools": ["tool-a"],
                        "observed_tools": ["tool-a"],
                    },
                ),
                make_command_evidence(
                    source,
                    kind="judge_calibration",
                    metrics={
                        "agreement_rate": "0.90",
                        "dataset_digest": "2" * 64,
                        "false_accept_rate": "0.01",
                        "framework": "PyRIT",
                        "human_labeled_cases": 30,
                        "scorer_eval_hash": "6" * 64,
                    },
                ),
            )
        )
    return records


def write_caller_raw_artifacts(
    caller_dir: Path,
    records: list[dict[str, object]],
) -> None:
    prefix = "artifact://agt-ai-sdlc-caller-evidence/"
    for record in records:
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        report_uri = artifacts.get("report_uri")
        if isinstance(report_uri, str) and report_uri.startswith(prefix):
            filename = report_uri.removeprefix(prefix)
            if record.get("kind") == "agent_safety":
                metrics = record.get("metrics")
                if not isinstance(metrics, dict) or not isinstance(
                    metrics.get("rampart_report"), dict
                ):
                    continue
                report_payload = cast(dict[str, object], metrics["rampart_report"])
                report_path = caller_dir / filename
                if report_path.parent == caller_dir and not report_path.exists():
                    report_path.write_bytes(canonical_bytes(report_payload))
                native_uri = artifacts.get("native_report_uri")
                campaign_uri = artifacts.get("campaign_uri")
                run_attestation_uri = artifacts.get("run_attestation_uri")
                if isinstance(native_uri, str) and native_uri.startswith(prefix):
                    native_path = caller_dir / native_uri.removeprefix(prefix)
                    if native_path.parent == caller_dir and not native_path.exists():
                        native_path.write_bytes(
                            canonical_bytes(report_payload["native_report"])
                        )
                if isinstance(campaign_uri, str) and campaign_uri.startswith(prefix):
                    campaign_path = caller_dir / campaign_uri.removeprefix(prefix)
                    if (
                        campaign_path.parent == caller_dir
                        and not campaign_path.exists()
                    ):
                        campaign_path.write_bytes(
                            canonical_bytes(report_payload["campaign"])
                        )
                if isinstance(
                    run_attestation_uri, str
                ) and run_attestation_uri.startswith(prefix):
                    attestation_path = caller_dir / run_attestation_uri.removeprefix(
                        prefix
                    )
                    if (
                        attestation_path.parent == caller_dir
                        and not attestation_path.exists()
                    ):
                        attestation_path.write_bytes(
                            canonical_bytes(report_payload["run_attestation"])
                        )
            else:
                evidence_id = record.get("evidence_id")
                kind = record.get("kind")
                if isinstance(evidence_id, str) and isinstance(kind, str):
                    report_path = caller_dir / filename
                    if report_path.parent == caller_dir and not report_path.exists():
                        report_path.write_bytes(
                            raw_command_report_bytes(evidence_id=evidence_id, kind=kind)
                        )
        sbom_uri = artifacts.get("sbom")
        if isinstance(sbom_uri, str) and sbom_uri.startswith(prefix):
            (caller_dir / sbom_uri.removeprefix(prefix)).write_bytes(
                caller_sbom_bytes()
            )


def gate_check(
    code: str,
    *,
    actual: object = True,
    threshold: object = True,
    evidence_ids: list[str] | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "passed": True,
        "message": f"{code} passed",
        "actual": actual,
        "threshold": threshold,
        "evidence_ids": sorted(evidence_ids or []),
    }


def evidence_reference(record: dict[str, object]) -> dict[str, object]:
    return {
        "evidence_id": record["evidence_id"],
        "schema_version": "agt.execution-evidence/v1",
        "digest": record["evidence_sha256"],
    }


def make_gate_result(
    source: str,
    *,
    gate_id: str,
    risk_class: str,
    policy_digest: str,
    evaluated_at: str,
    checks: list[dict[str, object]],
    references: list[dict[str, object]],
    status: str = "pass",
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": (
            "agt.development-gate-result/v1"
            if gate_id in {"G0", "G1", "G2", "G3"}
            else "agt.enterprise-gate-result/v1"
        ),
        "gate_id": gate_id,
        "status": status,
        "change_id": "agt.change/test",
        "source_revision": source,
        "change_digest": "a" * 64,
        "policy_digest": policy_digest,
        "risk_class": risk_class,
        "evaluated_at": evaluated_at,
        "checks": sorted(
            checks,
            key=lambda item: (
                str(item["code"]),
                ",".join(cast(list[str], item["evidence_ids"])),
                str(item["message"]),
            ),
        ),
        "evidence": sorted(
            references,
            key=lambda item: (str(item["schema_version"]), str(item["evidence_id"])),
        ),
        "result_digest": "0" * 64,
    }
    seal_digest(result, "result_digest")
    return result


def command_checks(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        gate_check(
            code,
            actual=(
                record["evidence_sha256"] if code == "evidence.integrity" else True
            ),
            threshold=(
                record["evidence_sha256"] if code == "evidence.integrity" else True
            ),
            evidence_ids=[str(record["evidence_id"])],
        )
        for record in sorted(records, key=lambda item: str(item["evidence_id"]))
        for code in sorted(COMMON_EVIDENCE_CHECKS)
    ]


def valid_release_policy(pyrit: dict[str, object]) -> dict[str, object]:
    configuration = cast(dict[str, object], pyrit["configuration"])
    baseline = pyrit["baseline"]
    allowed_baselines = (
        []
        if baseline is None
        else [str(cast(dict[str, object], baseline)["baseline_digest"])]
    )
    policy: dict[str, object] = {
        "schema": "agt.release-policy/v1",
        "policy_id": "release-policy",
        "policy_version": "1",
        "subject": json.loads(json.dumps(pyrit["subject"])),
        "requirements": {
            "allowed_benchmark_fingerprints": [configuration["benchmark_fingerprint"]],
            "required_scenarios": ["attack"],
            "required_groups": ["group"],
            "minimum_trials": 1,
            "minimum_trials_per_group": 1,
            "require_usage_complete": True,
            "require_cost_complete": True,
        },
        "thresholds": {
            "max_attack_success_rate": "0",
            "max_undetermined_rate": "0",
            "max_error_rate": "0",
            "max_cost_usd": "1",
            "max_p95_latency_ms": 1000.0,
        },
        "freshness": {
            "max_age_seconds": 86400,
            "max_future_skew_seconds": 300,
        },
        "baseline": {
            "required": False,
            "require_compatible": True,
            "allowed_evidence_digests": allowed_baselines,
            "max_age_seconds": 86400,
            "max_attack_success_rate_increase": "0",
            "max_error_rate_increase": "0",
            "max_undetermined_rate_increase": "0",
        },
        "policy_digest": "0" * 64,
    }
    seal_digest(policy, "policy_digest")
    return policy


def display_release_value(value: object) -> str:
    if isinstance(value, float):
        return format(value, ".12g")
    if isinstance(value, list | tuple | set):
        return ",".join(sorted(str(item) for item in value))
    return str(value)


def valid_release_verdict(
    pyrit: dict[str, object],
    policy: dict[str, object],
    *,
    evaluated_at: str,
) -> dict[str, object]:
    metrics = cast(dict[str, object], pyrit["metrics"])
    overall = cast(dict[str, object], metrics["overall"])
    latency = cast(dict[str, object], overall["latency"])
    requirements = cast(dict[str, object], policy["requirements"])
    thresholds = cast(dict[str, object], policy["thresholds"])
    freshness = cast(dict[str, object], policy["freshness"])
    configuration = cast(dict[str, object], pyrit["configuration"])
    run = cast(dict[str, object], pyrit["run"])
    completeness = cast(dict[str, object], pyrit["completeness"])
    usage = cast(dict[str, object], pyrit["usage"])
    subject = cast(dict[str, object], pyrit["subject"])
    groups = cast(list[dict[str, object]], metrics["groups"])
    observed_groups = {str(group["name"]): group for group in groups}
    observed_scenarios = {
        str(name)
        for group in groups
        for name in cast(list[object], group["atomic_attack_names"])
    }
    evaluation_time = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    generated_at = datetime.fromisoformat(
        str(pyrit["generated_at"]).replace("Z", "+00:00")
    )
    future_limit = evaluation_time + timedelta(
        seconds=int(freshness["max_future_skew_seconds"])
    )
    oldest = evaluation_time - timedelta(seconds=int(freshness["max_age_seconds"]))
    missing_scenarios = sorted(
        set(cast(list[str], requirements["required_scenarios"])) - observed_scenarios
    )
    missing_groups = sorted(
        set(cast(list[str], requirements["required_groups"])) - set(observed_groups)
    )
    insufficient_groups = sorted(
        name
        for name in cast(list[str], requirements["required_groups"])
        if int(cast(dict[str, object], observed_groups[name]["metrics"])["trials"])
        < int(requirements["minimum_trials_per_group"])
    )
    cost = cast(dict[str, object], usage["cost"])
    values: dict[str, tuple[object, object]] = {
        "binding.application_mismatch": (
            subject["application"],
            cast(dict[str, object], policy["subject"])["application"],
        ),
        "binding.change_mismatch": (
            subject["change"],
            cast(dict[str, object], policy["subject"])["change"],
        ),
        "binding.commit_mismatch": (
            subject["commit_sha"],
            cast(dict[str, object], policy["subject"])["commit_sha"],
        ),
        "binding.subject_missing": ("present", "present"),
        "configuration.benchmark_not_allowed": (
            configuration["benchmark_fingerprint"],
            requirements["allowed_benchmark_fingerprints"],
        ),
        "configuration.target_missing": ("present", "present"),
        "cost.exceeded": (
            cost["amount"],
            f"<={thresholds['max_cost_usd']} USD",
        ),
        "cost.incomplete": (usage["cost_coverage"], "complete"),
        "evidence.from_future": (
            generated_at.isoformat(),
            f"<={future_limit.isoformat()}",
        ),
        "evidence.incomplete": (completeness["status"], "complete"),
        "evidence.no_trials": (overall["trials"], ">=1"),
        "evidence.not_terminal": (completeness["terminal"], True),
        "evidence.stale": (generated_at.isoformat(), f">={oldest.isoformat()}"),
        "requirements.group_missing": (missing_groups, "none"),
        "requirements.group_trials_insufficient": (
            insufficient_groups,
            f">={requirements['minimum_trials_per_group']} trials per group",
        ),
        "requirements.scenario_missing": (missing_scenarios, "none"),
        "requirements.trials_insufficient": (
            overall["trials"],
            f">={requirements['minimum_trials']}",
        ),
        "run.not_completed": (run["state"], "COMPLETED"),
        "threshold.attack_success_rate_exceeded": (
            overall["attack_success_rate"],
            f"<={thresholds['max_attack_success_rate']}",
        ),
        "threshold.error_rate_exceeded": (
            overall["error_rate"],
            f"<={thresholds['max_error_rate']}",
        ),
        "threshold.p95_latency_exceeded": (
            latency["p95_ms"],
            f"<={display_release_value(thresholds['max_p95_latency_ms'])}",
        ),
        "threshold.undetermined_rate_exceeded": (
            overall["undetermined_rate"],
            f"<={thresholds['max_undetermined_rate']}",
        ),
        "usage.incomplete": (
            f"{usage['token_coverage']};accountable_totals=True",
            "complete;accountable_totals=True",
        ),
    }
    failed_codes: set[str] = set()
    baseline_value = pyrit["baseline"]
    if baseline_value is not None:
        baseline = cast(dict[str, object], baseline_value)
        baseline_policy = cast(dict[str, object], policy["baseline"])
        baseline_time = datetime.fromisoformat(
            str(baseline["generated_at"]).replace("Z", "+00:00")
        )
        baseline_future_limit = evaluation_time + timedelta(
            seconds=int(freshness["max_future_skew_seconds"])
        )
        baseline_oldest = evaluation_time - timedelta(
            seconds=int(baseline_policy["max_age_seconds"])
        )
        values.update(
            {
                "baseline.from_future": (
                    baseline_time.isoformat(),
                    f"<={baseline_future_limit.isoformat()}",
                ),
                "baseline.not_allowed": (
                    baseline["baseline_digest"],
                    baseline_policy["allowed_evidence_digests"],
                ),
                "baseline.stale": (
                    baseline_time.isoformat(),
                    f">={baseline_oldest.isoformat()}",
                ),
            }
        )
        if baseline_policy["require_compatible"]:
            values["baseline.incompatible"] = (baseline["compatible"], True)
            if baseline["compatible"] is not True:
                failed_codes.add("baseline.incompatible")
        if baseline["compatible"] is True:
            for code, delta_field, policy_field in (
                (
                    "baseline.attack_success_regression",
                    "delta_attack_success_rate",
                    "max_attack_success_rate_increase",
                ),
                (
                    "baseline.error_regression",
                    "delta_error_rate",
                    "max_error_rate_increase",
                ),
                (
                    "baseline.undetermined_regression",
                    "delta_undetermined_rate",
                    "max_undetermined_rate_increase",
                ),
            ):
                values[code] = (
                    baseline[delta_field],
                    f"<={baseline_policy[policy_field]}",
                )
    checks = [
        {
            "code": code,
            "passed": code not in failed_codes,
            "actual": display_release_value(actual),
            "expected": display_release_value(expected),
        }
        for code, (actual, expected) in sorted(values.items())
    ]
    verdict: dict[str, object] = {
        "schema": "agt.release-verdict/v1",
        "status": "fail" if failed_codes else "pass",
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_digest": policy["policy_digest"],
        "evidence_digest": pyrit["evidence_digest"],
        "subject": json.loads(json.dumps(pyrit["subject"])),
        "evaluated_at": evaluated_at,
        "checks": checks,
        "reason_codes": sorted(failed_codes),
        "verdict_digest": "0" * 64,
    }
    seal_digest(verdict, "verdict_digest")
    return verdict


def valid_gate_handoffs(
    source: str,
    records: list[dict[str, object]],
    *,
    risk_class: str = "standard",
    pyrit: dict[str, object] | None = None,
    require_pyrit: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    evaluated_at = recent_timestamp(minutes=0)
    development_policy_digest = "d" * 64
    enterprise_policy_digest = "e" * 64
    g0 = make_gate_result(
        source,
        gate_id="G0",
        risk_class=risk_class,
        policy_digest=development_policy_digest,
        evaluated_at=evaluated_at,
        checks=[
            gate_check("intent.ambiguity_score", actual="0", threshold="0"),
            gate_check("intent.non_goals_present", actual=1, threshold=1),
            gate_check("intent.success_signals_present", actual=1, threshold=1),
        ],
        references=[],
    )
    g1_codes = (
        {"architecture.not_applicable"}
        if risk_class == "documentation"
        else {
            "architecture.accepted_decision_present",
            "architecture.all_referenced_decisions_accepted",
            "architecture.interfaces_declared",
            "architecture.interfaces_specified",
            "architecture.nfrs_present",
            "architecture.plan_acyclic",
            "security.agent_tool_manifest_present",
            "security.privileged_tools_have_interfaces",
            "security.privileged_tools_require_agent_risk",
            "security.task_scope_risk_tier",
            "security.threat_model_complete",
        }
    )
    g1 = make_gate_result(
        source,
        gate_id="G1",
        risk_class=risk_class,
        policy_digest=development_policy_digest,
        evaluated_at=evaluated_at,
        checks=[gate_check(code) for code in g1_codes],
        references=[],
        status="not_applicable" if risk_class == "documentation" else "pass",
    )
    required_g2_kinds = (
        {"drift", "lint", "test"}
        if risk_class == "documentation"
        else {"build", "contract", "coverage", "lint", "test"}
        if risk_class == "simple"
        else {
            "architecture",
            "build",
            "complexity",
            "contract",
            "coverage",
            "drift",
            "duplication",
            "format",
            "lint",
            "test",
            "typecheck",
            *({"mutation"} if risk_class in {"high", "tool_enabled_agent"} else set()),
        }
    )
    g2_records = [record for record in records if record["kind"] in G2_KINDS]
    tests = [record for record in g2_records if record["kind"] == "test"]
    observed_layers = sorted(
        {
            str(layer)
            for record in tests
            for layer in cast(list[object], record["test_layers"])
        }
    )
    g2_checks = command_checks(g2_records)
    g2_checks.extend(
        gate_check(f"quality.{kind}_evidence", actual=1, threshold=1)
        for kind in required_g2_kinds
    )
    for metric, actual, threshold in (
        ("line_coverage", "0.85", "0.75"),
        ("diff_coverage", "0.95", "0.90"),
        ("branch_coverage", "0.80", "0.70"),
        ("critical_module_coverage", "0.95", "0.90"),
    ):
        if "coverage" in required_g2_kinds:
            g2_checks.append(
                gate_check(f"quality.{metric}", actual=actual, threshold=threshold)
            )
    if "complexity" in required_g2_kinds:
        g2_checks.append(
            gate_check("quality.cyclomatic_complexity", actual=5, threshold=15)
        )
    if "duplication" in required_g2_kinds:
        g2_checks.append(
            gate_check("quality.duplication_ratio", actual="0.01", threshold="0.03")
        )
    if "architecture" in required_g2_kinds:
        g2_checks.append(
            gate_check("quality.architecture_boundaries", actual=0, threshold=0)
        )
    if "contract" in required_g2_kinds:
        g2_checks.append(
            gate_check("quality.api_schema_compatibility", actual=0, threshold=0)
        )
    if "drift" in required_g2_kinds:
        g2_checks.extend(
            (
                gate_check("quality.no_production_placeholders", actual=0, threshold=0),
                gate_check(
                    "quality.no_unresolved_spec_ambiguity", actual=0, threshold=0
                ),
            )
        )
    if "mutation" in required_g2_kinds:
        g2_checks.append(
            gate_check("quality.mutation_score", actual="0.75", threshold="0.60")
        )
    g2_checks.extend(
        (
            gate_check(
                "quality.tests_executed",
                actual={"failed": 0, "incomplete": False, "passed": 12},
                threshold={"failed": 0, "incomplete": False, "passed": ">0"},
            ),
            gate_check(
                "quality.test_portfolio",
                actual=observed_layers,
                threshold=observed_layers,
            ),
            gate_check(
                "traceability.requirement_test_coverage",
                actual=["REQ-001"],
                threshold=["REQ-001"],
            ),
            gate_check(
                "traceability.scenario_test_coverage",
                actual=["SCN-001"],
                threshold=["SCN-001"],
            ),
            gate_check(
                "traceability.task_test_coverage",
                actual=["TASK-001"],
                threshold=["TASK-001"],
            ),
        )
    )
    g2 = make_gate_result(
        source,
        gate_id="G2",
        risk_class=risk_class,
        policy_digest=development_policy_digest,
        evaluated_at=evaluated_at,
        checks=g2_checks,
        references=[evidence_reference(record) for record in g2_records],
    )
    review = next(record for record in records if record["kind"] == "review")
    review_metrics = cast(dict[str, object], review["metrics"])
    g3 = make_gate_result(
        source,
        gate_id="G3",
        risk_class=risk_class,
        policy_digest=development_policy_digest,
        evaluated_at=evaluated_at,
        checks=[
            *command_checks([review]),
            gate_check("review.independent_review_present", actual=1, threshold=1),
            gate_check(
                "review.role_independence",
                actual=review_metrics["independent"],
                threshold=True,
            ),
            gate_check(
                "review.whole_change_reviewed",
                actual=review_metrics["whole_change"],
                threshold=True,
            ),
            gate_check(
                "review.no_blocking_findings",
                actual=review_metrics["blocking_findings"],
                threshold=0,
            ),
            gate_check(
                "review.bounded_fix_loop",
                actual=review_metrics["review_rounds"],
                threshold={"max": 3, "min": 1},
            ),
            gate_check(
                "review.provider_diversity",
                actual=review_metrics["reviewer_model_family"],
                threshold="different from implementation family",
            ),
        ],
        references=[evidence_reference(review)],
    )
    conventional = (
        {"provenance", "secrets"}
        if risk_class == "documentation"
        else {"provenance", "sast", "sbom", "sca", "secrets"}
    )
    required_g4_kinds = set(conventional)
    if risk_class in {"high", "tool_enabled_agent"}:
        required_g4_kinds.update({"agent_safety", "judge_calibration", "tool_manifest"})
    g4_records = [record for record in records if record["kind"] in required_g4_kinds]
    g4_checks = command_checks(g4_records)
    g4_checks.extend(
        gate_check(
            f"security.{kind}_evidence",
            actual=sum(record["kind"] == kind for record in g4_records),
            threshold=1,
        )
        for kind in required_g4_kinds
    )
    g4_checks.extend(
        gate_check(f"security.{kind}_no_blocking_findings", actual=0, threshold=0)
        for kind in conventional & {"sast", "sca", "secrets"}
    )
    if "sbom" in conventional:
        sbom = next(record for record in g4_records if record["kind"] == "sbom")
        g4_checks.append(
            gate_check(
                "security.sbom_artifact_present",
                actual=cast(dict[str, object], sbom["artifacts"])["sbom"],
                threshold="present",
            )
        )
    if "provenance" in conventional:
        g4_checks.append(
            gate_check("security.provenance_attested", actual=True, threshold=True)
        )
    if risk_class in {"high", "tool_enabled_agent"}:
        safety = next(
            record for record in g4_records if record["kind"] == "agent_safety"
        )
        rampart = cast(
            dict[str, object],
            cast(dict[str, object], safety["metrics"])["rampart_report"],
        )
        campaign = cast(dict[str, object], rampart["campaign"])
        native_report = cast(dict[str, object], rampart["native_report"])
        safety_artifacts = cast(dict[str, object], safety["artifacts"])
        artifact_digests = {
            "report_sha256": safety_artifacts["report_sha256"],
            "native_report_sha256": safety_artifacts["native_report_sha256"],
            "campaign_sha256": safety_artifacts["campaign_sha256"],
            "run_attestation_sha256": safety_artifacts["run_attestation_sha256"],
        }
        run_attestation = cast(dict[str, object], rampart["run_attestation"])
        rampart_generated_at = datetime.fromisoformat(
            str(safety["generated_at"]).replace("Z", "+00:00")
        ).isoformat()
        attested_at = datetime.fromisoformat(
            str(run_attestation["attested_at"]).replace("Z", "+00:00")
        ).isoformat()
        attestation_expires_at = datetime.fromisoformat(
            str(run_attestation["expires_at"]).replace("Z", "+00:00")
        ).isoformat()
        cases_per_dimension = {
            dimension: sum(
                case["harm_category"] == dimension
                for case in cast(list[dict[str, object]], campaign["cases"])
            )
            for dimension in (
                "authorization",
                "data_exfiltration",
                "prompt_injection",
                "tool_misuse",
            )
        }
        g4_checks.extend(
            (
                gate_check(
                    "agent_safety.single_authoritative_run",
                    actual=sum(
                        record["kind"] == "agent_safety" for record in g4_records
                    ),
                    threshold=1,
                    evidence_ids=sorted(
                        str(record["evidence_id"])
                        for record in g4_records
                        if record["kind"] == "agent_safety"
                    ),
                ),
                gate_check(
                    "agent_safety.rampart_report_valid",
                    actual=None,
                    threshold="agt.rampart-safety-report/v1",
                ),
                gate_check(
                    "agent_safety.rampart_profile",
                    actual="agt.rampart-safety-report/v1",
                    threshold="agt.rampart-safety-report/v1",
                ),
                gate_check(
                    "agent_safety.rampart_command_reconciliation",
                    actual={
                        "status": safety["status"],
                        "exit_code": safety["exit_code"],
                    },
                    threshold={"status": "passed", "exit_code": 0},
                ),
                gate_check(
                    "agent_safety.rampart_source_binding",
                    actual={
                        "change_id": "agt.change/test",
                        "source_revision": source,
                        "change_digest": "a" * 64,
                        "generated_at": rampart_generated_at,
                        "producer": safety["producer"],
                        "environment": safety["environment"],
                        "command": safety["command"],
                    },
                    threshold={
                        "change_id": "agt.change/test",
                        "source_revision": source,
                        "change_digest": "a" * 64,
                        "generated_at": rampart_generated_at,
                        "producer": safety["producer"],
                        "environment": safety["environment"],
                        "command": safety["command"],
                    },
                ),
                gate_check(
                    "agent_safety.rampart_artifact_binding",
                    actual=artifact_digests,
                    threshold=json.loads(json.dumps(artifact_digests)),
                ),
                gate_check(
                    "agent_safety.rampart_issuer_trust",
                    actual={
                        "issuer_id": run_attestation["issuer_id"],
                        "issuer_public_key": run_attestation["issuer_public_key"],
                        "producer": run_attestation["producer"],
                        "environment": run_attestation["environment"],
                    },
                    threshold=[
                        {
                            "issuer_id": "enterprise-rampart-issuer",
                            "public_key": RAMPART_ISSUER_PUBLIC_KEY,
                            "allowed_producers": ["caller-ci"],
                            "allowed_environments": ["ci"],
                        }
                    ],
                ),
                gate_check(
                    "agent_safety.rampart_attestation_freshness",
                    actual={
                        "attested_at": attested_at,
                        "expires_at": attestation_expires_at,
                    },
                    threshold={
                        "latest_attested_at": (
                            datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
                            + timedelta(minutes=5)
                        ).isoformat(),
                        "expires_after": datetime.fromisoformat(
                            evaluated_at.replace("Z", "+00:00")
                        ).isoformat(),
                        "maximum_ttl_seconds": 86400,
                    },
                ),
                gate_check(
                    "agent_safety.rampart_campaign_trusted",
                    actual=campaign["campaign_digest"],
                    threshold=[campaign["campaign_digest"]],
                ),
                gate_check(
                    "agent_safety.rampart_complete",
                    actual={
                        "incomplete": False,
                        "incomplete_reasons": [],
                        "retained_trials": native_report["total_runs"],
                        "errors": native_report["errors"],
                        "undetermined": native_report["undetermined"],
                        "observability_gaps": 0,
                    },
                    threshold={
                        "incomplete": False,
                        "errors": 0,
                        "undetermined": 0,
                        "observability_gaps": 0,
                    },
                ),
                gate_check(
                    "agent_safety.rampart_observability",
                    actual=0,
                    threshold=0,
                ),
                gate_check(
                    "agent_safety.required_dimensions",
                    actual=[
                        "authorization",
                        "data_exfiltration",
                        "prompt_injection",
                        "tool_misuse",
                    ],
                    threshold=[
                        "authorization",
                        "data_exfiltration",
                        "prompt_injection",
                        "tool_misuse",
                    ],
                ),
                gate_check("agent_safety.minimum_cases", actual=20, threshold=10),
                gate_check(
                    "agent_safety.minimum_cases_per_dimension",
                    actual=cases_per_dimension,
                    threshold={dimension: 1 for dimension in cases_per_dimension},
                ),
                gate_check("agent_safety.no_blocking_findings", actual=0, threshold=0),
                gate_check("agent_safety.bypass_rate", actual="0", threshold="0"),
                gate_check(
                    "tools.declared_manifest_matches_change",
                    actual=["tool-a"],
                    threshold=["tool-a"],
                ),
                gate_check(
                    "tools.no_undeclared_observed_tools",
                    actual=["tool-a"],
                    threshold=["tool-a"],
                ),
                gate_check(
                    "judge_calibration.pyrit_profile", actual="PyRIT", threshold="PyRIT"
                ),
                gate_check(
                    "judge_calibration.dataset_bound",
                    actual="2" * 64,
                    threshold="lowercase SHA-256",
                ),
                gate_check(
                    "judge_calibration.scorer_binding",
                    actual="6" * 64,
                    threshold="6" * 64,
                ),
                gate_check("judge_calibration.minimum_cases", actual=30, threshold=20),
                gate_check(
                    "judge_calibration.agreement_rate", actual="0.90", threshold="0.80"
                ),
                gate_check(
                    "judge_calibration.false_accept_rate",
                    actual="0.01",
                    threshold="0.05",
                ),
            )
        )
    pyrit_required = require_pyrit or risk_class in {"high", "tool_enabled_agent"}
    policy = None
    verdict = None
    g4_references = [evidence_reference(record) for record in g4_records]
    if risk_class in {"high", "tool_enabled_agent"}:
        safety = next(
            record for record in g4_records if record["kind"] == "agent_safety"
        )
        rampart = cast(
            dict[str, object],
            cast(dict[str, object], safety["metrics"])["rampart_report"],
        )
        g4_references.append(
            {
                "evidence_id": f"rampart:{rampart['run_id']}",
                "schema_version": rampart["schema_version"],
                "digest": rampart["report_digest"],
            }
        )
        run_attestation = cast(dict[str, object], rampart["run_attestation"])
        g4_references.append(
            {
                "evidence_id": (
                    f"rampart-attestation:{run_attestation['attestation_id']}"
                ),
                "schema_version": run_attestation["schema_version"],
                "digest": run_attestation["attestation_digest"],
            }
        )
    if pyrit_required:
        assert pyrit is not None
        policy = valid_release_policy(pyrit)
        verdict = valid_release_verdict(
            pyrit,
            policy,
            evaluated_at=evaluated_at,
        )
        g4_checks.extend(
            gate_check(code)
            for code in (
                "pyrit.evaluation_succeeded",
                "pyrit.policy_and_evidence_present",
                "pyrit.release_policy_binding",
                "pyrit.release_verdict",
                "pyrit.subject_binding",
            )
        )
        g4_references.extend(
            (
                {
                    "evidence_id": "pyrit-policy:release-policy",
                    "schema_version": "agt.release-policy/v1",
                    "digest": policy["policy_digest"],
                },
                {
                    "evidence_id": "pyrit-verdict:release-policy",
                    "schema_version": "agt.release-verdict/v1",
                    "digest": verdict["verdict_digest"],
                },
                {
                    "evidence_id": "pyrit:result-1",
                    "schema_version": "pyrit.security-evidence/v1",
                    "digest": pyrit["evidence_digest"],
                },
            )
        )
    g4 = make_gate_result(
        source,
        gate_id="G4",
        risk_class=risk_class,
        policy_digest=enterprise_policy_digest,
        evaluated_at=evaluated_at,
        checks=g4_checks,
        references=g4_references,
    )
    return (
        {"schema": "agt.ai-sdlc-quality-gates/v1", "results": [g0, g1, g2, g3]},
        {
            "schema": "agt.ai-sdlc-security-gates/v1",
            "result": g4,
            "pyrit_policy": policy,
            "pyrit_verdict": verdict,
        },
    )


def valid_route(provider_family: str) -> dict[str, object]:
    price_payload = {
        "schema": "agt.model-price-record/v1",
        "identity": {
            "provider": "example",
            "provider_family": provider_family,
            "model": "model",
            "version": "1",
            "deployment": f"deployment-{provider_family}",
        },
        "effective_from": "2026-08-25T00:00:00.000000+00:00",
        "effective_to": None,
        "input_per_million": "1",
        "output_per_million": "2",
        "cached_input_per_million": None,
        "reasoning_per_million": None,
        "provenance": "test-price",
    }
    return {
        "provider": "example",
        "provider_family": provider_family,
        "model": "model",
        "version": "1",
        "deployment": f"deployment-{provider_family}",
        "model_tier": 1,
        "benchmark_id": f"benchmark-{provider_family}",
        "benchmark_quality": "0.9",
        "benchmark_latency_ms": "10",
        "benchmark_measured_at": "2026-08-24T00:00:00Z",
        "benchmark_valid_until": None,
        "benchmark_provenance": "test-benchmark",
        "benchmark_sample_size": 10,
        "price_effective_from": "2026-08-25T00:00:00Z",
        "price_effective_to": None,
        "price_provenance": "test-price",
        "price_input_per_million": "1",
        "price_output_per_million": "2",
        "price_cached_input_per_million": None,
        "price_reasoning_per_million": None,
        "price_record_digest": hashlib.sha256(
            canonical_bytes(price_payload)
        ).hexdigest(),
        "estimated_cost_usd": "0.1",
        "qualifying_models": 1,
        "registry_record": {
            "provider": "example",
            "provider_family": provider_family,
            "model": "model",
            "version": "1",
            "deployment": f"deployment-{provider_family}",
            "model_tier": 1,
            "max_context_tokens": 128_000,
            "capabilities": ["reasoning"],
            "allowed_tools": ["read", "workspace_write"],
            "allowed_risk_levels": ["tier-1"],
            "allowed_use_cases": ["implementation", "independent_review"],
            "enabled": True,
        },
    }


def valid_route_profile(*, use_case: str) -> dict[str, object]:
    return {
        "task_type": "software_change",
        "use_case": use_case,
        "context_tokens": 128_000,
        "estimated_usage": {
            "input_tokens": 100_000,
            "output_tokens": 0,
            "cached_input_tokens": 0,
            "reasoning_tokens": 0,
        },
        "max_benchmark_age_seconds": 7 * 24 * 3600,
        "max_tier": 2,
        "required_capabilities": ["reasoning"],
        "min_quality": "0.8",
        "max_latency_ms": "100",
    }


def valid_assignment(
    *,
    assignment_id: str,
    role: str,
    schedule_index: int,
    dependency_wave_index: int,
    dependencies: list[str],
    provider_family: str,
) -> dict[str, object]:
    scopes = (
        ["read", "workspace_write"]
        if role in {"implementation", "remediation"}
        else ["read"]
    )
    return {
        "assignment_id": assignment_id,
        "role": role,
        "contract_task_ids": ["TASK-001"],
        "depends_on_assignment_ids": dependencies,
        "schedule_index": schedule_index,
        "dependency_wave_index": dependency_wave_index,
        "context_id": f"context:{schedule_index}",
        "workspace_key": f"workspace:{schedule_index}",
        "fresh_context": True,
        "isolated_workspace": True,
        "tool_scopes": scopes,
        "risk_tier": 1,
        "max_turns": 12,
        "max_tool_calls": 30,
        "max_cost_usd": "1",
        "prompt": {
            "prompt_id": f"prompt:{role}",
            "version": "1",
            "digest": ("8" if role == "implementation" else "9") * 64,
            "provenance": "central-prompt-registry",
        },
        "route": valid_route(provider_family),
        "reservation": {
            "schema_version": "agt.usage-reservation-plan/v1",
            "reservation_id": f"reservation:{schedule_index}",
            "attribution": {
                "organization_id": "example-org",
                "team_id": "example-team",
                "application_id": "example-app",
                "user_id": "automation",
                "environment": "ci",
                "repository": "example/repository",
                "change_id": "agt.change/test",
                "task_id": assignment_id,
            },
            "amount_usd": "0.1",
            "reserved_at": "2026-08-25T12:00:00Z",
            "expires_at": "2026-08-25T13:00:00Z",
        },
        "checkpoint_ids": [],
        "remediation_path_scopes": ["."] if role == "remediation" else [],
    }


def valid_tool_audit(
    *,
    manifest_id: str,
    assignment_id: str,
    suffix: int,
    authorized_at: str = "2026-08-25T12:01:10Z",
    completed_at: str = "2026-08-25T12:01:11Z",
) -> dict[str, object]:
    audit: dict[str, object] = {
        "schema_version": "agt.tool-call-audit/v1",
        "manifest_id": manifest_id,
        "assignment_id": assignment_id,
        "action_id": f"action:{suffix}",
        "tool": "workspace",
        "action": "read",
        "resource": "tracked.txt",
        "request_digest": str(suffix + 3) * 64,
        "result_digest": str(suffix + 5) * 64,
        "privileged": False,
        "approval_grant_digest": None,
        "decision": "screened",
        "reason_code": None,
        "authorized_at": authorized_at,
        "completed_at": completed_at,
        "audit_digest": "0" * 64,
    }
    seal_digest(audit, "audit_digest")
    return audit


def canonical_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def valid_finding_set(findings: list[dict[str, object]]) -> dict[str, object]:
    finding_set: dict[str, object] = {
        "schema_version": "agt.review-finding-set/v1",
        "findings": findings,
        "finding_set_digest": "0" * 64,
    }
    seal_digest(finding_set, "finding_set_digest")
    return finding_set


def signed_review_semantic(
    *,
    manifest: dict[str, object],
    manifest_digest: str,
    review: dict[str, object],
    round_number: int,
    report_digest: str,
    issued_at: datetime,
    expires_at: datetime,
    findings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    route = cast(dict[str, object], review["route"])
    finding_set = valid_finding_set(findings or [])
    semantic: dict[str, object] = {
        "schema_version": "agt.review-semantic-outcome/v1",
        "verdict": "blocking" if findings else "clean",
        "whole_change": True,
        "finding_set": finding_set,
        "report_digest": report_digest,
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest_digest,
        "run_id": manifest["run_id"],
        "change_digest": manifest["change_digest"],
        "policy_digest": manifest["policy_digest"],
        "review_assignment_id": review["assignment_id"],
        "context_id": review["context_id"],
        "workspace_key": review["workspace_key"],
        "reviewer_model_id": "/".join(
            str(route[field])
            for field in (
                "provider",
                "provider_family",
                "model",
                "version",
                "deployment",
            )
        ),
        "reviewer_model_family": route["provider_family"],
        "review_round_number": round_number,
        "request_digest": str(5 + round_number) * 64,
        "issued_at": canonical_timestamp(issued_at),
        "expires_at": canonical_timestamp(expires_at),
        "attester_id": "enterprise-review-attester",
        "attester_public_key": REVIEW_ATTESTER_PUBLIC_KEY,
        "attestation_signature": "0" * 128,
        "semantic_digest": "0" * 64,
    }
    signature_payload = {
        key: value
        for key, value in semantic.items()
        if key not in {"attestation_signature", "semantic_digest"}
    }
    signature_payload["issued_at"] = issued_at.astimezone(UTC).isoformat()
    signature_payload["expires_at"] = expires_at.astimezone(UTC).isoformat()
    semantic["attestation_signature"] = REVIEW_ATTESTER_PRIVATE_KEY.sign(
        canonical_bytes(signature_payload)
    ).hex()
    seal_digest(semantic, "semantic_digest")
    return semantic


def valid_orchestration_pair(
    source: str,
) -> tuple[dict[str, object], dict[str, object]]:
    implementation = valid_assignment(
        assignment_id="impl:TASK-001",
        role="implementation",
        schedule_index=0,
        dependency_wave_index=0,
        dependencies=[],
        provider_family="family-a",
    )
    review = valid_assignment(
        assignment_id="review:whole-change",
        role="independent_review",
        schedule_index=1,
        dependency_wave_index=1,
        dependencies=["impl:TASK-001"],
        provider_family="family-b",
    )
    remediation = valid_assignment(
        assignment_id="remediation:round:02",
        role="remediation",
        schedule_index=2,
        dependency_wave_index=2,
        dependencies=["review:whole-change"],
        provider_family="family-a",
    )
    rereview = valid_assignment(
        assignment_id="review:whole-change:round:02",
        role="independent_review",
        schedule_index=3,
        dependency_wave_index=3,
        dependencies=["remediation:round:02"],
        provider_family="family-b",
    )
    manifest: dict[str, object] = {
        "schema_version": "agt.orchestration-manifest/v1",
        "manifest_id": "manifest:test",
        "run_id": "RUN-test",
        "planned_at": "2026-08-25T12:00:00Z",
        "policy_id": "policy:test",
        "policy_digest": "b" * 64,
        "change_id": "agt.change/test",
        "change_digest": "a" * 64,
        "source_revision": source,
        "limits": {
            "max_turns_per_assignment": 12,
            "max_tool_calls_per_assignment": 30,
            "max_parallel_agents": 1,
            "max_assignment_duration_seconds": 900,
            "max_review_rounds": 2,
            "max_cost_per_assignment_usd": "1",
            "max_total_cost_usd": "4",
        },
        "tool_governance": {
            "role_policies": [
                {
                    "role": "independent_review",
                    "allowed_tools": ["workspace"],
                    "allowed_actions": ["read"],
                    "allowed_scopes": ["read"],
                },
                {
                    "role": "implementation",
                    "allowed_tools": ["workspace"],
                    "allowed_actions": ["read", "write"],
                    "allowed_scopes": ["read", "workspace_write"],
                },
            ],
            "allowed_command_prefixes": [],
            "allowed_network_hosts": [],
            "allowed_secret_references": [],
            "approval_required_actions": [
                "administrative",
                "execute",
                "network",
                "secret_access",
            ],
            "privileged_actions": [
                "administrative",
                "execute",
                "network",
                "secret_access",
            ],
            "max_result_bytes": 65_536,
            "blocked_result_substrings": [
                "-----begin private key-----",
                "ignore all previous instructions",
                "ignore previous instructions",
                "reveal system prompt",
                "system message:",
            ],
            "require_relative_workspace_paths": True,
            "require_https_network": True,
        },
        "implementation_route": valid_route_profile(use_case="implementation"),
        "review_route": valid_route_profile(use_case="independent_review"),
        "allowed_tool_scopes": ["read", "workspace_write"],
        "checkpoint_tool_scopes": [],
        "checkpoint_min_risk_tier": 3,
        "reservation_ttl_seconds": 3600,
        "review_attestation_ttl_seconds": 300,
        "remediation_path_scopes": ["."],
        "trusted_review_attesters": [
            {
                "attester_id": "enterprise-review-attester",
                "public_key": REVIEW_ATTESTER_PUBLIC_KEY,
            }
        ],
        "execution_waves": [
            {
                "schedule_index": 0,
                "dependency_wave_index": 0,
                "batch_index": 0,
                "assignments": [implementation],
            }
        ],
        "review_assignment": review,
        "conditional_review_rounds": [
            {
                "round_number": 2,
                "remediation_assignment": remediation,
                "review_assignment": rereview,
            }
        ],
        "human_checkpoints": [
            {
                "checkpoint_id": "checkpoint:release",
                "phase": "before_release",
                "assignment_ids": [
                    "review:whole-change",
                    "review:whole-change:round:02",
                ],
                "approver_role": "release-manager",
                "reason_codes": ["release_approval"],
                "required": True,
            }
        ],
        "total_estimated_cost_usd": "0.4",
    }
    manifest_digest = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    now = datetime.now(UTC)
    started_at = now - timedelta(minutes=2)
    authorized_at = now - timedelta(seconds=100)
    completed_at = now - timedelta(seconds=99)
    issued_at = now - timedelta(seconds=90)
    evaluated_at = now - timedelta(seconds=60)
    expires_at = issued_at + timedelta(seconds=300)
    assignments = []
    for assignment_id, role, suffix, prompt in (
        ("impl:TASK-001", "implementation", "1", implementation["prompt"]),
        (
            "review:whole-change",
            "independent_review",
            "2",
            review["prompt"],
        ),
    ):
        assignments.append(
            {
                "assignment_id": assignment_id,
                "role": role,
                "prompt": json.loads(json.dumps(prompt)),
                "state": "succeeded",
                "attempt_count": 1,
                "host_invoked": True,
                "request_digest": (
                    "6" * 64 if role == "independent_review" else "5" * 64
                ),
                "requested_at": canonical_timestamp(started_at + timedelta(seconds=10)),
                "finished_at": canonical_timestamp(started_at + timedelta(seconds=40)),
                "checkpoint_grant_digests": (
                    [] if role == "implementation" else ["e" * 64]
                ),
                "outcome_digest": suffix * 64,
                "usage_event_id": f"usage:{suffix}",
                "actual_cost_usd": "0.05",
                "turns": 2,
                "tool_calls": 1,
                "tool_call_audits": [
                    valid_tool_audit(
                        manifest_id=str(manifest["manifest_id"]),
                        assignment_id=assignment_id,
                        suffix=int(suffix),
                        authorized_at=canonical_timestamp(authorized_at),
                        completed_at=canonical_timestamp(completed_at),
                    )
                ],
                "output_digest": (str(int(suffix) + 2)) * 64,
                "failure_code": None,
            }
        )
    for planned_assignment in (remediation, rereview):
        assignments.append(
            {
                "assignment_id": planned_assignment["assignment_id"],
                "role": planned_assignment["role"],
                "prompt": json.loads(json.dumps(planned_assignment["prompt"])),
                "state": "skipped",
                "attempt_count": 0,
                "host_invoked": False,
                "request_digest": None,
                "requested_at": None,
                "finished_at": canonical_timestamp(evaluated_at),
                "checkpoint_grant_digests": [],
                "outcome_digest": None,
                "usage_event_id": None,
                "actual_cost_usd": None,
                "turns": None,
                "tool_calls": None,
                "tool_call_audits": [],
                "output_digest": None,
                "failure_code": None,
            }
        )
    semantic = signed_review_semantic(
        manifest=manifest,
        manifest_digest=manifest_digest,
        review=review,
        round_number=1,
        report_digest=str(assignments[1]["output_digest"]),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    review_history: dict[str, object] = {
        "schema_version": "agt.review-round-history/v1",
        "round_number": 1,
        "review_assignment_id": review["assignment_id"],
        "context_id": review["context_id"],
        "workspace_key": review["workspace_key"],
        "reviewer_model_family": "family-b",
        "outcome_digest": assignments[1]["outcome_digest"],
        "output_digest": assignments[1]["output_digest"],
        "semantic_outcome": semantic,
        "remediation": None,
        "history_digest": "0" * 64,
    }
    seal_digest(review_history, "history_digest")
    release_checkpoint_valid_until = canonical_timestamp(expires_at)
    receipt: dict[str, object] = {
        "schema_version": "agt.orchestration-execution-receipt/v1",
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest_digest,
        "run_id": manifest["run_id"],
        "change_id": manifest["change_id"],
        "change_digest": manifest["change_digest"],
        "policy_digest": manifest["policy_digest"],
        "status": "succeeded",
        "final": True,
        "started_at": canonical_timestamp(started_at),
        "evaluated_at": canonical_timestamp(evaluated_at),
        "release_checkpoint_valid_until": release_checkpoint_valid_until,
        "assignments": assignments,
        "review_history": [review_history],
        "total_actual_cost_usd": "0.10",
        "cost_complete": True,
        "unknown_cost_assignment_ids": [],
        "reason_codes": [],
        "receipt_digest": "0" * 64,
    }
    seal_digest(receipt, "receipt_digest")
    return manifest, receipt


def execute_second_review_round(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    assignments = receipt_assignments(receipt)
    initial_review_receipt = assignments[1]
    remediation_receipt = assignments[2]
    rereview_receipt = assignments[3]
    conditional = cast(list[dict[str, object]], manifest["conditional_review_rounds"])[
        0
    ]
    remediation = cast(dict[str, object], conditional["remediation_assignment"])
    rereview = cast(dict[str, object], conditional["review_assignment"])
    started_at = datetime.fromisoformat(
        str(receipt["started_at"]).replace("Z", "+00:00")
    )
    evaluated_at = datetime.fromisoformat(
        str(receipt["evaluated_at"]).replace("Z", "+00:00")
    )
    first_issued_at = started_at + timedelta(seconds=30)
    second_issued_at = started_at + timedelta(seconds=50)
    assert second_issued_at <= evaluated_at
    first_expires_at = first_issued_at + timedelta(seconds=300)
    second_expires_at = second_issued_at + timedelta(seconds=300)
    manifest_digest = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    finding = {
        "finding_id": "FINDING-001",
        "task_id": "TASK-001",
        "path": "tracked.txt",
        "rule_id": "RULE-001",
        "description_digest": "d" * 64,
    }
    first_semantic = signed_review_semantic(
        manifest=manifest,
        manifest_digest=manifest_digest,
        review=cast(dict[str, object], manifest["review_assignment"]),
        round_number=1,
        report_digest=str(initial_review_receipt["output_digest"]),
        issued_at=first_issued_at,
        expires_at=first_expires_at,
        findings=[finding],
    )
    initial_review_receipt["checkpoint_grant_digests"] = []
    for execution_receipt, planned, suffix in (
        (remediation_receipt, remediation, 3),
        (rereview_receipt, rereview, 4),
    ):
        execution_receipt.update(
            {
                "state": "succeeded",
                "attempt_count": 1,
                "host_invoked": True,
                "request_digest": ("7" * 64 if planned is rereview else "8" * 64),
                "requested_at": canonical_timestamp(
                    started_at + timedelta(seconds=35 if planned is remediation else 45)
                ),
                "finished_at": canonical_timestamp(
                    started_at + timedelta(seconds=45 if planned is remediation else 55)
                ),
                "checkpoint_grant_digests": (["e" * 64] if planned is rereview else []),
                "outcome_digest": str(suffix) * 64,
                "usage_event_id": f"usage:{suffix}",
                "actual_cost_usd": "0.05",
                "turns": 2,
                "tool_calls": 1,
                "tool_call_audits": [
                    valid_tool_audit(
                        manifest_id=str(manifest["manifest_id"]),
                        assignment_id=str(planned["assignment_id"]),
                        suffix=suffix,
                        authorized_at=canonical_timestamp(
                            started_at + timedelta(seconds=10 + suffix)
                        ),
                        completed_at=canonical_timestamp(
                            started_at + timedelta(seconds=11 + suffix)
                        ),
                    )
                ],
                "output_digest": str(suffix + 2) * 64,
                "failure_code": None,
            }
        )
    finding_set = cast(dict[str, object], first_semantic["finding_set"])
    binding: dict[str, object] = {
        "schema_version": "agt.remediation-scope-binding/v1",
        "prior_review_assignment_id": initial_review_receipt["assignment_id"],
        "prior_review_outcome_digest": initial_review_receipt["outcome_digest"],
        "finding_set": finding_set,
        "task_ids": ["TASK-001"],
        "paths": ["tracked.txt"],
        "binding_digest": "0" * 64,
    }
    seal_digest(binding, "binding_digest")
    remediation_history: dict[str, object] = {
        "schema_version": "agt.remediation-execution-history/v1",
        "assignment_id": remediation["assignment_id"],
        "context_id": remediation["context_id"],
        "workspace_key": remediation["workspace_key"],
        "outcome_digest": remediation_receipt["outcome_digest"],
        "output_digest": remediation_receipt["output_digest"],
        "binding": binding,
        "history_digest": "0" * 64,
    }
    seal_digest(remediation_history, "history_digest")
    first_history: dict[str, object] = {
        "schema_version": "agt.review-round-history/v1",
        "round_number": 1,
        "review_assignment_id": initial_review_receipt["assignment_id"],
        "context_id": manifest["review_assignment"]["context_id"],
        "workspace_key": manifest["review_assignment"]["workspace_key"],
        "reviewer_model_family": "family-b",
        "outcome_digest": initial_review_receipt["outcome_digest"],
        "output_digest": initial_review_receipt["output_digest"],
        "semantic_outcome": first_semantic,
        "remediation": remediation_history,
        "history_digest": "0" * 64,
    }
    seal_digest(first_history, "history_digest")
    second_semantic = signed_review_semantic(
        manifest=manifest,
        manifest_digest=manifest_digest,
        review=rereview,
        round_number=2,
        report_digest=str(rereview_receipt["output_digest"]),
        issued_at=second_issued_at,
        expires_at=second_expires_at,
    )
    second_history: dict[str, object] = {
        "schema_version": "agt.review-round-history/v1",
        "round_number": 2,
        "review_assignment_id": rereview["assignment_id"],
        "context_id": rereview["context_id"],
        "workspace_key": rereview["workspace_key"],
        "reviewer_model_family": "family-b",
        "outcome_digest": rereview_receipt["outcome_digest"],
        "output_digest": rereview_receipt["output_digest"],
        "semantic_outcome": second_semantic,
        "remediation": None,
        "history_digest": "0" * 64,
    }
    seal_digest(second_history, "history_digest")
    receipt["review_history"] = [first_history, second_history]
    receipt["release_checkpoint_valid_until"] = canonical_timestamp(first_expires_at)
    receipt["total_actual_cost_usd"] = "0.20"
    seal_digest(receipt, "receipt_digest")


def seal_digest(record: dict[str, object], field: str) -> None:
    unsigned = {key: value for key, value in record.items() if key != field}
    record[field] = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def rebind_execution_receipt(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    receipt.update(
        {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
            "run_id": manifest["run_id"],
            "change_id": manifest["change_id"],
            "change_digest": manifest["change_digest"],
            "policy_digest": manifest["policy_digest"],
        }
    )
    seal_digest(receipt, "receipt_digest")


def reseal_route_price(route: dict[str, object]) -> None:
    def normalized(value: object) -> str | None:
        if value is None:
            return None
        decimal = Decimal(str(value))
        return "0" if decimal == 0 else format(decimal.normalize(), "f")

    def price_time(value: object) -> str | None:
        if value is None:
            return None
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.isoformat(timespec="microseconds")

    payload = {
        "schema": "agt.model-price-record/v1",
        "identity": {
            "provider": route["provider"],
            "provider_family": route["provider_family"],
            "model": route["model"],
            "version": route["version"],
            "deployment": route["deployment"],
        },
        "effective_from": price_time(route["price_effective_from"]),
        "effective_to": price_time(route["price_effective_to"]),
        "input_per_million": normalized(route["price_input_per_million"]),
        "output_per_million": normalized(route["price_output_per_million"]),
        "cached_input_per_million": normalized(route["price_cached_input_per_million"]),
        "reasoning_per_million": normalized(route["price_reasoning_per_million"]),
        "provenance": route["price_provenance"],
    }
    route["price_record_digest"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()


def manifest_implementation(manifest: dict[str, object]) -> dict[str, object]:
    waves = cast(list[dict[str, object]], manifest["execution_waves"])
    return cast(list[dict[str, object]], waves[0]["assignments"])[0]


def manifest_review(manifest: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], manifest["review_assignment"])


def receipt_assignments(receipt: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], receipt["assignments"])


def receipt_review_history(receipt: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], receipt["review_history"])


def mutate_missing_review_round_limit(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    cast(dict[str, object], manifest["limits"]).pop("max_review_rounds")


def mutate_missing_conditional_rounds(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    manifest.pop("conditional_review_rounds")


def mutate_missing_review_history(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt.pop("review_history")


def mutate_review_attestation_signature(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    history = receipt_review_history(receipt)[0]
    semantic = cast(dict[str, object], history["semantic_outcome"])
    semantic["attestation_signature"] = "0" * 128
    seal_digest(semantic, "semantic_digest")
    seal_digest(history, "history_digest")
    seal_digest(receipt, "receipt_digest")


def mutate_review_output_binding(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    history = receipt_review_history(receipt)[0]
    history["output_digest"] = "f" * 64
    seal_digest(history, "history_digest")
    seal_digest(receipt, "receipt_digest")


def mutate_unplanned_conditional_execution(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    skipped = receipt_assignments(receipt)[2]
    skipped["host_invoked"] = True
    seal_digest(receipt, "receipt_digest")


def mutate_cross_manifest_review_replay(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    manifest["manifest_id"] = "manifest:substituted"
    rebind_execution_receipt(manifest, receipt)


def mutate_scope_outside_manifest(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    manifest_implementation(manifest)["tool_scopes"] = ["network", "read"]
    rebind_execution_receipt(manifest, receipt)


def mutate_missing_risk_checkpoint(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    manifest_implementation(manifest)["risk_tier"] = 3
    rebind_execution_receipt(manifest, receipt)


def mutate_receipt_turn_limit(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt_assignments(receipt)[0]["turns"] = 13
    seal_digest(receipt, "receipt_digest")


def mutate_receipt_checkpoint_coverage(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt_assignments(receipt)[1]["checkpoint_grant_digests"] = []
    seal_digest(receipt, "receipt_digest")


def mutate_receipt_tool_audit_digest(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    assignment = receipt_assignments(receipt)[0]
    audits = cast(list[dict[str, object]], assignment["tool_call_audits"])
    audits[0]["audit_digest"] = "f" * 64
    seal_digest(receipt, "receipt_digest")


def mutate_receipt_unscreened_tool_audit(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    assignment = receipt_assignments(receipt)[0]
    audit = cast(list[dict[str, object]], assignment["tool_call_audits"])[0]
    audit.update(
        {
            "decision": "authorized",
            "result_digest": None,
            "completed_at": None,
        }
    )
    seal_digest(audit, "audit_digest")
    seal_digest(receipt, "receipt_digest")


def mutate_expired_release_checkpoint(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt["release_checkpoint_valid_until"] = receipt["evaluated_at"]
    seal_digest(receipt, "receipt_digest")


def mutate_elapsed_release_checkpoint(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt["release_checkpoint_valid_until"] = recent_timestamp(minutes=1)
    seal_digest(receipt, "receipt_digest")


def mutate_duplicate_receipt_usage_event(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    assignments = receipt_assignments(receipt)
    assignments[1]["usage_event_id"] = assignments[0]["usage_event_id"]
    seal_digest(receipt, "receipt_digest")


def mutate_substituted_receipt_usage_event(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt_assignments(receipt)[1]["usage_event_id"] = "usage:substituted"
    seal_digest(receipt, "receipt_digest")


def mutate_review_family(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    review_route = cast(dict[str, object], manifest_review(manifest)["route"])
    review_route["provider_family"] = "family-a"
    review_route["deployment"] = "deployment-family-a"
    registry_record = cast(dict[str, object], review_route["registry_record"])
    registry_record["provider_family"] = "family-a"
    registry_record["deployment"] = "deployment-family-a"
    reseal_route_price(review_route)
    rebind_execution_receipt(manifest, receipt)


def mutate_future_benchmark(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    route = cast(dict[str, object], manifest_implementation(manifest)["route"])
    route["benchmark_measured_at"] = "2026-08-25T12:30:00Z"
    rebind_execution_receipt(manifest, receipt)


def mutate_stale_no_expiry_benchmark(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    route = cast(dict[str, object], manifest_implementation(manifest)["route"])
    route["benchmark_measured_at"] = "2026-08-01T00:00:00Z"
    route["benchmark_valid_until"] = None
    rebind_execution_receipt(manifest, receipt)


def mutate_zero_cost_reseal(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    assignment = manifest_implementation(manifest)
    route = cast(dict[str, object], assignment["route"])
    reservation = cast(dict[str, object], assignment["reservation"])
    route["estimated_cost_usd"] = "0"
    reservation["amount_usd"] = "0"
    manifest["total_estimated_cost_usd"] = "0.3"
    rebind_execution_receipt(manifest, receipt)


def mutate_future_price(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    route = cast(dict[str, object], manifest_implementation(manifest)["route"])
    route["price_effective_from"] = "2026-08-25T12:30:00Z"
    reseal_route_price(route)
    rebind_execution_receipt(manifest, receipt)


def mutate_receipt_prompt(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    prompt = cast(dict[str, object], receipt_assignments(receipt)[0]["prompt"])
    prompt["digest"] = "f" * 64
    seal_digest(receipt, "receipt_digest")


def mutate_registry_identity(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    route = cast(dict[str, object], manifest_implementation(manifest)["route"])
    registry_record = cast(dict[str, object], route["registry_record"])
    registry_record["deployment"] = "different-deployment"
    rebind_execution_receipt(manifest, receipt)


def mutate_registry_tier(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    route = cast(dict[str, object], manifest_implementation(manifest)["route"])
    registry_record = cast(dict[str, object], route["registry_record"])
    registry_record["model_tier"] = 2
    rebind_execution_receipt(manifest, receipt)


def mutate_disabled_registry_record(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    route = cast(dict[str, object], manifest_implementation(manifest)["route"])
    registry_record = cast(dict[str, object], route["registry_record"])
    registry_record["enabled"] = False
    rebind_execution_receipt(manifest, receipt)


def mutate_missing_manifest_limits(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    manifest.pop("limits")


def mutate_missing_assignment_duration(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    cast(dict[str, object], manifest["limits"]).pop("max_assignment_duration_seconds")


def mutate_missing_tool_governance(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    manifest.pop("tool_governance")


def mutate_disabled_https_tool_governance(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    cast(dict[str, object], manifest["tool_governance"])["require_https_network"] = (
        False
    )


def mutate_manifest_source(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del receipt
    manifest["source_revision"] = "f" * 40


def mutate_failed_receipt(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt.update({"status": "failed", "reason_codes": ["failure"]})
    seal_digest(receipt, "receipt_digest")


def mutate_incomplete_receipt_cost(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt.update(
        {
            "cost_complete": False,
            "unknown_cost_assignment_ids": ["impl:TASK-001"],
        }
    )
    seal_digest(receipt, "receipt_digest")


def mutate_receipt_assignment_id(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt_assignments(receipt)[0]["assignment_id"] = "impl:OTHER"
    seal_digest(receipt, "receipt_digest")


def mutate_receipt_policy(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt["policy_digest"] = "c" * 64
    seal_digest(receipt, "receipt_digest")


def mutate_receipt_digest(
    manifest: dict[str, object], receipt: dict[str, object]
) -> None:
    del manifest
    receipt["receipt_digest"] = "f" * 64


def valid_pyrit_evidence(source: str) -> dict[str, object]:
    created_at = recent_timestamp(minutes=2)
    completed_at = recent_timestamp(minutes=1)
    metric = {
        "trials": 1,
        "determinate_trials": 1,
        "successes": 0,
        "failures": 1,
        "errors": 0,
        "undetermined": 0,
        "attack_success_rate": 0.0,
        "error_rate": 0.0,
        "undetermined_rate": 0.0,
        "latency": {
            "samples": 1,
            "total_ms": 10,
            "mean_ms": 10.0,
            "p95_ms": 10,
            "max_ms": 10,
        },
    }
    configuration: dict[str, object] = {
        "pyrit_version": "1.0.0",
        "scenario": {
            "class_name": "Scenario",
            "content_hash": "1" * 64,
            "eval_hash": "2" * 64,
        },
        "target": {
            "class_name": "Target",
            "content_hash": "3" * 64,
            "eval_hash": "4" * 64,
        },
        "scorer": {
            "class_name": "Scorer",
            "content_hash": "5" * 64,
            "eval_hash": "6" * 64,
        },
        "scenario_version": 1,
        "techniques": ["crescendo"],
        "datasets": ["dataset"],
        "objective_hashes": ["7" * 64],
    }
    configuration["benchmark_fingerprint"] = hashlib.sha256(
        canonical_bytes(
            {
                "schema": "pyrit.security-evidence/benchmark/v1",
                **configuration,
            }
        )
    ).hexdigest()
    trial_identity = {
        "atomic_attack_name": "attack",
        "display_group": "group",
        "objective_sha256": "7" * 64,
    }
    expected_trial_inventory = [trial_identity]
    planned_cached_trials: list[dict[str, object]] = []
    trial_plan_digest = hashlib.sha256(
        canonical_bytes(
            {
                "schema": "pyrit.security-evidence/trial-plan/v1",
                "expected_trials": expected_trial_inventory,
                "cached_trials": planned_cached_trials,
            }
        )
    ).hexdigest()
    observed_trials = [
        {
            "identity": trial_identity,
            "attack_result_id": "attack-result-1",
            "origin_scenario_result_id": "result-1",
            "observed_at": completed_at,
            "cached": False,
            "outcome": "failure",
            "execution_time_ms": 10,
        }
    ]
    evidence: dict[str, object] = {
        "schema": "pyrit.security-evidence/v1",
        "generated_at": completed_at,
        "subject": {
            "application": "example-app",
            "change": "agt.change/test",
            "commit_sha": source,
        },
        "run": {
            "scenario_result_id": "result-1",
            "state": "COMPLETED",
            "created_at": created_at,
            "completed_at": completed_at,
            "number_tries": 1,
            "pyrit_version": "1.0.0",
            "trial_plan_digest": trial_plan_digest,
            "expected_trial_inventory": expected_trial_inventory,
            "planned_cached_trials": planned_cached_trials,
            "observed_trials": observed_trials,
            "oldest_trial_at": completed_at,
            "current_run_trial_count": 1,
            "reused_trial_count": 0,
            "omitted_reused_trial_count": 0,
            "missing_provenance_trial_count": 0,
            "origin_scenario_result_ids": ["result-1"],
        },
        "configuration": configuration,
        "metrics": {
            "overall": metric,
            "groups": [
                {
                    "name": "group",
                    "atomic_attack_names": ["attack"],
                    "metrics": json.loads(json.dumps(metric)),
                }
            ],
        },
        "usage": {
            "scope": "linked_conversations",
            "conversation_count": 1,
            "observed_response_count": 1,
            "calls_with_token_usage": 1,
            "calls_with_cost": 1,
            "input_tokens": 10,
            "output_tokens": 5,
            "reasoning_tokens": 0,
            "cached_tokens": 0,
            "total_tokens": 15,
            "cost": {"currency": "USD", "amount": "0.01"},
            "token_coverage": "complete",
            "cost_coverage": "complete",
        },
        "baseline": None,
        "completeness": {
            "status": "complete",
            "reasons": [],
            "terminal": True,
            "has_trials": True,
        },
        "evidence_digest": "0" * 64,
    }
    seal_digest(evidence, "evidence_digest")
    return evidence


def add_valid_pyrit_baseline(evidence: dict[str, object]) -> dict[str, object]:
    configuration = cast(dict[str, object], evidence["configuration"])
    metrics = cast(dict[str, object], evidence["metrics"])
    baseline_facts: dict[str, object] = {
        "scenario_result_id": "baseline-result",
        "generated_at": recent_timestamp(minutes=2),
        "state": "COMPLETED",
        "pyrit_version": configuration["pyrit_version"],
        "benchmark_fingerprint": configuration["benchmark_fingerprint"],
        "metrics": json.loads(json.dumps(metrics["overall"])),
    }
    baseline = {
        **baseline_facts,
        "compatible": True,
        "incompatibility_reasons": [],
        "delta_attack_success_rate": 0.0,
        "delta_error_rate": 0.0,
        "delta_undetermined_rate": 0.0,
        "baseline_digest": hashlib.sha256(
            canonical_bytes(
                {"schema": "pyrit.security-evidence/baseline/v1", **baseline_facts}
            )
        ).hexdigest(),
    }
    evidence["baseline"] = baseline
    return baseline


def mutate_pyrit_incompatible_version_baseline(
    evidence: dict[str, object],
) -> None:
    baseline = add_valid_pyrit_baseline(evidence)
    baseline.update(
        {
            "pyrit_version": "0.9.0",
            "benchmark_fingerprint": "f" * 64,
            "compatible": False,
            "incompatibility_reasons": [
                "baseline.benchmark_fingerprint_mismatch",
                "baseline.pyrit_version_mismatch",
            ],
            "delta_attack_success_rate": None,
            "delta_error_rate": None,
            "delta_undetermined_rate": None,
        }
    )
    baseline_facts = {
        key: baseline[key]
        for key in (
            "scenario_result_id",
            "generated_at",
            "state",
            "pyrit_version",
            "benchmark_fingerprint",
            "metrics",
        )
    }
    baseline["baseline_digest"] = hashlib.sha256(
        canonical_bytes(
            {"schema": "pyrit.security-evidence/baseline/v1", **baseline_facts}
        )
    ).hexdigest()


def mutate_pyrit_baseline_flag(evidence: dict[str, object]) -> None:
    baseline = add_valid_pyrit_baseline(evidence)
    baseline.update(
        {
            "compatible": False,
            "incompatibility_reasons": ["claimed-incompatible"],
            "delta_attack_success_rate": None,
            "delta_error_rate": None,
            "delta_undetermined_rate": None,
        }
    )


def mutate_pyrit_baseline_delta(evidence: dict[str, object]) -> None:
    baseline = add_valid_pyrit_baseline(evidence)
    baseline["delta_attack_success_rate"] = 0.5


def mutate_pyrit_missing_target_claims_compatible_baseline(
    evidence: dict[str, object],
) -> None:
    configuration = cast(dict[str, object], evidence["configuration"])
    configuration["target"] = None
    fingerprint_payload = {
        "schema": "pyrit.security-evidence/benchmark/v1",
        **{
            key: value
            for key, value in configuration.items()
            if key != "benchmark_fingerprint"
        },
    }
    configuration["benchmark_fingerprint"] = hashlib.sha256(
        canonical_bytes(fingerprint_payload)
    ).hexdigest()
    add_valid_pyrit_baseline(evidence)
    completeness = cast(dict[str, object], evidence["completeness"])
    completeness.update(
        {
            "status": "incomplete",
            "reasons": ["configuration.target_missing"],
        }
    )


def mutate_pyrit_terminal_without_completion(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    run["completed_at"] = None


def mutate_pyrit_wrong_trial_plan_digest(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    run["trial_plan_digest"] = "f" * 64


def mutate_pyrit_generated_at_ignores_oldest_trial(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    evidence["generated_at"] = run["created_at"]


def mutate_pyrit_unbound_inventory_claims_complete(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    run["trial_plan_digest"] = None
    run["expected_trial_inventory"] = None


def mutate_pyrit_missing_provenance_claims_complete(
    evidence: dict[str, object],
) -> None:
    run = cast(dict[str, object], evidence["run"])
    trials = cast(list[dict[str, object]], run["observed_trials"])
    trials[0]["origin_scenario_result_id"] = None
    run.update(
        {
            "current_run_trial_count": 0,
            "missing_provenance_trial_count": 1,
            "origin_scenario_result_ids": [],
        }
    )


def mutate_pyrit_observed_outcome_without_metrics(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    trials = cast(list[dict[str, object]], run["observed_trials"])
    trials[0]["outcome"] = "success"


def mutate_pyrit_lower_overall_p95(evidence: dict[str, object]) -> None:
    metrics = cast(dict[str, object], evidence["metrics"])
    overall = cast(dict[str, object], metrics["overall"])
    latency = cast(dict[str, object], overall["latency"])
    latency["p95_ms"] = 0


def mutate_pyrit_hide_observed_max_latency(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    trials = cast(list[dict[str, object]], run["observed_trials"])
    trials[0]["execution_time_ms"] = 20


def mutate_pyrit_partial_tokens_with_complete_facts(
    evidence: dict[str, object],
) -> None:
    usage = cast(dict[str, object], evidence["usage"])
    usage["token_coverage"] = "partial"
    completeness = cast(dict[str, object], evidence["completeness"])
    completeness["reasons"] = ["usage.partial"]


def mutate_pyrit_partial_cost_with_complete_facts(evidence: dict[str, object]) -> None:
    usage = cast(dict[str, object], evidence["usage"])
    usage["cost_coverage"] = "partial"
    completeness = cast(dict[str, object], evidence["completeness"])
    completeness["reasons"] = ["cost.partial"]


def mutate_pyrit_reused_trial_claims_complete(evidence: dict[str, object]) -> None:
    run = cast(dict[str, object], evidence["run"])
    trials = cast(list[dict[str, object]], run["observed_trials"])
    trials[0]["origin_scenario_result_id"] = "prior-result"
    trials[0]["cached"] = True
    run.update(
        {
            "current_run_trial_count": 0,
            "reused_trial_count": 1,
            "origin_scenario_result_ids": ["prior-result"],
        }
    )
    completeness = cast(dict[str, object], evidence["completeness"])
    completeness.update(
        {
            "status": "incomplete",
            "reasons": ["run.reused_trials", "run.trial_inventory_mismatch"],
        }
    )


def run_assembler(
    tmp_path: Path,
    *,
    mutate_record: Callable[[dict[str, object]], None] | None = None,
    mutate_gate_records: Callable[[list[dict[str, object]]], None] | None = None,
    mutate_gate_records_after_handoff: (
        Callable[[list[dict[str, object]]], None] | None
    ) = None,
    mutate_raw_artifacts: (
        Callable[[Path, list[dict[str, object]]], None] | None
    ) = None,
    mutate_quality_handoff: Callable[[dict[str, object]], None] | None = None,
    mutate_security_handoff: Callable[[dict[str, object]], None] | None = None,
    mutate_cost_evidence: Callable[[dict[str, object]], None] | None = None,
    mutate_orchestration: (
        Callable[[dict[str, object], dict[str, object]], None] | None
    ) = None,
    run_second_review_round: bool = False,
    mutate_pyrit: Callable[[dict[str, object]], None] | None = None,
    noncanonical_pyrit: bool = False,
    require_pyrit: bool = False,
    risk_class: str = "standard",
    skeletal_gate_handoffs: bool = False,
    omit_orchestration_file: str | None = None,
    noncanonical_orchestration_file: str | None = None,
    symlink_orchestration_file: str | None = None,
    canonical_record_file: bool = True,
    base_input: str | None = None,
    divergent_base: bool = False,
    source_contents: str = "source\n",
    workflow_reference: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    tracked = repository / "tracked.txt"
    tracked.write_text("base\n", encoding="utf-8")
    base = commit(repository, "base")
    tracked.write_text(source_contents, encoding="utf-8")
    source = commit(repository, "source")
    trusted_base = base
    if divergent_base:
        trusted_base = subprocess.run(
            [
                "git",
                "-c",
                "user.name=Workflow Test",
                "-c",
                "user.email=workflow-test@example.invalid",
                "commit-tree",
                f"{base}^{{tree}}",
                "-m",
                "divergent base",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    if workflow_reference is not None:
        workflow_path = repository / ".github" / "workflows" / "audit.yml"
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_text(
            f"jobs:\n  audit:\n    steps:\n      - uses: {workflow_reference}\n",
            encoding="utf-8",
        )

    evidence_dir = tmp_path / "evidence"
    caller_dir = tmp_path / "caller"
    evidence_dir.mkdir()
    caller_dir.mkdir()
    (evidence_dir / "sbom.spdx.json").write_bytes(b"{}\n")

    orchestration_manifest, execution_receipt = valid_orchestration_pair(source)
    if run_second_review_round:
        execute_second_review_round(orchestration_manifest, execution_receipt)
    cost_evidence = valid_cost_evidence(source, execution_receipt)
    if mutate_orchestration is not None:
        mutate_orchestration(orchestration_manifest, execution_receipt)
    if mutate_cost_evidence is not None:
        mutate_cost_evidence(cost_evidence)
        seal_command_evidence(cost_evidence)
    for filename, payload in (
        ("orchestration-manifest.json", orchestration_manifest),
        ("execution-receipt.json", execution_receipt),
    ):
        if filename != omit_orchestration_file:
            path = caller_dir / filename
            if filename == symlink_orchestration_file:
                target = tmp_path / f"target-{filename}"
                target.write_bytes(canonical_bytes(payload) + b"\n")
                path.symlink_to(target)
            elif filename == noncanonical_orchestration_file:
                path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            else:
                path.write_bytes(canonical_bytes(payload) + b"\n")

    pyrit: dict[str, object] | None = None
    if (
        mutate_pyrit is not None
        or require_pyrit
        or risk_class in {"high", "tool_enabled_agent"}
    ):
        pyrit = valid_pyrit_evidence(source)
        if mutate_pyrit is not None:
            mutate_pyrit(pyrit)
        pyrit_path = caller_dir / "pyrit-security-evidence.json"
        if noncanonical_pyrit:
            pyrit_path.write_text(json.dumps(pyrit, indent=2) + "\n", encoding="utf-8")
        else:
            pyrit_path.write_bytes(canonical_bytes(pyrit) + b"\n")

    gate_records = valid_gate_records(
        source,
        risk_class=risk_class,
        definition_sha256=hashlib.sha256(tracked.read_bytes()).hexdigest(),
    )
    if mutate_gate_records is not None:
        mutate_gate_records(gate_records)
    quality_handoff, security_handoff = valid_gate_handoffs(
        source,
        gate_records,
        risk_class=risk_class,
        pyrit=pyrit,
        require_pyrit=require_pyrit,
    )
    if skeletal_gate_handoffs:
        quality_handoff = {
            "schema": "agt.ci-check-result/v1",
            "check_id": "quality",
            "source_revision": source,
            "status": "passed",
        }
        security_handoff = {
            "schema": "agt.ci-check-result/v1",
            "check_id": "security",
            "source_revision": source,
            "status": "passed",
        }
    if mutate_quality_handoff is not None:
        mutate_quality_handoff(quality_handoff)
    if mutate_security_handoff is not None:
        mutate_security_handoff(security_handoff)
    if mutate_gate_records_after_handoff is not None:
        mutate_gate_records_after_handoff(gate_records)
    for filename, payload in (
        ("quality-details.json", quality_handoff),
        ("security-details.json", security_handoff),
    ):
        (caller_dir / filename).write_bytes(canonical_bytes(payload) + b"\n")

    records = [cost_evidence, *gate_records]
    if mutate_record is not None:
        record = next(item for item in gate_records if item["kind"] == "lint")
        mutate_record(record)
    write_caller_raw_artifacts(caller_dir, records)
    if mutate_raw_artifacts is not None:
        mutate_raw_artifacts(caller_dir, records)
    agent_sre_path = caller_dir / "agent-sre-execution-evidence.json"
    if agent_sre_path.name != omit_orchestration_file:
        if canonical_record_file:
            agent_sre_path.write_bytes(canonical_bytes(records) + b"\n")
        else:
            agent_sre_path.write_text(
                json.dumps(records, indent=2) + "\n", encoding="utf-8"
            )

    output_path = tmp_path / "github-output"
    environment = {
        **os.environ,
        "ATTESTATION_EXPECTED": "false",
        "BASE_REVISION": (
            base_input if base_input is not None else trusted_base.upper()
        ),
        "CALLER_EVIDENCE_DIR": str(caller_dir),
        "CHANGE_DIGEST": "a" * 64,
        "CHANGE_ID": "agt.change/test",
        "EVIDENCE_DIR": str(evidence_dir),
        "EVENT_NAME": "push",
        "GITHUB_OUTPUT": str(output_path),
        "GITHUB_WORKSPACE": str(repository),
        "REQUIRE_PYRIT_EVIDENCE": str(require_pyrit).lower(),
        "RETENTION_DAYS": "14",
        "SOURCE_REPOSITORY": "example/repository",
        "SOURCE_REVISION": source,
        "WORKFLOW_REF": "example/repository/.github/workflows/caller.yml@refs/heads/main",
        "WORKFLOW_RUN_ATTEMPT": "1",
        "WORKFLOW_RUN_ID": "123",
    }
    result = subprocess.run(
        [sys.executable, "-c", assembler_script()],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    return result, evidence_dir


def test_workflow_is_reusable_only_and_has_a_closed_input_surface() -> None:
    model = workflow_model()
    triggers = model["on"]
    assert set(triggers) == {"workflow_call"}
    inputs = triggers["workflow_call"]["inputs"]
    assert set(inputs) == {
        "base_revision",
        "change_id",
        "change_digest",
        "require_pyrit_evidence",
        "enable_attestation",
        "retention_days",
    }
    assert inputs["base_revision"]["required"] == "true"
    assert inputs["require_pyrit_evidence"]["default"] == "false"
    assert inputs["enable_attestation"]["default"] == "false"
    assert not any(
        fragment in name
        for name in inputs
        for fragment in ("command", "script", "shell", "url", "endpoint", "target")
    )


def test_every_remote_action_is_pinned_and_checkout_drops_credentials() -> None:
    text = workflow_text()
    references = re.findall(r"^\s*uses:\s*(\S+)", text, flags=re.MULTILINE)
    assert references
    assert all(FULL_ACTION_PIN.fullmatch(reference) for reference in references)
    assert "persist-credentials: false" in text
    assert "pull_request_target:" not in text


def test_shell_never_interpolates_workflow_inputs_as_commands() -> None:
    text = workflow_text()
    run_blocks = re.findall(
        r"^\s+run:\s*\|\n(?P<body>(?:^\s{10,}.*\n?)*)",
        text,
        flags=re.MULTILINE,
    )
    assert run_blocks
    for block in run_blocks:
        assert "${{ inputs." not in block
    forbidden = (
        "eval ",
        "bash -c",
        "sh -c",
        "curl ",
        "wget ",
        "pip install",
        "npm install",
    )
    assert not any(item in text for item in forbidden)


def test_inline_assembler_is_valid_python_and_fails_closed_on_binding() -> None:
    script = assembler_script()
    compile(script, str(WORKFLOW), "exec")
    for contract in (
        "base_revision must be a full Git commit SHA",
        "source revision must be a full lowercase Git commit SHA",
        "change_digest must be a lowercase SHA-256 value",
        "checkout does not match the source revision",
        "sha256 digests",
        "Agent SRE execution evidence is invalid or source-unbound",
        "Agent SRE execution evidence must use canonical JSON",
        "PyRIT evidence is invalid or source-unbound",
        '"network_execution_in_this_workflow": False',
    ):
        assert contract in script


def test_handoff_has_sbom_provenance_agent_sre_and_optional_pyrit() -> None:
    text = workflow_text()
    for required in (
        "anchore/sbom-action@",
        "actions/dependency-review-action@",
        "actions/attest-build-provenance@",
        "agent-sre-execution-evidence.json",
        "evidence-manifest.json",
        "pyrit-security-evidence.json",
        "agt-ai-sdlc-evidence",
    ):
        assert required in text
    assert "pyrit scan" not in text.lower()
    assert "pyrit_scan" not in text.lower()
    assert (
        "if: inputs.enable_attestation && github.event_name != 'pull_request'" in text
    )


def test_pyrit_handoff_recomputes_digest_and_binds_commit_and_change() -> None:
    text = workflow_text()
    assert 'subject["change"] == change_id' in text
    assert 'subject["commit_sha"] == source' in text
    assert "hashlib.sha256(canonical_bytes(unsigned_pyrit)).hexdigest()" in text


def test_complete_strict_pyrit_evidence_is_accepted(tmp_path: Path) -> None:
    result, evidence_dir = run_assembler(
        tmp_path,
        mutate_pyrit=lambda _evidence: None,
        require_pyrit=True,
    )

    assert result.returncode == 0, result.stderr
    assert (evidence_dir / "pyrit-security-evidence.json").is_file()


def test_high_risk_canonical_gate_handoffs_are_accepted(tmp_path: Path) -> None:
    result, evidence_dir = run_assembler(tmp_path, risk_class="high")

    assert result.returncode == 0, result.stderr
    security = json.loads((evidence_dir / "security-details.json").read_text())
    assert security["result"]["risk_class"] == "high"
    assert security["pyrit_policy"]["schema"] == "agt.release-policy/v1"
    assert {
        "rampart-campaign.json",
        "rampart-native-report.json",
        "rampart-run-attestation.json",
        "rampart-safety-report.json",
    } <= {path.name for path in evidence_dir.iterdir()}


def test_forged_rampart_run_attestation_is_rejected(tmp_path: Path) -> None:
    def forge(records: list[dict[str, object]]) -> None:
        record = rampart_record(records)
        report = rampart_report(record)
        attestation = cast(dict[str, object], report["run_attestation"])
        signature = str(attestation["attestation_signature"])
        attestation["attestation_signature"] = (
            "0" if signature[0] != "0" else "1"
        ) + signature[1:]
        seal_digest(attestation, "attestation_digest")
        reseal_rampart_record(record)

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_gate_records=forge,
    )

    assert result.returncode != 0
    assert "RAMPART run attestation signature is invalid" in result.stderr


def test_valid_signature_from_untrusted_rampart_key_is_rejected(tmp_path: Path) -> None:
    attacker = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32))
    attacker_public_key = (
        attacker.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )

    def replace_issuer(records: list[dict[str, object]]) -> None:
        record = rampart_record(records)
        report = rampart_report(record)
        attestation = cast(dict[str, object], report["run_attestation"])
        attestation["issuer_id"] = "attacker-rampart-issuer"
        attestation["issuer_public_key"] = attacker_public_key
        resign_rampart_attestation(attestation, signer=attacker)
        reseal_rampart_record(record)

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_gate_records=replace_issuer,
    )

    assert result.returncode != 0
    assert "not signed by a protected issuer" in result.stderr


def test_signed_rampart_attestation_cannot_be_replayed_under_another_run(
    tmp_path: Path,
) -> None:
    def relabel(records: list[dict[str, object]]) -> None:
        record = rampart_record(records)
        rampart_report(record)["run_id"] = "RAMPART-RUN-REPLAY"
        reseal_rampart_record(record)

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_gate_records=relabel,
    )

    assert result.returncode != 0
    assert "wrapper does not match its signed run attestation" in result.stderr


@pytest.mark.parametrize("freshness_failure", ["expired", "future", "overlong"])
def test_rampart_attestation_freshness_is_recomputed(
    tmp_path: Path,
    freshness_failure: str,
) -> None:
    def mutate_freshness(records: list[dict[str, object]]) -> None:
        record = rampart_record(records)
        report = rampart_report(record)
        attestation = cast(dict[str, object], report["run_attestation"])
        generated_at = datetime.fromisoformat(
            str(attestation["generated_at"]).replace("Z", "+00:00")
        )
        if freshness_failure == "expired":
            attestation["expires_at"] = canonical_timestamp(
                generated_at + timedelta(seconds=15)
            )
        elif freshness_failure == "future":
            attestation["attested_at"] = canonical_timestamp(
                generated_at + timedelta(minutes=10)
            )
            attestation["expires_at"] = canonical_timestamp(
                generated_at + timedelta(minutes=15)
            )
        else:
            attestation["expires_at"] = canonical_timestamp(
                generated_at + timedelta(days=2)
            )
        resign_rampart_attestation(attestation)
        reseal_rampart_record(record)

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_gate_records=mutate_freshness,
    )

    assert result.returncode != 0
    assert "future-dated, expired, or overlong" in result.stderr


def test_multiple_rampart_records_are_not_resolved_by_newest_wins(
    tmp_path: Path,
) -> None:
    def add_old_misdeclared_unsafe(records: list[dict[str, object]]) -> None:
        old = cast(dict[str, object], json.loads(json.dumps(rampart_record(records))))
        old["evidence_id"] = "EVD-CALLER-AGENT-SAFETY-OLD"
        report = rampart_report(old)
        native = cast(dict[str, object], report["native_report"])
        buckets = cast(dict[str, list[dict[str, object]]], native["by_harm_category"])
        result = buckets["authorization"][0]
        result["safe"] = False
        result["status"] = "unsafe"
        result["summary"] = "attack objective detected"
        native.update({"passed": 19, "failed": 1})
        summary = cast(dict[str, object], native["population_summary"])
        summary.update(
            {
                "safe_count": 19,
                "unsafe_count": 1,
                "attack_success_rate": 0.05,
                "safety_pass_rate": 0.95,
            }
        )
        old_time = datetime.now(UTC) - timedelta(minutes=2)
        old["generated_at"] = canonical_timestamp(old_time)
        report["started_at"] = canonical_timestamp(old_time)
        report["generated_at"] = canonical_timestamp(old_time)
        report["native_report_digest"] = hashlib.sha256(
            canonical_bytes(native)
        ).hexdigest()
        attestation = cast(dict[str, object], report["run_attestation"])
        attestation.update(
            {
                "attestation_id": "RAMPART-ATTESTATION-OLD",
                "report_id": "RAMPART-REPORT-OLD",
                "run_id": "RAMPART-RUN-OLD",
                "started_at": canonical_timestamp(old_time),
                "generated_at": canonical_timestamp(old_time),
                "attested_at": canonical_timestamp(old_time),
                "expires_at": canonical_timestamp(old_time + timedelta(minutes=5)),
                "native_report_digest": report["native_report_digest"],
            }
        )
        report.update(
            {
                "report_id": attestation["report_id"],
                "run_id": attestation["run_id"],
            }
        )
        resign_rampart_attestation(attestation)
        artifacts = cast(dict[str, object], old["artifacts"])
        for uri_field, filename in (
            ("report_uri", "rampart-safety-report-old.json"),
            ("native_report_uri", "rampart-native-report-old.json"),
            ("campaign_uri", "rampart-campaign-old.json"),
            ("run_attestation_uri", "rampart-run-attestation-old.json"),
        ):
            artifacts[uri_field] = "artifact://agt-ai-sdlc-caller-evidence/" + filename
        reseal_rampart_record(old)
        records.append(old)

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_gate_records=add_old_misdeclared_unsafe,
    )

    assert result.returncode != 0
    assert "exactly one authoritative RAMPART run" in result.stderr


def test_rampart_command_status_cannot_claim_pass_for_signed_unsafe_results(
    tmp_path: Path,
) -> None:
    def misdeclare_unsafe(records: list[dict[str, object]]) -> None:
        record = rampart_record(records)
        report = rampart_report(record)
        native = cast(dict[str, object], report["native_report"])
        buckets = cast(dict[str, list[dict[str, object]]], native["by_harm_category"])
        result = buckets["authorization"][0]
        result.update(
            {
                "safe": False,
                "status": "unsafe",
                "summary": "attack objective detected",
            }
        )
        native.update({"passed": 19, "failed": 1})
        summary = cast(dict[str, object], native["population_summary"])
        summary.update(
            {
                "safe_count": 19,
                "unsafe_count": 1,
                "attack_success_rate": 0.05,
                "safety_pass_rate": 0.95,
            }
        )
        native_digest = hashlib.sha256(canonical_bytes(native)).hexdigest()
        report["native_report_digest"] = native_digest
        attestation = cast(dict[str, object], report["run_attestation"])
        attestation["native_report_digest"] = native_digest
        resign_rampart_attestation(attestation)
        reseal_rampart_record(record)

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_gate_records=misdeclare_unsafe,
    )

    assert result.returncode != 0
    assert "command status and exit code do not match signed results" in result.stderr


def test_noncanonical_rampart_attestation_artifact_is_rejected(tmp_path: Path) -> None:
    def append_newline(caller_dir: Path, _records: list[dict[str, object]]) -> None:
        path = caller_dir / "rampart-run-attestation.json"
        path.write_bytes(path.read_bytes() + b"\n")

    result, _ = run_assembler(
        tmp_path,
        risk_class="high",
        mutate_raw_artifacts=append_newline,
    )

    assert result.returncode != 0
    assert "caller command report digest mismatch" in result.stderr


@pytest.mark.parametrize("mutation", ["missing", "mismatch", "symlink"])
def test_referenced_raw_command_reports_are_content_addressed_regular_files(
    tmp_path: Path,
    mutation: str,
) -> None:
    def mutate_raw(caller_dir: Path, records: list[dict[str, object]]) -> None:
        lint = next(record for record in records if record["kind"] == "lint")
        artifacts = cast(dict[str, object], lint["artifacts"])
        filename = str(artifacts["report_uri"]).rsplit("/", 1)[-1]
        path = caller_dir / filename
        if mutation == "missing":
            path.unlink()
        elif mutation == "mismatch":
            path.write_bytes(path.read_bytes() + b"tampered")
        else:
            payload = path.read_bytes()
            path.unlink()
            target = caller_dir.parent / "outside-caller-report.json"
            target.write_bytes(payload)
            path.symlink_to(target)

    result, _ = run_assembler(tmp_path, mutate_raw_artifacts=mutate_raw)

    assert result.returncode != 0
    if mutation == "symlink":
        assert "top-level regular files" in result.stderr
    else:
        assert (
            "missing retained report" in result.stderr
            or "command report digest mismatch" in result.stderr
        )


def test_raw_report_uri_cannot_name_a_nested_path(tmp_path: Path) -> None:
    def nest_uri(records: list[dict[str, object]]) -> None:
        lint = next(record for record in records if record["kind"] == "lint")
        artifacts = cast(dict[str, object], lint["artifacts"])
        artifacts["report_uri"] = (
            "artifact://agt-ai-sdlc-caller-evidence/nested/caller-lint.json"
        )
        seal_command_evidence(lint)

    result, _ = run_assembler(tmp_path, mutate_gate_records=nest_uri)

    assert result.returncode != 0
    assert "one safe, non-reserved basename" in result.stderr


def test_raw_report_basenames_cannot_collide(tmp_path: Path) -> None:
    def collide(records: list[dict[str, object]]) -> None:
        build = next(record for record in records if record["kind"] == "build")
        lint = next(record for record in records if record["kind"] == "lint")
        build_artifacts = cast(dict[str, object], build["artifacts"])
        lint_artifacts = cast(dict[str, object], lint["artifacts"])
        lint_artifacts["report_uri"] = build_artifacts["report_uri"]
        lint_artifacts["report_sha256"] = build_artifacts["report_sha256"]
        seal_command_evidence(lint)

    result, _ = run_assembler(tmp_path, mutate_gate_records=collide)

    assert result.returncode != 0
    assert "basenames must be unique" in result.stderr


def test_unreferenced_raw_report_is_rejected(tmp_path: Path) -> None:
    def add_unreferenced(caller_dir: Path, _records: list[dict[str, object]]) -> None:
        (caller_dir / "unreferenced-report.json").write_bytes(b"{}")

    result, _ = run_assembler(tmp_path, mutate_raw_artifacts=add_unreferenced)

    assert result.returncode != 0
    assert "unexpected files" in result.stderr


def test_skeletal_passed_gate_summaries_are_rejected(tmp_path: Path) -> None:
    result, _ = run_assembler(tmp_path, skeletal_gate_handoffs=True)

    assert result.returncode != 0
    assert "caller G0-G4 gate evidence is invalid or unbound" in result.stderr


def test_resealed_gate_result_missing_mandatory_check_is_rejected(
    tmp_path: Path,
) -> None:
    def remove_intent_check(handoff: dict[str, object]) -> None:
        results = cast(list[dict[str, object]], handoff["results"])
        checks = cast(list[dict[str, object]], results[0]["checks"])
        checks.pop()
        seal_digest(results[0], "result_digest")

    result, _ = run_assembler(
        tmp_path,
        mutate_quality_handoff=remove_intent_check,
    )

    assert result.returncode != 0
    assert "caller G0-G4 gate evidence is invalid or unbound" in result.stderr


def test_gate_result_requires_every_per_record_common_check(tmp_path: Path) -> None:
    def remove_one_common_check(handoff: dict[str, object]) -> None:
        results = cast(list[dict[str, object]], handoff["results"])
        g2 = results[2]
        checks = cast(list[dict[str, object]], g2["checks"])
        index = next(
            index
            for index, check in enumerate(checks)
            if check["code"] == "evidence.source_binding"
        )
        checks.pop(index)
        seal_digest(g2, "result_digest")

    result, _ = run_assembler(
        tmp_path,
        mutate_quality_handoff=remove_one_common_check,
    )

    assert result.returncode != 0
    assert "exact per-record evidence checks" in result.stderr


@pytest.mark.parametrize(
    "missing_kind",
    ["build", "test", "review", "sast", "secrets", "provenance"],
)
@pytest.mark.parametrize("risk_class", ["standard", "high"])
def test_risk_mandatory_raw_gate_evidence_cannot_be_omitted(
    tmp_path: Path,
    missing_kind: str,
    risk_class: str,
) -> None:
    def remove_after_evaluation(records: list[dict[str, object]]) -> None:
        records[:] = [record for record in records if record["kind"] != missing_kind]

    result, _ = run_assembler(
        tmp_path,
        mutate_gate_records_after_handoff=remove_after_evaluation,
        risk_class=risk_class,
    )

    assert result.returncode != 0
    assert "caller G0-G4 gate evidence is invalid or unbound" in result.stderr


def test_resealed_review_pass_cannot_hide_raw_blockers(tmp_path: Path) -> None:
    def add_blocker(records: list[dict[str, object]]) -> None:
        review = next(record for record in records if record["kind"] == "review")
        metrics = cast(dict[str, object], review["metrics"])
        metrics["blocking_findings"] = 1
        seal_command_evidence(review)

    result, _ = run_assembler(tmp_path, mutate_gate_records=add_blocker)

    assert result.returncode != 0
    assert "review evidence is not independent" in result.stderr


def test_resealed_pyrit_pass_cannot_hide_attack_success_above_policy(
    tmp_path: Path,
) -> None:
    def exceed_asr(evidence: dict[str, object]) -> None:
        metrics = cast(dict[str, object], evidence["metrics"])
        overall = cast(dict[str, object], metrics["overall"])
        overall.update({"successes": 1, "failures": 0, "attack_success_rate": 1.0})
        groups = cast(list[dict[str, object]], metrics["groups"])
        group_metrics = cast(dict[str, object], groups[0]["metrics"])
        group_metrics.update(
            {"successes": 1, "failures": 0, "attack_success_rate": 1.0}
        )
        run = cast(dict[str, object], evidence["run"])
        observed_trials = cast(list[dict[str, object]], run["observed_trials"])
        observed_trials[0]["outcome"] = "success"
        seal_digest(evidence, "evidence_digest")

    result, _ = run_assembler(
        tmp_path,
        mutate_pyrit=exceed_asr,
        require_pyrit=True,
    )

    assert result.returncode != 0
    assert "threshold.attack_success_rate_exceeded" in result.stderr


def test_pyrit_incompatible_version_baseline_is_valid_diagnostic_but_fails_policy(
    tmp_path: Path,
) -> None:
    def mutate_and_reseal(evidence: dict[str, object]) -> None:
        mutate_pyrit_incompatible_version_baseline(evidence)
        seal_digest(evidence, "evidence_digest")

    result, _ = run_assembler(
        tmp_path,
        mutate_pyrit=mutate_and_reseal,
        require_pyrit=True,
    )

    assert result.returncode != 0
    assert "PyRIT release verdict is failed" in result.stderr
    assert "PyRIT evidence is invalid or source-unbound" not in result.stderr


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            lambda evidence: evidence.pop("usage"), id="missing-top-level-field"
        ),
        pytest.param(
            lambda evidence: cast(dict[str, object], evidence["configuration"]).pop(
                "scorer"
            ),
            id="missing-nested-field",
        ),
        pytest.param(
            lambda evidence: cast(dict[str, object], evidence["completeness"]).update(
                {"unexpected": True}
            ),
            id="nested-extra-field",
        ),
        pytest.param(mutate_pyrit_baseline_flag, id="forged-baseline-compatible-flag"),
        pytest.param(mutate_pyrit_baseline_delta, id="forged-baseline-delta"),
        pytest.param(
            mutate_pyrit_missing_target_claims_compatible_baseline,
            id="missing-target-compatible-baseline",
        ),
        pytest.param(
            mutate_pyrit_terminal_without_completion,
            id="terminal-without-completed-at",
        ),
        pytest.param(
            mutate_pyrit_wrong_trial_plan_digest,
            id="trial-plan-digest-mismatch",
        ),
        pytest.param(
            mutate_pyrit_generated_at_ignores_oldest_trial,
            id="generated-at-ignores-oldest-trial",
        ),
        pytest.param(
            mutate_pyrit_unbound_inventory_claims_complete,
            id="unbound-inventory-claims-complete",
        ),
        pytest.param(
            mutate_pyrit_missing_provenance_claims_complete,
            id="missing-provenance-claims-complete",
        ),
        pytest.param(
            mutate_pyrit_observed_outcome_without_metrics,
            id="observed-outcome-metric-mismatch",
        ),
        pytest.param(
            mutate_pyrit_lower_overall_p95,
            id="lowered-overall-p95",
        ),
        pytest.param(
            mutate_pyrit_hide_observed_max_latency,
            id="lowered-overall-max",
        ),
        pytest.param(
            mutate_pyrit_partial_tokens_with_complete_facts,
            id="partial-token-coverage-with-complete-facts",
        ),
        pytest.param(
            mutate_pyrit_partial_cost_with_complete_facts,
            id="partial-cost-coverage-with-complete-facts",
        ),
    ],
)
def test_structurally_invalid_rehashed_pyrit_is_rejected(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], object],
) -> None:
    def mutate_and_reseal(evidence: dict[str, object]) -> None:
        mutation(evidence)
        seal_digest(evidence, "evidence_digest")

    result, _ = run_assembler(tmp_path, mutate_pyrit=mutate_and_reseal)

    assert result.returncode != 0
    assert "PyRIT evidence is invalid or source-unbound" in result.stderr


def test_required_pyrit_rejects_reused_trials_even_with_consistent_provenance(
    tmp_path: Path,
) -> None:
    def mutate_and_reseal(evidence: dict[str, object]) -> None:
        mutate_pyrit_reused_trial_claims_complete(evidence)
        seal_digest(evidence, "evidence_digest")

    result, _ = run_assembler(
        tmp_path,
        mutate_pyrit=mutate_and_reseal,
        require_pyrit=True,
    )

    assert result.returncode != 0
    assert "required PyRIT evidence must be complete" in result.stderr


def test_pyrit_evidence_must_be_canonical_json(tmp_path: Path) -> None:
    result, _ = run_assembler(
        tmp_path,
        mutate_pyrit=lambda _evidence: None,
        noncanonical_pyrit=True,
    )

    assert result.returncode != 0
    assert "PyRIT evidence must use canonical JSON" in result.stderr


def test_base_is_normalized_bound_and_used_for_patch_validation(tmp_path: Path) -> None:
    result, evidence_dir = run_assembler(tmp_path)

    assert result.returncode == 0, result.stderr
    manifest = json.loads((evidence_dir / "evidence-manifest.json").read_text())
    quality = json.loads((evidence_dir / "quality-report.json").read_text())
    security = json.loads((evidence_dir / "security-report.json").read_text())
    provenance = json.loads((evidence_dir / "provenance.json").read_text())
    normalized_base = manifest["base_revision"]
    assert re.fullmatch(r"[0-9a-f]{40}", normalized_base)
    assert quality == {
        "base_revision": normalized_base,
        "classification": "central_quality_metadata",
        "gate_result": False,
        "metadata_id": "central-source-quality",
        "observations": {
            "base_binding": True,
            "checkout_binding": True,
            "patch_whitespace_errors": 0,
        },
        "schema": "agt.ci-quality-metadata/v1",
        "source_revision": manifest["source_revision"],
    }
    assert security["base_revision"] == normalized_base
    assert provenance["base_revision"] == normalized_base


def test_patch_whitespace_is_checked_across_base_to_source(tmp_path: Path) -> None:
    result, _ = run_assembler(tmp_path, source_contents="trailing whitespace  \n")

    assert result.returncode != 0
    assert "deterministic source quality check failed" in result.stderr


@pytest.mark.parametrize("base_input", ["a" * 39, "g" * 40, "a" * 40 + " --help"])
def test_malformed_base_revision_is_rejected(tmp_path: Path, base_input: str) -> None:
    result, _ = run_assembler(tmp_path, base_input=base_input)

    assert result.returncode != 0
    assert "base_revision must be a full Git commit SHA" in result.stderr


def test_base_revision_must_be_an_ancestor_of_source(tmp_path: Path) -> None:
    result, _ = run_assembler(tmp_path, divergent_base=True)

    assert result.returncode != 0
    assert "base_revision must be an ancestor of source_revision" in result.stderr


@pytest.mark.parametrize(
    "filename",
    [
        "agent-sre-execution-evidence.json",
        "orchestration-manifest.json",
        "execution-receipt.json",
    ],
)
def test_governed_execution_files_are_mandatory(tmp_path: Path, filename: str) -> None:
    result, _ = run_assembler(tmp_path, omit_orchestration_file=filename)

    assert result.returncode != 0
    assert "caller evidence is missing required files" in result.stderr


@pytest.mark.parametrize(
    "filename",
    ["orchestration-manifest.json", "execution-receipt.json"],
)
def test_orchestration_files_must_be_canonical(tmp_path: Path, filename: str) -> None:
    result, _ = run_assembler(tmp_path, noncanonical_orchestration_file=filename)

    assert result.returncode != 0
    assert "must use canonical JSON" in result.stderr


@pytest.mark.parametrize(
    "filename",
    ["orchestration-manifest.json", "execution-receipt.json"],
)
def test_orchestration_files_cannot_be_symlinks(tmp_path: Path, filename: str) -> None:
    result, _ = run_assembler(tmp_path, symlink_orchestration_file=filename)

    assert result.returncode != 0
    assert "caller evidence entries must be top-level regular files" in result.stderr


def test_orchestration_manifest_and_receipt_bind_provenance_and_artifact_manifest(
    tmp_path: Path,
) -> None:
    result, evidence_dir = run_assembler(tmp_path)

    assert result.returncode == 0, result.stderr
    manifest = json.loads((evidence_dir / "orchestration-manifest.json").read_text())
    receipt = json.loads((evidence_dir / "execution-receipt.json").read_text())
    provenance = json.loads((evidence_dir / "provenance.json").read_text())
    artifact_manifest = json.loads(
        (evidence_dir / "evidence-manifest.json").read_text()
    )
    orchestration = provenance["orchestration"]
    assert (
        orchestration["manifest_digest"]
        == hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    )
    assert orchestration["receipt_digest"] == receipt["receipt_digest"]
    assert orchestration["policy_digest"] == manifest["policy_digest"]
    assert orchestration["assignment_ids"] == [
        "impl:TASK-001",
        "review:whole-change",
        "remediation:round:02",
        "review:whole-change:round:02",
    ]
    assert [item["state"] for item in receipt["assignments"]] == [
        "succeeded",
        "succeeded",
        "skipped",
        "skipped",
    ]
    assert [item["round_number"] for item in receipt["review_history"]] == [1]
    assert receipt["review_history"][-1]["semantic_outcome"]["verdict"] == "clean"
    artifact_names = {artifact["name"] for artifact in artifact_manifest["artifacts"]}
    assert {"orchestration-manifest.json", "execution-receipt.json"} <= artifact_names


def test_blocking_review_scoped_fix_and_clean_rereview_are_accepted(
    tmp_path: Path,
) -> None:
    result, evidence_dir = run_assembler(tmp_path, run_second_review_round=True)

    assert result.returncode == 0, result.stderr
    receipt = json.loads((evidence_dir / "execution-receipt.json").read_text())
    assert [item["state"] for item in receipt["assignments"]] == [
        "succeeded",
        "succeeded",
        "succeeded",
        "succeeded",
    ]
    assert [
        item["semantic_outcome"]["verdict"] for item in receipt["review_history"]
    ] == ["blocking", "clean"]
    assert receipt["review_history"][0]["remediation"]["binding"]["paths"] == [
        "tracked.txt"
    ]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(mutate_missing_manifest_limits, id="manifest-missing-field"),
        pytest.param(
            mutate_missing_assignment_duration,
            id="manifest-missing-assignment-duration",
        ),
        pytest.param(
            mutate_missing_review_round_limit,
            id="manifest-missing-review-round-limit",
        ),
        pytest.param(
            mutate_missing_conditional_rounds,
            id="manifest-missing-conditional-rounds",
        ),
        pytest.param(
            mutate_missing_tool_governance,
            id="manifest-missing-tool-governance",
        ),
        pytest.param(
            mutate_disabled_https_tool_governance,
            id="manifest-tool-governance-https-disabled",
        ),
        pytest.param(mutate_manifest_source, id="manifest-source-mismatch"),
        pytest.param(mutate_failed_receipt, id="receipt-not-successful"),
        pytest.param(mutate_incomplete_receipt_cost, id="receipt-cost-incomplete"),
        pytest.param(mutate_receipt_assignment_id, id="receipt-assignment-mismatch"),
        pytest.param(mutate_receipt_policy, id="receipt-policy-mismatch"),
        pytest.param(mutate_receipt_digest, id="receipt-digest-tampering"),
        pytest.param(
            mutate_missing_review_history, id="receipt-missing-review-history"
        ),
        pytest.param(
            mutate_review_attestation_signature,
            id="review-attestation-forgery",
        ),
        pytest.param(mutate_review_output_binding, id="review-output-unbound"),
        pytest.param(
            mutate_unplanned_conditional_execution,
            id="unplanned-conditional-execution",
        ),
        pytest.param(
            mutate_cross_manifest_review_replay,
            id="cross-manifest-review-replay",
        ),
        pytest.param(mutate_scope_outside_manifest, id="assignment-scope-not-allowed"),
        pytest.param(mutate_missing_risk_checkpoint, id="missing-risk-checkpoint"),
        pytest.param(mutate_receipt_turn_limit, id="receipt-turn-limit"),
        pytest.param(
            mutate_receipt_checkpoint_coverage,
            id="receipt-checkpoint-coverage",
        ),
        pytest.param(
            mutate_receipt_tool_audit_digest,
            id="receipt-tool-audit-digest",
        ),
        pytest.param(
            mutate_receipt_unscreened_tool_audit,
            id="receipt-tool-audit-unscreened",
        ),
        pytest.param(
            mutate_expired_release_checkpoint,
            id="receipt-expired-release-checkpoint",
        ),
        pytest.param(
            mutate_elapsed_release_checkpoint,
            id="receipt-release-checkpoint-elapsed-before-assembly",
        ),
        pytest.param(
            mutate_duplicate_receipt_usage_event,
            id="receipt-duplicate-usage-event",
        ),
        pytest.param(mutate_review_family, id="review-provider-family"),
        pytest.param(mutate_future_benchmark, id="future-benchmark"),
        pytest.param(mutate_stale_no_expiry_benchmark, id="stale-no-expiry-benchmark"),
        pytest.param(mutate_zero_cost_reseal, id="zero-cost-reseal"),
        pytest.param(mutate_future_price, id="future-price"),
        pytest.param(mutate_receipt_prompt, id="receipt-prompt-mismatch"),
        pytest.param(mutate_registry_identity, id="registry-identity-mismatch"),
        pytest.param(mutate_registry_tier, id="registry-tier-mismatch"),
        pytest.param(mutate_disabled_registry_record, id="registry-disabled"),
    ],
)
def test_invalid_or_unbound_orchestration_is_rejected(
    tmp_path: Path,
    mutate: Callable[[dict[str, object], dict[str, object]], None],
) -> None:
    result, _ = run_assembler(tmp_path, mutate_orchestration=mutate)

    assert result.returncode != 0
    assert "orchestration evidence is invalid or unbound" in result.stderr


def test_cost_evidence_rejects_same_count_and_cost_for_substituted_event_set(
    tmp_path: Path,
) -> None:
    result, _ = run_assembler(
        tmp_path,
        mutate_orchestration=mutate_substituted_receipt_usage_event,
    )

    assert result.returncode != 0
    assert "COST evidence is invalid or unbound" in result.stderr


@pytest.mark.parametrize(
    ("status", "exit_code"),
    [
        pytest.param("failed", 1, id="failed"),
        pytest.param("incomplete", None, id="incomplete"),
    ],
)
def test_cost_evidence_must_be_a_passed_zero_exit_record(
    tmp_path: Path,
    status: str,
    exit_code: int | None,
) -> None:
    def mutate(record: dict[str, object]) -> None:
        record["status"] = status
        record["exit_code"] = exit_code

    result, _ = run_assembler(tmp_path, mutate_cost_evidence=mutate)

    assert result.returncode != 0
    assert "COST evidence is invalid or unbound" in result.stderr


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        pytest.param("cost_complete", False, id="incomplete"),
        pytest.param("event_count", 1, id="wrong-event-count"),
        pytest.param("event_set_digest", "f" * 64, id="wrong-event-set"),
        pytest.param(
            "orchestration_event_set_digest",
            "f" * 64,
            id="wrong-orchestration-event-set",
        ),
        pytest.param("total_cost_usd", "0.11", id="wrong-total"),
        pytest.param("unpriced_events", 1, id="unpriced-event"),
    ],
)
def test_cost_evidence_must_exactly_reconcile_execution_receipt(
    tmp_path: Path,
    field_name: str,
    replacement: object,
) -> None:
    def mutate(record: dict[str, object]) -> None:
        metrics = cast(dict[str, object], record["metrics"])
        metrics[field_name] = replacement

    result, _ = run_assembler(tmp_path, mutate_cost_evidence=mutate)

    assert result.returncode != 0
    assert "COST evidence is invalid or unbound" in result.stderr


def test_cost_evidence_rejects_resealed_native_accounting_substitution(
    tmp_path: Path,
) -> None:
    def mutate(record: dict[str, object]) -> None:
        metrics = cast(dict[str, object], record["metrics"])
        report = cast(dict[str, object], metrics["change_cost_report"])
        component = cast(list[dict[str, object]], report["components"])[0]
        component["source_digest"] = "f" * 64
        seal_digest(component, "partition_digest")
        seal_digest(report, "accounting_digest")

    result, _ = run_assembler(tmp_path, mutate_cost_evidence=mutate)

    assert result.returncode != 0
    assert "COST evidence is invalid or unbound" in result.stderr


@pytest.mark.parametrize(
    "mutate_record",
    [
        pytest.param(
            lambda record: record.update({"unexpected": True}),
            id="extra-field",
        ),
        pytest.param(
            lambda record: record.pop("metrics"),
            id="missing-field",
        ),
        pytest.param(
            lambda record: record.update({"kind": "unknown"}),
            id="unknown-kind",
        ),
        pytest.param(
            lambda record: record.update({"status": "unknown"}),
            id="unknown-status",
        ),
        pytest.param(
            lambda record: record.update({"generated_at": "2026-08-25T07:00:00-05:00"}),
            id="noncanonical-timestamp",
        ),
        pytest.param(
            lambda record: record.update({"command": "   "}),
            id="empty-command",
        ),
        pytest.param(
            lambda record: record.update({"status": "passed", "exit_code": 1}),
            id="false-pass-claim",
        ),
        pytest.param(
            lambda record: record.update({"status": "failed", "exit_code": "1"}),
            id="noninteger-exit-code",
        ),
        pytest.param(
            lambda record: record.update({"kind": "test", "test_layers": []}),
            id="test-without-layer",
        ),
        pytest.param(
            lambda record: record.update({"test_layers": ["unit"]}),
            id="layer-on-nontest",
        ),
        pytest.param(
            lambda record: record.update({"metrics": []}),
            id="metrics-not-object",
        ),
        pytest.param(
            lambda record: record.update({"artifacts": {"report_uri": 7}}),
            id="artifact-value-not-string",
        ),
        pytest.param(
            lambda record: record.update({"requirement_ids": ["REQ-2", "REQ-1"]}),
            id="identifiers-not-canonical",
        ),
    ],
)
def test_malformed_command_evidence_is_rejected(
    tmp_path: Path,
    mutate_record: Callable[[dict[str, object]], None],
) -> None:
    def mutate_and_reseal(record: dict[str, object]) -> None:
        mutate_record(record)
        seal_command_evidence(record)

    result, _ = run_assembler(tmp_path, mutate_record=mutate_and_reseal)

    assert result.returncode != 0
    assert "Agent SRE execution evidence is invalid or source-unbound" in result.stderr


def test_canonical_command_evidence_is_accepted(tmp_path: Path) -> None:
    result, evidence_dir = run_assembler(
        tmp_path,
        mutate_record=lambda _record: None,
    )

    assert result.returncode == 0, result.stderr
    records = json.loads(
        (evidence_dir / "agent-sre-execution-evidence.json").read_text()
    )
    assert any(record["evidence_id"] == "EVD-CALLER-LINT" for record in records)


def test_command_evidence_digest_tampering_is_rejected(tmp_path: Path) -> None:
    def tamper(record: dict[str, object]) -> None:
        record["evidence_sha256"] = "f" * 64

    result, _ = run_assembler(tmp_path, mutate_record=tamper)

    assert result.returncode != 0
    assert "Agent SRE execution evidence is invalid or source-unbound" in result.stderr


def test_command_evidence_file_must_be_canonical_json(tmp_path: Path) -> None:
    result, _ = run_assembler(
        tmp_path,
        mutate_record=lambda _record: None,
        canonical_record_file=False,
    )

    assert result.returncode != 0
    assert "Agent SRE execution evidence must use canonical JSON" in result.stderr


def test_unpinned_docker_action_is_rejected(tmp_path: Path) -> None:
    result, _ = run_assembler(
        tmp_path,
        workflow_reference="docker://alpine:3.20",
    )

    assert result.returncode != 0
    assert "docker actions must use sha256 digests" in result.stderr


def test_digest_pinned_docker_action_is_accepted(tmp_path: Path) -> None:
    result, _ = run_assembler(
        tmp_path,
        workflow_reference=f"docker://alpine@sha256:{'1' * 64}",
    )

    assert result.returncode == 0, result.stderr


def test_central_whitespace_metadata_is_not_build_gate_evidence(
    tmp_path: Path,
) -> None:
    result, evidence_dir = run_assembler(tmp_path)

    assert result.returncode == 0, result.stderr
    records = json.loads(
        (evidence_dir / "agent-sre-execution-evidence.json").read_text()
    )
    assert all(record["evidence_id"] != "EVD-CENTRAL-BUILD" for record in records)
    assert any(record["evidence_id"] == "EVD-CALLER-BUILD" for record in records)


def test_caller_evidence_rejects_non_regular_and_oversized_entries_before_parsing() -> (
    None
):
    text = workflow_text()
    assert "if not stat.S_ISREG(mode):" in text
    assert "caller evidence entries must be top-level regular files" in text
    assert "max_caller_file_bytes = 16 * 1024 * 1024" in text
    assert "max_caller_records = 256" in text
    assert "max_caller_total_bytes = 32 * 1024 * 1024" in text
    assert text.index("total_caller_bytes = sum") < text.index(
        "report = load_json(path)"
    )


def test_pre_attestation_provenance_never_claims_attested() -> None:
    text = workflow_text()
    assert '"attestation_expected": attestation_expected' in text
    assert '"attested": False' in text
    assert '"attested": attestation_expected' not in text
    assert '"EVD-CENTRAL-PROVENANCE"' not in text


def test_permissions_are_read_only_except_isolated_attestation_job() -> None:
    model = workflow_model()
    assert model["permissions"] == {"actions": "read", "contents": "read"}
    assert model["jobs"]["evidence"]["permissions"] == {
        "actions": "read",
        "contents": "read",
    }
    assert model["jobs"]["attest"]["permissions"] == {
        "actions": "read",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
    }


def test_documented_caller_uses_an_immutable_reference_and_names_trust_boundaries() -> (
    None
):
    text = DOCUMENTATION.read_text(encoding="utf-8")
    assert "@<FULL_COMMIT_SHA>" in text
    assert "@main" not in text
    assert "agt-ai-sdlc-caller-evidence" in text
    assert "protected" in text.lower()
    assert "does not execute PyRIT" in text
    assert "`base_revision` is required" in text
    assert "EVD-CENTRAL-BUILD" in text
    assert "## Required repository evidence" in text
    assert "`orchestration-manifest.json`" in text
    assert "`execution-receipt.json`" in text
    assert "has_caller_evidence" not in text
    assert "must first execute the governed orchestration runtime" in text
