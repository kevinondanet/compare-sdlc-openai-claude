# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for complete cross-harness change-cost accounting."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agent_sre.sdlc.canonical import canonical_json_bytes
from agent_sre.sdlc.change_contract import RiskClass
from agent_sre.sdlc.cost_evidence import (
    ChangeCostReport,
    CostComponentKind,
    change_cost_report_from_usage_rollups,
    ledger_cost_component,
    parse_change_cost_report,
    pyrit_external_usage_component,
    rampart_external_usage_component,
)
from agent_sre.sdlc.development_gates import GateStatus
from agent_sre.sdlc.enterprise_gates import (
    EnterpriseGateEvaluator,
    command_evidence_from_usage_rollup,
)
from agent_sre.sdlc.usage_ledger import UsageRollup, usage_event_set_digest

from .test_enterprise_gates import (
    NOW,
    agent_security,
    bound_change,
    complete_rollup,
    conventional_security,
    prior_results,
    successful_execution,
)
from .test_rampart import make_rampart_report
from .test_release_policy import parse_evidence, parse_policy


def _partition(
    base: UsageRollup,
    *,
    event_id: str,
    cost_usd: Decimal,
) -> UsageRollup:
    return replace(
        base,
        event_count=1,
        distinct_tasks=1,
        accepted_tasks=1,
        known_cost_usd=cost_usd,
        unpriced_events=0,
        cost_per_task_usd=cost_usd,
        cost_per_accepted_task_usd=cost_usd,
        event_set_digest=usage_event_set_digest((event_id,)),
    )


def cross_harness_rollups(
    *,
    scanner_cost_usd: Decimal = Decimal("0.50"),
    change=None,
) -> tuple[UsageRollup, UsageRollup, tuple]:
    """Return a whole ledger rollup, orchestration subset, and exact partitions."""

    change = change or bound_change()
    orchestration = complete_rollup(change)
    ci = _partition(orchestration, event_id="usage:ci", cost_usd=Decimal("1.00"))
    scanner = _partition(
        orchestration,
        event_id="usage:scanner",
        cost_usd=scanner_cost_usd,
    )
    whole = replace(
        orchestration,
        event_count=orchestration.event_count + ci.event_count + scanner.event_count,
        distinct_tasks=orchestration.distinct_tasks + 2,
        accepted_tasks=orchestration.accepted_tasks + 2,
        known_cost_usd=orchestration.known_cost_usd + ci.known_cost_usd + scanner.known_cost_usd,
        event_set_digest=usage_event_set_digest(
            (
                "usage:impl:TASK-001",
                "usage:impl:TASK-002",
                "usage:review:whole-change",
                "usage:ci",
                "usage:scanner",
            )
        ),
    )
    components = (
        ledger_cost_component(
            kind=CostComponentKind.ORCHESTRATION,
            component_id="governed-orchestration",
            source_schema="agt.usage-ledger/rollup/v1",
            source_digest="1" * 64,
            event_ids=(
                "usage:impl:TASK-001",
                "usage:impl:TASK-002",
                "usage:review:whole-change",
            ),
            rollup=orchestration,
        ),
        ledger_cost_component(
            kind=CostComponentKind.CI,
            component_id="ci-validation",
            source_schema="agt.usage-ledger/rollup/v1",
            source_digest="2" * 64,
            event_ids=("usage:ci",),
            rollup=ci,
        ),
        ledger_cost_component(
            kind=CostComponentKind.SCANNER,
            component_id="security-scanners",
            source_schema="agt.usage-ledger/rollup/v1",
            source_digest="3" * 64,
            event_ids=("usage:scanner",),
            rollup=scanner,
        ),
    )
    return whole, orchestration, components


def make_change_cost_report(
    *,
    scanner_cost_usd: Decimal = Decimal("0.50"),
) -> ChangeCostReport:
    change = bound_change()
    whole, orchestration, components = cross_harness_rollups(scanner_cost_usd=scanner_cost_usd)
    return change_cost_report_from_usage_rollups(
        whole,
        orchestration_rollup=orchestration,
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        ledger_components=components,
        external_components=(
            pyrit_external_usage_component(parse_evidence()),
            rampart_external_usage_component(make_rampart_report(change)),
        ),
    )


def test_change_cost_report_reconciles_ledger_and_external_harnesses() -> None:
    report = make_change_cost_report()

    parsed = parse_change_cost_report(report.model_dump_json())

    assert parsed == report
    assert parsed.ledger_rollup.event_count == 5
    assert parsed.orchestration_rollup.event_count == 3
    assert parsed.total_event_count == 34
    assert parsed.total_cost_usd == Decimal("7.012300")
    assert parsed.cost_complete
    assert {component.component_type for component in parsed.components} == {
        "ledger",
        "pyrit_external",
        "rampart_external",
    }


def test_change_cost_report_rejects_tampered_total_and_partition() -> None:
    report = make_change_cost_report()
    payload = report.model_dump(mode="json")
    payload["total_cost_usd"] = "0"

    with pytest.raises(ValidationError, match="total_cost_usd"):
        ChangeCostReport.model_validate_json(canonical_json_bytes(payload), strict=True)

    whole, orchestration, components = cross_harness_rollups()
    with pytest.raises(ValidationError, match="ledger components do not partition"):
        change_cost_report_from_usage_rollups(
            replace(whole, known_cost_usd=whole.known_cost_usd + Decimal("1")),
            orchestration_rollup=orchestration,
            change_id=bound_change().change_id,
            source_revision=bound_change().source_revision,
            change_digest=bound_change().digest,
            generated_at=NOW,
            ledger_components=components,
        )


def test_change_cost_report_requires_explicit_disjoint_ledger_event_proofs() -> None:
    change = bound_change()
    whole, orchestration, components = cross_harness_rollups()

    with pytest.raises(ValueError, match="explicit ledger_components"):
        change_cost_report_from_usage_rollups(
            whole,
            orchestration_rollup=orchestration,
            change_id=change.change_id,
            source_revision=change.source_revision,
            change_digest=change.digest,
            generated_at=NOW,
            ledger_components=(),
        )

    duplicated = ledger_cost_component(
        kind=CostComponentKind.CI,
        component_id="ci-validation",
        source_schema="agt.usage-ledger/rollup/v1",
        source_digest="4" * 64,
        event_ids=("usage:impl:TASK-001",),
        rollup=_partition(
            orchestration,
            event_id="usage:impl:TASK-001",
            cost_usd=Decimal("1.00"),
        ),
    )
    with pytest.raises(ValidationError, match="event inventories must be disjoint"):
        change_cost_report_from_usage_rollups(
            whole,
            orchestration_rollup=orchestration,
            change_id=change.change_id,
            source_revision=change.source_revision,
            change_digest=change.digest,
            generated_at=NOW,
            ledger_components=(components[0], duplicated, components[2]),
        )


def test_g5_budgets_whole_change_while_g6_reconciles_orchestration_subset() -> None:
    change = bound_change()
    whole, orchestration, components = cross_harness_rollups()
    external = (
        pyrit_external_usage_component(parse_evidence()),
        rampart_external_usage_component(make_rampart_report(change)),
    )
    evidence = command_evidence_from_usage_rollup(
        whole,
        orchestration_rollup=orchestration,
        ledger_components=components,
        external_components=external,
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/whole-change.json",
        report_sha256="a" * 64,
    )
    evaluator = EnterpriseGateEvaluator()
    g5 = evaluator.evaluate_g5(change=change, evidence=evidence, evaluated_at=NOW)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    g6 = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=evidence,
        evaluated_at=NOW,
    )

    assert g5.status is GateStatus.PASS
    cost_check = next(check for check in g6.checks if check.code == "orchestration.cost_reconciled")
    assert cost_check.passed
    assert cost_check.actual["whole_change_total_cost_usd"] == "7.012300"


def test_high_risk_release_binds_cost_components_to_exact_g4_artifacts() -> None:
    change = bound_change(RiskClass.HIGH)
    whole, orchestration, components = cross_harness_rollups(change=change)
    evaluator = EnterpriseGateEvaluator()
    g4 = evaluator.evaluate_g4(
        change=change,
        evidence=[*conventional_security(change), *agent_security(change)],
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    exact_external = (
        pyrit_external_usage_component(parse_evidence()),
        rampart_external_usage_component(make_rampart_report(change)),
    )
    exact_evidence = command_evidence_from_usage_rollup(
        whole,
        orchestration_rollup=orchestration,
        ledger_components=components,
        external_components=exact_external,
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/high-risk.json",
        report_sha256="a" * 64,
    )
    prior = [g4 if result.gate_id == "G4" else result for result in prior_results(change)]
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    exact_g6 = evaluator.evaluate_g6(
        change=change,
        prior_results=prior,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=exact_evidence,
        evaluated_at=NOW,
    )

    assert (
        evaluator.evaluate_g5(
            change=change,
            evidence=exact_evidence,
            evaluated_at=NOW,
        ).status
        is GateStatus.PASS
    )
    assert next(
        check for check in exact_g6.checks if check.code == "release.cost_g4_external_binding"
    ).passed

    substituted_external = (
        pyrit_external_usage_component(parse_evidence()),
        rampart_external_usage_component(
            make_rampart_report(change, run_id="RAMPART-RUN-SUBSTITUTED")
        ),
    )
    substituted_evidence = command_evidence_from_usage_rollup(
        whole,
        orchestration_rollup=orchestration,
        ledger_components=components,
        external_components=substituted_external,
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/substituted.json",
        report_sha256="b" * 64,
    )
    substituted_g6 = evaluator.evaluate_g6(
        change=change,
        prior_results=prior,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=substituted_evidence,
        evaluated_at=NOW,
    )

    assert not next(
        check for check in substituted_g6.checks if check.code == "release.cost_g4_external_binding"
    ).passed


def test_g5_enforces_budget_against_whole_change_not_orchestration_only() -> None:
    change = bound_change()
    whole, orchestration, components = cross_harness_rollups(scanner_cost_usd=Decimal("100"))
    evidence = command_evidence_from_usage_rollup(
        whole,
        orchestration_rollup=orchestration,
        ledger_components=components,
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/over-budget.json",
        report_sha256="a" * 64,
    )

    result = EnterpriseGateEvaluator().evaluate_g5(
        change=change,
        evidence=evidence,
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "economics.cost_threshold" in result.blocking_reason_codes
