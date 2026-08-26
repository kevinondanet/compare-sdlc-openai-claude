# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Focused tests for enterprise G0-G6 composition and signed issuance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

import agent_sre.sdlc.enterprise_gates as enterprise_gates
from agent_sre.sdlc.canonical import canonical_sha256
from agent_sre.sdlc.change_contract import ChangePackage, RiskClass
from agent_sre.sdlc.cost_evidence import (
    CostComponentKind,
    LedgerCostComponent,
    ledger_cost_component,
    pyrit_external_usage_component,
    rampart_external_usage_component,
)
from agent_sre.sdlc.development_gates import (
    CommandEvidence,
    DevelopmentGatePolicy,
    DevelopmentGateResult,
    EvidenceKind,
    EvidenceStatus,
    GateCheck,
    GateStatus,
)
from agent_sre.sdlc.enterprise_gates import (
    ApprovalDecision,
    ApprovalIssuerTrust,
    EffectiveProjectPolicy,
    EnterpriseGateEvaluator,
    EnterpriseGatePolicy,
    EnterpriseGateResult,
    EnterpriseReadinessBundle,
    HumanApproval,
    PolicyWeakeningError,
    ReadinessStatus,
    ReleaseIssuanceError,
    command_evidence_from_usage_rollup,
    effective_project_policy,
    issue_release_bundle,
    load_readiness_bundle,
    verify_release_bundle,
    write_readiness_bundle,
)
from agent_sre.sdlc.orchestration_runtime import (
    AssignmentExecutionReceipt,
    AssignmentExecutionRequest,
    AssignmentExecutionState,
    ExecutionReceipt,
    ExecutionStatus,
)
from agent_sre.sdlc.rampart import (
    RampartSafetyReport,
    command_evidence_from_rampart_report,
)
from agent_sre.sdlc.review_binding import attach_review_execution_binding
from agent_sre.sdlc.review_loop import ReviewRoundHistory, ReviewSemanticOutcome, ReviewVerdict
from agent_sre.sdlc.risk import RiskClassification, RiskSignal
from agent_sre.sdlc.usage_ledger import UsageRollup, usage_event_set_digest
from agent_sre.signing import ArtifactSigner

from .test_change_contract import make_change
from .test_development_gates import NOW as DEVELOPMENT_NOW
from .test_development_gates import complete_standard_evidence
from .test_orchestration import (
    REVIEW_ATTESTER_ID,
    REVIEW_ATTESTER_SIGNER,
    make_planner,
    make_policy,
)
from .test_rampart import (
    DEFAULT_RAMPART_CAMPAIGN_DIGEST,
    RAMPART_ISSUER_TRUST,
    make_rampart_report,
    make_unsafe_rampart_report,
)
from .test_release_policy import (
    COMMIT,
    parse_evidence,
    parse_policy,
    policy_payload,
    redigest_policy,
)

if TYPE_CHECKING:
    from agent_sre.sdlc.orchestration import OrchestrationManifest

NOW = datetime(2026, 8, 25, 12, 30, tzinfo=UTC)
APPROVAL_ISSUER_ID = "enterprise-idp"
APPROVAL_ISSUER_SIGNER = ArtifactSigner()
APPROVAL_ISSUER_TRUST = ApprovalIssuerTrust(
    issuer_id=APPROVAL_ISSUER_ID,
    public_key=APPROVAL_ISSUER_SIGNER.public_key_bytes.hex(),
    allowed_roles=("release-owner", "security"),
)


def enterprise_policy_with_approval_trust(**kwargs) -> EnterpriseGatePolicy:
    """Return a policy that trusts the deterministic test identity provider."""

    return enterprise_policy_with_rampart_campaign(
        trusted_approval_issuers=(APPROVAL_ISSUER_TRUST,),
        **kwargs,
    )


def enterprise_policy_with_rampart_campaign(**kwargs) -> EnterpriseGatePolicy:
    """Return a policy that pins the deterministic test RAMPART campaign."""

    kwargs.setdefault("trusted_rampart_issuers", (RAMPART_ISSUER_TRUST,))
    base = EnterpriseGatePolicy(**kwargs)
    payload = base.model_dump(mode="python")
    payload["profiles"] = tuple(
        profile.model_copy(
            update={"allowed_rampart_campaign_digests": (DEFAULT_RAMPART_CAMPAIGN_DIGEST,)}
        )
        if profile.require_agent_safety
        else profile
        for profile in base.profiles
    )
    return EnterpriseGatePolicy.model_validate(payload)


def replace_risk_profile(
    policy: EnterpriseGatePolicy,
    risk_class: RiskClass,
    **updates: object,
) -> EnterpriseGatePolicy:
    """Return a revalidated policy with one risk profile changed."""

    payload = policy.model_dump(mode="python")
    payload["profiles"] = tuple(
        profile.model_copy(update=updates) if profile.risk_class is risk_class else profile
        for profile in policy.profiles
    )
    return EnterpriseGatePolicy.model_validate(payload)


def bound_change(
    risk_class: RiskClass = RiskClass.STANDARD,
    *,
    tier: int = 2,
) -> ChangePackage:
    """Return a release-bindable change with the selected maximum task tier."""
    payload = make_change(risk_class=risk_class).model_dump(mode="json")
    payload["source_revision"] = COMMIT
    payload["tasks"][0]["risk_tier"] = tier
    return ChangePackage.model_validate(payload)


def signed_risk_classification(
    change: ChangePackage,
) -> tuple[RiskClassification, str]:
    """Return a fresh source-bound classification and its trusted public key."""
    signer = ArtifactSigner()
    signal = {
        RiskClass.DOCUMENTATION: RiskSignal.DOCUMENTATION_ONLY,
        RiskClass.SIMPLE: RiskSignal.LOW_RISK_CODE,
        RiskClass.STANDARD: RiskSignal.SOURCE_CODE,
        RiskClass.HIGH: RiskSignal.PRIVATE_RESTRICTED_DATA,
        RiskClass.TOOL_ENABLED_AGENT: RiskSignal.TOOL_EXECUTION,
    }[change.risk_class]
    classification = RiskClassification.create(
        classification_id="RISK-ENT-001",
        classifier_id="central-diff-classifier",
        classifier_version="1",
        change=change,
        changed_paths=("src/change.py", "tests/test_change.py"),
        signals=(signal,),
        classified_at=NOW,
        expires_at=NOW + timedelta(days=1),
        signer=signer,
    )
    return classification, signer.public_key_bytes.hex()


def execution_bound_evidence(
    change: ChangePackage,
    manifest: OrchestrationManifest,
    receipt: ExecutionReceipt,
    *,
    generated_at: datetime | None = None,
) -> list[CommandEvidence]:
    """Return standard G0-G3 evidence bound to the exact runtime review output."""
    evidence = complete_standard_evidence(change)
    if generated_at is not None:
        evidence = [
            CommandEvidence.create(
                evidence_id=item.evidence_id,
                change_id=item.change_id,
                source_revision=item.source_revision,
                change_digest=item.change_digest,
                kind=item.kind,
                status=item.status,
                producer=item.producer,
                environment=item.environment,
                command=item.command,
                exit_code=item.exit_code,
                requirement_ids=list(item.requirement_ids),
                scenario_ids=list(item.scenario_ids),
                task_ids=list(item.task_ids),
                test_layers=list(item.test_layers),
                metrics=item.metrics,
                artifacts=item.artifacts,
                generated_at=generated_at,
            )
            for item in evidence
        ]
    review_index = next(
        index for index, item in enumerate(evidence) if item.kind is EvidenceKind.REVIEW
    )
    evidence[review_index] = attach_review_execution_binding(
        evidence[review_index],
        manifest=manifest,
        receipt=receipt,
    )
    return evidence


def command(
    change: ChangePackage,
    kind: EvidenceKind,
    sequence: int,
    *,
    metrics: dict | None = None,
    artifacts: dict[str, str] | None = None,
    generated_at: datetime = NOW,
    status: EvidenceStatus = EvidenceStatus.PASSED,
    exit_code: int | None = 0,
) -> CommandEvidence:
    """Create CI evidence with a durable report reference."""
    supplied_artifacts = {
        "report_uri": f"evidence/{sequence}-{kind.value}.json",
        "report_sha256": "a" * 64,
    }
    supplied_artifacts.update(artifacts or {})
    return CommandEvidence.create(
        evidence_id=f"EVD-ENT-{sequence:03d}",
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        kind=kind,
        status=status,
        producer="enterprise-ci",
        command=f"verify-{kind.value}",
        exit_code=exit_code,
        generated_at=generated_at,
        metrics=metrics,
        artifacts=supplied_artifacts,
    )


def conventional_security(change: ChangePackage) -> list[CommandEvidence]:
    """Create passing conventional G4 evidence."""
    result: list[CommandEvidence] = []
    for sequence, kind in enumerate(
        (
            EvidenceKind.PROVENANCE,
            EvidenceKind.SAST,
            EvidenceKind.SBOM,
            EvidenceKind.SCA,
            EvidenceKind.SECRETS,
        ),
        start=1,
    ):
        metrics: dict = {}
        artifacts: dict[str, str] = {}
        if kind in {EvidenceKind.SAST, EvidenceKind.SCA, EvidenceKind.SECRETS}:
            metrics["blocking_findings"] = 0
        elif kind is EvidenceKind.PROVENANCE:
            metrics["attested"] = True
        elif kind is EvidenceKind.SBOM:
            artifacts["sbom"] = "evidence/sbom.spdx.json"
        result.append(
            command(
                change,
                kind,
                sequence,
                metrics=metrics,
                artifacts=artifacts,
            )
        )
    return result


def agent_security(
    change: ChangePackage,
    *,
    observed_tools: list[str] | None = None,
) -> list[CommandEvidence]:
    """Create passing RAMPART evidence and a declared-vs-observed tool manifest."""
    declared_tools = list(change.architecture.threat_model.privileged_tools)
    observed = declared_tools if observed_tools is None else observed_tools
    scorer = parse_evidence().configuration.scorer
    assert scorer is not None
    rampart = make_rampart_report(change)
    return [
        command_evidence_from_rampart_report(
            rampart,
            report_uri="artifact://rampart/CHG-001/report.json",
            native_report_uri="artifact://rampart/CHG-001/native-report.json",
            campaign_uri="artifact://rampart/CHG-001/campaign.json",
            run_attestation_uri="artifact://rampart/CHG-001/run-attestation.json",
            evidence_id="EVD-ENT-020",
        ),
        command(
            change,
            EvidenceKind.TOOL_MANIFEST,
            21,
            metrics={
                "declared_tools": declared_tools,
                "observed_tools": observed,
            },
        ),
        command(
            change,
            EvidenceKind.JUDGE_CALIBRATION,
            22,
            metrics={
                "framework": "PyRIT",
                "dataset_digest": "d" * 64,
                "scorer_eval_hash": scorer.eval_hash,
                "human_labeled_cases": 50,
                "agreement_rate": "0.92",
                "false_accept_rate": "0.02",
            },
        ),
    ]


def complete_rollup(change: ChangePackage, *, unpriced_events: int = 0) -> UsageRollup:
    """Build exact runtime economics for one change."""
    event_ids = orchestration_event_ids(change)
    return UsageRollup(
        group=(("change_id", change.change_id),),
        event_count=3,
        distinct_tasks=3,
        accepted_tasks=3,
        input_tokens=100,
        output_tokens=50,
        cached_input_tokens=10,
        reasoning_tokens=5,
        tool_calls=3,
        turns=10,
        known_cost_usd=Decimal("4.25"),
        unpriced_events=unpriced_events,
        average_latency_ms=Decimal("125.5"),
        p95_latency_ms=250,
        cache_hit_rate=Decimal("0.1"),
        cost_per_task_usd=None if unpriced_events else Decimal("1.416666666666666666"),
        cost_per_accepted_task_usd=(None if unpriced_events else Decimal("1.416666666666666666")),
        event_set_digest=usage_event_set_digest(event_ids),
    )


def orchestration_event_ids(change: ChangePackage) -> tuple[str, ...]:
    """Return the exact event inventory represented by ``complete_rollup``."""

    return tuple(
        sorted(
            (
                *(f"usage:impl:{task.task_id}" for task in change.tasks),
                "usage:review:whole-change",
            )
        )
    )


def standard_ledger_components(
    change: ChangePackage,
    orchestration_rollup: UsageRollup,
    *,
    event_ids: tuple[str, ...] | None = None,
) -> tuple[LedgerCostComponent, ...]:
    """Supply explicit orchestration, CI, and scanner ledger partitions."""

    empty = replace(
        orchestration_rollup,
        event_count=0,
        distinct_tasks=0,
        accepted_tasks=0,
        input_tokens=0,
        output_tokens=0,
        cached_input_tokens=0,
        reasoning_tokens=0,
        tool_calls=0,
        turns=0,
        known_cost_usd=Decimal("0"),
        unpriced_events=0,
        average_latency_ms=None,
        p95_latency_ms=None,
        cache_hit_rate=None,
        cost_per_task_usd=None,
        cost_per_accepted_task_usd=None,
        event_set_digest=usage_event_set_digest(()),
    )
    return (
        ledger_cost_component(
            kind=CostComponentKind.ORCHESTRATION,
            component_id="governed-orchestration",
            source_schema="agt.usage-ledger/partition/v1",
            source_digest="1" * 64,
            event_ids=event_ids or orchestration_event_ids(change),
            rollup=orchestration_rollup,
        ),
        ledger_cost_component(
            kind=CostComponentKind.CI,
            component_id="ci-validation",
            source_schema="agt.usage-ledger/partition/v1",
            source_digest="2" * 64,
            event_ids=(),
            rollup=empty,
        ),
        ledger_cost_component(
            kind=CostComponentKind.SCANNER,
            component_id="security-scanners",
            source_schema="agt.usage-ledger/partition/v1",
            source_digest="3" * 64,
            event_ids=(),
            rollup=empty,
        ),
    )


def successful_execution(
    change: ChangePackage,
    *,
    evaluated_at: datetime = DEVELOPMENT_NOW,
) -> tuple[OrchestrationManifest, ExecutionReceipt]:
    """Build deterministic successful orchestration facts for release tests."""

    manifest = make_planner().plan(
        change,
        run_id="RUN-enterprise-release",
        planned_at=NOW - timedelta(minutes=5),
    )
    assignments = (
        *(assignment for wave in manifest.execution_waves for assignment in wave.assignments),
        manifest.review_assignment,
    )
    review_requested_at = evaluated_at - timedelta(seconds=1)
    review_request = AssignmentExecutionRequest.create(
        manifest=manifest,
        assignment=manifest.review_assignment,
        checkpoint_grant_digests=(),
        requested_at=review_requested_at,
    )
    costs = [Decimal("1") for _ in assignments]
    costs[-1] = Decimal("4.25") - sum(costs[:-1], Decimal("0"))
    receipts = tuple(
        AssignmentExecutionReceipt(
            assignment_id=assignment.assignment_id,
            role=assignment.role,
            prompt=assignment.prompt,
            state=AssignmentExecutionState.SUCCEEDED,
            attempt_count=1,
            host_invoked=True,
            request_digest=(
                review_request.request_digest
                if assignment is manifest.review_assignment
                else hashlib.sha256(f"request:{assignment.assignment_id}".encode()).hexdigest()
            ),
            requested_at=(
                review_requested_at
                if assignment is manifest.review_assignment
                else evaluated_at - timedelta(seconds=2)
            ),
            finished_at=evaluated_at - timedelta(milliseconds=1),
            checkpoint_grant_digests=(
                ("c" * 64,)
                if assignment.checkpoint_ids or assignment is manifest.review_assignment
                else ()
            ),
            outcome_digest=hashlib.sha256(
                f"outcome:{assignment.assignment_id}".encode()
            ).hexdigest(),
            usage_event_id=f"usage:{assignment.assignment_id}",
            actual_cost_usd=cost,
            turns=1,
            tool_calls=0,
            output_digest=hashlib.sha256(f"output:{assignment.assignment_id}".encode()).hexdigest(),
            failure_code=None,
        )
        for assignment, cost in zip(assignments, costs, strict=True)
    )
    receipt = ExecutionReceipt.create(
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
        run_id=manifest.run_id,
        change_id=change.change_id,
        change_digest=change.digest,
        policy_digest=manifest.policy_digest,
        status=ExecutionStatus.SUCCEEDED,
        final=True,
        started_at=NOW - timedelta(minutes=4),
        evaluated_at=evaluated_at,
        release_checkpoint_valid_until=evaluated_at + timedelta(minutes=15),
        assignments=receipts,
        review_history=(
            ReviewRoundHistory.create(
                round_number=1,
                review_assignment_id=manifest.review_assignment.assignment_id,
                context_id=manifest.review_assignment.context_id,
                workspace_key=manifest.review_assignment.workspace_key,
                reviewer_model_family=manifest.review_assignment.route.provider_family,
                outcome_digest=receipts[-1].outcome_digest,
                output_digest=receipts[-1].output_digest,
                semantic_outcome=ReviewSemanticOutcome.create(
                    verdict=ReviewVerdict.CLEAN,
                    report_digest=receipts[-1].output_digest,
                    manifest_id=manifest.manifest_id,
                    manifest_digest=manifest.digest,
                    run_id=manifest.run_id,
                    change_digest=manifest.change_digest,
                    policy_digest=manifest.policy_digest,
                    review_assignment_id=manifest.review_assignment.assignment_id,
                    context_id=manifest.review_assignment.context_id,
                    workspace_key=manifest.review_assignment.workspace_key,
                    reviewer_model_id=manifest.review_assignment.route.identity.canonical_id,
                    reviewer_model_family=manifest.review_assignment.route.provider_family,
                    review_round_number=1,
                    request_digest=review_request.request_digest,
                    issued_at=review_requested_at,
                    expires_at=review_requested_at + timedelta(minutes=5),
                    attester_id=REVIEW_ATTESTER_ID,
                    signer=REVIEW_ATTESTER_SIGNER,
                ),
                remediation=None,
            ),
        ),
        total_actual_cost_usd=Decimal("4.25"),
        cost_complete=True,
        unknown_cost_assignment_ids=(),
        reason_codes=(),
    )
    return manifest, receipt


def rebuild_execution_receipt(
    receipt: ExecutionReceipt,
    assignments: tuple[AssignmentExecutionReceipt, ...],
) -> ExecutionReceipt:
    """Reissue a self-consistent receipt around deliberately changed assignment facts."""

    return ExecutionReceipt.create(
        manifest_id=receipt.manifest_id,
        manifest_digest=receipt.manifest_digest,
        run_id=receipt.run_id,
        change_id=receipt.change_id,
        change_digest=receipt.change_digest,
        policy_digest=receipt.policy_digest,
        status=receipt.status,
        final=receipt.final,
        started_at=receipt.started_at,
        evaluated_at=receipt.evaluated_at,
        release_checkpoint_valid_until=receipt.release_checkpoint_valid_until,
        assignments=assignments,
        review_history=receipt.review_history,
        total_actual_cost_usd=receipt.total_actual_cost_usd,
        cost_complete=receipt.cost_complete,
        unknown_cost_assignment_ids=receipt.unknown_cost_assignment_ids,
        reason_codes=receipt.reason_codes,
    )


def execution_economics(
    change: ChangePackage,
    *,
    rampart_report: RampartSafetyReport | None = None,
) -> tuple[CommandEvidence, CommandEvidence]:
    rollup = complete_rollup(change)
    external = (
        (
            pyrit_external_usage_component(parse_evidence()),
            rampart_external_usage_component(rampart_report or make_rampart_report(change)),
        )
        if change.risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}
        else ()
    )
    return command_evidence_from_usage_rollup(
        rollup,
        orchestration_rollup=rollup,
        ledger_components=standard_ledger_components(change, rollup),
        external_components=external,
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/execution-rollup.json",
        report_sha256="a" * 64,
    )


def enterprise_result(
    gate_id: str,
    change: ChangePackage,
    *,
    status: GateStatus = GateStatus.PASS,
    evaluated_at: datetime = NOW,
    policy: EnterpriseGatePolicy | None = None,
) -> EnterpriseGateResult:
    """Create a minimal canonical G4-G6 result for aggregation tests."""
    assert gate_id in {"G4", "G5", "G6"}
    return EnterpriseGateResult.create(
        gate_id=gate_id,  # type: ignore[arg-type]
        status=status,
        change=change,
        policy_digest=(policy or EnterpriseGatePolicy()).digest,
        evaluated_at=evaluated_at,
        checks=(
            GateCheck(
                code=f"{gate_id.lower()}.fixture",
                passed=status is not GateStatus.FAIL,
                message="fixture check",
            ),
        ),
    )


def prior_results(
    change: ChangePackage,
    *,
    enterprise_policy: EnterpriseGatePolicy | None = None,
) -> list[DevelopmentGateResult | EnterpriseGateResult]:
    """Return canonical passing G0-G5 inputs."""
    results: list[DevelopmentGateResult | EnterpriseGateResult] = []
    for gate_id in ("G0", "G1", "G2", "G3"):
        results.append(
            DevelopmentGateResult.create(
                gate_id=gate_id,  # type: ignore[arg-type]
                status=GateStatus.PASS,
                change=change,
                policy_digest=DevelopmentGatePolicy().digest,
                evaluated_at=NOW,
                checks=(
                    GateCheck(
                        code=f"{gate_id.lower()}.fixture",
                        passed=True,
                        message="fixture check",
                    ),
                ),
            )
        )
    policy = enterprise_policy or (
        enterprise_policy_with_rampart_campaign()
        if change.risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}
        else EnterpriseGatePolicy()
    )
    g4 = (
        EnterpriseGateEvaluator(policy).evaluate_g4(
            change=change,
            evidence=[*conventional_security(change), *agent_security(change)],
            release_policy=parse_policy(),
            pyrit_evidence=parse_evidence(),
            evaluated_at=NOW,
        )
        if change.risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}
        else enterprise_result("G4", change, policy=policy)
    )
    results.extend((g4, enterprise_result("G5", change, policy=policy)))
    return results


def approvals(
    change: ChangePackage,
    *,
    tier: int,
    count: int,
    policy: EnterpriseGatePolicy | None = None,
) -> list[HumanApproval]:
    """Create distinct valid approvals."""
    bound_policy = policy or enterprise_policy_with_approval_trust()
    return [
        HumanApproval.create(
            approval_id=f"APR-{index:03d}",
            change=change,
            enterprise_policy_digest=bound_policy.digest,
            risk_tier=tier,  # type: ignore[arg-type]
            approver=f"person-{index}",
            role="security" if tier == 4 and index == 2 else "release-owner",
            decision=ApprovalDecision.APPROVE,
            approved_at=NOW,
            expires_at=NOW + timedelta(days=1),
            issuer_id=APPROVAL_ISSUER_ID,
            signer=APPROVAL_ISSUER_SIGNER,
        )
        for index in range(1, count + 1)
    ]


def test_policy_is_strict_versioned_and_defines_every_risk_depth() -> None:
    policy = EnterpriseGatePolicy()

    assert policy.schema_version == "agt.enterprise-gate-policy/v1"
    assert {profile.risk_class for profile in policy.profiles} == set(RiskClass)
    assert policy.profile_for(RiskClass.HIGH).require_pyrit
    assert policy.profile_for(RiskClass.TOOL_ENABLED_AGENT).require_tool_manifest
    assert not policy.profile_for(RiskClass.DOCUMENTATION).require_cost
    assert policy.digest == EnterpriseGatePolicy().digest

    with pytest.raises(ValidationError, match="profiles must define every"):
        EnterpriseGatePolicy(profiles=policy.profiles[:-1])
    with pytest.raises(ValidationError, match="extra_forbidden"):
        EnterpriseGatePolicy.model_validate({**policy.model_dump(), "unknown": True})


def test_effective_project_policy_accepts_only_narrowing_overlays() -> None:
    organization_payload = EnterpriseGatePolicy().model_dump()
    organization_payload["allowed_model_families"] = ("family-a", "family-b")
    organization = EnterpriseGatePolicy.model_validate(organization_payload)
    project_profiles = list(organization.profiles)
    standard_index = next(
        index
        for index, profile in enumerate(project_profiles)
        if profile.risk_class is RiskClass.STANDARD
    )
    project_profiles[standard_index] = project_profiles[standard_index].model_copy(
        update={"maximum_change_cost_usd": Decimal("40")}
    )
    project = organization.model_copy(
        update={
            "profiles": tuple(project_profiles),
            "allowed_model_families": ("family-a",),
            "required_tier3_approval_roles": ("compliance", "release-owner"),
        }
    )
    organization_development = DevelopmentGatePolicy()
    project_development = organization_development.model_copy(
        update={"min_line_coverage": Decimal("0.80")}
    )

    effective = effective_project_policy(
        organization_enterprise=organization,
        project_enterprise=project,
        organization_development=organization_development,
        project_development=project_development,
        organization_orchestration=make_policy(),
        project_orchestration=make_policy(),
        organization_release=parse_policy(),
        project_release=parse_policy(),
    )

    assert isinstance(effective, EffectiveProjectPolicy)
    assert effective.enterprise.allowed_model_families == ("family-a",)
    assert (
        effective.digest
        == effective_project_policy(
            organization_enterprise=organization,
            project_enterprise=project,
            organization_development=organization_development,
            project_development=project_development,
            organization_orchestration=make_policy(),
            project_orchestration=make_policy(),
            organization_release=parse_policy(),
            project_release=parse_policy(),
        ).digest
    )


def test_effective_project_policy_rejects_every_silent_weakening_surface() -> None:
    organization_payload = EnterpriseGatePolicy().model_dump()
    organization_payload["allowed_model_families"] = ("family-a",)
    organization = EnterpriseGatePolicy.model_validate(organization_payload)
    weakened_profiles = list(organization.profiles)
    standard_index = next(
        index
        for index, profile in enumerate(weakened_profiles)
        if profile.risk_class is RiskClass.STANDARD
    )
    standard = weakened_profiles[standard_index]
    weakened_profiles[standard_index] = standard.model_copy(
        update={
            "conventional_security_kinds": tuple(
                kind
                for kind in standard.conventional_security_kinds
                if kind is not EvidenceKind.SCA
            ),
            "maximum_change_cost_usd": Decimal("500"),
        }
    )
    weakened_enterprise = organization.model_copy(
        update={
            "profiles": tuple(weakened_profiles),
            "allowed_evidence_environments": ("ci", "developer-laptop"),
            "allowed_model_families": ("family-a", "family-unapproved"),
            "required_tier3_approval_roles": ("compliance",),
            "require_report_uri": False,
            "release_audience": "unapproved-environment",
        }
    )
    organization_development = DevelopmentGatePolicy()
    weakened_development = organization_development.model_copy(
        update={
            "min_line_coverage": Decimal("0.10"),
            "max_cyclomatic_complexity": 100,
            "allowed_evidence_environments": ("ci", "local"),
        }
    )
    weakened_release_payload = policy_payload()
    weakened_release_payload["requirements"]["required_scenarios"] = ["RedTeamScenario"]
    weakened_release_payload["requirements"]["required_groups"] = []
    weakened_release_payload["requirements"]["allowed_benchmark_fingerprints"] = ["f" * 64]
    weakened_release_payload["thresholds"]["max_attack_success_rate"] = 0.5
    weakened_release_payload["baseline"]["allowed_evidence_digests"] = ["f" * 64]
    weakened_release_payload["baseline"]["max_age_seconds"] = 99999
    weakened_release = parse_policy(redigest_policy(weakened_release_payload))
    organization_orchestration = make_policy()
    weakened_orchestration = organization_orchestration.model_copy(
        update={
            "limits": organization_orchestration.limits.model_copy(
                update={"max_total_cost_usd": Decimal("999")}
            )
        }
    )

    with pytest.raises(PolicyWeakeningError) as captured:
        effective_project_policy(
            organization_enterprise=organization,
            project_enterprise=weakened_enterprise,
            organization_development=organization_development,
            project_development=weakened_development,
            organization_orchestration=organization_orchestration,
            project_orchestration=weakened_orchestration,
            organization_release=parse_policy(),
            project_release=weakened_release,
        )

    assert set(captured.value.violations) >= {
        "profile.standard.required_evidence_removed",
        "profile.standard.maximum_change_cost_usd_raised",
        "enterprise.allowed_evidence_environments_broadened",
        "enterprise.allowed_model_families_broadened",
        "enterprise.required_tier3_approval_roles_removed",
        "enterprise.require_report_uri_disabled",
        "enterprise.release_audience_changed",
        "development.min_line_coverage_lowered",
        "development.max_cyclomatic_complexity_raised",
        "development.allowed_evidence_environments_broadened",
        "orchestration.limits.max_total_cost_usd_increased",
        "release.required_scenarios_removed",
        "release.required_groups_removed",
        "release.allowed_benchmark_fingerprints_broadened",
        "release.baseline.allowed_evidence_digests_broadened",
        "release.baseline.max_age_seconds_raised",
        "release.thresholds.max_attack_success_rate_raised",
    }


def test_effective_policy_rejects_rampart_campaign_broadening_and_lowered_depth() -> None:
    organization = replace_risk_profile(
        enterprise_policy_with_rampart_campaign(),
        RiskClass.HIGH,
        minimum_agent_safety_cases_per_dimension=2,
    )
    high = organization.profile_for(RiskClass.HIGH)
    project = replace_risk_profile(
        organization,
        RiskClass.HIGH,
        minimum_agent_safety_cases_per_dimension=1,
        allowed_rampart_campaign_digests=tuple(
            sorted((*high.allowed_rampart_campaign_digests, "f" * 64))
        ),
    )

    with pytest.raises(PolicyWeakeningError) as captured:
        effective_project_policy(
            organization_enterprise=organization,
            project_enterprise=project,
            organization_development=DevelopmentGatePolicy(),
            project_development=DevelopmentGatePolicy(),
            organization_orchestration=make_policy(),
            project_orchestration=make_policy(),
        )

    assert set(captured.value.violations) >= {
        "profile.high.allowed_rampart_campaign_digests_broadened",
        "profile.high.minimum_agent_safety_cases_per_dimension_lowered",
    }


def test_effective_policy_rejects_broadened_human_approval_issuer_authority() -> None:
    organization = enterprise_policy_with_approval_trust()
    attacker = ArtifactSigner()
    broadened = organization.model_copy(
        update={
            "trusted_approval_issuers": (
                *organization.trusted_approval_issuers,
                ApprovalIssuerTrust(
                    issuer_id="unapproved-idp",
                    public_key=attacker.public_key_bytes.hex(),
                    allowed_roles=("security",),
                ),
            )
        }
    )

    with pytest.raises(PolicyWeakeningError) as captured:
        effective_project_policy(
            organization_enterprise=organization,
            project_enterprise=broadened,
            organization_development=DevelopmentGatePolicy(),
            project_development=DevelopmentGatePolicy(),
            organization_orchestration=make_policy(),
            project_orchestration=make_policy(),
        )

    assert "enterprise.trusted_approval_issuers_broadened" in captured.value.violations


def test_effective_policy_rejects_broadened_rampart_issuer_context() -> None:
    organization = enterprise_policy_with_rampart_campaign()
    broadened_trust = RAMPART_ISSUER_TRUST.model_copy(
        update={"allowed_environments": ("ci", "developer")}
    )
    project = organization.model_copy(update={"trusted_rampart_issuers": (broadened_trust,)})

    with pytest.raises(PolicyWeakeningError) as captured:
        effective_project_policy(
            organization_enterprise=organization,
            project_enterprise=project,
            organization_development=DevelopmentGatePolicy(),
            project_development=DevelopmentGatePolicy(),
            organization_orchestration=make_policy(),
            project_orchestration=make_policy(),
        )

    assert "enterprise.trusted_rampart_issuers_broadened" in captured.value.violations


def test_effective_project_policy_rejects_project_release_without_org_release() -> None:
    enterprise = EnterpriseGatePolicy()
    development = DevelopmentGatePolicy()

    with pytest.raises(PolicyWeakeningError) as captured:
        effective_project_policy(
            organization_enterprise=enterprise,
            project_enterprise=enterprise,
            organization_development=development,
            project_development=development,
            organization_orchestration=make_policy(),
            project_orchestration=make_policy(),
            organization_release=None,
            project_release=parse_policy(),
        )

    assert captured.value.violations == ("release.policy_added_without_organization_policy",)


def test_standard_g4_requires_conventional_scans_sbom_and_provenance() -> None:
    change = bound_change()
    evaluator = EnterpriseGateEvaluator()
    evidence = conventional_security(change)

    passing = evaluator.evaluate_g4(change=change, evidence=evidence, evaluated_at=NOW)
    assert passing.status is GateStatus.PASS
    assert len(passing.evidence) == 5

    missing_sbom = [item for item in evidence if item.kind is not EvidenceKind.SBOM]
    failing = evaluator.evaluate_g4(change=change, evidence=missing_sbom, evaluated_at=NOW)
    assert failing.status is GateStatus.FAIL
    assert {check.code for check in failing.checks if not check.passed} >= {
        "security.sbom_evidence",
        "security.sbom_artifact_present",
    }


def test_g4_rejects_stale_failed_and_unbound_scan_evidence() -> None:
    change = bound_change()
    evidence = conventional_security(change)
    evidence.append(
        CommandEvidence.create(
            evidence_id="EVD-ENT-999",
            change_id=change.change_id,
            source_revision="wrong-revision",
            change_digest=change.digest,
            kind=EvidenceKind.SAST,
            status=EvidenceStatus.FAILED,
            producer="enterprise-ci",
            command="verify-sast",
            exit_code=1,
            generated_at=NOW - timedelta(days=2),
            artifacts={"report_uri": "evidence/stale.json", "report_sha256": "a" * 64},
        )
    )

    result = EnterpriseGateEvaluator().evaluate_g4(
        change=change,
        evidence=evidence,
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert {check.code for check in result.checks if not check.passed} >= {
        "evidence.source_binding",
        "evidence.freshness",
        "evidence.command_succeeded",
    }


def test_g4_rejects_same_revision_evidence_replayed_for_a_different_change_digest() -> None:
    original = bound_change()
    replayed_payload = original.model_dump(mode="json")
    replayed_payload["intent"]["goal"] = "A materially different implementation intent."
    replayed_change = ChangePackage.model_validate(replayed_payload)

    assert replayed_change.change_id == original.change_id
    assert replayed_change.source_revision == original.source_revision
    assert replayed_change.digest != original.digest

    result = EnterpriseGateEvaluator().evaluate_g4(
        change=replayed_change,
        evidence=conventional_security(original),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "evidence.source_binding" in result.blocking_reason_codes


def test_high_risk_g4_composes_rampart_and_passing_pyrit_verdict() -> None:
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]
    policy = enterprise_policy_with_rampart_campaign()

    result = EnterpriseGateEvaluator(policy).evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.PASS
    assert {reference.schema_version for reference in result.evidence} >= {
        "pyrit.security-evidence/v1",
        "agt.release-verdict/v1",
        "agt.rampart-run-attestation/v1",
    }
    trust_check = next(
        check for check in result.checks if check.code == "agent_safety.rampart_issuer_trust"
    )
    assert trust_check.threshold == (
        {
            "issuer_id": RAMPART_ISSUER_TRUST.issuer_id,
            "public_key": RAMPART_ISSUER_TRUST.public_key,
            "allowed_producers": RAMPART_ISSUER_TRUST.allowed_producers,
            "allowed_environments": RAMPART_ISSUER_TRUST.allowed_environments,
        },
    )

    without_pyrit = EnterpriseGateEvaluator(policy).evaluate_g4(
        change=change,
        evidence=evidence,
        evaluated_at=NOW,
    )
    assert "pyrit.policy_and_evidence_present" in without_pyrit.blocking_reason_codes
    assert "judge_calibration.scorer_binding" in without_pyrit.blocking_reason_codes

    wrong_scorer = [item for item in evidence if item.kind is not EvidenceKind.JUDGE_CALIBRATION]
    wrong_scorer.append(
        command(
            change,
            EvidenceKind.JUDGE_CALIBRATION,
            23,
            metrics={
                "framework": "PyRIT",
                "dataset_digest": "d" * 64,
                "scorer_eval_hash": "f" * 64,
                "human_labeled_cases": 50,
                "agreement_rate": "0.92",
                "false_accept_rate": "0.02",
            },
        )
    )
    calibration_mismatch = EnterpriseGateEvaluator(policy).evaluate_g4(
        change=change,
        evidence=wrong_scorer,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert "judge_calibration.scorer_binding" in calibration_mismatch.blocking_reason_codes


def test_g4_rejects_unpinned_rampart_campaign_and_per_dimension_undercoverage() -> None:
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]

    unpinned = EnterpriseGateEvaluator().evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert "agent_safety.rampart_campaign_trusted" in unpinned.blocking_reason_codes

    strict_policy = replace_risk_profile(
        enterprise_policy_with_rampart_campaign(),
        RiskClass.HIGH,
        minimum_agent_safety_cases_per_dimension=7,
    )
    undercovered = EnterpriseGateEvaluator(strict_policy).evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert "agent_safety.minimum_cases_per_dimension" in undercovered.blocking_reason_codes

    tampered_evidence = list(evidence)
    safety_index = next(
        index
        for index, item in enumerate(tampered_evidence)
        if item.kind is EvidenceKind.AGENT_SAFETY
    )
    safety = tampered_evidence[safety_index]
    tampered_evidence[safety_index] = safety.model_copy(
        update={"artifacts": {**safety.artifacts, "campaign_sha256": "f" * 64}}
    )
    artifact_mismatch = EnterpriseGateEvaluator(
        enterprise_policy_with_rampart_campaign()
    ).evaluate_g4(
        change=change,
        evidence=tampered_evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert "agent_safety.rampart_artifact_binding" in artifact_mismatch.blocking_reason_codes
    assert "evidence.integrity" in artifact_mismatch.blocking_reason_codes


@pytest.mark.parametrize(
    ("artifact_key", "replacement"),
    (
        ("report_uri", None),
        ("report_sha256", "f" * 64),
        ("native_report_uri", None),
        ("native_report_sha256", "f" * 64),
        ("campaign_uri", None),
        ("campaign_sha256", "f" * 64),
        ("run_attestation_uri", None),
        ("run_attestation_sha256", "f" * 64),
    ),
)
def test_g4_rejects_each_missing_or_mutated_rampart_artifact_binding(
    artifact_key: str,
    replacement: str | None,
) -> None:
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]
    safety_index = next(
        index for index, item in enumerate(evidence) if item.kind is EvidenceKind.AGENT_SAFETY
    )
    safety = evidence[safety_index]
    artifacts = dict(safety.artifacts)
    if replacement is None:
        artifacts.pop(artifact_key)
    else:
        artifacts[artifact_key] = replacement
    evidence[safety_index] = CommandEvidence.create(
        evidence_id=safety.evidence_id,
        change_id=safety.change_id,
        source_revision=safety.source_revision,
        change_digest=safety.change_digest,
        kind=safety.kind,
        status=safety.status,
        producer=safety.producer,
        environment=safety.environment,
        command=safety.command,
        exit_code=safety.exit_code,
        generated_at=safety.generated_at,
        metrics=safety.metrics,
        artifacts=artifacts,
    )

    result = EnterpriseGateEvaluator(enterprise_policy_with_rampart_campaign()).evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "agent_safety.rampart_artifact_binding" in result.blocking_reason_codes


@pytest.mark.parametrize(
    ("producer", "environment"),
    (
        ("untrusted-rampart-adapter", "ci"),
        ("rampart-adapter", "developer"),
    ),
)
def test_g4_rejects_rampart_attestation_outside_trusted_context(
    producer: str,
    environment: str,
) -> None:
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]
    report = make_rampart_report(
        change,
        producer=producer,
        environment=environment,
        run_id=f"RAMPART-RUN-{environment.upper()}",
    )
    replacement = command_evidence_from_rampart_report(
        report,
        report_uri="artifact://rampart/CHG-001/context-report.json",
        native_report_uri="artifact://rampart/CHG-001/context-native-report.json",
        campaign_uri="artifact://rampart/CHG-001/campaign.json",
        run_attestation_uri="artifact://rampart/CHG-001/context-attestation.json",
        evidence_id="EVD-ENT-020",
    )
    evidence = [
        replacement if item.kind is EvidenceKind.AGENT_SAFETY else item for item in evidence
    ]
    policy = enterprise_policy_with_rampart_campaign(
        allowed_evidence_environments=("ci", "developer")
    )

    result = EnterpriseGateEvaluator(policy).evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )

    assert "agent_safety.rampart_issuer_trust" in result.blocking_reason_codes


def test_g4_rejects_untrusted_expired_and_overlong_rampart_attestations() -> None:
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]
    untrusted_policy = enterprise_policy_with_rampart_campaign(trusted_rampart_issuers=())

    untrusted = EnterpriseGateEvaluator(untrusted_policy).evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert "agent_safety.rampart_issuer_trust" in untrusted.blocking_reason_codes

    for report, evaluated_at in (
        (
            make_rampart_report(
                change,
                expires_at=NOW + timedelta(hours=1),
                run_id="RAMPART-RUN-EXPIRES",
            ),
            NOW + timedelta(hours=1),
        ),
        (
            make_rampart_report(
                change,
                expires_at=NOW + timedelta(days=2),
                run_id="RAMPART-RUN-TTL",
            ),
            NOW,
        ),
    ):
        replacement = command_evidence_from_rampart_report(
            report,
            report_uri="artifact://rampart/CHG-001/report.json",
            native_report_uri="artifact://rampart/CHG-001/native-report.json",
            campaign_uri="artifact://rampart/CHG-001/campaign.json",
            run_attestation_uri="artifact://rampart/CHG-001/run-attestation.json",
            evidence_id="EVD-ENT-020",
        )
        replaced = [
            replacement if item.kind is EvidenceKind.AGENT_SAFETY else item for item in evidence
        ]
        result = EnterpriseGateEvaluator(enterprise_policy_with_rampart_campaign()).evaluate_g4(
            change=change,
            evidence=replaced,
            release_policy=parse_policy(),
            pyrit_evidence=parse_evidence(),
            evaluated_at=evaluated_at,
        )
        assert "agent_safety.rampart_attestation_freshness" in result.blocking_reason_codes


def test_g4_rejects_ambiguous_or_misdeclared_rampart_run_history() -> None:
    change = bound_change(RiskClass.HIGH)
    normal_evidence = [*conventional_security(change), *agent_security(change)]
    unsafe_report = make_unsafe_rampart_report(change)
    unsafe_evidence = command_evidence_from_rampart_report(
        unsafe_report,
        report_uri="artifact://rampart/CHG-001/unsafe-report.json",
        native_report_uri="artifact://rampart/CHG-001/unsafe-native-report.json",
        campaign_uri="artifact://rampart/CHG-001/campaign.json",
        run_attestation_uri="artifact://rampart/CHG-001/unsafe-attestation.json",
        evidence_id="EVD-ENT-019",
    )
    misdeclared_unsafe = CommandEvidence.create(
        evidence_id=unsafe_evidence.evidence_id,
        change_id=unsafe_evidence.change_id,
        source_revision=unsafe_evidence.source_revision,
        change_digest=unsafe_evidence.change_digest,
        kind=unsafe_evidence.kind,
        status=EvidenceStatus.PASSED,
        producer=unsafe_evidence.producer,
        environment=unsafe_evidence.environment,
        command=unsafe_evidence.command,
        exit_code=0,
        generated_at=unsafe_evidence.generated_at,
        metrics=unsafe_evidence.metrics,
        artifacts=unsafe_evidence.artifacts,
    )
    evaluator = EnterpriseGateEvaluator(enterprise_policy_with_rampart_campaign())

    ambiguous = evaluator.evaluate_g4(
        change=change,
        evidence=[*normal_evidence, misdeclared_unsafe],
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert "agent_safety.single_authoritative_run" in ambiguous.blocking_reason_codes

    only_misdeclared = [
        item for item in normal_evidence if item.kind is not EvidenceKind.AGENT_SAFETY
    ]
    only_misdeclared.append(misdeclared_unsafe)
    reconciled = evaluator.evaluate_g4(
        change=change,
        evidence=only_misdeclared,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert {
        "agent_safety.rampart_command_reconciliation",
        "agent_safety.no_blocking_findings",
    } <= set(reconciled.blocking_reason_codes)


def test_g4_rejects_caller_written_rampart_summary_without_raw_report() -> None:
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]
    evidence = [item for item in evidence if item.kind is not EvidenceKind.AGENT_SAFETY]
    evidence.append(
        command(
            change,
            EvidenceKind.AGENT_SAFETY,
            24,
            metrics={
                "framework": "RAMPART",
                "dimensions": list(make_rampart_report(change).dimensions),
                "tested_cases": 1_000_000,
                "blocking_findings": 0,
                "policy_bypass_rate": "0",
            },
        )
    )

    result = EnterpriseGateEvaluator().evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "agent_safety.rampart_report_valid" in result.blocking_reason_codes


def test_effective_release_policy_is_defaulted_and_mismatched_override_fails() -> None:
    active_release = parse_policy()
    enterprise = enterprise_policy_with_rampart_campaign()
    effective = effective_project_policy(
        organization_enterprise=enterprise,
        project_enterprise=enterprise,
        organization_development=DevelopmentGatePolicy(),
        project_development=DevelopmentGatePolicy(),
        organization_orchestration=make_policy(),
        project_orchestration=make_policy(),
        organization_release=active_release,
        project_release=active_release,
    )
    evaluator = EnterpriseGateEvaluator.from_effective_policy(effective)
    change = bound_change(RiskClass.HIGH)
    evidence = [*conventional_security(change), *agent_security(change)]

    defaulted = evaluator.evaluate_g4(
        change=change,
        evidence=evidence,
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )
    assert defaulted.status is GateStatus.PASS

    weaker_payload = policy_payload()
    weaker_payload["thresholds"]["max_attack_success_rate"] = 0.5
    weaker = parse_policy(redigest_policy(weaker_payload))
    mismatched = evaluator.evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=weaker,
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )

    assert mismatched.status is GateStatus.FAIL
    assert "pyrit.release_policy_binding" in mismatched.blocking_reason_codes
    policy_reference = next(
        reference
        for reference in mismatched.evidence
        if reference.schema_version == "agt.release-policy/v1"
    )
    assert policy_reference.digest == active_release.policy_digest


def test_tool_agent_manifest_compares_declared_and_observed_tools() -> None:
    change = bound_change(RiskClass.TOOL_ENABLED_AGENT)
    evidence = [
        *conventional_security(change),
        *agent_security(change, observed_tools=["delete_account", "send_email"]),
    ]

    result = EnterpriseGateEvaluator().evaluate_g4(
        change=change,
        evidence=evidence,
        release_policy=parse_policy(),
        pyrit_evidence=parse_evidence(),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "tools.no_undeclared_observed_tools" in result.blocking_reason_codes


def test_usage_rollup_helper_is_deterministic_and_unknown_cost_fails_closed() -> None:
    change = bound_change()
    complete = complete_rollup(change)
    first = command_evidence_from_usage_rollup(
        complete,
        orchestration_rollup=complete,
        ledger_components=standard_ledger_components(change, complete),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/rollup.json",
        report_sha256="a" * 64,
    )
    second = command_evidence_from_usage_rollup(
        complete,
        orchestration_rollup=complete,
        ledger_components=standard_ledger_components(change, complete),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/rollup.json",
        report_sha256="a" * 64,
    )
    assert [item.evidence_sha256 for item in first] == [item.evidence_sha256 for item in second]
    assert (
        EnterpriseGateEvaluator()
        .evaluate_g5(change=change, evidence=first, evaluated_at=NOW)
        .status
        is GateStatus.PASS
    )

    partial = replace(
        complete,
        unpriced_events=1,
        cost_per_task_usd=None,
        cost_per_accepted_task_usd=None,
    )
    unknown = command_evidence_from_usage_rollup(
        partial,
        orchestration_rollup=partial,
        ledger_components=standard_ledger_components(change, partial),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/partial-rollup.json",
        report_sha256="a" * 64,
    )
    result = EnterpriseGateEvaluator().evaluate_g5(
        change=change,
        evidence=unknown,
        evaluated_at=NOW,
    )
    assert result.status is GateStatus.FAIL
    assert {check.code for check in result.checks if not check.passed} >= {
        "economics.cost_complete",
        "economics.cost_threshold",
    }
    assert unknown[0].metrics["total_cost_usd"] is None


def test_documentation_profile_makes_g5_explicitly_not_applicable() -> None:
    change = bound_change(RiskClass.DOCUMENTATION)

    result = EnterpriseGateEvaluator().evaluate_g5(
        change=change,
        evidence=(),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.NOT_APPLICABLE
    assert all(check.passed for check in result.checks)

    with pytest.raises(ValidationError, match="not-applicable gate"):
        EnterpriseGateResult.create(
            gate_id="G5",
            status=GateStatus.NOT_APPLICABLE,
            change=change,
            policy_digest=EnterpriseGatePolicy().digest,
            evaluated_at=NOW,
            checks=(GateCheck(code="waiver.invalid", passed=False, message="invalid waiver"),),
        )


def test_evaluate_readiness_composes_all_seven_gates() -> None:
    change = bound_change()
    rollup = complete_rollup(change)
    economics = command_evidence_from_usage_rollup(
        rollup,
        orchestration_rollup=rollup,
        ledger_components=standard_ledger_components(change, rollup),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/rollup.json",
        report_sha256="a" * 64,
    )
    manifest, receipt = successful_execution(change)
    evidence = [
        *execution_bound_evidence(change, manifest, receipt),
        *conventional_security(change),
        *economics,
    ]
    risk_classification, classifier_key = signed_risk_classification(change)
    enterprise_policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    effective = effective_project_policy(
        organization_enterprise=enterprise_policy,
        project_enterprise=enterprise_policy,
        organization_development=DevelopmentGatePolicy(),
        project_development=DevelopmentGatePolicy(),
        organization_orchestration=make_policy(),
        project_orchestration=make_policy(),
    )

    bundle = EnterpriseGateEvaluator.from_effective_policy(effective).evaluate_readiness(
        change=change,
        evidence=evidence,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        risk_classification=risk_classification,
        evaluated_at=DEVELOPMENT_NOW,
    )

    assert bundle.status is ReadinessStatus.READY
    assert tuple(gate.gate_id for gate in bundle.gates) == (
        "G0",
        "G1",
        "G2",
        "G3",
        "G4",
        "G5",
        "G6",
    )
    assert all(gate.status is GateStatus.PASS for gate in bundle.gates)


def test_g6_requires_exact_fresh_bound_gates_and_tier4_approvals() -> None:
    change = bound_change(RiskClass.HIGH, tier=4)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    risk_classification, classifier_key = signed_risk_classification(change)
    enterprise_policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    evaluator = EnterpriseGateEvaluator(
        enterprise_policy,
        active_orchestration_policy=make_policy(),
    )
    economics = [
        *execution_bound_evidence(change, manifest, receipt),
        *execution_economics(change),
    ]

    one_approval = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=approvals(change, tier=4, count=1, policy=enterprise_policy),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=economics,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )
    assert one_approval.status is GateStatus.FAIL
    assert "approval.required_count" in one_approval.blocking_reason_codes

    two_approvals = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=approvals(change, tier=4, count=2, policy=enterprise_policy),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=economics,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )
    assert two_approvals.status is GateStatus.PASS

    stale = prior_results(change, enterprise_policy=enterprise_policy)
    stale[0] = stale[0].model_copy(update={"evaluated_at": NOW - timedelta(days=2)})
    stale_result = evaluator.evaluate_g6(
        change=change,
        prior_results=stale,
        approvals=approvals(change, tier=4, count=2, policy=enterprise_policy),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=economics,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )
    assert "release.g0_freshness" in stale_result.blocking_reason_codes
    assert "release.g0_integrity" in stale_result.blocking_reason_codes

    wrong_policy = prior_results(change, enterprise_policy=enterprise_policy)
    wrong_policy[0] = wrong_policy[0].model_copy(update={"policy_digest": "f" * 64})
    wrong_policy_result = evaluator.evaluate_g6(
        change=change,
        prior_results=wrong_policy,
        approvals=approvals(change, tier=4, count=2, policy=enterprise_policy),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=economics,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )
    assert "release.g0_policy_binding" in wrong_policy_result.blocking_reason_codes
    assert "release.g0_integrity" in wrong_policy_result.blocking_reason_codes


def test_g6_rejects_untrusted_or_policy_replayed_signed_approvals() -> None:
    change = bound_change(RiskClass.HIGH, tier=4)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    risk_classification, classifier_key = signed_risk_classification(change)
    enterprise_policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    evaluator = EnterpriseGateEvaluator(
        enterprise_policy,
        active_orchestration_policy=make_policy(),
    )
    evidence = [
        *execution_bound_evidence(change, manifest, receipt),
        *execution_economics(change),
    ]
    valid_release_owner = approvals(
        change,
        tier=4,
        count=1,
        policy=enterprise_policy,
    )[0]
    forged_security = HumanApproval.create(
        approval_id="APR-untrusted-security",
        change=change,
        enterprise_policy_digest=enterprise_policy.digest,
        risk_tier=4,
        approver="attacker",
        role="security",
        decision=ApprovalDecision.APPROVE,
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        issuer_id="attacker-idp",
        signer=ArtifactSigner(),
    )

    untrusted = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=(valid_release_owner, forged_security),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=evidence,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )

    assert untrusted.status is GateStatus.FAIL
    assert "approval.issuer_trust" in untrusted.blocking_reason_codes
    assert "approval.required_roles" in untrusted.blocking_reason_codes

    replay_policy = enterprise_policy.model_copy(update={"policy_version": "other"})
    replayed = HumanApproval.create(
        approval_id="APR-replayed-policy",
        change=change,
        enterprise_policy_digest=replay_policy.digest,
        risk_tier=4,
        approver="person-2",
        role="security",
        decision=ApprovalDecision.APPROVE,
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        issuer_id=APPROVAL_ISSUER_ID,
        signer=APPROVAL_ISSUER_SIGNER,
    )
    replay_result = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=(valid_release_owner, replayed),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=evidence,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )

    assert replay_result.status is GateStatus.FAIL
    assert "approval.policy_binding" in replay_result.blocking_reason_codes

    boundary_expired = HumanApproval.create(
        approval_id="APR-expired-at-evaluation",
        change=change,
        enterprise_policy_digest=enterprise_policy.digest,
        risk_tier=4,
        approver="person-2",
        role="security",
        decision=ApprovalDecision.APPROVE,
        approved_at=NOW - timedelta(minutes=1),
        expires_at=NOW,
        issuer_id=APPROVAL_ISSUER_ID,
        signer=APPROVAL_ISSUER_SIGNER,
    )
    expired_result = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=(valid_release_owner, boundary_expired),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=evidence,
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )
    assert "approval.freshness" in expired_result.blocking_reason_codes


def test_g6_rejects_in_memory_reject_to_approve_mutation() -> None:
    change = bound_change(tier=3)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    risk_classification, classifier_key = signed_risk_classification(change)
    policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    signed_rejection = HumanApproval.create(
        approval_id="APR-signed-rejection",
        change=change,
        enterprise_policy_digest=policy.digest,
        risk_tier=3,
        approver="person-rejecting",
        role="release-owner",
        decision=ApprovalDecision.REJECT,
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        issuer_id=APPROVAL_ISSUER_ID,
        signer=APPROVAL_ISSUER_SIGNER,
    )
    forged_approval = signed_rejection.model_copy(update={"decision": ApprovalDecision.APPROVE})
    evaluator = EnterpriseGateEvaluator(policy, active_orchestration_policy=make_policy())

    result = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=policy),
        approvals=(forged_approval,),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=[
            *execution_bound_evidence(change, manifest, receipt, generated_at=NOW),
            *execution_economics(change),
        ],
        risk_classification=risk_classification,
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert {
        "approval.integrity",
        "approval.required_count",
    } <= set(result.blocking_reason_codes)


def test_g6_binds_exact_usage_event_set_not_only_equal_aggregate_cost() -> None:
    change = bound_change()
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    unrelated = replace(
        complete_rollup(change),
        event_set_digest=usage_event_set_digest(
            ("usage:unrelated-1", "usage:unrelated-2", "usage:unrelated-3")
        ),
    )
    evidence = command_evidence_from_usage_rollup(
        unrelated,
        orchestration_rollup=unrelated,
        ledger_components=standard_ledger_components(
            change,
            unrelated,
            event_ids=("usage:unrelated-1", "usage:unrelated-2", "usage:unrelated-3"),
        ),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/unrelated-rollup.json",
        report_sha256="a" * 64,
    )

    result = EnterpriseGateEvaluator().evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=evidence,
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "orchestration.cost_reconciled" in result.blocking_reason_codes


def test_g6_rejects_an_expired_release_checkpoint() -> None:
    change = bound_change()
    manifest, receipt = successful_execution(change, evaluated_at=NOW)

    result = EnterpriseGateEvaluator().evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=execution_economics(change),
        evaluated_at=receipt.release_checkpoint_valid_until,
    )

    assert result.status is GateStatus.FAIL
    assert "orchestration.release_checkpoint_freshness" in result.blocking_reason_codes


def test_g6_authorizes_actual_implementation_and_review_model_families() -> None:
    change = bound_change()
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    evaluator = EnterpriseGateEvaluator(EnterpriseGatePolicy(allowed_model_families=("family-a",)))

    result = evaluator.evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=execution_economics(change),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert "orchestration.model_families_allowed" in result.blocking_reason_codes
    assert "release.implementation_model_allowed" not in result.blocking_reason_codes


def test_g6_rejects_prompt_substitution_and_missing_runtime_checkpoint_grants() -> None:
    change = bound_change()
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    first = receipt.assignments[0]
    substituted_prompt = first.prompt.model_copy(
        update={"version": "substituted", "digest": "e" * 64}
    )
    substituted_assignments = (
        first.model_copy(update={"prompt": substituted_prompt}),
        *receipt.assignments[1:],
    )
    substituted = rebuild_execution_receipt(receipt, substituted_assignments)

    prompt_result = EnterpriseGateEvaluator().evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=manifest,
        execution_receipt=substituted,
        evidence=execution_economics(change),
        evaluated_at=NOW,
    )
    assert "orchestration.prompt_binding" in prompt_result.blocking_reason_codes

    without_grants = rebuild_execution_receipt(
        receipt,
        tuple(
            item.model_copy(update={"checkpoint_grant_digests": ()}) for item in receipt.assignments
        ),
    )
    checkpoint_result = EnterpriseGateEvaluator().evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=manifest,
        execution_receipt=without_grants,
        evidence=execution_economics(change),
        evaluated_at=NOW,
    )
    assert "orchestration.execution_succeeded" in checkpoint_result.blocking_reason_codes


def test_g6_binds_manifest_assignments_to_the_exact_change_task_dag() -> None:
    change = bound_change()
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    waves = list(manifest.execution_waves)
    first_wave = waves[0]
    first = first_wave.assignments[0]
    down_tiered = first.model_copy(update={"risk_tier": max(0, first.risk_tier - 1)})
    waves[0] = first_wave.model_copy(
        update={"assignments": (down_tiered, *first_wave.assignments[1:])}
    )
    forged = manifest.model_copy(update={"execution_waves": tuple(waves)})

    result = EnterpriseGateEvaluator().evaluate_g6(
        change=change,
        prior_results=prior_results(change),
        orchestration_manifest=forged,
        execution_receipt=receipt,
        evidence=execution_economics(change),
        evaluated_at=NOW,
    )

    assert "orchestration.change_plan_binding" in result.blocking_reason_codes
    check = next(item for item in result.checks if item.code == "orchestration.change_plan_binding")
    assert "orchestration.change_task_binding_mismatch" in check.actual["violations"]

    omitted_waves = list(manifest.execution_waves)
    omitted_waves[0] = omitted_waves[0].model_copy(
        update={"assignments": omitted_waves[0].assignments[1:]}
    )
    omitted = manifest.model_copy(update={"execution_waves": tuple(omitted_waves)})
    assert set(enterprise_gates._change_plan_violations(change, omitted)) >= {
        "orchestration.change_dependency_waves_mismatch",
        "orchestration.change_task_inventory_mismatch",
    }


def test_current_rejection_and_unbound_approval_block_g6() -> None:
    change = bound_change(tier=3)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    enterprise_policy = enterprise_policy_with_approval_trust()
    valid = approvals(change, tier=3, count=1, policy=enterprise_policy)[0]
    rejected = HumanApproval.create(
        approval_id="APR-REJECT",
        change=change,
        enterprise_policy_digest=enterprise_policy.digest,
        risk_tier=3,
        approver="security-owner",
        role="security",
        decision=ApprovalDecision.REJECT,
        approved_at=NOW,
        expires_at=NOW + timedelta(days=1),
        issuer_id=APPROVAL_ISSUER_ID,
        signer=APPROVAL_ISSUER_SIGNER,
    )
    wrong_change_payload = change.model_dump(mode="json")
    wrong_change_payload["source_revision"] = "b" * 40
    wrong_change = ChangePackage.model_validate(wrong_change_payload)
    unbound = HumanApproval.create(
        approval_id="APR-WRONG",
        change=wrong_change,
        enterprise_policy_digest=enterprise_policy.digest,
        risk_tier=3,
        approver="wrong-revision-owner",
        role="security",
        decision=ApprovalDecision.APPROVE,
        approved_at=NOW,
        expires_at=NOW + timedelta(days=1),
        issuer_id=APPROVAL_ISSUER_ID,
        signer=APPROVAL_ISSUER_SIGNER,
    )

    result = EnterpriseGateEvaluator(enterprise_policy).evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=(valid, rejected, unbound),
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=execution_economics(change),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert {check.code for check in result.checks if not check.passed} >= {
        "approval.no_active_rejection",
        "approval.source_binding",
    }


def test_g6_fails_closed_without_orchestration_manifest_and_receipt() -> None:
    change = bound_change(tier=3)
    enterprise_policy = enterprise_policy_with_approval_trust()

    result = EnterpriseGateEvaluator(enterprise_policy).evaluate_g6(
        change=change,
        prior_results=prior_results(change, enterprise_policy=enterprise_policy),
        approvals=approvals(change, tier=3, count=1, policy=enterprise_policy),
        evaluated_at=NOW,
    )

    assert result.status is GateStatus.FAIL
    assert {
        "orchestration.manifest_subject_binding",
        "orchestration.receipt_binding",
        "orchestration.execution_succeeded",
        "orchestration.assignment_set",
        "orchestration.cost_reconciled",
        "orchestration.receipt_freshness",
        "orchestration.release_checkpoint_freshness",
    } <= set(result.blocking_reason_codes)


def ready_issuance_inputs(
    change: ChangePackage,
) -> tuple[
    EnterpriseReadinessBundle,
    EffectiveProjectPolicy,
    list[CommandEvidence],
    list[HumanApproval],
    RiskClassification,
]:
    """Build trusted inputs and their deterministic ready G0-G6 bundle."""
    rollup = complete_rollup(change)
    economics = command_evidence_from_usage_rollup(
        rollup,
        orchestration_rollup=rollup,
        ledger_components=standard_ledger_components(change, rollup),
        change_id=change.change_id,
        source_revision=change.source_revision,
        change_digest=change.digest,
        generated_at=NOW,
        report_uri="artifact://usage/CHG-001/rollup.json",
        report_sha256="a" * 64,
    )
    manifest, receipt = successful_execution(change)
    evidence = [
        *execution_bound_evidence(change, manifest, receipt),
        *conventional_security(change),
        *economics,
    ]
    risk_classification, classifier_key = signed_risk_classification(change)
    enterprise_policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    approval = approvals(change, tier=3, count=1, policy=enterprise_policy)
    development_policy = DevelopmentGatePolicy()
    orchestration_policy = make_policy()
    effective = effective_project_policy(
        organization_enterprise=enterprise_policy,
        project_enterprise=enterprise_policy,
        organization_development=development_policy,
        project_development=development_policy,
        organization_orchestration=orchestration_policy,
        project_orchestration=orchestration_policy,
    )
    bundle = EnterpriseGateEvaluator.from_effective_policy(effective).evaluate_readiness(
        change=change,
        evidence=evidence,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        risk_classification=risk_classification,
        approvals=approval,
        evaluated_at=DEVELOPMENT_NOW,
    )
    return bundle, effective, evidence, approval, risk_classification


def ready_bundle(change: ChangePackage) -> EnterpriseReadinessBundle:
    """Build a ready G0-G6 bundle for persistence tests."""
    return ready_issuance_inputs(change)[0]


def test_readiness_bundle_is_canonical_atomic_and_round_trips(tmp_path) -> None:
    change = bound_change(tier=3)
    bundle = ready_bundle(change)
    destination = tmp_path / "release" / "readiness.json"

    write_readiness_bundle(destination, bundle)

    assert bundle.status is ReadinessStatus.READY
    assert bundle.artifact_kind == "readiness"
    assert bundle.signature_state == "unsigned"
    assert load_readiness_bundle(destination) == bundle
    assert destination.read_bytes().endswith(b"\n")
    assert not list(destination.parent.glob(f".{destination.name}.*"))


def test_readiness_bundle_rejects_empty_or_cross_bound_gate_snapshots() -> None:
    change = bound_change(tier=3)
    bundle = ready_bundle(change)

    empty = bundle.model_dump(mode="python")
    empty["gates"][0]["checks"] = ()
    with pytest.raises(ValidationError, match="at least one check"):
        EnterpriseReadinessBundle.model_validate(empty)

    other_payload = change.model_dump(mode="json")
    other_payload["source_revision"] = "b" * 40
    other_change = ChangePackage.model_validate(other_payload)
    other_bundle = ready_bundle(other_change)
    cross_bound = bundle.model_dump(mode="python")
    cross_bound["gates"] = list(cross_bound["gates"])
    cross_bound["gates"][0] = other_bundle.gates[0].model_dump(mode="python")
    cross_bound["gates"] = tuple(cross_bound["gates"])
    with pytest.raises(ValidationError, match="bind the readiness subject"):
        EnterpriseReadinessBundle.model_validate(cross_bound)


def test_release_issuance_signs_verifies_trust_and_detects_tampering(tmp_path, monkeypatch) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    signer = ArtifactSigner()
    destination = tmp_path / "release.json"
    monkeypatch.setattr(
        enterprise_gates,
        "_utc_now",
        lambda value: DEVELOPMENT_NOW if value is None else value.astimezone(UTC),
    )

    issuance = issue_release_bundle(
        destination,
        bundle,
        change=change,
        effective_policy=effective,
        trusted_change_digest=change.digest,
        trusted_effective_policy_digest=effective.digest,
        evidence=evidence,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        risk_classification=risk_classification,
        approvals=approval,
        signer=signer,
        signer_did="did:web:release.example",
    )

    assert issuance.bundle_path == destination
    assert issuance.signature_path.is_file()
    issued_bundle = load_readiness_bundle(destination)
    assert issued_bundle.release_audience == effective.enterprise.release_audience
    assert issuance.sidecar.readiness_digest == issued_bundle.readiness_digest
    assert issuance.sidecar.valid_until == min(
        receipt.release_checkpoint_valid_until,
        *(item.semantic_outcome.expires_at for item in receipt.review_history),
    )
    assert verify_release_bundle(
        destination,
        issuance.signature_path,
        trusted_public_key=signer.public_key_bytes,
        expected_change=change,
        expected_orchestration_manifest=manifest,
        expected_execution_receipt=receipt,
        effective_policy=effective,
        trusted_change_digest=change.digest,
        trusted_effective_policy_digest=effective.digest,
    )
    assert not verify_release_bundle(destination, issuance.signature_path)
    assert not verify_release_bundle(
        destination,
        issuance.signature_path,
        trusted_public_key=b"x" * 32,
        expected_change=change,
        expected_orchestration_manifest=manifest,
        expected_execution_receipt=receipt,
        effective_policy=effective,
        trusted_change_digest=change.digest,
        trusted_effective_policy_digest=effective.digest,
    )
    with monkeypatch.context() as clock:
        clock.setattr(
            enterprise_gates,
            "_utc_now",
            lambda _value: issuance.sidecar.valid_until,
        )
        assert not verify_release_bundle(
            destination,
            issuance.signature_path,
            trusted_public_key=signer.public_key_bytes,
            expected_change=change,
            expected_orchestration_manifest=manifest,
            expected_execution_receipt=receipt,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
        )

    sidecar_payload = json.loads(issuance.signature_path.read_text(encoding="utf-8"))
    sidecar_payload["signer_did"] = "did:web:attacker.example"
    unsigned_sidecar = {
        key: value for key, value in sidecar_payload.items() if key != "sidecar_digest"
    }
    sidecar_payload["sidecar_digest"] = canonical_sha256(unsigned_sidecar)
    tampered_sidecar = tmp_path / "tampered-signature.json"
    tampered_sidecar.write_text(json.dumps(sidecar_payload), encoding="utf-8")
    assert not verify_release_bundle(
        destination,
        tampered_sidecar,
        trusted_public_key=signer.public_key_bytes,
        expected_change=change,
        expected_orchestration_manifest=manifest,
        expected_execution_receipt=receipt,
        effective_policy=effective,
        trusted_change_digest=change.digest,
        trusted_effective_policy_digest=effective.digest,
    )

    payload = json.loads(destination.read_text(encoding="utf-8"))
    payload["repository"] = "tampered/repository"
    destination.write_text(json.dumps(payload), encoding="utf-8")
    assert not verify_release_bundle(
        destination,
        issuance.signature_path,
        trusted_public_key=signer.public_key_bytes,
        expected_change=change,
        expected_orchestration_manifest=manifest,
        expected_execution_receipt=receipt,
        effective_policy=effective,
        trusted_change_digest=change.digest,
        trusted_effective_policy_digest=effective.digest,
    )


def test_high_risk_release_expires_with_rampart_attestation(tmp_path, monkeypatch) -> None:
    change = bound_change(RiskClass.HIGH, tier=4)
    attestation_expiry = NOW + timedelta(minutes=1)
    rampart_report = make_rampart_report(
        change,
        run_id="RAMPART-RUN-RELEASE-EXPIRY",
        attested_at=NOW,
        expires_at=attestation_expiry,
    )
    safety_evidence = command_evidence_from_rampart_report(
        rampart_report,
        report_uri="artifact://rampart/CHG-001/release-report.json",
        native_report_uri="artifact://rampart/CHG-001/release-native-report.json",
        campaign_uri="artifact://rampart/CHG-001/campaign.json",
        run_attestation_uri="artifact://rampart/CHG-001/release-attestation.json",
        evidence_id="EVD-ENT-020",
    )
    agent_evidence = [
        safety_evidence if item.kind is EvidenceKind.AGENT_SAFETY else item
        for item in agent_security(change)
    ]
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    evidence = [
        *execution_bound_evidence(change, manifest, receipt, generated_at=NOW),
        command(
            change,
            EvidenceKind.MUTATION,
            888,
            metrics={"mutation_score": "0.60"},
        ),
        *conventional_security(change),
        *agent_evidence,
        *execution_economics(change, rampart_report=rampart_report),
    ]
    risk_classification, classifier_key = signed_risk_classification(change)
    enterprise_policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    release_policy = parse_policy()
    development_policy = DevelopmentGatePolicy()
    orchestration_policy = make_policy()
    effective = effective_project_policy(
        organization_enterprise=enterprise_policy,
        project_enterprise=enterprise_policy,
        organization_development=development_policy,
        project_development=development_policy,
        organization_orchestration=orchestration_policy,
        project_orchestration=orchestration_policy,
        organization_release=release_policy,
        project_release=release_policy,
    )
    approval = approvals(change, tier=4, count=2, policy=enterprise_policy)
    pyrit_evidence = parse_evidence()
    bundle = EnterpriseGateEvaluator.from_effective_policy(effective).evaluate_readiness(
        change=change,
        evidence=evidence,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        pyrit_evidence=pyrit_evidence,
        risk_classification=risk_classification,
        approvals=approval,
        evaluated_at=NOW,
    )
    signer = ArtifactSigner()
    destination = tmp_path / "high-risk-release.json"
    monkeypatch.setattr(
        enterprise_gates,
        "_utc_now",
        lambda value: NOW if value is None else value.astimezone(UTC),
    )

    issuance = issue_release_bundle(
        destination,
        bundle,
        change=change,
        effective_policy=effective,
        trusted_change_digest=change.digest,
        trusted_effective_policy_digest=effective.digest,
        evidence=evidence,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        pyrit_evidence=pyrit_evidence,
        risk_classification=risk_classification,
        approvals=approval,
        signer=signer,
    )

    assert issuance.sidecar.valid_until == attestation_expiry
    with monkeypatch.context() as clock:
        clock.setattr(enterprise_gates, "_utc_now", lambda _value: attestation_expiry)
        assert not verify_release_bundle(
            destination,
            issuance.signature_path,
            trusted_public_key=signer.public_key_bytes,
            expected_change=change,
            expected_orchestration_manifest=manifest,
            expected_execution_receipt=receipt,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
        )


def test_release_issuance_rejects_in_memory_pyrit_mutation(
    tmp_path,
    monkeypatch,
) -> None:
    change = bound_change(RiskClass.HIGH, tier=4)
    rampart_report = make_rampart_report(change)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    evidence = [
        *execution_bound_evidence(change, manifest, receipt, generated_at=NOW),
        command(
            change,
            EvidenceKind.MUTATION,
            888,
            metrics={"mutation_score": "0.60"},
        ),
        *conventional_security(change),
        *agent_security(change),
        *execution_economics(change, rampart_report=rampart_report),
    ]
    risk_classification, classifier_key = signed_risk_classification(change)
    enterprise_policy = enterprise_policy_with_approval_trust(
        trusted_risk_classifier_public_keys=(classifier_key,)
    )
    release_policy = parse_policy()
    development_policy = DevelopmentGatePolicy()
    orchestration_policy = make_policy()
    effective = effective_project_policy(
        organization_enterprise=enterprise_policy,
        project_enterprise=enterprise_policy,
        organization_development=development_policy,
        project_development=development_policy,
        organization_orchestration=orchestration_policy,
        project_orchestration=orchestration_policy,
        organization_release=release_policy,
        project_release=release_policy,
    )
    approval = approvals(change, tier=4, count=2, policy=enterprise_policy)
    pyrit_evidence = parse_evidence()
    bundle = EnterpriseGateEvaluator.from_effective_policy(effective).evaluate_readiness(
        change=change,
        evidence=evidence,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        pyrit_evidence=pyrit_evidence,
        risk_classification=risk_classification,
        approvals=approval,
        evaluated_at=NOW,
    )
    assert bundle.status is ReadinessStatus.READY

    forged_latency = pyrit_evidence.metrics.overall.latency.model_copy(update={"p95_ms": 0})
    forged_overall = pyrit_evidence.metrics.overall.model_copy(update={"latency": forged_latency})
    forged_metrics = pyrit_evidence.metrics.model_copy(update={"overall": forged_overall})
    forged_pyrit = pyrit_evidence.model_copy(update={"metrics": forged_metrics})
    destination = tmp_path / "forged-pyrit-release.json"
    monkeypatch.setattr(
        enterprise_gates,
        "_utc_now",
        lambda value: NOW if value is None else value.astimezone(UTC),
    )

    with pytest.raises(
        ReleaseIssuanceError,
        match="does not match trusted",
    ):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=receipt,
            pyrit_evidence=forged_pyrit,
            risk_classification=risk_classification,
            approvals=approval,
        )

    assert not destination.exists()


def test_release_issuance_refuses_untrusted_readiness_inputs(tmp_path) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    destination = tmp_path / "must-not-be-issued.json"

    with pytest.raises(ReleaseIssuanceError, match="does not match trusted"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence[:-1],
            orchestration_manifest=manifest,
            execution_receipt=receipt,
            risk_classification=risk_classification,
            approvals=approval,
        )

    assert not destination.exists()


def test_release_issuance_rejects_in_memory_approval_mutation(tmp_path, monkeypatch) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    forged = approval[0].model_copy(update={"approver": "forged-person"})
    destination = tmp_path / "forged-approval-release.json"
    monkeypatch.setattr(
        enterprise_gates,
        "_utc_now",
        lambda value: DEVELOPMENT_NOW if value is None else value.astimezone(UTC),
    )

    with pytest.raises(ReleaseIssuanceError, match="does not match trusted"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=receipt,
            risk_classification=risk_classification,
            approvals=(forged,),
            signer=ArtifactSigner(),
        )

    assert not destination.exists()


def test_release_issuance_rejects_in_memory_readiness_mutation(tmp_path) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    gates = list(bundle.gates)
    gates[-1] = gates[-1].model_copy(update={"status": GateStatus.FAIL})
    forged = bundle.model_copy(update={"gates": tuple(gates)})
    destination = tmp_path / "forged-readiness-release.json"

    with pytest.raises(ReleaseIssuanceError, match="strict canonical revalidation"):
        issue_release_bundle(
            destination,
            forged,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=receipt,
            risk_classification=risk_classification,
            approvals=approval,
            signer=ArtifactSigner(),
        )

    assert not destination.exists()


def test_release_issuance_rejects_tampered_or_failed_execution_receipt(tmp_path) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    destination = tmp_path / "invalid-execution-must-not-be-issued.json"

    tampered = receipt.model_copy(update={"total_actual_cost_usd": Decimal("0")})
    with pytest.raises(ReleaseIssuanceError, match="re-evaluation failed"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=tampered,
            risk_classification=risk_classification,
            approvals=approval,
            signer=ArtifactSigner(),
        )

    failed_assignments = list(receipt.assignments)
    failed_assignments[0] = failed_assignments[0].model_copy(
        update={
            "state": AssignmentExecutionState.FAILED,
            "failure_code": "host.assignment_failed",
        }
    )
    failed = ExecutionReceipt.create(
        manifest_id=receipt.manifest_id,
        manifest_digest=receipt.manifest_digest,
        run_id=receipt.run_id,
        change_id=receipt.change_id,
        change_digest=receipt.change_digest,
        policy_digest=receipt.policy_digest,
        status=ExecutionStatus.FAILED,
        final=True,
        started_at=receipt.started_at,
        evaluated_at=receipt.evaluated_at,
        assignments=tuple(failed_assignments),
        total_actual_cost_usd=receipt.total_actual_cost_usd,
        cost_complete=True,
        unknown_cost_assignment_ids=(),
        reason_codes=("assignment.failed",),
    )
    with pytest.raises(ReleaseIssuanceError, match="does not match trusted"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=failed,
            risk_classification=risk_classification,
            approvals=approval,
            signer=ArtifactSigner(),
        )

    assert not destination.exists()


def test_release_issuance_requires_an_explicit_persistent_signer(tmp_path, monkeypatch) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    destination = tmp_path / "unsigned-must-not-be-issued.json"
    monkeypatch.setattr(
        enterprise_gates,
        "_utc_now",
        lambda value: DEVELOPMENT_NOW if value is None else value.astimezone(UTC),
    )

    with pytest.raises(ReleaseIssuanceError, match="persistent signer"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=receipt,
            risk_classification=risk_classification,
            approvals=approval,
        )

    assert not destination.exists()


def test_release_issuance_rechecks_freshness_at_signing_time(tmp_path, monkeypatch) -> None:
    change = bound_change(tier=3)
    bundle, effective, evidence, approval, risk_classification = ready_issuance_inputs(change)
    manifest, receipt = successful_execution(change)
    destination = tmp_path / "stale-must-not-be-issued.json"

    future = DEVELOPMENT_NOW + timedelta(days=2)

    def controlled_now(value: datetime | None) -> datetime:
        return future if value is None else value.astimezone(UTC)

    monkeypatch.setattr("agent_sre.sdlc.enterprise_gates._utc_now", controlled_now)
    with pytest.raises(ReleaseIssuanceError, match="not release-ready at issuance time"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=evidence,
            orchestration_manifest=manifest,
            execution_receipt=receipt,
            risk_classification=risk_classification,
            approvals=approval,
        )

    assert not destination.exists()


def test_release_issuance_refuses_failed_readiness_without_writing(tmp_path) -> None:
    change = bound_change(tier=3)
    manifest, receipt = successful_execution(change, evaluated_at=NOW)
    economics = execution_economics(change)
    enterprise_policy = enterprise_policy_with_approval_trust()
    effective = EffectiveProjectPolicy(
        enterprise=enterprise_policy,
        development=DevelopmentGatePolicy(),
        orchestration=make_policy(),
        release=None,
    )
    approval = approvals(change, tier=3, count=1, policy=enterprise_policy)
    gate_results = prior_results(change, enterprise_policy=enterprise_policy)
    gate_results[-1] = enterprise_result(
        "G5",
        change,
        status=GateStatus.FAIL,
        policy=enterprise_policy,
    )
    g6 = EnterpriseGateEvaluator(enterprise_policy).evaluate_g6(
        change=change,
        prior_results=gate_results,
        approvals=approval,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        evidence=economics,
        evaluated_at=NOW,
    )
    bundle = EnterpriseReadinessBundle.create(
        change=change,
        development_policy_digest=DevelopmentGatePolicy().digest,
        enterprise_policy_digest=enterprise_policy.digest,
        release_policy_digest=None,
        effective_policy_digest=effective.digest,
        orchestration_manifest=manifest,
        execution_receipt=receipt,
        release_audience=enterprise_policy.release_audience,
        evaluated_at=NOW,
        gate_results=(*gate_results, g6),
        approvals=approval,
    )
    destination = tmp_path / "must-not-exist.json"

    with pytest.raises(ReleaseIssuanceError, match="passing G6"):
        issue_release_bundle(
            destination,
            bundle,
            change=change,
            effective_policy=effective,
            trusted_change_digest=change.digest,
            trusted_effective_policy_digest=effective.digest,
            evidence=(),
            orchestration_manifest=manifest,
            execution_receipt=receipt,
        )

    assert bundle.status is ReadinessStatus.NOT_READY
    assert not destination.exists()
