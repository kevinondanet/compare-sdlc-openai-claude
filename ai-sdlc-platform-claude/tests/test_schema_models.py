"""Tests for aisdlc.schema.models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aisdlc.schema.models import (
    ArchitectureDecision,
    Assumption,
    ChangePackage,
    ChangeState,
    CostEvidence,
    EvidenceBundle,
    EvidenceStatus,
    FinalVerdict,
    Finding,
    GateId,
    GateResult,
    Intent,
    Interface,
    Kernel,
    Mitigation,
    OpenQuestion,
    Plan,
    QuestionStatus,
    Requirement,
    ReviewEvidence,
    ReviewVerdict,
    RiskClass,
    Scenario,
    SecurityEvidence,
    Severity,
    Task,
    TaskStatus,
    TestEvidence,
    Threat,
    ThreatModel,
    ThreatStatus,
    Verification,
    Wave,
    utcnow,
)


def _req(num: int = 1, with_scenario: bool = True) -> Requirement:
    scenarios = (
        [Scenario(id=f"SCN-{num:03d}-01", when="input arrives", then="output is produced")]
        if with_scenario
        else []
    )
    return Requirement(id=f"REQ-{num:03d}", text="The system SHALL work.", scenarios=scenarios)


def _intent() -> Intent:
    return Intent(
        id="CHG-demo",
        title="Demo",
        owner="kevin",
        kernel=Kernel(why="w", capabilities=["c"], non_goals=["n"], success_signal="s"),
    )


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is not None


def test_extra_forbidden() -> None:
    with pytest.raises(ValidationError):
        Intent(id="CHG-x", title="t", bogus=1)  # type: ignore[call-arg]


def test_kernel_completeness() -> None:
    assert not Kernel().is_complete()
    assert Kernel(why="w", capabilities=["c"], non_goals=["n"], success_signal="s").is_complete()


def test_scenario_requires_content_and_renders() -> None:
    with pytest.raises(ValidationError, match="needs when\\+then"):
        Scenario(id="SCN-001-01")
    structured = Scenario(id="SCN-001-01", given="g", when="w", then="t")
    assert structured.render() == "GIVEN g\nWHEN w\nTHEN t"
    assert structured.requirement_id == "REQ-001"
    raw = Scenario(id="SCN-001-02", raw="WHEN a THEN b")
    assert raw.render() == "WHEN a THEN b"
    assert raw.text == "WHEN a THEN b"
    both = Scenario(id="SCN-001-03", when="w", then="t", raw="note")
    assert both.text == "WHEN w\nTHEN t\nnote"


def test_requirement_scenario_ownership() -> None:
    with pytest.raises(ValidationError, match="does not belong"):
        Requirement(
            id="REQ-001",
            text="SHALL",
            scenarios=[Scenario(id="SCN-002-01", when="w", then="t")],
        )
    with pytest.raises(ValidationError, match="duplicate scenario"):
        Requirement(
            id="REQ-001",
            text="SHALL",
            scenarios=[
                Scenario(id="SCN-001-01", when="w", then="t"),
                Scenario(id="SCN-001-01", when="w2", then="t2"),
            ],
        )


def test_open_question_rules() -> None:
    q = OpenQuestion(id="OQ-001", question="why?", blocking=True)
    assert q.is_open_blocking
    with pytest.raises(ValidationError, match="records no decision"):
        OpenQuestion(id="OQ-001", question="why?", status=QuestionStatus.RESOLVED)
    resolved = OpenQuestion(
        id="OQ-001", question="why?", status="resolved", decision="because", blocking=True
    )
    assert not resolved.is_open_blocking


def test_threat_model_validation_and_helpers() -> None:
    high = Threat(id="THR-001", title="inject", severity=Severity.HIGH)
    low = Threat(id="THR-002", title="minor", severity=Severity.LOW)
    mitigated = Threat(
        id="THR-003", title="x", severity=Severity.CRITICAL, status=ThreatStatus.MITIGATED
    )
    tm = ThreatModel(
        threats=[high, low, mitigated],
        mitigations=[Mitigation(id="M1", description="d", threat_ids=["THR-001"])],
    )
    assert tm.unresolved_high_risk() == [high]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    with pytest.raises(ValidationError, match="duplicate threat"):
        ThreatModel(threats=[high, high])
    with pytest.raises(ValidationError, match="references unknown"):
        ThreatModel(mitigations=[Mitigation(id="M1", description="d", threat_ids=["THR-009"])])
    with pytest.raises(ValidationError, match="duplicate mitigation"):
        ThreatModel(
            mitigations=[Mitigation(id="M1", description="d"), Mitigation(id="M1", description="e")]
        )


def test_plan_validation_and_lookup() -> None:
    plan = Plan(
        waves=[
            Wave(index=0, task_ids=["TASK-001", "TASK-002"]),
            Wave(index=1, task_ids=["TASK-003"], checkpoint=True),
        ]
    )
    assert plan.wave_of("TASK-003") == 1
    assert plan.wave_of("TASK-009") is None
    assert plan.task_ids == ["TASK-001", "TASK-002", "TASK-003"]
    with pytest.raises(ValidationError, match="strictly increasing"):
        Plan(waves=[Wave(index=1), Wave(index=0)])
    with pytest.raises(ValidationError, match="more than one wave"):
        Plan(waves=[Wave(index=0, task_ids=["TASK-001"]), Wave(index=1, task_ids=["TASK-001"])])


def test_task_validation() -> None:
    with pytest.raises(ValidationError, match="depends on itself"):
        Task(id="TASK-001", title="t", depends_on=["TASK-001"])
    task = Task(
        id="TASK-001",
        title="t",
        verification=Verification(command="pytest -q", expect_output_regex="passed"),
        model_tier="high",
    )
    assert task.status is TaskStatus.PENDING
    assert task.verification is not None and task.verification.expect_exit_code == 0


def test_evidence_id_must_match_kind() -> None:
    with pytest.raises(ValidationError, match="does not match kind"):
        TestEvidence(id="EVD-cost-001")
    ok = TestEvidence(id="EVD-tests-001", status="complete", exit_code=0, passed=3)
    assert ok.is_complete and ok.succeeded
    failing = TestEvidence(id="EVD-tests-002", status="complete", exit_code=0, failed=1)
    assert not failing.succeeded
    assert not TestEvidence(id="EVD-tests-003", exit_code=0).succeeded  # incomplete


def test_review_evidence_helpers() -> None:
    blocking = Finding(id="FND-001", grounded=True, blocking=True, severity="high")
    overturned = Finding(id="FND-002", grounded=True, blocking=True, overturned=True)
    ungrounded = Finding(id="FND-003", grounded=False, blocking=True)
    review = ReviewEvidence(
        id="EVD-reviews-001",
        reviewer_model_family="a",
        implementer_model_family="b",
        findings=[blocking, overturned, ungrounded],
    )
    assert review.independent
    assert review.grounded_blocking_findings() == [blocking]
    same = ReviewEvidence(
        id="EVD-reviews-002", reviewer_model_family="a", implementer_model_family="a"
    )
    assert not same.independent
    assert not ReviewEvidence(id="EVD-reviews-003").independent


def test_cost_evidence_variance() -> None:
    cost = CostEvidence(id="EVD-cost-001", total_cost_usd=12, budget_usd=10)
    assert cost.variance == pytest.approx(0.2)
    assert cost.over_budget
    explicit = CostEvidence(id="EVD-cost-002", total_cost_usd=1, budget_usd=10, variance=-0.5)
    assert explicit.variance == -0.5 and not explicit.over_budget
    assert CostEvidence(id="EVD-cost-003", total_cost_usd=1).variance is None


def test_security_evidence_and_bundle() -> None:
    sec = SecurityEvidence(
        id="EVD-security-001",
        status="complete",
        pyrit={"campaign_id": "c1", "asr": 0.01, "complete": True},
        safety_regression={"asr_by_category": {"harm": 0.0}, "complete": True},
    )
    bundle = EvidenceBundle(
        tests=[TestEvidence(id="EVD-tests-001")],
        reviews=[ReviewEvidence(id="EVD-reviews-001")],
        security=sec,
    )
    assert bundle.ids() == ["EVD-tests-001", "EVD-reviews-001", "EVD-security-001"]
    assert len(bundle.all()) == 3


def test_final_verdict_lookup() -> None:
    verdict = FinalVerdict(
        change_id="CHG-demo",
        gate_results=[GateResult(gate=GateId.G0, passed=True), GateResult(gate="G2", passed=False)],
        produced_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert verdict.result_for(GateId.G2) is not None
    assert verdict.result_for(GateId.G2).passed is False  # type: ignore[union-attr]
    assert verdict.result_for(GateId.G6) is None


def test_adr_and_interface_models() -> None:
    adr = ArchitectureDecision(id="ADR-0001", title="Use X", status="accepted", supersedes=None)
    assert adr.consequences == []
    ifc = Interface(id="IFC-001", name="API", kind="event")
    assert ifc.kind.value == "event"
    with pytest.raises(ValidationError):
        ArchitectureDecision(id="ADR-001", title="bad id")


def test_change_package_duplicates_and_lookups() -> None:
    pkg = ChangePackage(
        intent=_intent(),
        requirements=[_req(1), _req(2)],
        assumptions=[Assumption(id="ASM-001", text="a")],
        tasks=[Task(id="TASK-001", title="t", requirement_ids=["REQ-001"])],
    )
    assert pkg.change_id == "CHG-demo"
    assert pkg.requirement("REQ-002") is not None
    assert pkg.requirement("REQ-009") is None
    assert pkg.task("TASK-001") is not None
    assert len(pkg.scenarios()) == 2
    assert set(pkg.all_ids()) >= {"CHG-demo", "REQ-001", "SCN-002-01", "ASM-001", "TASK-001"}
    with pytest.raises(ValidationError, match="duplicate requirement id"):
        ChangePackage(intent=_intent(), requirements=[_req(1), _req(1)])


def test_change_package_all_ids_covers_evidence_and_findings() -> None:
    pkg = ChangePackage(
        intent=_intent(),
        threat_model=ThreatModel(threats=[Threat(id="THR-001", title="t")]),
        evidence=EvidenceBundle(
            reviews=[ReviewEvidence(id="EVD-reviews-001", findings=[Finding(id="FND-001")])]
        ),
    )
    assert {"THR-001", "EVD-reviews-001", "FND-001"} <= set(pkg.all_ids())


def test_derive_state_progression() -> None:
    pkg = ChangePackage(intent=_intent())
    assert pkg.derive_state() is ChangeState.DRAFT

    pkg.requirements = [_req(1, with_scenario=False)]
    assert pkg.derive_state() is ChangeState.DRAFT
    pkg.requirements = [_req(1)]
    assert pkg.derive_state() is ChangeState.SPECIFIED

    pkg.tasks = [Task(id="TASK-001", title="t"), Task(id="TASK-002", title="u")]
    assert pkg.derive_state() is ChangeState.SPECIFIED  # no plan yet
    pkg.plan = Plan(waves=[Wave(index=0, task_ids=["TASK-001", "TASK-002"])])
    assert pkg.derive_state() is ChangeState.PLANNED

    pkg.tasks[0].status = TaskStatus.IN_PROGRESS
    assert pkg.derive_state() is ChangeState.IMPLEMENTING
    pkg.tasks[0].status = TaskStatus.DONE
    pkg.tasks[1].status = TaskStatus.SKIPPED
    assert pkg.derive_state() is ChangeState.VERIFYING

    review = ReviewEvidence(id="EVD-reviews-001", verdict=ReviewVerdict.APPROVED)
    pkg.evidence = EvidenceBundle(reviews=[review])
    assert pkg.derive_state() is ChangeState.VERIFYING  # incomplete evidence never counts
    review.status = EvidenceStatus.COMPLETE
    assert pkg.derive_state() is ChangeState.REVIEWED
    review.findings = [Finding(id="FND-001", grounded=True, blocking=True)]
    assert pkg.derive_state() is ChangeState.VERIFYING
    review.findings[0].overturned = True
    assert pkg.derive_state() is ChangeState.REVIEWED

    sec = SecurityEvidence(id="EVD-security-001", status="complete", critical_open=1)
    pkg.evidence.security = sec
    assert pkg.derive_state() is ChangeState.REVIEWED
    sec.critical_open = 0
    assert pkg.derive_state() is ChangeState.SECURED
    sec.pyrit = {"campaign_id": "c", "asr": 0.0, "complete": False}  # type: ignore[assignment]
    assert pkg.derive_state() is ChangeState.REVIEWED
    sec.pyrit.complete = True
    sec.manifest_drift = True
    assert pkg.derive_state() is ChangeState.REVIEWED
    sec.manifest_drift = False

    pkg.final_verdict = FinalVerdict(change_id="CHG-demo", overall=False)
    assert pkg.derive_state() is ChangeState.SECURED
    pkg.final_verdict.overall = True
    assert pkg.derive_state() is ChangeState.RELEASED
    assert ChangeState.RELEASED.rank > ChangeState.DRAFT.rank


def test_change_package_json_round_trip() -> None:
    pkg = ChangePackage(
        intent=_intent(),
        requirements=[_req(1)],
        open_questions=[OpenQuestion(id="OQ-001", question="q?", owner="x")],
        decisions=[ArchitectureDecision(id="ADR-0001", title="d", date=utcnow())],
        threat_model=ThreatModel(assets=["db"]),
        plan=Plan(waves=[Wave(index=0, task_ids=["TASK-001"])]),
        tasks=[Task(id="TASK-001", title="t", verification=Verification(command="true"))],
        evidence=EvidenceBundle(cost=CostEvidence(id="EVD-cost-001", total_cost_usd=1.5)),
        bodies={"intent.md": "# hi\n"},
        root=None,
    )
    data = pkg.model_dump(mode="json")
    assert "root" not in data and "base_fingerprint" not in data
    again = ChangePackage.model_validate(data)
    assert again == pkg
    assert again.intent.risk_class is RiskClass.STANDARD


def test_review_independence_fails_closed_without_implementer_family() -> None:
    """G3 needs a *different* family: an unrecorded implementer family is not independent."""
    assert not ReviewEvidence(
        id="EVD-reviews-004", reviewer_model_family="claude", implementer_model_family=""
    ).independent
    assert not ReviewEvidence(
        id="EVD-reviews-005", reviewer_model_family="  ", implementer_model_family="gpt"
    ).independent
    assert ReviewEvidence(
        id="EVD-reviews-006", reviewer_model_family="claude", implementer_model_family="gpt"
    ).independent
