"""Plan checker: coverage, verification, wave order, references, checkpoints, staleness."""

from __future__ import annotations

from aisdlc.planning import plan_checker, planner, risk
from aisdlc.policy.project_config import ProjectConfig
from aisdlc.schema.models import (
    ChangePackage,
    Intent,
    Kernel,
    ModelTier,
    Plan,
    Priority,
    Requirement,
    RiskClass,
    Scenario,
    Task,
    Verification,
    Wave,
)


def _req(
    num: int, text: str = "The system SHALL work.", priority: Priority = Priority.MUST
) -> Requirement:
    return Requirement(
        id=f"REQ-{num:03d}",
        text=text,
        priority=priority,
        scenarios=[Scenario(id=f"SCN-{num:03d}-01", when="x", then="y")],
    )


def _task(
    num: int,
    reqs: list[str],
    deps: list[str] | None = None,
    *,
    wave: int | None = None,
    title: str = "Implement",
    verification: Verification | None = Verification(command="pytest -q"),
) -> Task:
    return Task(
        id=f"TASK-{num:03d}",
        title=title,
        requirement_ids=reqs,
        depends_on=deps or [],
        wave=wave,
        verification=verification,
        model_tier=ModelTier.STANDARD,
    )


def _pkg(
    reqs: list[Requirement], tasks: list[Task], plan: Plan | None, *, stamp: bool = True
) -> ChangePackage:
    intent = Intent(
        id="CHG-demo", title="Demo", owner="kev", kernel=Kernel(why="w"), risk_class=RiskClass.LOW
    )
    pkg = ChangePackage(intent=intent, requirements=reqs, tasks=tasks, plan=plan)
    if stamp:
        pkg.bodies["plan.md"] = planner.stamp_plan_fingerprint(
            "# Plan\n", planner.requirements_fingerprint(reqs)
        )
    return pkg


def _codes(report: plan_checker.PlanCheckReport) -> set[str]:
    return {i.code for i in report.issues}


def _blocking(report: plan_checker.PlanCheckReport) -> set[str]:
    return {i.code for i in report.blocking}


def _good_plan() -> ChangePackage:
    reqs = [_req(1), _req(2)]
    tasks = [_task(1, ["REQ-001"], wave=0), _task(2, ["REQ-002"], ["TASK-001"], wave=1)]
    plan = Plan(
        waves=[
            Wave(index=0, task_ids=["TASK-001"]),
            Wave(index=1, task_ids=["TASK-002"], checkpoint=True),
        ]
    )
    return _pkg(reqs, tasks, plan)


def test_good_plan_passes() -> None:
    report = plan_checker.check_plan(_good_plan(), profile=risk.gate_depth_profile(RiskClass.LOW))
    assert report.passed, report.issues
    assert report.fingerprint_status == "fresh"
    assert report.coverage == {"REQ-001": ["TASK-001"], "REQ-002": ["TASK-002"]}
    assert "PASS" in report.summary()


def test_uncovered_requirement_blocks_unless_low_priority() -> None:
    pkg = _good_plan()
    pkg.requirements.append(_req(3))
    pkg.requirements.append(_req(4, priority=Priority.COULD))
    pkg.bodies["plan.md"] = planner.stamp_plan_fingerprint(
        "", planner.requirements_fingerprint(pkg.requirements)
    )
    report = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.LOW))
    assert not report.passed
    uncovered = [i for i in report.issues if i.code == "REQ_UNCOVERED"]
    assert {(i.artifact_id, i.blocking) for i in uncovered} == {
        ("REQ-003", True),
        ("REQ-004", False),
    }


def test_missing_verification_and_bad_command_block() -> None:
    pkg = _good_plan()
    pkg.tasks[0] = pkg.tasks[0].model_copy(update={"verification": None})
    pkg.tasks[1] = pkg.tasks[1].model_copy(update={"verification": Verification(command="   ")})
    report = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.LOW))
    assert {"TASK_NO_VERIFICATION", "TASK_VERIFICATION_EMPTY_COMMAND"} <= _blocking(report)


def test_wave_order_violation_and_unscheduled() -> None:
    reqs = [_req(1), _req(2), _req(3)]
    tasks = [
        _task(1, ["REQ-001"], ["TASK-002"], wave=0),
        _task(2, ["REQ-002"], wave=1),
        _task(3, ["REQ-003"], wave=5),
    ]
    plan = Plan(
        waves=[
            Wave(index=0, task_ids=["TASK-001"]),
            Wave(index=1, task_ids=["TASK-002", "TASK-009"], checkpoint=True),
        ]
    )
    report = plan_checker.check_plan(
        _pkg(reqs, tasks, plan), profile=risk.gate_depth_profile(RiskClass.LOW)
    )
    assert {"WAVE_ORDER_VIOLATION", "TASK_NOT_SCHEDULED", "PLAN_UNKNOWN_TASK"} <= _blocking(report)
    violation = next(i for i in report.blocking if i.code == "WAVE_ORDER_VIOLATION")
    assert violation.artifact_id == "TASK-001"


def test_wave_mismatch_is_advisory() -> None:
    pkg = _good_plan()
    pkg.tasks[1] = pkg.tasks[1].model_copy(update={"wave": 0})
    report = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.LOW))
    assert report.passed
    assert "TASK_WAVE_MISMATCH" in {i.code for i in report.advisory}


def test_unknown_references_and_cycle_block() -> None:
    reqs = [_req(1)]
    tasks = [
        _task(1, ["REQ-001", "REQ-099"], ["TASK-002"], wave=0),
        _task(2, ["REQ-001"], ["TASK-001", "TASK-042"], wave=0),
    ]
    plan = Plan(waves=[Wave(index=0, task_ids=["TASK-001", "TASK-002"], checkpoint=True)])
    report = plan_checker.check_plan(
        _pkg(reqs, tasks, plan), profile=risk.gate_depth_profile(RiskClass.LOW)
    )
    assert {
        "TASK_UNKNOWN_REQUIREMENT",
        "TASK_UNKNOWN_DEPENDENCY",
        "TASK_DEPENDENCY_CYCLE",
    } <= _blocking(report)


def test_checkpoints_required_by_risk_class() -> None:
    reqs = [_req(1), _req(2)]
    tasks = [
        _task(1, ["REQ-001"], wave=0),
        _task(2, ["REQ-002"], ["TASK-001"], wave=1, title="Deploy to production"),
    ]
    plan = Plan(waves=[Wave(index=0, task_ids=["TASK-001"]), Wave(index=1, task_ids=["TASK-002"])])
    pkg = _pkg(reqs, tasks, plan)
    report = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.STANDARD))
    assert {"CHECKPOINT_TIER3_MISSING", "CHECKPOINT_RELEASE_MISSING"} <= _blocking(report)
    assert "PLAN_NOT_APPROVED" in {i.code for i in report.advisory}
    # docs_only demands none of it
    docs = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.DOCS_ONLY))
    assert not {
        "CHECKPOINT_TIER3_MISSING",
        "CHECKPOINT_RELEASE_MISSING",
        "PLAN_NOT_APPROVED",
    } & _codes(docs)
    # privileged work in wave 0 needs plan approval
    first = Plan(waves=[Wave(index=0, task_ids=["TASK-001", "TASK-002"], checkpoint=True)])
    tasks0 = [
        _task(1, ["REQ-001"], wave=0),
        _task(2, ["REQ-002"], wave=0, title="Deploy to production"),
    ]
    unapproved = plan_checker.check_plan(
        _pkg(reqs, tasks0, first), profile=risk.gate_depth_profile(RiskClass.HIGH)
    )
    assert "CHECKPOINT_TIER3_MISSING" in _blocking(unapproved)
    approved = first.model_copy(update={"approved_by": "kev"})
    ok = plan_checker.check_plan(
        _pkg(reqs, tasks0, approved), profile=risk.gate_depth_profile(RiskClass.HIGH)
    )
    assert "CHECKPOINT_TIER3_MISSING" not in _codes(ok)


def test_stale_and_unknown_fingerprint() -> None:
    pkg = _good_plan()
    pkg.requirements[0] = pkg.requirements[0].model_copy(
        update={"text": "The system SHALL differ."}
    )
    stale = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.LOW))
    assert "PLAN_STALE" in _blocking(stale) and stale.fingerprint_status == "stale"
    unstamped = _good_plan()
    unstamped.bodies["plan.md"] = "# Plan\n"
    report = plan_checker.check_plan(unstamped, profile=risk.gate_depth_profile(RiskClass.LOW))
    assert report.passed and report.fingerprint_status == "unknown"
    assert "PLAN_FINGERPRINT_UNKNOWN" in {i.code for i in report.advisory}


def test_empty_package_reports_missing_everything() -> None:
    pkg = _pkg([], [], None, stamp=False)
    report = plan_checker.check_plan(pkg, project_config=ProjectConfig())
    assert {"PLAN_MISSING", "TASKS_MISSING", "REQUIREMENTS_MISSING"} <= _blocking(report)
    assert report.risk_class == "standard"  # declared low never lowers the project default


def test_model_tier_missing_is_advisory_and_generated_plan_checks_clean() -> None:
    pkg = _good_plan()
    pkg.tasks[0] = pkg.tasks[0].model_copy(update={"model_tier": None})
    report = plan_checker.check_plan(pkg, profile=risk.gate_depth_profile(RiskClass.LOW))
    assert report.passed and "TASK_MODEL_TIER_MISSING" in {i.code for i in report.advisory}
    generated = _pkg(
        [_req(1, "The system SHALL export."), _req(2, "The system SHALL email after REQ-001.")],
        [],
        None,
        stamp=False,
    )
    result = planner.generate_plan(generated, ProjectConfig())
    planner.apply_plan(generated, result)
    generated.plan = (
        generated.plan.model_copy(update={"approved_by": "kev"}) if generated.plan else None
    )
    clean = plan_checker.check_plan(generated, project_config=ProjectConfig())
    assert clean.passed and not clean.advisory, clean.issues
