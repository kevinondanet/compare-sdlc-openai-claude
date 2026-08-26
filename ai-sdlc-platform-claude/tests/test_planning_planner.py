"""Planner: task derivation, dependency inference, waves, cycles, checkpoints, tiers."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.planning import planner, risk
from aisdlc.policy.project_config import ProjectConfig, TestCommands
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    AdrStatus,
    ArchitectureDecision,
    ChangePackage,
    Intent,
    Interface,
    Kernel,
    ModelTier,
    Priority,
    Requirement,
    RiskClass,
    Scenario,
    Task,
    Verification,
)


def _req(num: int, text: str, **kw: object) -> Requirement:
    return Requirement(
        id=f"REQ-{num:03d}",
        text=text,
        scenarios=[Scenario(id=f"SCN-{num:03d}-01", when="something", then="result")],
        **kw,  # type: ignore[arg-type]
    )


def _task(num: int, deps: list[str] | None = None, title: str = "t") -> Task:
    return Task(
        id=f"TASK-{num:03d}",
        title=title,
        depends_on=deps or [],
        requirement_ids=["REQ-001"],
        verification=Verification(command="true"),
    )


def _pkg(reqs: list[Requirement], **kw: object) -> ChangePackage:
    intent = Intent(
        id="CHG-demo",
        title="Demo",
        owner="kev",
        kernel=Kernel(why="w", capabilities=["c"], non_goals=["n"], success_signal="s"),
    )
    return ChangePackage(intent=intent, requirements=reqs, **kw)  # type: ignore[arg-type]


# -- waves and cycles ----------------------------------------------------------------------


def test_compute_waves_levels_and_sorting() -> None:
    tasks = [
        _task(1),
        _task(2, ["TASK-001"]),
        _task(3, ["TASK-001"]),
        _task(4, ["TASK-002", "TASK-003"]),
        _task(5),
    ]
    assert planner.compute_waves(tasks) == [
        ["TASK-001", "TASK-005"],
        ["TASK-002", "TASK-003"],
        ["TASK-004"],
    ]


def test_compute_waves_cycle_error_names_cycle() -> None:
    tasks = [_task(1, ["TASK-003"]), _task(2, ["TASK-001"]), _task(3, ["TASK-002"])]
    with pytest.raises(planner.DependencyCycleError) as info:
        planner.compute_waves(tasks)
    assert info.value.cycle[0] == info.value.cycle[-1]
    assert set(info.value.cycle) == {"TASK-001", "TASK-002", "TASK-003"}
    assert "dependency cycle" in str(info.value)


def test_compute_waves_unknown_dependency_and_duplicates() -> None:
    with pytest.raises(planner.PlanningError, match="unknown task"):
        planner.compute_waves([_task(1, ["TASK-009"])])
    with pytest.raises(planner.PlanningError, match="duplicate"):
        planner.compute_waves([_task(1), _task(1)])
    assert planner.compute_waves([]) == []


def test_find_cycle_none_for_dag() -> None:
    assert planner.find_cycle({"a": ["b"], "b": []}) is None
    assert planner.find_cycle({"a": ["a"]}) == ["a", "a"]


# -- dependency inference ------------------------------------------------------------------


def test_infer_dependencies_rules() -> None:
    reqs = [
        _req(1, "The system SHALL store devices."),
        _req(2, "The system SHALL enrol devices after REQ-001 stores them."),
        _req(3, "The system SHALL list devices.", tags=["after:REQ-002"]),
        _req(4, "The system SHALL call IFC-001 to sync."),
        _req(5, "The system SHALL audit.", tags=["provides:IFC-002"]),
        _req(6, "The system SHALL report."),
    ]
    interfaces = [
        Interface(id="IFC-001", name="Store", provider="REQ-001"),
        Interface(id="IFC-002", name="Audit", consumers=["REQ-006"]),
    ]
    adr = ArchitectureDecision(
        id="ADR-0001", title="Order", status=AdrStatus.ACCEPTED, decision="REQ-006 then REQ-003"
    )
    deps = planner.infer_dependencies(reqs, interfaces=interfaces, decisions=[adr])
    assert deps["REQ-002"] == ["REQ-001"]  # citation
    assert deps["REQ-003"] == ["REQ-002", "REQ-006"]  # tag + ADR ordering
    assert deps["REQ-004"] == ["REQ-001"]  # interface mention -> provider
    assert deps["REQ-006"] == ["REQ-005"]  # interface consumers -> provides: tag
    assert deps["REQ-001"] == []


def test_infer_dependencies_explicit_ordering_and_unknown() -> None:
    reqs = [_req(1, "The system SHALL a."), _req(2, "The system SHALL b.")]
    cfg = planner.PlannerConfig(ordering={"REQ-001": ["REQ-002"]})
    assert planner.infer_dependencies(reqs, config=cfg)["REQ-001"] == ["REQ-002"]
    with pytest.raises(planner.PlanningError, match="unknown requirement"):
        planner.infer_dependencies(reqs, config=planner.PlannerConfig(ordering={"REQ-009": []}))


# -- task derivation -----------------------------------------------------------------------


def test_derive_tasks_shape_and_verification() -> None:
    reqs = [
        _req(1, "The system SHALL export a report."),
        _req(2, "The system SHALL email the report after REQ-001 exports it."),
        _req(3, "The system SHALL skip this.", priority=Priority.WONT),
    ]
    tasks = planner.derive_tasks(reqs, ProjectConfig(), change_dir="changes/CHG-demo")
    assert [t.id for t in tasks] == ["TASK-001", "TASK-002", "TASK-003", "TASK-004"]
    impl1, impl2, tests, docs = tasks
    assert impl1.requirement_ids == ["REQ-001"] and impl1.depends_on == []
    assert impl2.depends_on == ["TASK-001"]
    assert impl1.verification is not None
    assert impl1.verification.command == "pytest -q tests/test_req001_export_a_report.py"
    assert impl1.verification.expect_exit_code == 0
    assert impl1.files == ["tests/test_req001_export_a_report.py"]
    assert tests.depends_on == ["TASK-001", "TASK-002"]
    assert tests.requirement_ids == ["REQ-001", "REQ-002"]
    assert tests.verification is not None and tests.verification.command == "pytest -q"
    assert docs.model_tier is ModelTier.LOW
    assert docs.verification is not None
    assert docs.verification.command == "aisdlc change validate changes/CHG-demo"
    assert all(t.verification is not None for t in tasks)


def test_derive_tasks_config_knobs_and_non_pytest_runner() -> None:
    reqs = [
        _req(1, "The system SHALL a.", tags=["billing"]),
        _req(2, "The system SHALL b.", tags=["billing"]),
    ]
    project = ProjectConfig(test_commands=TestCommands(unit="npm test", coverage="npm run cov"))
    cfg = planner.PlannerConfig(include_test_task=False, include_docs_task=False, group_by_tag=True)
    tasks = planner.derive_tasks(reqs, project, config=cfg)
    assert len(tasks) == 1
    assert tasks[0].requirement_ids == ["REQ-001", "REQ-002"]
    assert tasks[0].title.startswith("Implement billing")
    assert tasks[0].verification is not None and tasks[0].verification.command == "npm test"
    with_tests = planner.derive_tasks(
        reqs, project, config=planner.PlannerConfig(include_docs_task=False)
    )
    assert with_tests[-1].verification is not None
    assert with_tests[-1].verification.command == "npm run cov"
    assert planner.derive_tasks([], ProjectConfig()) == []


def test_verification_for_rejects_unparseable_unit_command() -> None:
    project = ProjectConfig(test_commands=TestCommands(unit='pytest "unterminated'))
    with pytest.raises(planner.PlanningError):
        planner.verification_for("x", project)


def test_model_tier_hints() -> None:
    assert (
        planner.model_tier_for(_req(1, "The system SHALL paginate the list.")) is ModelTier.STANDARD
    )
    assert planner.model_tier_for(_req(1, "The system SHALL hash the password.")) is ModelTier.HIGH
    assert planner.model_tier_for(_req(1, "The system SHALL migrate the schema.")) is ModelTier.HIGH
    assert planner.model_tier_for(_req(1, "The system SHALL follow ADR-0001.")) is ModelTier.HIGH
    assert (
        planner.model_tier_for(_req(1, "The system SHALL be fast [NEEDS CLARIFICATION]."))
        is ModelTier.HIGH
    )
    provider = Interface(id="IFC-001", name="x", provider="REQ-001")
    assert (
        planner.model_tier_for(_req(1, "The system SHALL serve."), interfaces=[provider])
        is ModelTier.HIGH
    )


def test_is_privileged_task() -> None:
    assert planner.is_privileged_task(_task(1, title="Deploy to production"))
    assert planner.is_privileged_task(_task(1, title="Open pull request"))
    assert not planner.is_privileged_task(_task(1, title="Implement pagination"))


# -- plan building and checkpoints ---------------------------------------------------------


def test_build_plan_checkpoints_by_profile() -> None:
    tasks = [
        _task(1, title="Implement store"),
        _task(2, ["TASK-001"], title="Run the migration in production"),
        _task(3, ["TASK-002"], title="Docs"),
    ]
    scheduled, plan = planner.build_plan(tasks, risk.gate_depth_profile(RiskClass.STANDARD))
    assert [t.wave for t in scheduled] == [0, 1, 2]
    assert [w.checkpoint for w in plan.waves] == [True, False, True]
    assert "before privileged" in plan.waves[0].description
    assert "before release" in plan.waves[2].description
    _scheduled, docs_plan = planner.build_plan(tasks, risk.gate_depth_profile(RiskClass.DOCS_ONLY))
    assert not any(w.checkpoint for w in docs_plan.waves)


def test_generate_and_apply_plan_roundtrip(tmp_path: Path) -> None:
    intent = Intent(
        id="CHG-demo",
        title="Demo",
        owner="kev",
        kernel=Kernel(why="w", capabilities=["c"], non_goals=["n"], success_signal="s"),
    )
    pkg = pkgio.create(tmp_path, "CHG-demo", intent)
    pkg.requirements = [
        _req(1, "The system SHALL export."),
        _req(2, "The system SHALL email after REQ-001."),
    ]
    result = planner.generate_plan(pkg, ProjectConfig())
    assert result.profile.risk_class is RiskClass.STANDARD
    assert result.assessment.effective is RiskClass.STANDARD
    assert [w.task_ids for w in result.plan.waves] == [
        ["TASK-001"],
        ["TASK-002"],
        ["TASK-003", "TASK-004"],
    ]
    assert result.plan.waves[-1].checkpoint
    assert any("plan approval required" in n for n in result.notes)
    assert result.tasks[-1].verification is not None
    assert str(pkg.root) in result.tasks[-1].verification.command
    planner.apply_plan(pkg, result)
    assert planner.read_plan_fingerprint(pkg.bodies["plan.md"]) == result.requirements_fingerprint
    pkg.save()
    loaded = pkgio.load(pkg.root)
    assert loaded.plan is not None and len(loaded.plan.waves) == 3
    assert [t.wave for t in loaded.tasks] == [0, 1, 2, 2]
    assert loaded.derive_state().value == "planned"
    # re-stamping replaces the marker rather than appending
    stamped = planner.stamp_plan_fingerprint(pkg.bodies["plan.md"], "0" * 64)
    assert stamped.count(planner.PLAN_FINGERPRINT_MARKER) == 1
    assert planner.read_plan_fingerprint(stamped) == "0" * 64


def test_generate_plan_privileged_in_wave_zero_note() -> None:
    pkg = _pkg([_req(1, "The system SHALL deploy the service to production.")])
    result = planner.generate_plan(
        pkg, ProjectConfig(), config=planner.PlannerConfig(include_docs_task=False)
    )
    assert any("relies on plan approval" in n for n in result.notes)
    assert result.tasks[0].model_tier is ModelTier.HIGH


def test_requirements_fingerprint_order_insensitive_and_content_sensitive() -> None:
    a, b = _req(1, "The system SHALL a."), _req(2, "The system SHALL b.")
    assert planner.requirements_fingerprint([a, b]) == planner.requirements_fingerprint([b, a])
    changed = a.model_copy(update={"text": "The system SHALL a!"})
    assert planner.requirements_fingerprint([a, b]) != planner.requirements_fingerprint(
        [changed, b]
    )
