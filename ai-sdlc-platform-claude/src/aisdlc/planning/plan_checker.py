"""Goal-backward plan validation (the ``plan_checker`` role, consumed by G1).

Starting from the goal — every requirement delivered and verified — the checker walks
backwards through the plan and reports what would prevent that:

* every planned requirement is covered by at least one task (``REQ_UNCOVERED``);
* every task has runnable verification (command present, parseable, exit code set);
* wave ordering respects ``depends_on`` (``WAVE_ORDER_VIOLATION``);
* no task references unknown tasks/requirements; ids are sequential; no cycles;
* the human checkpoints the risk class demands are present;
* the plan is not stale relative to the requirements it was generated for.

Issues are **blocking** (G1 fails) or **advisory** (reported, gate still passes).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from pydantic import Field

from aisdlc.planning import planner
from aisdlc.planning import risk as riskmod
from aisdlc.policy.org_policy import OrgPolicy
from aisdlc.policy.project_config import ProjectConfig
from aisdlc.schema import grammar
from aisdlc.schema.models import ArtifactModel, ChangePackage, Plan, Priority, Requirement, Task
from aisdlc.schema.package import PLAN_FILE

__all__ = [
    "PlanCheckIssue",
    "PlanCheckReport",
    "FingerprintStatus",
    "check_plan",
    "check_coverage",
    "check_wave_order",
    "check_checkpoints",
    "check_staleness",
]

FingerprintStatus = Literal["fresh", "stale", "unknown", "unchecked"]


class PlanCheckIssue(ArtifactModel):
    """One plan-checker finding."""

    code: str
    blocking: bool
    message: str
    artifact_id: str | None = None

    def __str__(self) -> str:
        level = "BLOCKING" if self.blocking else "ADVISORY"
        where = f" [{self.artifact_id}]" if self.artifact_id else ""
        return f"{level} {self.code}{where}: {self.message}"


class PlanCheckReport(ArtifactModel):
    """Outcome of :func:`check_plan`."""

    change_id: str
    risk_class: str
    passed: bool = Field(description="``True`` when no blocking issue was found.")
    blocking: list[PlanCheckIssue] = Field(default_factory=list)
    advisory: list[PlanCheckIssue] = Field(default_factory=list)
    coverage: dict[str, list[str]] = Field(
        default_factory=dict, description="Requirement id -> covering task ids."
    )
    fingerprint_status: FingerprintStatus = "unchecked"

    @property
    def issues(self) -> list[PlanCheckIssue]:
        """Blocking then advisory issues."""
        return [*self.blocking, *self.advisory]

    def summary(self) -> str:
        """One-line human summary."""
        verdict = "PASS" if self.passed else "FAIL"
        return (
            f"{self.change_id}: plan check {verdict} — {len(self.blocking)} blocking, "
            f"{len(self.advisory)} advisory; requirements fingerprint {self.fingerprint_status}"
        )


def _issue(
    code: str, message: str, *, blocking: bool, artifact_id: str | None = None
) -> PlanCheckIssue:
    return PlanCheckIssue(code=code, blocking=blocking, message=message, artifact_id=artifact_id)


# --------------------------------------------------------------------------------------
# Individual checks (each returns issues; pure)
# --------------------------------------------------------------------------------------


def check_coverage(
    requirements: Sequence[Requirement], tasks: Sequence[Task]
) -> tuple[list[PlanCheckIssue], dict[str, list[str]]]:
    """Every requirement must be traced from >= 1 task.

    ``must``/``should`` gaps block; ``could``/``wont`` gaps are advisory.
    """
    coverage: dict[str, list[str]] = {r.id: [] for r in requirements}
    for task in tasks:
        for req_id in task.requirement_ids:
            if req_id in coverage:
                coverage[req_id].append(task.id)
    issues: list[PlanCheckIssue] = []
    for requirement in requirements:
        if coverage[requirement.id]:
            continue
        blocking = requirement.priority in (Priority.MUST, Priority.SHOULD)
        issues.append(
            _issue(
                "REQ_UNCOVERED",
                f"{requirement.priority.value} requirement has no task",
                blocking=blocking,
                artifact_id=requirement.id,
            )
        )
    return issues, coverage


def check_wave_order(plan: Plan, tasks: Sequence[Task]) -> list[PlanCheckIssue]:
    """Plan/task consistency and dependency ordering across waves."""
    issues: list[PlanCheckIssue] = []
    by_id = {t.id: t for t in tasks}
    wave_of: dict[str, int] = {}
    for wave in plan.waves:
        for task_id in wave.task_ids:
            wave_of[task_id] = wave.index
            if task_id not in by_id:
                issues.append(
                    _issue(
                        "PLAN_UNKNOWN_TASK",
                        f"plan schedules unknown task {task_id}",
                        blocking=True,
                        artifact_id=task_id,
                    )
                )
    for task in tasks:
        if task.id not in wave_of:
            issues.append(
                _issue(
                    "TASK_NOT_SCHEDULED",
                    "task is not in any wave",
                    blocking=True,
                    artifact_id=task.id,
                )
            )
            continue
        if task.wave is not None and task.wave != wave_of[task.id]:
            issues.append(
                _issue(
                    "TASK_WAVE_MISMATCH",
                    f"task.wave={task.wave} but plan places it in wave {wave_of[task.id]}",
                    blocking=False,
                    artifact_id=task.id,
                )
            )
        for dep in task.depends_on:
            if dep in wave_of and wave_of[dep] >= wave_of[task.id]:
                issues.append(
                    _issue(
                        "WAVE_ORDER_VIOLATION",
                        f"depends on {dep} (wave {wave_of[dep]}) but runs in wave "
                        f"{wave_of[task.id]}",
                        blocking=True,
                        artifact_id=task.id,
                    )
                )
    return issues


def check_checkpoints(
    plan: Plan, tasks: Sequence[Task], profile: riskmod.GateDepthProfile
) -> list[PlanCheckIssue]:
    """Checkpoints demanded by the risk class: plan approval, before tier >= 3, release."""
    issues: list[PlanCheckIssue] = []
    if not plan.waves:
        return issues
    by_id = {t.id: t for t in tasks}
    if profile.plan_approval_required and not (plan.approved_by or "").strip():
        issues.append(
            _issue(
                "PLAN_NOT_APPROVED",
                f"risk class {profile.risk_class.value} requires plan approval "
                "(plan.approved_by) before wave 0 runs",
                blocking=False,
            )
        )
    if profile.checkpoint_before_tier3:
        waves = sorted(plan.waves, key=lambda w: w.index)
        for position, wave in enumerate(waves):
            privileged = [
                t for t in wave.task_ids if t in by_id and planner.is_privileged_task(by_id[t])
            ]
            if not privileged:
                continue
            if position == 0:
                if not (plan.approved_by or "").strip():
                    issues.append(
                        _issue(
                            "CHECKPOINT_TIER3_MISSING",
                            "privileged task(s) in the first wave need plan approval: "
                            + ", ".join(privileged),
                            blocking=True,
                        )
                    )
            elif not waves[position - 1].checkpoint:
                issues.append(
                    _issue(
                        "CHECKPOINT_TIER3_MISSING",
                        f"wave {waves[position - 1].index} must be a checkpoint: wave "
                        f"{wave.index} contains privileged task(s) {', '.join(privileged)}",
                        blocking=True,
                    )
                )
    if profile.checkpoint_before_release:
        last = max(plan.waves, key=lambda w: w.index)
        if not last.checkpoint:
            issues.append(
                _issue(
                    "CHECKPOINT_RELEASE_MISSING",
                    f"last wave {last.index} must be a human checkpoint before release",
                    blocking=True,
                )
            )
    return issues


def check_staleness(
    pkg: ChangePackage,
) -> tuple[list[PlanCheckIssue], FingerprintStatus]:
    """Compare the fingerprint stamped in ``plan.md`` with the current requirements."""
    body = pkg.bodies.get(PLAN_FILE, "")
    stamped = planner.read_plan_fingerprint(body)
    if stamped is None:
        return (
            [
                _issue(
                    "PLAN_FINGERPRINT_UNKNOWN",
                    "plan.md carries no requirements fingerprint; staleness cannot be checked",
                    blocking=False,
                )
            ],
            "unknown",
        )
    current = planner.requirements_fingerprint(pkg.requirements)
    if stamped != current:
        return (
            [
                _issue(
                    "PLAN_STALE",
                    f"requirements changed since the plan was generated "
                    f"({stamped[:12]}… -> {current[:12]}…); regenerate or re-check the plan",
                    blocking=True,
                )
            ],
            "stale",
        )
    return [], "fresh"


# --------------------------------------------------------------------------------------
# Whole package
# --------------------------------------------------------------------------------------


def check_plan(
    pkg: ChangePackage,
    *,
    profile: riskmod.GateDepthProfile | None = None,
    project_config: ProjectConfig | None = None,
    policy: OrgPolicy | None = None,
) -> PlanCheckReport:
    """Run every plan check over *pkg* and return a :class:`PlanCheckReport`.

    The risk class is taken from *profile* or derived with
    :func:`aisdlc.planning.risk.classify` (never lower than the declared one).
    """
    if profile is None:
        manifest = pkg.threat_model.tool_data_manifest if pkg.threat_model else None
        assessment = riskmod.classify(
            pkg.intent,
            pkg.requirements,
            project_config,
            manifest,
            paths=[f for t in pkg.tasks for f in t.files],
        )
        profile = riskmod.gate_depth_profile(assessment.effective, policy)

    issues: list[PlanCheckIssue] = []
    coverage: dict[str, list[str]] = {}
    plan = pkg.plan
    tasks = pkg.tasks

    if plan is None or not plan.waves:
        issues.append(_issue("PLAN_MISSING", "plan has no waves", blocking=True))
    if not tasks:
        issues.append(_issue("TASKS_MISSING", "no tasks defined", blocking=True))
    if not pkg.requirements:
        issues.append(
            _issue("REQUIREMENTS_MISSING", "no requirements to plan against", blocking=True)
        )

    coverage_issues, coverage = check_coverage(pkg.requirements, tasks)
    issues.extend(coverage_issues)

    for grammar_issue in grammar.validate_tasks(tasks, (r.id for r in pkg.requirements)):
        blocking = grammar_issue.severity is grammar.IssueSeverity.ERROR
        issues.append(
            _issue(
                grammar_issue.code,
                grammar_issue.message,
                blocking=blocking,
                artifact_id=grammar_issue.artifact_id,
            )
        )
    for task in tasks:
        if task.model_tier is None:
            issues.append(
                _issue(
                    "TASK_MODEL_TIER_MISSING",
                    "task has no model tier hint; routing will use the role default",
                    blocking=False,
                    artifact_id=task.id,
                )
            )

    if plan is not None and plan.waves:
        issues.extend(check_wave_order(plan, tasks))
        issues.extend(check_checkpoints(plan, tasks, profile))

    stale_issues, status = check_staleness(pkg)
    issues.extend(stale_issues)

    blocking_issues = [i for i in issues if i.blocking]
    advisory_issues = [i for i in issues if not i.blocking]
    return PlanCheckReport(
        change_id=pkg.change_id,
        risk_class=profile.risk_class.value,
        passed=not blocking_issues,
        blocking=blocking_issues,
        advisory=advisory_issues,
        coverage=coverage,
        fingerprint_status=status,
    )
