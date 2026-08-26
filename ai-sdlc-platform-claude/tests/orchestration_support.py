"""Shared helpers for the orchestration tests (synthetic packages in a tmp git repo)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from aisdlc.control_plane.ledger import UsageLedger
from aisdlc.orchestration.executor import (
    ActionChecker,
    Checkpoint,
    Executor,
    ExecutorConfig,
    approve_all_checkpoints,
)
from aisdlc.orchestration.runner import AgentRunner
from aisdlc.policy.org_policy import OrgPolicy, default_org_policy
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    ArchitectureDecision,
    ChangePackage,
    Intent,
    Interface,
    Kernel,
    Plan,
    Requirement,
    Scenario,
    Task,
    Verification,
    Wave,
)

CHANGE_ID = "CHG-demo"


def marker_verification(task_id: str) -> Verification:
    """Verification that passes once the dry-run marker exists in the worktree."""
    return Verification(command=f"test -f {task_id}.dryrun")


def default_tasks() -> list[Task]:
    """Three tasks: two independent, one depending on both."""
    return [
        Task(
            id="TASK-001",
            title="first",
            description="Create the first marker.",
            requirement_ids=["REQ-001"],
            verification=marker_verification("TASK-001"),
        ),
        Task(
            id="TASK-002",
            title="second",
            description="Create the second marker.",
            requirement_ids=["REQ-001"],
            verification=marker_verification("TASK-002"),
        ),
        Task(
            id="TASK-003",
            title="third",
            description="Create the third marker after the others.",
            requirement_ids=["REQ-001", "REQ-002"],
            depends_on=["TASK-001", "TASK-002"],
            verification=marker_verification("TASK-003"),
        ),
    ]


def make_package(
    repo: Path,
    *,
    tasks: Sequence[Task] | None = None,
    change_id: str = CHANGE_ID,
    with_plan: bool = True,
    approved: bool = False,
) -> ChangePackage:
    """Create and reload a synthetic change package under ``<repo>/changes/<id>``."""
    intent = Intent(
        id=change_id,
        title="Demo change",
        owner="kevin",
        kernel=Kernel(
            why="demonstrate orchestration",
            capabilities=["markers"],
            constraints=["Keep changes small"],
            non_goals=["No UI work"],
            success_signal="markers exist",
        ),
    )
    pkg = pkgio.create(repo, change_id, intent)
    pkg.requirements = [
        Requirement(
            id="REQ-001",
            text="The system SHALL write a marker file for every task.",
            scenarios=[
                Scenario(
                    id="SCN-001-01",
                    name="marker",
                    when="a task runs",
                    then="a marker file named after the task exists",
                )
            ],
        ),
        Requirement(
            id="REQ-002",
            text="The system SHALL keep the markers under version control.",
            scenarios=[
                Scenario(
                    id="SCN-002-01",
                    name="tracked",
                    when="a task completes",
                    then="its marker is committed on the task branch",
                )
            ],
        ),
    ]
    pkg.interfaces = [
        Interface(id="IFC-001", name="MarkerStore", description="Writes marker files.")
    ]
    pkg.decisions = [
        ArchitectureDecision(
            id="ADR-0001", title="Use marker files", decision="Markers are plain text files."
        )
    ]
    task_list = list(tasks) if tasks is not None else default_tasks()
    pkg.tasks = task_list
    if with_plan:
        waves: dict[int, list[str]] = {}
        for task in task_list:
            index = 1 if task.depends_on else 0
            waves.setdefault(index, []).append(task.id)
        pkg.plan = Plan(
            summary="two waves",
            waves=[Wave(index=i, task_ids=waves[i]) for i in sorted(waves)],
            approved_by="kevin" if approved else None,
        )
    pkg.save()
    assert pkg.root is not None
    return pkgio.load(pkg.root)


def make_executor(
    pkg: ChangePackage,
    runner: AgentRunner,
    *,
    ledger: UsageLedger | None = None,
    checkpoint: Checkpoint = approve_all_checkpoints,
    config: ExecutorConfig | None = None,
    policy: OrgPolicy | None = None,
    enforcer: ActionChecker | None = None,
    reviewer_runner: AgentRunner | None = None,
    **kwargs: Any,
) -> Executor:
    """Executor over the synthetic package with sensible test defaults."""
    return Executor(
        pkg,
        policy or default_org_policy(),
        runner,
        ledger or UsageLedger(),
        enforcer,
        checkpoint=checkpoint,
        config=config or ExecutorConfig(),
        reviewer_runner=reviewer_runner,
        **kwargs,
    )


def deny_kind(kind: str) -> Callable[[Any], bool]:
    """Checkpoint callback approving everything except ``kind``."""

    def _cb(request: Any) -> bool:
        return bool(request.kind.value != kind)

    return _cb
