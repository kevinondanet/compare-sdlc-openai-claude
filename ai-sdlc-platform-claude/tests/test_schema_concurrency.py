"""Optimistic concurrency on the long-running writers: executor and intake commands.

A human editing ``requirements.md`` while the orchestrator runs (or between an intake
command's load and save) must never lose that edit.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.orchestration.brief import AgentBrief
from aisdlc.orchestration.executor import RunOutcome
from aisdlc.orchestration.roles import AgentRole
from aisdlc.orchestration.runner import AgentResult, DryRunRunner
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import TaskStatus
from tests.orchestration_support import make_executor, make_package

runner = CliRunner()


class HumanEditsDuringRun(DryRunRunner):
    """Dry runner that edits the change package's requirements on its first call."""

    def __init__(self, package_dir: Path) -> None:
        super().__init__()
        self.package_dir = package_dir
        self.edited = False

    def run(self, brief: AgentBrief) -> AgentResult:
        if not self.edited and brief.role is AgentRole.IMPLEMENTER:
            self.edited = True
            human = pkgio.load(self.package_dir)
            human.requirements[0].text = "The system SHALL honour the HUMAN EDIT."
            human.bodies["requirements.md"] = "# Requirements\n\nHUMAN EDIT\n"
            human.save(base_fingerprint=human.base_fingerprint)
        return super().run(brief)


def test_executor_keeps_concurrent_human_edit(tmp_repo: Path) -> None:
    pkg = make_package(tmp_repo)
    assert pkg.root is not None
    executor = make_executor(pkg, HumanEditsDuringRun(pkg.root))
    report = executor.run()
    assert report.outcome is RunOutcome.SUCCESS, report.messages
    text = (pkg.root / "requirements.md").read_text()
    assert "HUMAN EDIT" in text
    reloaded = pkgio.load(pkg.root)
    assert reloaded.requirements[0].text == "The system SHALL honour the HUMAN EDIT."
    # produced state still landed: statuses, evidence, cost
    assert all(t.status is TaskStatus.DONE for t in reloaded.tasks)
    assert len(reloaded.evidence.tests) == 3 and reloaded.evidence.cost is not None
    # the executor's in-memory package adopted the merged content
    assert executor.package.requirements[0].text == reloaded.requirements[0].text
    assert executor.package.base_fingerprint == reloaded.base_fingerprint


def test_intake_kernel_merges_concurrent_edit(tmp_repo: Path) -> None:
    pkg = make_package(tmp_repo)
    assert pkg.root is not None
    # simulate an edit that lands between the command's load and save by patching load:
    # the first load returns a package whose fingerprint is stale because we edit right after
    real_load = pkgio.load
    state = {"edited": False}

    def load_then_edit(directory: str | Path) -> object:
        loaded = real_load(directory)
        if not state["edited"]:
            state["edited"] = True
            human = real_load(directory)
            human.requirements[0].text = "The system SHALL keep the HUMAN EDIT."
            human.save(base_fingerprint=human.base_fingerprint)
        return loaded

    mp = pytest.MonkeyPatch()
    mp.setattr(pkgio, "load", load_then_edit)
    try:
        result = runner.invoke(
            app, ["intake", "kernel", str(pkg.root), "--why", "because merged", "--json"]
        )
    finally:
        mp.undo()
    assert result.exit_code in (0, 1), result.output
    assert "merged concurrent edits" in result.output
    reloaded = pkgio.load(pkg.root)
    assert reloaded.intent.kernel.why == "because merged"
    assert reloaded.requirements[0].text == "The system SHALL keep the HUMAN EDIT."


def test_intake_kernel_reports_conflicting_edit(tmp_repo: Path) -> None:
    pkg = make_package(tmp_repo)
    assert pkg.root is not None
    real_load = pkgio.load
    state = {"edited": False}

    def load_then_edit(directory: str | Path) -> object:
        loaded = real_load(directory)
        if not state["edited"]:
            state["edited"] = True
            human = real_load(directory)
            human.intent.kernel.why = "HUMAN why"
            human.save(base_fingerprint=human.base_fingerprint)
        return loaded

    mp = pytest.MonkeyPatch()
    mp.setattr(pkgio, "load", load_then_edit)
    try:
        result = runner.invoke(app, ["intake", "kernel", str(pkg.root), "--why", "agent why"])
    finally:
        mp.undo()
    assert result.exit_code == 2, result.output
    assert "conflict" in result.output and "intent" in result.output
    assert pkgio.load(pkg.root).intent.kernel.why == "HUMAN why"  # nothing overwritten
