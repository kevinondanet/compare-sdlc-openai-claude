"""``aisdlc run`` CLI: change / task / review / status with the dry runner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisdlc.cli.main import app
from tests.orchestration_support import default_tasks, make_package

runner = CliRunner()


def _common(repo: Path) -> list[str]:
    return ["--root", str(repo), "--ledger", str(repo / ".aisdlc" / "ledger.sqlite")]


def test_run_change_dry_success_and_status(tmp_repo: Path) -> None:
    make_package(tmp_repo)
    result = runner.invoke(app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--yes"])
    assert result.exit_code == 0, result.output
    assert "CHG-demo: success" in result.output
    assert "TASK-003" in result.output and "final review:" in result.output
    assert "release checkpoint: approved" in result.output
    for tid in ("TASK-001", "TASK-002", "TASK-003"):
        assert (tmp_repo / f"{tid}.dryrun").is_file()

    status = runner.invoke(app, ["run", "status", "CHG-demo", "--root", str(tmp_repo)])
    assert status.exit_code == 0, status.output
    assert "CHG-demo: reviewed" in status.output and "task_done" in status.output
    assert "TASK-001   done" in status.output
    as_json = runner.invoke(app, ["run", "status", "CHG-demo", "--root", str(tmp_repo), "--json"])
    data = json.loads(as_json.output)
    assert all(t["status"] == "done" and t["completed_handoff"] for t in data["tasks"])
    assert data["evidence"] and data["worktrees"] == []

    # resumed run: nothing to do, still success
    again = runner.invoke(app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--yes", "--json"])
    assert again.exit_code == 0, again.output
    report = json.loads(again.output)
    assert report["outcome"] == "success" and all(t["resumed"] for t in report["tasks"])
    dup = runner.invoke(
        app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--yes", "--no-resume"]
    )
    assert dup.exit_code == 4 and "duplicate" in dup.output


def test_run_change_non_interactive_denies_plan(tmp_repo: Path) -> None:
    make_package(tmp_repo)
    result = runner.invoke(
        app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--non-interactive"]
    )
    assert result.exit_code == 3, result.output
    assert "plan approval denied" in result.output


def test_run_change_by_directory_and_load_errors(tmp_repo: Path, tmp_path: Path) -> None:
    pkg = make_package(tmp_repo, tasks=default_tasks()[:1])
    result = runner.invoke(app, ["run", "change", str(pkg.root), *_common(tmp_repo), "--yes"])
    assert result.exit_code == 0, result.output
    missing = runner.invoke(app, ["run", "change", "CHG-missing", *_common(tmp_repo)])
    assert missing.exit_code == 2 and "error" in missing.output
    bad_runner = runner.invoke(
        app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--runner", "nope"]
    )
    assert bad_runner.exit_code == 2
    no_script = runner.invoke(
        app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--runner", "script"]
    )
    assert no_script.exit_code == 2 and "script-command" in no_script.output


def test_run_task_and_review_commands(tmp_repo: Path) -> None:
    make_package(tmp_repo)
    result = runner.invoke(
        app, ["run", "task", "TASK-001", "--change", "CHG-demo", *_common(tmp_repo), "--yes"]
    )
    assert result.exit_code == 0, result.output
    assert "TASK-001   done" in result.output
    assert (tmp_repo / "TASK-001.dryrun").is_file()
    unknown = runner.invoke(
        app, ["run", "task", "TASK-999", "--change", "CHG-demo", *_common(tmp_repo), "--yes"]
    )
    assert unknown.exit_code == 2
    denied = runner.invoke(
        app,
        [
            "run",
            "task",
            "TASK-002",
            "--change",
            "CHG-demo",
            *_common(tmp_repo),
            "--non-interactive",
        ],
    )
    assert denied.exit_code == 3 and "blocked" in denied.output

    review = runner.invoke(app, ["run", "review", "CHG-demo", *_common(tmp_repo)])
    assert review.exit_code == 0, review.output
    assert "EVD-reviews-" in review.output and "approved" in review.output
    review_json = runner.invoke(app, ["run", "review", "CHG-demo", *_common(tmp_repo), "--json"])
    data = json.loads(review_json.output)
    assert data["verdict"] == "approved" and data["kind"] == "reviews"


def test_run_change_with_script_runner(
    tmp_repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    make_package(tmp_repo, tasks=default_tasks()[:1])
    # outside the repository: an uncommitted script inside it would (rightly) block the run
    script = tmp_path_factory.mktemp("runner") / "agent.sh"
    script.write_text(
        '#!/bin/sh\ntouch "$AISDLC_TASK_ID.dryrun"\n'
        'printf \'{"status":"success","summary":"scripted","files_changed":["%s.dryrun"]}\\n\' '
        '"$AISDLC_TASK_ID"\n'
    )
    script.chmod(0o755)
    result = runner.invoke(
        app,
        [
            "run",
            "change",
            "CHG-demo",
            *_common(tmp_repo),
            "--yes",
            "--runner",
            "script",
            "--script-command",
            str(script),
            "--keep-worktrees",
            "--no-final-review",
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_repo / "TASK-001.dryrun").is_file()
    status = runner.invoke(app, ["run", "status", "CHG-demo", "--root", str(tmp_repo)])
    assert "worktrees:" in status.output and "aisdlc/CHG-demo/TASK-001" in status.output


def test_run_change_ignore_duplicates_reruns(tmp_repo: Path) -> None:
    make_package(tmp_repo, tasks=default_tasks()[:1])
    first = runner.invoke(app, ["run", "change", "CHG-demo", *_common(tmp_repo), "--yes"])
    assert first.exit_code == 0, first.output
    again = runner.invoke(
        app,
        [
            "run",
            "change",
            "CHG-demo",
            *_common(tmp_repo),
            "--yes",
            "--no-resume",
            "--ignore-duplicates",
            "--json",
        ],
    )
    assert again.exit_code == 0, again.output
    report = json.loads(again.output)
    assert report["duplicate"] is True and report["outcome"] == "success"
    assert report["tasks"][0]["resumed"] is False and report["waves_executed"] == [0]
