"""CLI error handling on realistic bad input: no tracebacks, exit code 2 with a message."""

from __future__ import annotations

import subprocess
from pathlib import Path

from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import Intent

runner = CliRunner()


def test_run_rejects_invalid_change_id(tmp_repo: Path) -> None:
    for args in (["run", "change", "not-an-id"], ["run", "status", "not-an-id"]):
        result = runner.invoke(app, [*args, "--root", str(tmp_repo)])
        assert result.exit_code == 2, result.output
        assert "not a valid CHG identifier" in result.output
        assert "Traceback" not in result.output


def test_run_change_in_repo_without_commits(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    pkgio.create(tmp_path, "CHG-x", Intent(id="CHG-x", title="x"))
    result = runner.invoke(app, ["run", "change", "CHG-x", "--root", str(tmp_path), "--yes"])
    assert result.exit_code == 2, result.output
    assert "error:" in result.output and "initial commit" in result.output
    assert "Traceback" not in result.output
    task = runner.invoke(
        app, ["run", "task", "TASK-001", "--change", "CHG-x", "--root", str(tmp_path), "--yes"]
    )
    assert task.exit_code == 2 and "Traceback" not in task.output


def test_cost_commands_reject_missing_paths(tmp_path: Path) -> None:
    ledger = tmp_path / "new" / "dir" / "ledger.sqlite"
    ok = runner.invoke(app, ["cost", "report", "--ledger", str(ledger), "--json"])
    assert ok.exit_code == 0, ok.output  # parent directory is created on demand
    assert ledger.is_file()

    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    result = runner.invoke(app, ["cost", "report", "--ledger", str(blocked / "ledger.sqlite")])
    assert result.exit_code == 2, result.output
    assert "ledger" in result.output and "Traceback" not in result.output

    kpis = runner.invoke(
        app, ["cost", "kpis", "--outcomes", str(tmp_path / "nope.json"), "--ledger", str(ledger)]
    )
    assert kpis.exit_code == 2 and "file not found" in kpis.output

    budget = runner.invoke(
        app,
        [
            "cost",
            "budget-check",
            "--scope",
            "team:x",
            "--forecast",
            "1",
            "--budgets",
            str(tmp_path / "nope.yaml"),
            "--ledger",
            str(ledger),
        ],
    )
    assert budget.exit_code == 2 and "file not found" in budget.output

    bad = tmp_path / "bad.yaml"
    bad.write_text("budgets: [\n")
    broken = runner.invoke(
        app,
        ["cost", "budget-check", "--scope", "team:x", "--forecast", "1", "--budgets", str(bad)],
    )
    assert broken.exit_code == 2 and "cannot read" in broken.output


def test_cost_user_files_report_path_and_exit_2(tmp_path: Path) -> None:
    """Malformed user files never surface a traceback: ``error: <path>: <message>``, exit 2."""
    ledger = ["--ledger", str(tmp_path / "ledger.sqlite")]
    budgets = tmp_path / "budgets.yaml"
    budgets.write_text("budgets:\n  - scope_type: application\n    limit_usd: -5\n")
    check = ["cost", "budget-check", "--scope", "application:x", "--forecast", "1"]
    result = runner.invoke(app, [*check, "--budgets", str(budgets), *ledger])
    assert result.exit_code == 2, result.output
    assert result.output.startswith(f"error: {budgets}: "), result.output
    assert "scope_id: Field required" in result.output
    assert "limit_usd: Input should be greater than 0" in result.output
    assert "Traceback" not in result.output

    not_mapping = tmp_path / "list.yaml"
    not_mapping.write_text("- 1\n")
    listed = runner.invoke(app, [*check, "--budgets", str(not_mapping), *ledger])
    assert listed.exit_code == 2 and f"error: {not_mapping}: budgets file must be" in listed.output

    exceptions = tmp_path / "exc.json"
    exceptions.write_text('{"exceptions": [{"scope_type": "team"}]}')
    exc = runner.invoke(app, [*check, "--budgets", str(exceptions), *ledger])
    assert exc.exit_code == 2 and exc.output.startswith(f"error: {exceptions}: scope_id")

    outcomes = tmp_path / "outcomes.json"
    outcomes.write_text('{"accepted_requirements": -1}')
    kpis = runner.invoke(app, ["cost", "kpis", "--outcomes", str(outcomes), *ledger])
    assert kpis.exit_code == 2, kpis.output
    assert kpis.output.startswith(f"error: {outcomes}: accepted_requirements: ")

    registry = tmp_path / "registry.yaml"
    registry.write_text("models:\n  - model: 1\n")
    reg = runner.invoke(app, ["cost", "registry", "list", "--registry", str(registry)])
    assert reg.exit_code == 2, reg.output
    assert reg.output.startswith(f"error: {registry}: ") and "Traceback" not in reg.output
    route = runner.invoke(app, ["cost", "route", "--registry", str(tmp_path / "missing.yaml")])
    assert route.exit_code == 2 and route.output.startswith("error: ")

    pieces = tmp_path / "pieces.json"
    pieces.write_text('{"pieces": 3}')
    imported = runner.invoke(app, ["cost", "import", "pyrit", str(pieces), *ledger])
    assert imported.exit_code == 2, imported.output
    assert imported.output.startswith(f"error: {pieces}: expected a JSON list of pieces")
    broken = tmp_path / "broken.json"
    broken.write_text("{")
    unparsable = runner.invoke(app, ["cost", "import", "pyrit", str(broken), *ledger])
    assert unparsable.exit_code == 2 and unparsable.output.startswith(
        f"error: {broken}: cannot read"
    )
