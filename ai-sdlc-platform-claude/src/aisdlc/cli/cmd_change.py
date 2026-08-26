"""``aisdlc change`` — create, validate, inspect and fingerprint change packages."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aisdlc import ids
from aisdlc.cli import _common as common
from aisdlc.schema import fingerprint as fp
from aisdlc.schema import grammar
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ChangePackage, Intent, Kernel, RiskClass

NAME = "change"
app = typer.Typer(help="Canonical change packages (changes/<change-id>/).", no_args_is_help=True)


def _load(directory: Path) -> ChangePackage:
    try:
        return pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("new")
def new(
    change_id: str = typer.Argument(..., help="CHG-<slug> id, or a title to slugify."),
    title: str | None = typer.Option(None, "--title", "-t", help="Human title."),
    why: str = typer.Option("", "--why", help="Kernel: why this change exists."),
    owner: str | None = typer.Option(None, "--owner", "-o", help="Accountable owner."),
    risk_class: RiskClass = typer.Option(RiskClass.STANDARD, "--risk-class", "--risk", "-r"),
    root: Path = typer.Option(Path("."), "--root", help="Repository root (holds changes/)."),
) -> None:
    """Create a skeleton change package."""
    if not ids.is_valid("CHG", change_id):
        derived = ids.change_id(change_id)
        title = title or change_id
        change_id = derived
    intent = Intent(
        id=change_id,
        title=title or change_id.removeprefix("CHG-").replace("-", " "),
        kernel=Kernel(why=why),
        owner=owner,
        risk_class=risk_class,
    )
    try:
        created = pkgio.create(root, change_id, intent)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"created {created.root}")


@app.command("validate")
def validate(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    warnings_as_errors: bool = typer.Option(False, "--strict", help="Fail on warnings too."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Run grammar and consistency checks; exit 1 when errors are found."""
    package = _load(directory)
    issues = grammar.validate_package(package)
    report = grammar.ambiguity_report(package)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "change_id": package.change_id,
                    "ambiguity_score": report.score,
                    "issues": [issue.model_dump(mode="json") for issue in issues],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for issue in issues:
            typer.echo(str(issue))
        typer.echo(
            f"{package.change_id}: {len(issues)} issue(s), ambiguity score {report.score:.2f}"
        )
    failing = {grammar.IssueSeverity.ERROR}
    if warnings_as_errors:
        failing.add(grammar.IssueSeverity.WARNING)
    if any(issue.severity in failing for issue in issues):
        raise typer.Exit(code=1)


@app.command("status")
def status(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Show the derived workflow state and artifact counts."""
    package = _load(directory)
    summary = {
        "change_id": package.change_id,
        "title": package.intent.title,
        "owner": package.intent.owner,
        "risk_class": package.intent.risk_class.value,
        "state": package.derive_state().value,
        "requirements": len(package.requirements),
        "scenarios": len(package.scenarios()),
        "open_questions": sum(1 for q in package.open_questions if q.status.value == "open"),
        "blocking_questions": sum(1 for q in package.open_questions if q.is_open_blocking),
        "decisions": len(package.decisions),
        "interfaces": len(package.interfaces),
        "tasks": len(package.tasks),
        "tasks_done": sum(1 for t in package.tasks if t.status.value == "done"),
        "evidence": package.evidence.ids(),
        "fingerprint": package.base_fingerprint,
    }
    if as_json:
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
        return
    for key, value in summary.items():
        typer.echo(f"{key:>19}: {value}")


@app.command("list")
def list_changes(
    root: Path = typer.Option(Path("."), "--root", help="Repository root (holds changes/)."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """List change packages under <root>/changes."""
    rows: list[dict[str, str]] = []
    for directory in pkgio.list_packages(root):
        try:
            package = pkgio.load(directory)
        except pkgio.PackageError as exc:
            rows.append({"change_id": directory.name, "state": "invalid", "detail": str(exc)})
            continue
        rows.append(
            {
                "change_id": package.change_id,
                "state": package.derive_state().value,
                "risk_class": package.intent.risk_class.value,
                "title": package.intent.title,
            }
        )
    if as_json:
        typer.echo(json.dumps(rows, indent=2, sort_keys=True))
        return
    if not rows:
        typer.echo("no change packages found")
        return
    for row in rows:
        typer.echo(
            f"{row['change_id']:<40} {row['state']:<13} "
            f"{row.get('risk_class', ''):<10} {row.get('title', row.get('detail', ''))}"
        )


@app.command("fingerprint")
def fingerprint_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    update: bool = typer.Option(False, "--update", help="Write .fingerprint."),
    check: str | None = typer.Option(
        None, "--check", help="Base fingerprint to compare against; exit 3 on mismatch."
    ),
) -> None:
    """Compute (and optionally store or check) the content fingerprint."""
    if not (directory / pkgio.INTENT_FILE).is_file():
        typer.echo(f"error: not a change package: {directory}", err=True)
        raise typer.Exit(code=2)
    if check is not None:
        try:
            current = fp.check_fingerprint(directory, check)
        except fp.OptimisticConcurrencyError as exc:
            typer.echo(f"stale: {exc}", err=True)
            raise typer.Exit(code=3) from exc
    else:
        current = fp.compute_fingerprint(directory)
    if update:
        fp.write_fingerprint(directory, current)
    stored = fp.read_fingerprint(directory)
    typer.echo(current)
    if stored is not None and stored != current and not update:
        typer.echo("note: stored .fingerprint differs (use --update to refresh)", err=True)
