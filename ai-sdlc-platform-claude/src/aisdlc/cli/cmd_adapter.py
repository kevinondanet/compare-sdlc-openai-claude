"""``aisdlc adapter`` — emit harness files and import/export OpenSpec change directories."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aisdlc import adapters
from aisdlc.adapters import openspec
from aisdlc.cli import _common as common
from aisdlc.policy import merge as policy_merge
from aisdlc.policy import org_policy as orgmod
from aisdlc.policy import project_config as projmod
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import RiskClass

NAME = "adapter"
app = typer.Typer(
    help="Harness adapters (Claude Code, Copilot, Codex, Cursor, Kiro) and OpenSpec I/O.",
    no_args_is_help=True,
)

_ORG_OPT = typer.Option(None, "--org", help="org-policy.yaml (auto-discovered if omitted).")
_PROJECT_OPT = typer.Option(
    None, "--project", help="project-config.yaml (auto-discovered if omitted)."
)
_ROOT_OPT = typer.Option(Path("."), "--root", help="Directory searched for policy files.")


def _resolve_policy(
    org: Path | None, project: Path | None, root: Path
) -> tuple[projmod.ProjectConfig, policy_merge.EffectivePolicy]:
    org_path = org if org is not None else orgmod.find_org_policy(root)
    project_path = project if project is not None else projmod.find_project_config(root)
    try:
        org_policy = orgmod.load_org_policy(org_path) if org_path else orgmod.default_org_policy()
        project_config = (
            projmod.load_project_config(project_path)
            if project_path
            else projmod.default_project_config()
        )
    except orgmod.PolicyLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    return project_config, policy_merge.effective_policy(org_policy, project_config)


@app.command("list")
def list_adapters(as_json: bool = typer.Option(False, "--json")) -> None:
    """List the available harness adapters."""
    rows = [
        {"name": name, "description": adapters.get_adapter(name).description}
        for name in adapters.adapter_names()
    ]
    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return
    for row in rows:
        typer.echo(f"{row['name']:<12} {row['description']}")


@app.command("emit")
def emit(
    harness: str = typer.Argument(..., help="claude_code | copilot | codex | cursor | kiro | all"),
    out: Path = typer.Option(Path("."), "--out", "-o", help="Target project directory."),
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    role: str = typer.Option("implementer", "--role", help="Role for the governance hook."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Emit the canonical workflow in a harness's native format under --out."""
    names = adapters.adapter_names() if harness.lower() == "all" else [harness]
    project_config, effective = _resolve_policy(org, project, root)
    results = []
    for name in names:
        try:
            adapter = adapters.get_adapter(name)
        except KeyError as exc:
            typer.echo(f"error: {exc.args[0]}", err=True)
            raise typer.Exit(code=2) from exc
        if isinstance(adapter, adapters.ClaudeCodeAdapter):
            adapter.role = role
        results.append(adapter.emit(project_config, effective, out))
    if as_json:
        typer.echo(
            json.dumps(
                [
                    {
                        "harness": r.harness,
                        "out_dir": str(r.out_dir),
                        "files": [
                            {"path": f.relative, "description": f.description} for f in r.files
                        ],
                    }
                    for r in results
                ],
                indent=2,
            )
        )
        return
    for result in results:
        typer.echo(f"{result.harness}: {len(result.files)} file(s) under {result.out_dir}")
        for emitted in result.files:
            typer.echo(f"  {emitted.relative}  — {emitted.description}")


def _echo_unmapped(items: list[openspec.Unmapped]) -> None:
    for item in items:
        typer.echo(f"unmapped {item}")


@app.command("import-openspec")
def import_openspec(
    change_dir: Path = typer.Argument(..., help="openspec/changes/<id>/ directory."),
    root: Path = typer.Option(Path("."), "--root", help="Repository root (holds changes/)."),
    change_id: str | None = typer.Option(None, "--change-id", help="Override the CHG-<slug> id."),
    owner: str | None = typer.Option(None, "--owner", "-o"),
    risk_class: RiskClass | None = typer.Option(None, "--risk-class", "-r"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing package."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Import an OpenSpec change directory as a canonical change package."""
    try:
        result = openspec.import_change(
            change_dir, change_id=change_id, owner=owner, risk_class=risk_class
        )
    except (openspec.OpenSpecError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    pkg = result.package
    try:
        created = pkgio.create(root, pkg.change_id, pkg.intent, exist_ok=force)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    pkg.bodies = {**created.bodies, **pkg.bodies}
    pkg.threat_model = created.threat_model
    if pkg.plan is None:
        pkg.plan = created.plan
    pkg.root = created.root
    pkg.save(created.root)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "change_id": pkg.change_id,
                    "directory": str(created.root),
                    "requirements": len(pkg.requirements),
                    "scenarios": len(pkg.scenarios()),
                    "tasks": len(pkg.tasks),
                    "id_map": result.id_map,
                    "warnings": result.warnings,
                    "unmapped": [u.model_dump(mode="json") for u in result.unmapped],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    typer.echo(
        f"imported {pkg.change_id} -> {created.root}: {len(pkg.requirements)} requirement(s), "
        f"{len(pkg.scenarios())} scenario(s), {len(pkg.tasks)} task(s)"
    )
    for warning in result.warnings:
        typer.echo(f"warning: {warning}")
    _echo_unmapped(result.unmapped)


@app.command("export-openspec")
def export_openspec(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="OpenSpec change dir (default openspec/changes/<slug>)."
    ),
    capability: str | None = typer.Option(
        None, "--capability", help="Default capability for untagged requirements."
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Export a change package as an OpenSpec change directory."""
    try:
        pkg = pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    target = (
        out
        if out is not None
        else Path("openspec") / "changes" / pkg.change_id.removeprefix("CHG-")
    )
    result = openspec.export_change(pkg, target, capability=capability)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "change_id": pkg.change_id,
                    "out_dir": str(result.out_dir),
                    "files": [str(p) for p in result.files],
                    "unmapped": [u.model_dump(mode="json") for u in result.unmapped],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    typer.echo(f"exported {pkg.change_id} -> {result.out_dir} ({len(result.files)} file(s))")
    for path in result.files:
        typer.echo(f"  {path.relative_to(result.out_dir).as_posix()}")
    _echo_unmapped(result.unmapped)
