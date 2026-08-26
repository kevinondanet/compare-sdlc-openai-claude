"""``aisdlc policy`` — show, validate and compute the effective policy."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

from aisdlc.policy import merge as policy_merge
from aisdlc.policy import org_policy as orgmod
from aisdlc.policy import project_config as projmod

NAME = "policy"
app = typer.Typer(help="Organization policy and project configuration.", no_args_is_help=True)

_ORG_OPT = typer.Option(None, "--org", help="org-policy.yaml (auto-discovered if omitted).")
_PROJECT_OPT = typer.Option(
    None, "--project", help="project-config.yaml (auto-discovered if omitted)."
)
_ROOT_OPT = typer.Option(Path("."), "--root", help="Directory searched for policy files.")


def _resolve(
    org: Path | None, project: Path | None, root: Path
) -> tuple[orgmod.OrgPolicy, projmod.ProjectConfig, Path | None, Path | None]:
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
    return org_policy, project_config, org_path, project_path


@app.command("show")
def show(
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    section: str = typer.Option("all", "--section", help="all | org | project"),
) -> None:
    """Print the loaded organization policy and project configuration as YAML."""
    org_policy, project_config, org_path, project_path = _resolve(org, project, root)
    if section in ("all", "org"):
        typer.echo(f"# organization policy ({org_path or 'built-in defaults'})")
        typer.echo(orgmod.dump_org_policy(org_policy))
    if section in ("all", "project"):
        typer.echo(f"# project configuration ({project_path or 'built-in defaults'})")
        typer.echo(projmod.dump_project_config(project_config))
    if section not in ("all", "org", "project"):
        typer.echo(f"error: unknown section {section!r}", err=True)
        raise typer.Exit(code=2)


@app.command("validate")
def validate(
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
) -> None:
    """Check that the project only tightens org policy; exit 1 on violations."""
    org_policy, project_config, _org_path, _project_path = _resolve(org, project, root)
    effective = policy_merge.effective_policy(org_policy, project_config)
    for path in effective.applied:
        typer.echo(f"applied  {path}")
    for violation in effective.violations:
        typer.echo(f"VIOLATION {violation}")
    typer.echo(
        f"{len(effective.applied)} override(s) applied, {len(effective.violations)} violation(s)"
    )
    if effective.violations:
        raise typer.Exit(code=1)


@app.command("effective")
def effective(
    org: Path | None = _ORG_OPT,
    project: Path | None = _PROJECT_OPT,
    root: Path = _ROOT_OPT,
    as_json: bool = typer.Option(False, "--json", help="JSON instead of YAML."),
    strict: bool = typer.Option(False, "--strict", help="Exit 1 when violations exist."),
) -> None:
    """Print the effective (merged) policy."""
    org_policy, project_config, _org_path, _project_path = _resolve(org, project, root)
    result = policy_merge.effective_policy(org_policy, project_config)
    data = result.model_dump(mode="json")
    if as_json:
        typer.echo(json.dumps(data, indent=2, sort_keys=True))
    else:
        typer.echo(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    if strict and result.violations:
        raise typer.Exit(code=1)
