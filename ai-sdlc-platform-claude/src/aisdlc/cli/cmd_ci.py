"""``aisdlc ci`` — reusable workflow rendering, pin verification, supply-chain evidence.

Exit codes: 0 = ok, 1 = pin/lint violation, incomplete evidence or manifest drift,
2 = usage or load error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from aisdlc.cli import _common as common

NAME = "ci"

app = typer.Typer(help="Plane 1 CI: render hardened workflows, verify pins, collect evidence.")


def _fail(message: str, code: int = 2) -> None:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code)


def _project(project: Path | None) -> Any:
    from aisdlc.policy import default_project_config, find_project_config, load_project_config

    try:
        if project is not None:
            return load_project_config(project)
        found = find_project_config(Path.cwd())
        return load_project_config(found) if found else default_project_config()
    except Exception as exc:  # noqa: BLE001 - surface loader failures as exit 2
        _fail(f"cannot load project config: {exc}")
        return None


@app.command("render")
def render(
    out: Path = typer.Option(
        Path(".github/workflows"), "--out", "-o", help="Directory to write rendered workflows."
    ),
    project: Path | None = typer.Option(None, "--project", help="project-config.yaml."),
    workflow: list[str] | None = typer.Option(
        None, "--workflow", "-w", help="Only render these workflows (repeatable)."
    ),
    workflows_repo: str = typer.Option("ORG/.github", "--workflows-repo"),
    workflows_ref: str = typer.Option(
        "0000000000000000000000000000000000000000",
        "--workflows-ref",
        help="Commit SHA of the workflows repository for the caller workflow.",
    ),
    workflows_version: str = typer.Option("v0.1.0", "--workflows-version"),
    python_version: str = typer.Option("3.12", "--python-version"),
    node_version: str = typer.Option("22", "--node-version"),
    matrix: list[str] | None = typer.Option(
        None, "--matrix", help="Toolchain versions for the primary language (repeatable)."
    ),
    aisdlc_spec: str = typer.Option("ai-sdlc-platform", "--aisdlc-spec"),
    pyrit_target: str = typer.Option("", "--pyrit-target"),
    safety_module: str = typer.Option("", "--safety-module"),
    no_caller: bool = typer.Option(False, "--no-caller", help="Skip the consumer workflow."),
    stdout: bool = typer.Option(False, "--stdout", help="Print instead of writing files."),
) -> None:
    """Render the organisation workflows (and the consumer caller) for a project."""
    from aisdlc.security.ci_templates import RenderError, RenderOptions, render, render_caller

    config = _project(project)
    if config is None:
        return
    options = RenderOptions(
        python_version=python_version,
        node_version=node_version,
        matrix={config.languages[0].lower(): list(matrix)} if matrix else {},
        aisdlc_spec=aisdlc_spec,
        workflows_repo=workflows_repo,
        workflows_ref=workflows_ref,
        workflows_version=workflows_version,
        pyrit_target=pyrit_target,
        safety_module=safety_module,
    )
    try:
        rendered = render(config, options=options, workflows=workflow)
        if not no_caller:
            rendered["aisdlc-ci.yml"] = render_caller(config, options=options)
    except (RenderError, FileNotFoundError) as exc:
        _fail(str(exc))
        return
    if stdout:
        for name, text in rendered.items():
            typer.echo(f"# ===== {name} =====")
            typer.echo(text)
        return
    out.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (out / name).write_text(text, encoding="utf-8")
        typer.echo(f"wrote {out / name}")


@app.command("list")
def list_cmd(
    project: Path | None = typer.Option(None, "--project"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List the reusable workflow templates and the pinned action catalogue."""
    from aisdlc.security.ci_templates import PINNED_ACTIONS, describe, list_workflows

    config = _project(project)
    if config is None:
        return
    if as_json:
        payload = describe(config)
        payload["pins"] = {k: {"sha": v[0], "version": v[1]} for k, v in PINNED_ACTIONS.items()}
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo("workflows:")
    for name in list_workflows():
        typer.echo(f"  {name}")
    typer.echo("pinned actions:")
    for action, (sha, version) in PINNED_ACTIONS.items():
        typer.echo(f"  {action}@{sha}  # {version}")


@app.command("verify-pins")
def verify_pins_cmd(
    paths: list[Path] | None = typer.Argument(
        None, help="Workflow files or directories (default: the bundled templates)."
    ),
    lint: bool = typer.Option(True, "--lint/--no-lint", help="Also apply the hardening lint."),
    version_comment: bool = typer.Option(
        True, "--version-comment/--no-version-comment", help="Require a '# vX' comment."
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Verify every `uses:` is pinned to a commit SHA (exit 1 on any violation)."""
    from aisdlc.security.ci_templates import (
        WORKFLOWS_DIR,
        PinIssue,
        WorkflowIssue,
        lint_workflow,
        verify_pins,
    )

    targets = paths or [WORKFLOWS_DIR]
    pin_issues: list[PinIssue] = []
    lint_issues: list[WorkflowIssue] = []
    for target in targets:
        if not target.exists():
            _fail(f"{target} does not exist")
            return
        pin_issues.extend(verify_pins(target, require_version_comment=version_comment))
        if lint:
            files = sorted(target.rglob("*.y*ml")) if target.is_dir() else [target]
            for file in files:
                lint_issues.extend(
                    i
                    for i in lint_workflow(file.read_text(encoding="utf-8"), str(file))
                    if i.code != "PIN"
                )
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "pins": [i.model_dump() for i in pin_issues],
                    "lint": [i.model_dump() for i in lint_issues],
                },
                indent=2,
            )
        )
    else:
        for issue in pin_issues:
            typer.echo(f"{issue.workflow}:{issue.line}: {issue.uses}: {issue.reason}")
        for lint_issue in lint_issues:
            where = f" [{lint_issue.job}]" if lint_issue.job else ""
            typer.echo(f"{lint_issue.workflow}{where}: {lint_issue.code}: {lint_issue.message}")
        if not pin_issues and not lint_issues:
            typer.echo("all uses: references are SHA-pinned and workflows pass the hardening lint")
    if pin_issues or lint_issues:
        raise typer.Exit(1)


@app.command("collect-security")
def collect_security(
    directory: Path = typer.Argument(..., exists=True, file_okay=False, help="Artifact dir."),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package to write evidence/security.json into.",
        callback=common.optional_package_arg,
    ),
    commit_sha: str = typer.Option("", "--commit-sha"),
    environment: str = typer.Option("ci", "--environment", "-e"),
    manifest_drift: bool = typer.Option(False, "--manifest-drift", help="Record drift=true."),
    out: Path | None = typer.Option(None, "--out", "-o"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Parse CI artifacts (SARIF, dependency review, gitleaks, SBOM, provenance, VEX...)."""
    from aisdlc.security.supply_chain import collect_directory, write_security_evidence

    try:
        evidence, found = collect_directory(
            directory,
            commit_sha=commit_sha,
            environment=environment,
            manifest_drift=manifest_drift,
            report_uri=str(out) if out is not None else str(directory),
        )
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        return
    if package is not None:
        if not (package / "intent.md").is_file():
            _fail(f"{package} is not a change package")
            return
        write_security_evidence(package, evidence)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence.model_dump(mode="json"), indent=2, default=str) + "\n")
    if as_json:
        typer.echo(
            json.dumps(
                {"evidence": evidence.model_dump(mode="json"), "inputs": found.model_dump()},
                indent=2,
                default=str,
            )
        )
    else:
        typer.echo(
            f"{evidence.id}: status={evidence.status.value} critical_open={evidence.critical_open} "
            f"high_open={evidence.high_open} sbom={evidence.sbom_present} "
            f"provenance={evidence.provenance_present}"
        )
        for note in found.notes:
            typer.echo(f"  note: {note}")
    if not evidence.is_complete:
        raise typer.Exit(1)


@app.command("manifest-drift")
def manifest_drift(
    package: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    audit: Path | None = typer.Option(
        None, "--audit", help="Audit log/export to observe (default: evidence/audit.json)."
    ),
    strict_unused: bool = typer.Option(False, "--strict-unused"),
    platform_tool: list[str] | None = typer.Option(
        None,
        "--platform-tool",
        help="Extra platform-internal tool name excluded from drift (exact match; "
        "repeatable). The built-in allowlist covers the orchestrator's own governed "
        "actions (aisdlc.orchestration).",
    ),
    platform_allowlist: bool = typer.Option(
        True,
        "--platform-allowlist/--no-platform-allowlist",
        help="Exclude platform-internal actors (the orchestrator's own writes, "
        "verification runs and commits) from drift; --no-platform-allowlist reports "
        "them as undeclared tools too.",
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Compare the threat model's tool/data manifest with observed tool calls (exit 1 on drift).

    Calls the platform records under its own name (``aisdlc.orchestration``) are not the
    agent's behaviour and are excluded by an explicit, exact-match allowlist; they are
    listed in the report as ``platform_tools`` so the exclusion stays visible.
    """
    from aisdlc.security.manifest import (
        PLATFORM_TOOLS,
        compare,
        drift_for_package,
        load_declared_manifest,
        observe_audit,
    )

    if not platform_allowlist:
        platform_tools: frozenset[str] = frozenset()
    else:
        platform_tools = PLATFORM_TOOLS | frozenset(platform_tool or ())
    try:
        if audit is None:
            report = drift_for_package(
                package, strict_unused=strict_unused, platform_tools=platform_tools
            )
        else:
            manifest = load_declared_manifest(package)
            report = compare(
                manifest,
                observe_audit(audit, platform_tools=platform_tools),
                strict_unused=strict_unused,
                platform_tools=platform_tools,
            )
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        return
    if as_json:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        for line in report.summary_lines():
            typer.echo(line)
    if report.drift:
        raise typer.Exit(1)
