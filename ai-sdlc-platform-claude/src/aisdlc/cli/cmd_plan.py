"""``aisdlc plan`` — planning and architecture governance commands.

``generate`` / ``check`` / ``waves`` (planner, plan checker), ``adr new|validate``,
``threat-model init|validate`` and ``risk classify``.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aisdlc.cli import _common as common
from aisdlc.planning import adr as adrmod
from aisdlc.planning import plan_checker, planner
from aisdlc.planning import risk as riskmod
from aisdlc.planning import threat_model as tmmod
from aisdlc.policy import org_policy as orgmod
from aisdlc.policy import project_config as projmod
from aisdlc.schema import package as pkgio
from aisdlc.schema.grammar import IssueSeverity
from aisdlc.schema.models import AdrStatus, ChangePackage, ToolDataManifest

NAME = "plan"
app = typer.Typer(
    help="Planning, ADRs, threat model and risk classification.", no_args_is_help=True
)
adr_app = typer.Typer(help="Architecture decision records.", no_args_is_help=True)
tm_app = typer.Typer(help="Threat model (architecture/threat-model.md).", no_args_is_help=True)
risk_app = typer.Typer(help="Risk classification.", no_args_is_help=True)
app.add_typer(adr_app, name="adr")
app.add_typer(tm_app, name="threat-model")
app.add_typer(risk_app, name="risk")

_PROJECT_OPT = typer.Option(
    None, "--project", help="project-config.yaml (auto-discovered from --root if omitted)."
)
_ORG_OPT = typer.Option(
    None, "--org", help="org-policy.yaml (auto-discovered from --root if omitted)."
)
_ROOT_OPT = typer.Option(
    None, "--root", help="Repository root for policy discovery (default: <dir>/../..)."
)
_JSON_OPT = typer.Option(False, "--json", help="Machine-readable output.")


def _load(directory: Path) -> ChangePackage:
    try:
        return pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _repo_root(directory: Path, root: Path | None) -> Path:
    if root is not None:
        return root
    resolved = directory.resolve()
    if resolved.parent.name == pkgio.CHANGES_DIR:
        return resolved.parent.parent
    return Path(".")


def _policies(
    directory: Path, project: Path | None, org: Path | None, root: Path | None
) -> tuple[projmod.ProjectConfig, orgmod.OrgPolicy]:
    base = _repo_root(directory, root)
    project_path = project if project is not None else projmod.find_project_config(base)
    org_path = org if org is not None else orgmod.find_org_policy(base)
    try:
        project_config = (
            projmod.load_project_config(project_path)
            if project_path
            else projmod.default_project_config()
        )
        policy = orgmod.load_org_policy(org_path) if org_path else orgmod.default_org_policy()
    except orgmod.PolicyLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    return project_config, policy


def _echo_json(data: object) -> None:
    typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))


# --------------------------------------------------------------------------------------
# generate / check / waves
# --------------------------------------------------------------------------------------


@app.command("generate")
def generate(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    project: Path | None = _PROJECT_OPT,
    org: Path | None = _ORG_OPT,
    root: Path | None = _ROOT_OPT,
    test_task: bool = typer.Option(True, "--test-task/--no-test-task"),
    docs_task: bool = typer.Option(True, "--docs-task/--no-docs-task"),
    group_by_tag: bool = typer.Option(False, "--group-by-tag", help="One task per tag group."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the plan without saving."),
    as_json: bool = _JSON_OPT,
) -> None:
    """Derive tasks and waves from the requirements and store them in the package."""
    package = _load(directory)
    project_config, policy = _policies(directory, project, org, root)
    config = planner.PlannerConfig(
        include_test_task=test_task, include_docs_task=docs_task, group_by_tag=group_by_tag
    )
    try:
        result = planner.generate_plan(package, project_config, config=config, policy=policy)
    except planner.PlanningError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not dry_run:
        planner.apply_plan(package, result)
        package.save(base_fingerprint=package.base_fingerprint)
    if as_json:
        _echo_json(
            {
                "change_id": package.change_id,
                "risk_class": result.profile.risk_class.value,
                "tasks": [t.model_dump(mode="json") for t in result.tasks],
                "plan": result.plan.model_dump(mode="json"),
                "notes": result.notes,
                "saved": not dry_run,
            }
        )
        return
    typer.echo(f"{package.change_id}: {result.plan.summary}")
    for wave in result.plan.waves:
        flag = " [checkpoint]" if wave.checkpoint else ""
        typer.echo(f"wave {wave.index}{flag}: {', '.join(wave.task_ids)}")
    for task in result.tasks:
        verification = task.verification.command if task.verification else "-"
        typer.echo(
            f"  {task.id} ({task.model_tier.value if task.model_tier else '-'}) {task.title}"
            f"\n      verify: {verification}"
        )
    for note in result.notes:
        typer.echo(f"note: {note}")
    typer.echo("dry run; nothing saved" if dry_run else f"saved {package.root}")


@app.command("check")
def check(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    project: Path | None = _PROJECT_OPT,
    org: Path | None = _ORG_OPT,
    root: Path | None = _ROOT_OPT,
    as_json: bool = _JSON_OPT,
) -> None:
    """Goal-backward plan validation; exit 1 on blocking issues."""
    package = _load(directory)
    project_config, policy = _policies(directory, project, org, root)
    report = plan_checker.check_plan(package, project_config=project_config, policy=policy)
    if as_json:
        _echo_json(report.model_dump(mode="json"))
    else:
        for issue in report.issues:
            typer.echo(str(issue))
        typer.echo(report.summary())
    if not report.passed:
        raise typer.Exit(code=1)


@app.command("waves")
def waves(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    as_json: bool = _JSON_OPT,
) -> None:
    """Compute dependency waves from the tasks (exit 1 on cycles)."""
    package = _load(directory)
    try:
        levels = planner.compute_waves(package.tasks)
    except planner.PlanningError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if as_json:
        _echo_json({"change_id": package.change_id, "waves": levels})
        return
    if not levels:
        typer.echo("no tasks")
        return
    by_id = {t.id: t for t in package.tasks}
    for index, members in enumerate(levels):
        typer.echo(f"wave {index}:")
        for task_id in members:
            typer.echo(f"  {task_id} {by_id[task_id].title}")


# --------------------------------------------------------------------------------------
# adr
# --------------------------------------------------------------------------------------


@adr_app.command("new")
def adr_new(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    title: str = typer.Argument(..., help="Decision title."),
    status: AdrStatus = typer.Option(AdrStatus.PROPOSED, "--status", "-s"),
    context: str = typer.Option("", "--context", help="Forces at play."),
    decision: str = typer.Option("", "--decision", help="The decision taken."),
    consequences: list[str] = typer.Option([], "--consequence", "-c"),
    alternatives: list[str] = typer.Option([], "--alternative", "-a"),
    requirements: list[str] = typer.Option([], "--requirement", "-r", help="Related REQ ids."),
    supersedes: str | None = typer.Option(None, "--supersedes"),
    deciders: list[str] = typer.Option([], "--decider", "-d"),
) -> None:
    """Create architecture/decisions/ADR-nnnn.md."""
    package = _load(directory)
    try:
        doc = adrmod.new_adr(
            title,
            existing_ids=[d.id for d in package.decisions],
            status=status,
            context=context,
            decision=decision,
            consequences=consequences,
            alternatives=alternatives,
            requirement_ids=requirements,
            supersedes=supersedes,
            deciders=deciders,
        )
    except (adrmod.AdrError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    known = {r.id for r in package.requirements}
    unknown = [r for r in doc.requirement_ids if r not in known]
    if unknown:
        typer.echo(f"error: unknown requirement(s): {', '.join(unknown)}", err=True)
        raise typer.Exit(code=1)
    path = adrmod.write_adr(directory, doc)
    typer.echo(f"created {path}")


@adr_app.command("validate")
def adr_validate(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    as_json: bool = _JSON_OPT,
) -> None:
    """Validate every ADR of the package; exit 1 on errors."""
    package = _load(directory)
    try:
        docs = adrmod.list_adrs(directory)
    except adrmod.AdrError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    issues = adrmod.validate_adrs(docs, known_requirements=[r.id for r in package.requirements])
    if as_json:
        _echo_json(
            {
                "change_id": package.change_id,
                "adrs": [d.id for d in docs],
                "issues": [i.model_dump(mode="json") for i in issues],
            }
        )
    else:
        for issue in issues:
            typer.echo(str(issue))
        typer.echo(f"{len(docs)} ADR(s), {len(issues)} issue(s)")
    if any(i.severity is IssueSeverity.ERROR for i in issues):
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------------------
# threat-model
# --------------------------------------------------------------------------------------


@tm_app.command("init")
def threat_model_init(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    project: Path | None = _PROJECT_OPT,
    root: Path | None = _ROOT_OPT,
    tools: list[str] = typer.Option([], "--tool", help="Declared tool (repeatable)."),
    data_sources: list[str] = typer.Option([], "--data-source", help="Declared data source."),
    egress: list[str] = typer.Option([], "--egress", help="Allowed egress host."),
    reset: bool = typer.Option(False, "--reset", help="Discard the existing model first."),
) -> None:
    """Seed (or extend) architecture/threat-model.md from the change and manifest."""
    package = _load(directory)
    project_config, _policy = _policies(directory, project, None, root)
    manifest = ToolDataManifest(tools=tools, data_sources=data_sources, network_egress=egress)
    existing = None if reset else package.threat_model
    model = tmmod.init_threat_model(
        package.intent,
        package.requirements,
        project_config,
        interfaces=package.interfaces,
        manifest=manifest,
        existing=existing,
    )
    package.threat_model = model
    package.save(base_fingerprint=package.base_fingerprint)
    typer.echo(
        f"{package.change_id}: {len(model.threats)} threat(s), {len(model.mitigations)} "
        f"mitigation(s), {len(model.assets)} asset(s), {len(model.actors)} actor(s)"
    )
    for threat in model.unresolved_high_risk():
        typer.echo(f"  open {threat.severity.value}: {threat.id} {threat.title}")


@tm_app.command("validate")
def threat_model_validate(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    project: Path | None = _PROJECT_OPT,
    root: Path | None = _ROOT_OPT,
    as_json: bool = _JSON_OPT,
) -> None:
    """Validate the threat model (manifest coverage, egress, approvals); exit 1 on errors."""
    package = _load(directory)
    project_config, _policy = _policies(directory, project, None, root)
    manifest = package.threat_model.tool_data_manifest if package.threat_model else None
    assessment = riskmod.classify(package.intent, package.requirements, project_config, manifest)
    report = tmmod.check_threat_model(package.threat_model, risk_class=assessment.effective)
    if as_json:
        _echo_json({"change_id": package.change_id, **report.model_dump(mode="json")})
    else:
        for issue in report.issues:
            typer.echo(str(issue))
        typer.echo(
            f"{package.change_id}: threat model {'PASS' if report.passed else 'FAIL'}; "
            f"{len(report.unresolved_high_risk)} unresolved high-risk threat(s)"
        )
    if not report.passed:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------------------
# risk
# --------------------------------------------------------------------------------------


@risk_app.command("classify")
def risk_classify(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    project: Path | None = _PROJECT_OPT,
    org: Path | None = _ORG_OPT,
    root: Path | None = _ROOT_OPT,
    paths: list[str] = typer.Option([], "--path", help="Touched path (repeatable)."),
    apply: bool = typer.Option(False, "--apply", help="Write the effective class to intent."),
    as_json: bool = _JSON_OPT,
) -> None:
    """Classify the change and show the gate depth profile."""
    package = _load(directory)
    project_config, policy = _policies(directory, project, org, root)
    manifest = package.threat_model.tool_data_manifest if package.threat_model else None
    all_paths = [*paths, *(f for t in package.tasks for f in t.files)]
    assessment = riskmod.classify(
        package.intent, package.requirements, project_config, manifest, paths=all_paths
    )
    profile = riskmod.gate_depth_profile(assessment.effective, policy)
    if apply and package.intent.risk_class is not assessment.effective:
        package.intent.risk_class = assessment.effective
        package.save(base_fingerprint=package.base_fingerprint)
    if as_json:
        _echo_json(
            {
                "change_id": package.change_id,
                "computed": assessment.computed.value,
                "declared": assessment.declared.value if assessment.declared else None,
                "effective": assessment.effective.value,
                "reasons": assessment.reasons,
                "signals": [s.model_dump(mode="json") for s in assessment.signals],
                "profile": profile.model_dump(mode="json"),
                "applied": apply,
            }
        )
        return
    typer.echo(
        f"{package.change_id}: computed {assessment.computed.value}, declared "
        f"{assessment.declared.value if assessment.declared else '-'}, "
        f"effective {assessment.effective.value}"
    )
    for reason in assessment.reasons:
        typer.echo(f"  - {reason}")
    typer.echo("gates: " + ", ".join(f"{g.value}={d.value}" for g, d in profile.depths.items()))
    typer.echo("checks: " + ", ".join(c.value for c in profile.checks))
    if apply:
        typer.echo(f"intent.risk_class = {package.intent.risk_class.value}")
