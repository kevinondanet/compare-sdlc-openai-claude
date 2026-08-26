"""``aisdlc intake`` — discovery, kernel, clarification, checklist, analysis, readiness."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from aisdlc.cli import _common as common
from aisdlc.intake import analyze as analyze_mod
from aisdlc.intake import checklist as checklist_mod
from aisdlc.intake import clarify as clarify_mod
from aisdlc.intake import discovery as discovery_mod
from aisdlc.intake import kernel as kernel_mod
from aisdlc.policy import PolicyLoadError, find_org_policy, load_org_policy
from aisdlc.schema import fingerprint as fp
from aisdlc.schema import package as pkgio
from aisdlc.schema.grammar import IssueSeverity
from aisdlc.schema.models import ChangePackage, Severity

NAME = "intake"
app = typer.Typer(
    help="Intake and specification quality: discover, kernel, clarify, checklist, analyze, "
    "readiness.",
    no_args_is_help=True,
)


def _load(directory: Path) -> ChangePackage:
    try:
        return pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _save(pkg: ChangePackage, base: ChangePackage) -> None:
    """Save *pkg* guarded by its base fingerprint.

    When the package changed on disk since *base* was loaded, the on-disk version is
    reloaded and our edits are re-applied through a three-way merge
    (:func:`aisdlc.schema.fingerprint.merge_packages`); conflicting edits abort with
    exit code 2 and nothing is written.
    """
    try:
        pkg.save(base_fingerprint=pkg.base_fingerprint)
        return
    except fp.OptimisticConcurrencyError:
        pass
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    assert pkg.root is not None
    theirs = _load(pkg.root)
    result = fp.merge_packages(base, pkg, theirs)
    if not result.clean:
        typer.echo(
            f"error: {pkg.root} changed while editing and the edits conflict; "
            "nothing written. Reload and reapply:",
            err=True,
        )
        for conflict in result.requirements.conflicts:
            typer.echo(
                f"  - {conflict.requirement_id}.{conflict.field}: {conflict.message}", err=True
            )
        for name in result.field_conflicts:
            typer.echo(f"  - {name}: edited differently on both sides", err=True)
        raise typer.Exit(code=2)
    try:
        result.package.save(base_fingerprint=theirs.base_fingerprint)
    except (fp.OptimisticConcurrencyError, pkgio.PackageError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    pkgio.adopt(pkg, result.package)
    typer.echo(f"note: merged concurrent edits to {pkg.root}", err=True)


def _threshold(directory: Path, override: float | None) -> float:
    """Ambiguity threshold: explicit override, else the nearest org policy, else default."""
    if override is not None:
        return override
    directory = common.resolve_package_dir(directory)
    for base in (directory, directory.parent, directory.parent.parent):
        found = find_org_policy(base)
        if found is not None:
            try:
                return load_org_policy(found).security_baselines.ambiguity_threshold
            except PolicyLoadError as exc:
                typer.echo(f"warning: ignoring {found}: {exc}", err=True)
                break
    return kernel_mod.default_ambiguity_threshold()


def _dump(data: object) -> None:
    typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))


# --------------------------------------------------------------------------------------
# discover
# --------------------------------------------------------------------------------------


@app.command("discover")
def discover(
    answers: Path | None = typer.Option(
        None, "--answers", "-a", help="JSON/YAML file of answers (non-interactive)."
    ),
    root: Path = typer.Option(Path("."), "--root", help="Repository root (holds changes/)."),
    markdown: Path | None = typer.Option(
        None, "--markdown", "-m", help="Also write the BRD/PRD summary to this file."
    ),
    print_summary: bool = typer.Option(False, "--summary", help="Print the BRD/PRD summary."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Do not create the change package."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Coached plain-language discovery -> intent, kernel and draft requirements."""
    try:
        if answers is not None:
            session = discovery_mod.DiscoverySession(discovery_mod.load_answers(answers))
            result = session.build()
        else:
            session = discovery_mod.DiscoverySession()

            def ask(question: discovery_mod.DiscoveryQuestion) -> str:
                hint = "" if question.required else " (optional, Enter to skip)"
                if question.help:
                    typer.echo(f"  {question.help}")
                if question.example:
                    typer.echo(f"  e.g. {question.example}")
                if question.multi:
                    typer.echo("  Separate several items with ';'.")
                return str(typer.prompt(f"{question.prompt}{hint}", default="", show_default=False))

            result = session.run(ask)
    except (discovery_mod.DiscoveryError, OSError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    created: Path | None = None
    if not dry_run:
        try:
            created = result.to_package(root).root
        except pkgio.PackageError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    if markdown is not None:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(result.to_markdown(), encoding="utf-8")
    if as_json:
        _dump(
            {
                "change_id": result.change_id,
                "package": str(created) if created else None,
                "risk_class": result.intent.risk_class.value,
                "requirements": [r.model_dump(mode="json") for r in result.requirements],
                "personas": [p.model_dump() for p in result.personas],
                "assumptions": [a.model_dump(mode="json") for a in result.assumptions],
                "open_questions": [q.model_dump(mode="json") for q in result.open_questions],
                "interfaces": [i.model_dump(mode="json") for i in result.interfaces],
            }
        )
        return
    if print_summary or dry_run:
        typer.echo(result.to_markdown())
    if created is not None:
        typer.echo(f"created {created}")
    typer.echo(
        f"{result.change_id}: {len(result.requirements)} draft requirement(s), "
        f"{len(result.personas)} persona(s), {len(result.assumptions)} assumption(s), "
        f"{len(result.open_questions)} open question(s), risk class "
        f"{result.intent.risk_class.value}"
    )


# --------------------------------------------------------------------------------------
# kernel
# --------------------------------------------------------------------------------------


@app.command("kernel")
def kernel_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    why: str | None = typer.Option(None, "--why", help="Set kernel.why."),
    capability: list[str] = typer.Option([], "--capability", "-c", help="Add a capability."),
    constraint: list[str] = typer.Option([], "--constraint", "-k", help="Add a constraint."),
    non_goal: list[str] = typer.Option([], "--non-goal", "-n", help="Add a non-goal."),
    success: str | None = typer.Option(None, "--success", "-s", help="Set success_signal."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Show (and optionally fill) the BMAD kernel; exit 1 while it is incomplete."""
    pkg = _load(directory)
    base = pkg.model_copy(deep=True)
    current = pkg.intent.kernel
    if why is not None or capability or constraint or non_goal or success is not None:
        pkg.intent.kernel = kernel_mod.build_kernel(
            why=why if why is not None else current.why,
            capabilities=[*current.capabilities, *capability],
            constraints=[*current.constraints, *constraint],
            non_goals=[*current.non_goals, *non_goal],
            success_signal=success if success is not None else current.success_signal,
        )
        _save(pkg, base)
    issues = kernel_mod.validate_kernel(pkg.intent.kernel, pkg.intent.id)
    if as_json:
        _dump(
            {
                "change_id": pkg.change_id,
                "kernel": pkg.intent.kernel.model_dump(),
                "missing": [p.value for p in kernel_mod.missing_parts(pkg.intent.kernel)],
                "issues": [i.model_dump(mode="json") for i in issues],
            }
        )
    else:
        kernel = pkg.intent.kernel
        typer.echo(f"why:            {kernel.why or '(empty)'}")
        typer.echo(f"capabilities:   {'; '.join(kernel.capabilities) or '(empty)'}")
        typer.echo(f"constraints:    {'; '.join(kernel.constraints) or '(empty)'}")
        typer.echo(f"non_goals:      {'; '.join(kernel.non_goals) or '(empty)'}")
        typer.echo(f"success_signal: {kernel.success_signal or '(empty)'}")
        for issue in issues:
            typer.echo(str(issue))
    if any(i.severity is IssueSeverity.ERROR for i in issues):
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------------------
# clarify
# --------------------------------------------------------------------------------------


def _parse_answers(pairs: list[str], file: Path | None) -> dict[str, str]:
    answers: dict[str, str] = {}
    if file is not None:
        answers.update(discovery_mod.load_answers(file))
    for pair in pairs:
        if "=" not in pair:
            raise typer.BadParameter(f"expected CQ-nnn=answer, got {pair!r}")
        key, value = pair.split("=", 1)
        answers[key.strip()] = value
    return answers


@app.command("clarify")
def clarify_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    limit: int = typer.Option(clarify_mod.DEFAULT_LIMIT, "--limit", "-n", help="Max questions."),
    answer: list[str] = typer.Option([], "--answer", help="Apply CQ-nnn=<answer> (repeatable)."),
    answers_file: Path | None = typer.Option(
        None, "--answers", "-a", help="JSON/YAML mapping of CQ ids to answers."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Apply answers without saving."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Rank clarification questions; optionally apply answers and save."""
    pkg = _load(directory)
    base = pkg.model_copy(deep=True)
    applied: list[clarify_mod.AnswerResult] = []
    try:
        answers = _parse_answers(answer, answers_file)
    except (discovery_mod.DiscoveryError, OSError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if answers:
        try:
            applied = clarify_mod.apply_answers(pkg, answers, limit=limit)
        except clarify_mod.AnswerError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        if not dry_run:
            _save(pkg, base)
    remaining = clarify_mod.generate_questions(pkg, limit=limit)
    if as_json:
        _dump(
            {
                "change_id": remaining.change_id,
                "ambiguity_score": remaining.ambiguity_score,
                "applied": [a.model_dump(mode="json") for a in applied],
                "candidates": remaining.candidates,
                "questions": [q.model_dump(mode="json") for q in remaining.questions],
            }
        )
        return
    for result in applied:
        typer.echo(
            f"applied {result.question_id} ({result.category.value}): " + "; ".join(result.changes)
        )
    for q in remaining.questions:
        refs = f" [{', '.join(q.artifact_ids)}]" if q.artifact_ids else ""
        typer.echo(f"{q.id} ({q.impact:.2f}, {q.category.value}){refs}: {q.question}")
        for option in q.options:
            typer.echo(f"    - {option}")
    typer.echo(
        f"{remaining.change_id}: {len(remaining.questions)} of {remaining.candidates} "
        f"question(s) shown, ambiguity score {remaining.ambiguity_score:.2f}"
    )


# --------------------------------------------------------------------------------------
# checklist
# --------------------------------------------------------------------------------------


@app.command("checklist")
def checklist_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    threshold: float | None = typer.Option(None, "--threshold", help="Ambiguity threshold."),
    strict: bool = typer.Option(False, "--strict", help="Fail on warning items too."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Run the requirements-quality checklist; exit 1 when an error item fails."""
    pkg = _load(directory)
    report = checklist_mod.run_checklist(pkg, ambiguity_threshold=_threshold(directory, threshold))
    if as_json:
        _dump(
            {
                "change_id": report.change_id,
                "passed": report.passed,
                "score": report.score,
                "ambiguity_score": report.ambiguity_score,
                "items": [i.model_dump(mode="json") for i in report.items],
            }
        )
    else:
        for item in report.items:
            typer.echo(str(item))
            if not item.passed:
                for detail in item.details:
                    typer.echo(f"    - {detail}")
                typer.echo(f"    fix: {item.remediation}")
        typer.echo(report.summary())
    failing = report.failures(errors_only=not strict)
    if failing:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------------------
# analyze
# --------------------------------------------------------------------------------------


@app.command("analyze")
def analyze_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    fail_on: Severity = typer.Option(Severity.HIGH, "--fail-on", help="Exit 1 at this severity."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Cross-artifact consistency analysis (requirements, tasks, plan, ADRs, threats)."""
    pkg = _load(directory)
    report = analyze_mod.analyze(pkg)
    if as_json:
        _dump(
            {
                "change_id": report.change_id,
                "passed": report.passed,
                "counts": report.counts(),
                "findings": [f.model_dump(mode="json") for f in report.findings],
            }
        )
    else:
        for finding in report.findings:
            typer.echo(str(finding))
            if finding.remediation:
                typer.echo(f"    fix: {finding.remediation}")
        counts = ", ".join(f"{k}={v}" for k, v in report.counts().items() if v)
        typer.echo(f"{report.change_id}: {len(report.findings)} finding(s) {counts or ''}".rstrip())
    if report.at_least(fail_on):
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------------------
# readiness
# --------------------------------------------------------------------------------------


@app.command("readiness")
def readiness_cmd(
    directory: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    threshold: float | None = typer.Option(None, "--threshold", help="Ambiguity threshold."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Evaluate G0 intent-readiness criteria; exit 1 when not ready."""
    pkg = _load(directory)
    report = kernel_mod.readiness(pkg, ambiguity_threshold=_threshold(directory, threshold))
    if as_json:
        _dump(report.model_dump(mode="json"))
    else:
        for criterion in report.criteria:
            mark = "PASS" if criterion.satisfied else ("FAIL" if criterion.blocking else "WARN")
            typer.echo(f"[{mark}] {criterion.id}: {criterion.description}")
            if not criterion.satisfied:
                for detail in criterion.details:
                    typer.echo(f"    - {detail}")
                typer.echo(f"    fix: {criterion.remediation}")
        for issue in report.issues:
            typer.echo(str(issue))
        typer.echo(report.summary())
    if not report.ready:
        raise typer.Exit(code=1)
