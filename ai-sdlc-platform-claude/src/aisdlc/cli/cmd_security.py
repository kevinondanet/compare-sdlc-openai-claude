"""``aisdlc security`` — PyRIT campaigns, safety regression suites and judge calibration.

Exit codes: 0 = passed, 1 = threshold breached / incomplete / failed, 2 = configuration error.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import typer

from aisdlc.cli import _common as common

NAME = "security"
LEDGER_ENV = "AISDLC_LEDGER"
DEFAULT_LEDGER = Path(".aisdlc") / "ledger.sqlite"

app = typer.Typer(help="AI/agent security testing: PyRIT campaigns, safety regression, judges.")
campaign_app = typer.Typer(help="Run and compare PyRIT red-team campaigns.")
safety_app = typer.Typer(help="Run RAMPART-style safety regression suites.")
judges_app = typer.Typer(help="Calibrate scorers (judges) against human labels.")
app.add_typer(campaign_app, name="campaign")
app.add_typer(safety_app, name="safety")
app.add_typer(judges_app, name="judges")


def _fail(message: str, code: int = 2) -> None:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code)


def _record_security(
    package: Path,
    environment: str,
    *,
    pyrit: dict[str, Any] | None = None,
    safety: dict[str, Any] | None = None,
    produced_by: str,
    report_uri: str | None,
) -> None:
    """Merge a plane-3 summary into the package's canonical ``evidence/security.json``."""
    from aisdlc.gates.verdict import git_head
    from aisdlc.security.supply_chain import update_security_evidence

    if not (package / "intent.md").is_file():
        _fail(f"{package} is not a change package (no intent.md)")
        return
    record = update_security_evidence(
        package,
        pyrit=pyrit,
        safety=safety,
        commit_sha=git_head(package) or "",
        environment=environment,
        produced_by=produced_by,
        report_uri=report_uri,
    )
    typer.echo(
        f"recorded {record.id} ({record.status.value}) in {package / 'evidence/security.json'}"
    )


def _write_json(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _ledger_path(package: Path | None, value: Path | None) -> str:
    """Ledger to meter campaign usage in: ``--ledger`` > ``$AISDLC_LEDGER`` > the project's
    ``.aisdlc/ledger.sqlite`` (next to the change package's repository, else the cwd)."""
    if value is not None:
        value.parent.mkdir(parents=True, exist_ok=True)
        return str(value)
    env = os.environ.get(LEDGER_ENV)
    if env:
        return env
    root = common.repo_root_for(package) if package is not None else Path.cwd()
    path = root / DEFAULT_LEDGER
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


@campaign_app.command("run")
def campaign_run(
    spec_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Campaign YAML."),
    target: str = typer.Option(
        ..., "--target", "-t", help="'module:callable' (app under test) or an http(s):// URL."
    ),
    trials: int | None = typer.Option(None, "--trials", min=1, help="Override trials."),
    memory: str = typer.Option("in_memory", "--memory", help="PyRIT memory: in_memory|sqlite."),
    baseline_dir: Path | None = typer.Option(None, "--baseline-dir", help="Baseline store dir."),
    baseline_id: str | None = typer.Option(None, "--baseline-id", help="Override baseline id."),
    save_baseline: str | None = typer.Option(
        None, "--save-baseline", help="Store this run as a baseline with the given id."
    ),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write full result JSON here."),
    evidence: Path | None = typer.Option(
        None, "--evidence", help="Write SecurityEvidence.pyrit-shaped JSON here."
    ),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package (dir or CHG-<slug> id); merge into evidence/security.json.",
        callback=common.optional_package_arg,
    ),
    environment: str = typer.Option("local", "--environment", "-e", help="Evidence environment."),
    ledger: Path | None = typer.Option(
        None,
        "--ledger",
        help="Usage ledger (SQLite) to meter the campaign's tokens/cost in "
        f"(default: ${LEDGER_ENV} or <repo>/{DEFAULT_LEDGER}).",
    ),
    no_ledger: bool = typer.Option(False, "--no-ledger", help="Do not record usage."),
    change_id: str | None = typer.Option(
        None, "--change-id", help="Change id for the usage events (default: from --package)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the full result as JSON."),
) -> None:
    """Run a campaign against an application target and report ASR / completeness.

    Model usage (prompts, tokens, priced cost) is recorded to the project usage ledger as
    ``source="pyrit"`` events attributed to the ``security_tester`` role.
    """
    try:
        from aisdlc.security.pyrit_campaign import BaselineStore, CampaignError, load_campaign
        from aisdlc.security.targets import ToolEventRecorder, resolve_target
    except ImportError as exc:
        _fail(f"PyRIT is required: {exc}")
        return
    try:
        spec = load_campaign(spec_path)
    except (CampaignError, ValueError) as exc:
        _fail(f"invalid campaign {spec_path}: {exc}")
        return
    try:
        prompt_target = resolve_target(target, recorder=ToolEventRecorder())
    except (ImportError, ValueError) as exc:
        _fail(f"cannot resolve target {target!r}: {exc}")
        return
    store = BaselineStore(baseline_dir) if baseline_dir else None
    from aisdlc.control_plane.ledger import UsageLedger
    from aisdlc.control_plane.registry import ModelRegistry, RegistryLoadError
    from aisdlc.security.pyrit_campaign import ledger_usage_sink, run_campaign

    ledger_path = None if no_ledger else _ledger_path(package, ledger)
    usage_ledger = UsageLedger(ledger_path) if ledger_path else None
    resolved_change = change_id or (package.name if package is not None else "")
    try:
        registry: ModelRegistry | None = ModelRegistry.default()
    except RegistryLoadError:
        registry = None
    try:
        result = run_campaign(
            spec,
            prompt_target,
            memory=memory,
            baseline_store=store,
            baseline_id=baseline_id,
            trials=trials,
            usage_sink=(
                ledger_usage_sink(
                    usage_ledger,
                    change_id=resolved_change,
                    environment=environment,
                    registry=registry,
                )
                if usage_ledger is not None
                else None
            ),
        )
    except CampaignError as exc:
        _fail(str(exc))
        return
    finally:
        if usage_ledger is not None:
            usage_ledger.close()
    if out is not None:
        result.save(out)
    _write_json(evidence, result.to_evidence())
    if package is not None:
        _record_security(
            package,
            environment,
            pyrit=result.to_evidence(),
            produced_by=f"aisdlc.security.pyrit_campaign ({result.run_id})",
            report_uri=str(out) if out is not None else None,
        )
    if save_baseline:
        if store is None:
            _fail("--save-baseline requires --baseline-dir")
            return
        path = store.save(result, save_baseline)
        typer.echo(f"baseline saved: {path}")
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
    else:
        typer.echo(
            f"campaign {result.campaign_id} run {result.run_id}: asr={result.asr:.3f} "
            f"undetermined={result.undetermined_rate:.3f} complete={result.complete} "
            f"trials={result.completed_trials}/{result.scheduled_trials}"
        )
        for cat, asr in result.asr_by_category.items():
            typer.echo(f"  {cat}: asr={asr:.3f}")
        for o in result.per_objective:
            typer.echo(
                f"  {o.objective_id} [{o.attack}] {o.successes}/{o.trials} succeeded"
                f"{'' if o.complete else ' (INCOMPLETE)'}"
            )
        for note in result.notes:
            typer.echo(f"  note: {note}")
        for breach in result.breaches:
            typer.echo(f"  BREACH: {breach}")
        if ledger_path:
            cost = "n/a" if result.usage.cost_usd is None else f"${result.usage.cost_usd:.6f}"
            typer.echo(
                f"  usage: {result.labels.get('aisdlc_ledger_events', '0')} event(s), "
                f"{result.usage.input_tokens}+{result.usage.output_tokens} tokens, cost {cost} "
                f"-> {ledger_path}"
            )
    raise typer.Exit(1 if result.threshold_breached else 0)


@campaign_app.command("compare")
def campaign_compare(
    result_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Result JSON."),
    baseline_id: str = typer.Option(..., "--baseline-id", help="Baseline id to compare with."),
    baseline_dir: Path = typer.Option(..., "--baseline-dir", help="Baseline store dir."),
    tolerance: float = typer.Option(0.0, "--tolerance", min=0.0, max=1.0),
    as_json: bool = typer.Option(False, "--json", help="Print the delta as JSON."),
) -> None:
    """Compare a saved campaign result with a stored baseline; exit 1 on regression."""
    from aisdlc.security.pyrit_campaign import BaselineNotFoundError, BaselineStore, CampaignResult

    try:
        result = CampaignResult.load(result_path)
    except ValueError as exc:
        _fail(f"invalid result {result_path}: {exc}")
        return
    try:
        delta = BaselineStore(baseline_dir).compare(result, baseline_id, tolerance=tolerance)
    except BaselineNotFoundError:
        _fail(f"baseline {baseline_id!r} not found in {baseline_dir}")
        return
    if as_json:
        typer.echo(delta.model_dump_json(indent=2))
    else:
        typer.echo(
            f"asr delta {delta.asr_delta:+.3f} vs baseline {delta.baseline_id} "
            f"({delta.baseline_run_id}); regressed={delta.regressed}"
        )
        for d in delta.per_objective:
            flag = " REGRESSION" if d.regression else (" new" if d.new else "")
            base = "n/a" if d.baseline_asr is None else f"{d.baseline_asr:.3f}"
            typer.echo(f"  {d.objective_id} [{d.attack}] {base} -> {d.current_asr:.3f}{flag}")
        for r in delta.removed_objectives:
            typer.echo(f"  removed: {r}")
    raise typer.Exit(1 if delta.regressed else 0)


@safety_app.command("run")
def safety_run(
    module: str = typer.Argument(
        ..., help="Module path holding @safety_case tests ('pkg.mod' or 'pkg.mod:attr')."
    ),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the report JSON here."),
    evidence: Path | None = typer.Option(
        None, "--evidence", help="Write SecurityEvidence.safety_regression-shaped JSON here."
    ),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package (dir or CHG-<slug> id); merge into evidence/security.json.",
        callback=common.optional_package_arg,
    ),
    environment: str = typer.Option("local", "--environment", "-e", help="Evidence environment."),
) -> None:
    """Run every safety case in a module (plugin-free) and fail closed on incompleteness."""
    from aisdlc.security.safety_regression import collect_cases, run_safety_suite, write_report

    module_name, _, attr = module.partition(":")
    sys.path.insert(0, str(Path.cwd()))
    try:
        mod = importlib.import_module(module_name)
    except ImportError as exc:
        _fail(f"cannot import {module_name!r}: {exc}")
        return
    source: Any = getattr(mod, attr) if attr else mod
    cases = collect_cases(source)
    if not cases:
        _fail(f"no @safety_case functions found in {module!r}")
        return
    report = run_safety_suite(cases)
    if out is not None:
        write_report(report, out)
    _write_json(evidence, report.to_evidence())
    if package is not None:
        _record_security(
            package,
            environment,
            safety=report.to_evidence(),
            produced_by="aisdlc.security.safety_regression",
            report_uri=str(out) if out is not None else None,
        )
    typer.echo(
        f"safety: {len(report.per_case)} cases, trials {report.completed_trials}/"
        f"{report.total_trials}, asr={report.asr:.3f}, complete={report.complete}"
    )
    for cat, asr in report.asr_by_category.items():
        typer.echo(f"  {cat}: asr={asr:.3f}")
    for breach in report.threshold_breaches:
        typer.echo(f"  BREACH: {breach}")
    raise typer.Exit(0 if report.passed else 1)


@judges_app.command("calibrate")
def judges_calibrate(
    scorer: str = typer.Option(
        ..., "--scorer", "-s", help="'substring:<s>', 'regex:<pattern>' or 'module:attr'."
    ),
    labelled: Path = typer.Option(
        ..., "--labelled", "-l", exists=True, dir_okay=False, help="JSONL labelled set."
    ),
    min_agreement: float = typer.Option(0.8, "--min-agreement", min=0.0, max=1.0),
    max_undetermined: float = typer.Option(0.1, "--max-undetermined", min=0.0, max=1.0),
    max_fpr: float | None = typer.Option(None, "--max-fpr", min=0.0, max=1.0),
    max_fnr: float | None = typer.Option(None, "--max-fnr", min=0.0, max=1.0),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the report JSON here."),
) -> None:
    """Measure a judge's agreement with human labels and apply G4 thresholds."""
    from aisdlc.security.judges import (
        JudgeThresholds,
        calibrate_scorer,
        check_calibration,
        load_labelled,
        resolve_judge,
    )

    try:
        rows = load_labelled(labelled)
        judge = resolve_judge(scorer)
    except (ValueError, ImportError) as exc:
        _fail(str(exc))
        return
    report = calibrate_scorer(judge, rows)
    verdict = check_calibration(
        report,
        JudgeThresholds(
            min_agreement=min_agreement,
            max_undetermined_rate=max_undetermined,
            max_fpr=max_fpr,
            max_fnr=max_fnr,
        ),
    )
    payload = report.to_dict()
    payload["verdict"] = verdict.model_dump()
    _write_json(out, payload)
    typer.echo(
        f"judge {report.scorer}: n={report.n} agreement={report.agreement:.3f} "
        f"precision={report.precision:.3f} recall={report.recall:.3f} fpr={report.fpr:.3f} "
        f"fnr={report.fnr:.3f} undetermined={report.undetermined_rate:.3f}"
    )
    for reason in verdict.reasons:
        typer.echo(f"  FAIL: {reason}")
    raise typer.Exit(0 if verdict.passed else 1)
