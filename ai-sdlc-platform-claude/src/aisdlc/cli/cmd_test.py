"""``aisdlc test`` — test evidence capture, coverage portfolio evaluation, mutation evidence.

Exit codes: 0 = ok, 1 = evidence incomplete / tests failed / portfolio breach, 2 = usage or
load error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, NoReturn, TypeVar

import typer
from pydantic import BaseModel, ValidationError

from aisdlc.cli import _common as common
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import EvidenceKind, RiskClass, TestEvidence

NAME = "test"

app = typer.Typer(help="Test evidence: run-evidence, portfolio, mutation.")

#: ``TestEvidence.command`` recorded by ``run-evidence --parse-only`` without ``--command``.
PARSED_FROM_ARTIFACTS = "<parsed-from-artifacts>"


_M = TypeVar("_M", bound=BaseModel)


def _fail(message: str, code: int = 2) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code)


def _dump(path: Path | None, payload: Any) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", "utf-8")


def _package_dir(package: Path | None) -> Path | None:
    if package is None:
        return None
    if not (package / "intent.md").is_file():
        _fail(f"{package} is not a change package (no intent.md)")
    return package


@app.command("run-evidence")
def run_evidence(
    change: Path | None = typer.Argument(
        None,
        help="Change package directory or CHG-<slug> id (same as --package).",
        callback=common.optional_package_arg,
    ),
    command: str | None = typer.Option(
        None,
        "--command",
        "-c",
        help="Test command to run (with --parse-only: the CI command that produced the "
        f"artifacts, recorded as-is; default {PARSED_FROM_ARTIFACTS!r}).",
    ),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package; evidence is appended to evidence/tests.json.",
        callback=common.optional_package_arg,
    ),
    parse_only: bool = typer.Option(
        False,
        "--parse-only",
        help="Do not run anything; parse CI artifacts (at least one of --junit, "
        "--coverage-xml, --coverage-json; --exit-code for complete evidence).",
    ),
    exit_code: int | None = typer.Option(None, "--exit-code", help="Exit code with --parse-only."),
    cwd: Path = typer.Option(Path("."), "--cwd", help="Working directory for the command."),
    junit: Path | None = typer.Option(None, "--junit", help="JUnit XML produced by the command."),
    coverage_xml: Path | None = typer.Option(None, "--coverage-xml", help="Cobertura XML."),
    coverage_json: Path | None = typer.Option(None, "--coverage-json", help="coverage.py JSON."),
    diff_base: str | None = typer.Option(None, "--diff-base", help="Git base for diff coverage."),
    diff_file: Path | None = typer.Option(None, "--diff-file", help="Unified diff file."),
    timeout: float | None = typer.Option(None, "--timeout", help="Seconds before fail-closed."),
    environment: str = typer.Option("local", "--environment", "-e"),
    commit_sha: str | None = typer.Option(None, "--commit-sha", help="Default: git HEAD."),
    evidence_id: str | None = typer.Option(None, "--evidence-id", help="Default: next free id."),
    report_uri: str | None = typer.Option(None, "--report-uri"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Also write the record here."),
    as_json: bool = typer.Option(False, "--json", help="Print the record as JSON."),
) -> None:
    """Run a test command (or parse CI artifacts) into a TestEvidence record.

    With ``--parse-only`` nothing is executed: ``--command`` is optional (the CI command
    string is recorded when given, ``<parsed-from-artifacts>`` otherwise) and at least one
    artifact must be supplied; without ``--parse-only`` ``--command`` is required.
    """
    from aisdlc.testing import evidence as capture_mod

    if not parse_only and not command:
        _fail("--command is required (or use --parse-only with CI artifacts)")
        return
    pkg_dir = _package_dir(package if package is not None else change)
    if parse_only:
        if junit is None and coverage_xml is None and coverage_json is None:
            _fail(
                "--parse-only needs at least one artifact: --junit, --coverage-xml or "
                "--coverage-json"
            )
            return
        command = command or PARSED_FROM_ARTIFACTS
    assert command is not None
    if evidence_id is None:
        evidence_id = (
            capture_mod.next_test_evidence_id(pkg_dir)
            if pkg_dir
            else capture_mod.DEFAULT_EVIDENCE_ID
        )
    diff_text: str | None = None
    if diff_file is not None:
        try:
            diff_text = diff_file.read_text(encoding="utf-8")
        except OSError as exc:
            _fail(f"cannot read {diff_file}: {exc}")
            return
    if parse_only:
        result = capture_mod.evidence_from_artifacts(
            command=command,
            exit_code=exit_code,
            junit_xml=junit,
            coverage_xml=coverage_xml,
            coverage_json=coverage_json,
            diff_text=diff_text,
            commit_sha=commit_sha or capture_mod.git_head(cwd),
            environment=environment,
            evidence_id=evidence_id,
            report_uri=report_uri,
        )
    else:
        try:
            result = capture_mod.capture(
                command,
                cwd=cwd,
                commit_sha=commit_sha,
                junit_xml=junit,
                coverage_xml=coverage_xml,
                coverage_json=coverage_json,
                timeout=timeout,
                diff_base=diff_base,
                diff_text=diff_text,
                environment=environment,
                evidence_id=evidence_id,
                report_uri=report_uri,
            )
        except ValueError as exc:
            _fail(str(exc))
            return
    record = result.evidence
    if pkg_dir is not None:
        capture_mod.record_test_evidence(pkg_dir, record)
    _dump(out, record.model_dump(mode="json"))
    if as_json:
        typer.echo(json.dumps(record.model_dump(mode="json"), indent=2, default=str))
    else:
        cov = record.coverage
        typer.echo(
            f"{record.id}: status={record.status.value} exit={record.exit_code} "
            f"passed={record.passed} failed={record.failed} skipped={record.skipped} "
            f"lines={cov.lines} branches={cov.branches} diff={cov.diff_lines}"
        )
        for problem in result.problems:
            typer.echo(f"  problem: {problem}", err=True)
    if not record.succeeded:
        raise typer.Exit(1)


def _load_json_file(path: Path | None, what: str) -> Any:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"{path}: cannot read {what}: {exc}")


def _validated_list(path: Path | None, what: str, model: type[_M]) -> list[_M] | None:
    """Records of *model* from a JSON list file; ``None`` without *path*.

    A malformed file exits 2 with ``error: <path>: <concise validation message>``.
    """
    if path is None:
        return None
    data = _load_json_file(path, what)
    if data is None:
        data = []
    if not isinstance(data, list):
        _fail(f"{path}: expected a JSON list of {what}")
    records: list[_M] = []
    for index, item in enumerate(data):
        try:
            records.append(model.model_validate(item))
        except ValidationError as exc:
            _fail(f"{path}: item {index}: {common.concise_validation_error(exc)}")
    return records


@app.command("portfolio")
def portfolio(
    package: Path = typer.Argument(
        ..., help="Change package directory or CHG-<slug> id.", callback=common.package_arg
    ),
    risk_class: str | None = typer.Option(
        None, "--risk-class", "-r", help="Override the intent's risk class."
    ),
    org: Path | None = typer.Option(None, "--org", help="Org policy YAML (default: discovered)."),
    layers: Path | None = typer.Option(
        None, "--layers", help="JSON list of extra LayerRun records (property, e2e, ...)."
    ),
    exceptions: Path | None = typer.Option(
        None, "--exceptions", help="JSON list of PortfolioException records."
    ),
    critical: Path | None = typer.Option(
        None, "--critical-coverage", help="JSON object: critical module -> line coverage %."
    ),
    write: bool = typer.Option(
        True,
        "--write/--no-write",
        help="Persist inputs + report to evidence/portfolio.json (read by gate G2).",
    ),
    reset_inputs: bool = typer.Option(
        False, "--reset-inputs", help="Ignore inputs persisted by an earlier run."
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Evaluate the coverage portfolio for a change package (exit 1 on a blocking breach).

    Extra layer runs, exceptions and critical-module coverage given here are merged with
    the inputs persisted in ``evidence/portfolio.json`` by earlier runs (an option given
    now replaces that part) and written back so gate G2 evaluates the same portfolio.
    """
    from aisdlc.policy import default_org_policy, find_org_policy, load_org_policy
    from aisdlc.testing import portfolio as pf

    try:
        pkg = pkgio.load(package)
    except (pkgio.PackageError, ValueError) as exc:
        _fail(f"cannot load {package}: {exc}")
        return
    try:
        policy = load_org_policy(org) if org else None
        if policy is None:
            found = find_org_policy(Path.cwd())
            policy = load_org_policy(found) if found else default_org_policy()
    except Exception as exc:  # noqa: BLE001 - surface any loader failure as exit 2
        _fail(f"cannot load org policy: {exc}")
        return
    thresholds = pf.PortfolioThresholds.from_org_policy(policy)
    try:
        rc = RiskClass(risk_class) if risk_class else pkg.intent.risk_class
    except ValueError:
        _fail(f"unknown risk class {risk_class!r}")
        return
    previous: pf.PortfolioInputs | None = None
    if not reset_inputs:
        try:
            stored = pf.read_portfolio_record(package)
        except ValueError as exc:
            _fail(str(exc))
            return
        previous = stored.inputs if stored is not None else None
    runs = _validated_list(layers, "layers", pf.LayerRun)
    extra_exceptions = _validated_list(exceptions, "exceptions", pf.PortfolioException)
    try:
        inputs = pf.PortfolioInputs(
            runs=runs if runs is not None else (previous.runs if previous else []),
            exceptions=extra_exceptions
            if extra_exceptions is not None
            else (previous.exceptions if previous else []),
            critical_module_coverage=(_load_json_file(critical, "critical coverage") or {})
            if critical is not None
            else (previous.critical_module_coverage if previous else {}),
        )
    except ValidationError as exc:
        _fail(f"{critical or 'portfolio inputs'}: {common.concise_validation_error(exc)}")
    except (ValueError, TypeError) as exc:
        _fail(f"invalid portfolio inputs: {exc}")
    evidence = pf.PortfolioEvidence.from_bundle(
        pkg.evidence,
        extra_runs=inputs.runs,
        critical_module_coverage=inputs.critical_module_coverage,
    )
    report = pf.evaluate(evidence, thresholds, rc, exceptions=inputs.exceptions)
    if write:
        record = pf.PortfolioRecord(risk_class=rc, inputs=inputs, report=report)
        written = pf.write_portfolio_record(package, record)
    if as_json:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, default=str))
    else:
        for line in report.summary_lines():
            typer.echo(line)
        if write:
            typer.echo(f"wrote {written}")
    if not report.passed:
        raise typer.Exit(1)


@app.command("perf-evidence")
def perf_evidence(
    source: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        help="k6 summary JSON, locust *_stats.csv, "
        "pytest-benchmark JSON, or a JSON object with p50_ms/p95_ms/throughput.",
    ),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package; the record becomes evidence/performance.json.",
        callback=common.optional_package_arg,
    ),
    fmt: str = typer.Option(
        "auto", "--format", "-f", help="auto | k6 | locust | pytest-benchmark | json"
    ),
    p50_max: float | None = typer.Option(None, "--p50-max-ms", min=0, help="p50 SLO (ms)."),
    p95_max: float | None = typer.Option(None, "--p95-max-ms", min=0, help="p95 SLO (ms)."),
    min_rps: float | None = typer.Option(
        None, "--min-throughput", min=0, help="Throughput SLO (requests per second)."
    ),
    commit_sha: str = typer.Option("", "--commit-sha", help="Commit measured (default HEAD)."),
    environment: str = typer.Option("ci", "--environment", "-e"),
    report_uri: str | None = typer.Option(
        None, "--report-uri", help="Where the raw report lives (default: the source path)."
    ),
    evidence_id: str = typer.Option("EVD-performance-001", "--id"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Also write the record here."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Turn load/latency tool output + SLO targets into evidence/performance.json.

    ``slo_met`` is derived from the measurements and the targets; without at least one
    target (or without a measurement) the record is incomplete and G5 fails closed.
    Exit 1 when the SLO is not met or the record is incomplete.
    """
    from aisdlc.gates.verdict import git_head
    from aisdlc.testing import performance as perf

    formats = ("auto", "k6", "locust", "pytest-benchmark", "json")
    if fmt not in formats:
        _fail(f"unknown format {fmt!r}; expected one of {', '.join(formats)}")
        return
    pkg_dir = _package_dir(package)
    try:
        measurement = perf.parse_measurement(source, fmt)  # type: ignore[arg-type]
    except (OSError, ValueError) as exc:
        _fail(f"cannot parse {source}: {exc}")
        return
    targets = perf.PerformanceTargets(
        p50_max_ms=p50_max, p95_max_ms=p95_max, throughput_min_rps=min_rps
    )
    sha = commit_sha or (git_head(pkg_dir) if pkg_dir is not None else None) or ""
    record = perf.build_performance_evidence(
        measurement,
        targets,
        evidence_id=evidence_id,
        commit_sha=sha,
        environment=environment,
        report_uri=report_uri if report_uri is not None else str(source.resolve()),
    )
    if pkg_dir is not None:
        perf.record_performance_evidence(pkg_dir, record)
    _dump(out, record.model_dump(mode="json"))
    if as_json:
        typer.echo(json.dumps(record.model_dump(mode="json"), indent=2, default=str))
    else:
        typer.echo(
            f"{record.id}: status={record.status.value} p50={record.p50_ms} "
            f"p95={record.p95_ms} throughput={record.throughput} slo_met={record.slo_met}"
        )
        for note in measurement.notes:
            typer.echo(f"  note: {note}")
        for problem in record.slo_problems():
            typer.echo(f"  problem: {problem}", err=True)
    if not (record.is_complete and record.slo_met):
        raise typer.Exit(1)


@app.command("mutation")
def mutation(
    files: list[Path] | None = typer.Argument(
        None, help="Files or directories to mutate with --builtin (directories expand to *.py)."
    ),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Attach the result to the latest evidence/tests.json record.",
        callback=common.optional_package_arg,
    ),
    report: Path | None = typer.Option(None, "--report", help="mutmut/cosmic-ray style JSON."),
    builtin: bool = typer.Option(
        False, "--builtin", help="Run the built-in Python mutation runner."
    ),
    command: str | None = typer.Option(None, "--command", "-c", help="Verification command."),
    cwd: Path = typer.Option(Path("."), "--cwd"),
    max_mutants: int = typer.Option(25, "--max-mutants", min=1),
    timeout: float = typer.Option(120.0, "--timeout", min=1),
    seed: int = typer.Option(0, "--seed"),
    scope: list[str] | None = typer.Option(None, "--scope", help="Declared scope for --report."),
    excluded: list[str] | None = typer.Option(None, "--excluded", help="Declared exclusions."),
    floor: float | None = typer.Option(
        None, "--floor", min=0, max=1, help="Previous mutation floor to ratchet from."
    ),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the report JSON here."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Produce mutation evidence from a tool report or the built-in runner."""
    from aisdlc.testing import mutation as mut

    if builtin == (report is not None):
        _fail("use exactly one of --report or --builtin")
        return
    if builtin:
        if not command:
            _fail("--builtin requires --command")
            return
        targets: list[Path] = []
        for item in files or []:
            path = item if item.is_absolute() else cwd / item
            if path.is_dir():
                targets.extend(
                    sorted(p for p in path.rglob("*.py") if "__pycache__" not in p.parts)
                )
            else:
                targets.append(path)
        if not targets:
            _fail("--builtin needs at least one file or directory to mutate")
            return
        result = mut.run_builtin_mutation(
            targets,
            command,
            cwd=cwd,
            max_mutants=max_mutants,
            timeout=timeout,
            seed=seed,
            excluded=excluded or [],
        )
    else:
        assert report is not None
        try:
            result = mut.load_mutation_report(report, scope=scope or [], excluded=excluded or [])
        except (OSError, ValueError) as exc:
            _fail(f"cannot parse {report}: {exc}")
            return
    payload = result.model_dump(mode="json")
    payload["score"] = result.score
    if floor is not None:
        payload["ratcheted_floor"] = mut.ratchet_mutation_floor(floor, result)
    _dump(out, payload)
    if package is not None:
        pkg_dir = _package_dir(package)
        assert pkg_dir is not None
        records = [
            e
            for e in pkgio.read_evidence(pkg_dir, EvidenceKind.TESTS)
            if isinstance(e, TestEvidence)
        ]
        if not records:
            _fail(f"{pkg_dir} has no test evidence to attach the mutation result to")
            return
        latest = records[-1]
        pkgio.append_evidence(pkg_dir, mut.attach_mutation(latest, result))
        payload["attached_to"] = latest.id
    if as_json:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        score = "n/a" if result.score is None else f"{result.score:.2f}"
        typer.echo(
            f"mutation[{result.tool}]: score={score} killed={result.killed} "
            f"survived={result.survived} timeout={result.timeout} "
            f"complete={result.complete} scope={result.scope}"
        )
        for note in result.notes:
            typer.echo(f"  note: {note}")
        if floor is not None:
            typer.echo(f"  ratcheted floor: {payload['ratcheted_floor']}")
    if not result.complete:
        raise typer.Exit(1)
