"""``aisdlc cost`` — control-plane CLI: ledger, budgets, KPIs, registry, routing, imports.

``aisdlc cost import {claude-code|agt-audit|pyrit}`` feeds external telemetry (Claude Code
session transcripts, AGT audit logs, PyRIT memory) into the ledger through
:mod:`aisdlc.control_plane.telemetry` so usage that did not flow through the executor's
recorder is still metered.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from aisdlc.cli import _common as common
from aisdlc.control_plane.benchmark import BenchmarkService
from aisdlc.control_plane.budget import (
    Budget,
    BudgetException,
    BudgetPolicyEngine,
    ExceptionRegister,
    Quotas,
)
from aisdlc.control_plane.kpis import Outcomes, compute_kpis
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.control_plane.pricing import cost_usd
from aisdlc.control_plane.registry import ModelRegistry, RegistryLoadError
from aisdlc.control_plane.routing import (
    Complexity,
    RoutingError,
    RoutingPolicy,
    RoutingTier,
    TaskProfile,
)
from aisdlc.control_plane.telemetry import (
    TelemetryDefaults,
    from_agt_audit,
    from_claude_code_jsonl,
    from_pyrit_memory,
    from_pyrit_pieces,
)
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import EvidenceKind

NAME = "cost"
app = typer.Typer(help="Control plane: usage ledger, budgets, KPIs, model registry, routing.")
registry_app = typer.Typer(help="Model registry commands.")
app.add_typer(registry_app, name="registry")
import_app = typer.Typer(help="Import external usage telemetry into the ledger.")
app.add_typer(import_app, name="import")

console = Console()

LEDGER_ENV = "AISDLC_LEDGER"
DEFAULT_LEDGER = Path(".aisdlc") / "ledger.sqlite"


def _ledger_path(value: Path | None) -> str:
    """Resolve the ledger path (``--ledger`` > ``$AISDLC_LEDGER`` > default), creating its
    parent directory; an uncreatable location is a ``BadParameter``."""
    path = value if value is not None else Path(os.environ.get(LEDGER_ENV) or DEFAULT_LEDGER)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise typer.BadParameter(f"cannot create ledger directory {path.parent}: {exc}") from exc
    return str(path)


def _open_ledger(value: Path | None) -> UsageLedger:
    """Open the usage ledger; sqlite failures surface as ``BadParameter`` (exit 2)."""
    path = _ledger_path(value)
    try:
        return UsageLedger(path)
    except sqlite3.OperationalError as exc:
        raise typer.BadParameter(f"cannot open ledger {path}: {exc}") from exc


def _load_registry(path: Path | None) -> ModelRegistry:
    """Load ``--registry`` (or the bundled default); load failures exit 2 with the path."""
    try:
        return ModelRegistry.load(path) if path else ModelRegistry.default()
    except (RegistryLoadError, ValidationError, yaml.YAMLError, OSError) as exc:
        message = (
            common.concise_validation_error(exc)
            if isinstance(exc, ValidationError)
            else _one_line(exc)
        )
        _user_file_error(path if path is not None else Path("<default registry>"), message)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise typer.BadParameter(f"invalid timestamp {value!r}") from exc


def _emit(data: Any, as_json: bool, render: Any = None) -> None:
    if as_json or render is None:
        typer.echo(json.dumps(data, indent=2, default=str))
    else:
        render()


def _user_file_error(path: Path, message: str) -> NoReturn:
    """Report a problem with a user-supplied file as ``error: <path>: <message>``; exit 2."""
    typer.echo(f"error: {path}: {message}", err=True)
    raise typer.Exit(code=common.EXIT_LOAD_ERROR)


def _load_yaml_or_json(path: Path) -> Any:
    """Read a YAML/JSON file; a missing or unparsable file exits 2 with ``error: <path>``."""
    if not path.is_file():
        _user_file_error(path, "file not found")
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            return json.loads(text)
        return yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        _user_file_error(path, f"cannot read: {_one_line(exc)}")


def _one_line(exc: BaseException) -> str:
    return " ".join(str(exc).split())


def _load_budget_config(path: Path) -> tuple[list[Budget], Quotas, ExceptionRegister]:
    """Budgets, quotas and exceptions from a ``--budgets`` YAML/JSON file (exit 2 on error)."""
    loaded = _load_yaml_or_json(path) or {}
    if not isinstance(loaded, dict):
        _user_file_error(path, "budgets file must be a mapping")
    try:
        budgets = [Budget.model_validate(b) for b in loaded.get("budgets") or []]
        quotas = Quotas.model_validate(loaded.get("quotas") or {})
        exceptions = ExceptionRegister(
            BudgetException.model_validate(e) for e in loaded.get("exceptions") or []
        )
    except ValidationError as exc:
        _user_file_error(path, common.concise_validation_error(exc))
    except (TypeError, ValueError, AttributeError) as exc:
        _user_file_error(path, f"invalid budgets document: {_one_line(exc)}")
    return budgets, quotas, exceptions


def _load_json_list(path: Path, what: str) -> list[Any]:
    """A JSON file holding a list of *what* (exit 2 with ``error: <path>`` otherwise)."""
    data = _load_yaml_or_json(path)
    if isinstance(data, dict) and isinstance(data.get(what), list):
        data = data[what]
    if not isinstance(data, list):
        _user_file_error(path, f"expected a JSON list of {what}")
    return data


# ---------------------------------------------------------------------- record
@app.command("record")
def record(
    model: str = typer.Option(..., help="Model id (registry id or free text)."),
    input_tokens: int = typer.Option(0, min=0),
    output_tokens: int = typer.Option(0, min=0),
    cached_tokens: int = typer.Option(0, min=0),
    reasoning_tokens: int = typer.Option(0, min=0),
    cache_write_tokens: int = typer.Option(0, min=0),
    tool_calls: int = typer.Option(0, min=0),
    latency_ms: float = typer.Option(0.0, min=0),
    cost: float | None = typer.Option(
        None, help="Override cost; computed from registry otherwise."
    ),
    change_id: str = typer.Option("", "--change"),
    task_id: str = typer.Option("", "--task"),
    role: str = typer.Option("", "--role"),
    team: str = typer.Option(""),
    application: str = typer.Option("", "--app"),
    user: str = typer.Option(""),
    repository: str = typer.Option("", "--repo"),
    harness: str = typer.Option(""),
    provider: str = typer.Option(""),
    prompt_version: str = typer.Option(""),
    environment: str = typer.Option("", "--env"),
    tier: str = typer.Option("", "--tier", help="Routing tier used."),
    escalated: bool = typer.Option(False, "--escalated"),
    source: str = typer.Option("cli"),
    ledger: Path | None = typer.Option(None, "--ledger", help=f"SQLite path (${LEDGER_ENV})."),
    registry: Path | None = typer.Option(None, "--registry"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Record one usage event in the ledger."""
    reg = _load_registry(registry)
    if cost is None:
        cost = (
            cost_usd(
                reg.get(model),
                input_tokens,
                output_tokens,
                cached_tokens,
                reasoning_tokens,
                cache_write_tokens=cache_write_tokens,
            )
            if model in reg
            else 0.0
        )
    if not provider and model in reg:
        provider = reg.get(model).provider
    event = UsageEvent(
        model=model,
        provider=provider,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
        reasoning_tokens=reasoning_tokens,
        cache_write_tokens=cache_write_tokens,
        tool_calls=tool_calls,
        latency_ms=latency_ms,
        cost_usd=cost,
        change_id=change_id,
        task_id=task_id,
        agent_role=role,
        team=team,
        application=application,
        user=user,
        repository=repository,
        harness=harness,
        prompt_version=prompt_version,
        environment=environment,
        routing_tier=tier,
        escalated=escalated,
        cache_hit=cached_tokens > 0,
        source=source,
    )
    with _open_ledger(ledger) as led:
        led.record(event)
    _emit(
        event.model_dump(mode="json"),
        as_json,
        lambda: console.print(f"recorded {event.event_id} model={model} cost=${cost:.6f}"),
    )


# ---------------------------------------------------------------------- report
@app.command("report")
def report(
    group_by: list[str] = typer.Option(["model"], "--group-by", "-g"),
    change_id: str | None = typer.Option(None, "--change"),
    team: str | None = typer.Option(None),
    application: str | None = typer.Option(None, "--app"),
    since: str | None = typer.Option(None, help="ISO timestamp."),
    until: str | None = typer.Option(None, help="ISO timestamp."),
    export_change: bool = typer.Option(
        False, "--export", help="Emit the CostEvidence extract for --change (JSON)."
    ),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package (dir or CHG-<slug> id): write the canonical evidence/cost.json "
        "for --change (defaults --change to the package id).",
        callback=common.optional_package_arg,
    ),
    budget: float | None = typer.Option(None, "--budget", help="Budget (USD) recorded."),
    environment: str = typer.Option("local", "--environment", "-e", help="Evidence environment."),
    commit_sha: str | None = typer.Option(None, "--commit-sha", help="Default: git HEAD."),
    ledger: Path | None = typer.Option(None, "--ledger"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Summarise ledger usage grouped by the given fields."""
    if package is not None and not change_id:
        change_id = package.resolve().name
    filters = {
        k: v
        for k, v in {"change_id": change_id, "team": team, "application": application}.items()
        if v
    }
    with _open_ledger(ledger) as led:
        if package is not None:
            from aisdlc.gates.verdict import git_head

            if not (package / pkgio.INTENT_FILE).is_file():
                raise typer.BadParameter(f"{package} is not a change package (no intent.md)")
            assert change_id is not None
            record = led.cost_evidence(
                change_id,
                budget_usd=budget,
                commit_sha=commit_sha or git_head(package) or "",
                environment=environment,
            )
            path = pkgio.write_evidence(package, EvidenceKind.COST, record)
            typer.echo(
                f"recorded {record.id} ({record.status.value}, ${record.total_cost_usd:.4f}) "
                f"in {path}"
            )
            if not export_change:
                return
        if export_change:
            if not change_id:
                raise typer.BadParameter("--export requires --change")
            typer.echo(json.dumps(led.export_change(change_id), indent=2, default=str))
            return
        try:
            rows = led.summarize(
                group_by, filters=filters or None, since=_parse_dt(since), until=_parse_dt(until)
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    def render() -> None:
        table = Table(title="usage")
        for g in group_by:
            table.add_column(g)
        for col in (
            "calls",
            "tokens",
            "cached",
            "tools",
            "cost_usd",
            "p50_ms",
            "p95_ms",
            "cache_hit",
        ):
            table.add_column(col, justify="right")
        for r in rows:
            table.add_row(
                *[r.group.get(g, "") for g in group_by],
                str(r.calls),
                str(r.total_tokens),
                str(r.cached_tokens),
                str(r.tool_calls),
                f"{r.cost_usd:.4f}",
                f"{r.latency_p50_ms:.0f}",
                f"{r.latency_p95_ms:.0f}",
                f"{r.cache_hit_rate:.0%}",
            )
        console.print(table)

    _emit([r.model_dump(mode="json") for r in rows], as_json, render)


# ---------------------------------------------------------------------- budget-check
@app.command("budget-check")
def budget_check(
    scope: list[str] = typer.Option(..., "--scope", "-s", help="e.g. application:payments"),
    forecast: float = typer.Option(..., "--forecast", min=0.0, help="Forecast cost in USD."),
    role: str | None = typer.Option(None),
    tier: str | None = typer.Option(None, help="Requested model tier low|standard|high."),
    budgets: Path | None = typer.Option(
        None, "--budgets", help="YAML/JSON with budgets:[...], quotas:{...}, exceptions:[...]"
    ),
    agent_turns: int | None = typer.Option(None),
    parallel_agents: int | None = typer.Option(None),
    review_rounds: int | None = typer.Option(None),
    tool_calls: int | None = typer.Option(None),
    context_tokens: int | None = typer.Option(None),
    ledger: Path | None = typer.Option(None, "--ledger"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Evaluate budgets/quotas for a forecast spend. Exit 1 on deny, 2 on require_approval."""
    budget_list: list[Budget] = []
    quotas = Quotas()
    exceptions = ExceptionRegister()
    if budgets is not None:
        budget_list, quotas, exceptions = _load_budget_config(budgets)
    with _open_ledger(ledger) as led:
        engine = BudgetPolicyEngine(led, budgets=budget_list, quotas=quotas, exceptions=exceptions)
        try:
            decision = engine.check(
                scope,
                forecast,
                role,
                tier,
                agent_turns=agent_turns,
                parallel_agents=parallel_agents,
                review_rounds=review_rounds,
                tool_calls=tool_calls,
                context_tokens=context_tokens,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    _emit(
        decision.model_dump(mode="json"),
        as_json,
        lambda: console.print(
            f"[bold]{decision.decision.value}[/bold] — {decision.reason}"
            + (
                f" (remaining ${decision.remaining_usd:.2f})"
                if decision.remaining_usd is not None
                else ""
            )
        ),
    )
    if decision.decision.value == "deny":
        raise typer.Exit(code=1)
    if decision.decision.value == "require_approval":
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------- kpis
@app.command("kpis")
def kpis(
    outcomes: Path | None = typer.Option(None, "--outcomes", help="JSON/YAML Outcomes file."),
    accepted_requirements: int = typer.Option(0, min=0),
    merged_changes: int = typer.Option(0, min=0),
    defects_found: int = typer.Option(0, min=0),
    vulns_found: int = typer.Option(0, min=0),
    benchmarks_passed: int = typer.Option(0, min=0),
    accepted_tasks: int = typer.Option(0, min=0),
    successful_runs: int = typer.Option(0, min=0),
    change_id: str | None = typer.Option(None, "--change"),
    since: str | None = typer.Option(None),
    until: str | None = typer.Option(None),
    benchmarks: Path | None = typer.Option(None, "--benchmarks", help="Benchmark SQLite path."),
    registry: Path | None = typer.Option(None, "--registry"),
    ledger: Path | None = typer.Option(None, "--ledger"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Compute control-plane KPIs from the ledger plus delivery outcomes."""
    if outcomes is not None:
        try:
            out = Outcomes.model_validate(_load_yaml_or_json(outcomes) or {})
        except ValidationError as exc:
            _user_file_error(outcomes, common.concise_validation_error(exc))
    else:
        out = Outcomes(
            accepted_requirements=accepted_requirements,
            merged_changes=merged_changes,
            defects_found=defects_found,
            vulns_found=vulns_found,
            benchmarks_passed=benchmarks_passed,
            accepted_tasks=accepted_tasks,
            successful_runs=successful_runs,
        )
    reg = _load_registry(registry)
    bench = BenchmarkService(str(benchmarks)) if benchmarks else None
    filters = {"change_id": change_id} if change_id else None
    with _open_ledger(ledger) as led:
        rep = compute_kpis(
            led,
            out,
            benchmarks=bench,
            registry=reg,
            filters=filters,
            since=_parse_dt(since),
            until=_parse_dt(until),
        )
    if bench is not None:
        bench.close()

    def render() -> None:
        table = Table(title="KPIs")
        table.add_column("kpi")
        table.add_column("value", justify="right")
        for key, value in rep.model_dump(mode="json").items():
            if key in {"notes", "since", "until"}:
                continue
            table.add_row(
                key,
                "n/a"
                if value is None
                else f"{value:.4f}"
                if isinstance(value, float)
                else str(value),
            )
        console.print(table)
        for note in rep.notes:
            console.print(f"[dim]note: {note}[/dim]")

    _emit(rep.model_dump(mode="json"), as_json, render)


# ---------------------------------------------------------------------- registry list
@registry_app.command("list")
def registry_list(
    registry: Path | None = typer.Option(None, "--registry"),
    capability: list[str] | None = typer.Option(None, "--capability", "-c"),
    family: str | None = typer.Option(None),
    exclude_family: list[str] | None = typer.Option(None, "--exclude-family"),
    provider: str | None = typer.Option(None),
    use_case: str | None = typer.Option(None, "--use-case"),
    allow: list[str] | None = typer.Option(None, "--allow", help="Allowlist model ids."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List registry models with prices and capabilities."""
    reg = _load_registry(registry)
    entries = reg.filter(
        capabilities=capability,
        family=family,
        exclude_families=exclude_family,
        provider=provider,
        use_case=use_case,
        allowlist=allow,
    )

    def render() -> None:
        table = Table(title=f"model registry ({reg.source or 'inline'})")
        for col in (
            "model",
            "provider",
            "family",
            "tier",
            "ctx",
            "$in/1M",
            "$out/1M",
            "$cached/1M",
            "caps",
        ):
            table.add_column(col)
        for e in entries:
            flag = " *" if e.price_configurable else ""
            table.add_row(
                e.model,
                e.provider,
                e.family,
                e.default_tier,
                str(e.context_limit),
                f"{e.price_in_per_1m:.2f}{flag}",
                f"{e.price_out_per_1m:.2f}{flag}",
                f"{e.price_cached_per_1m:.3f}{flag}",
                ",".join(e.capabilities),
            )
        console.print(table)
        if any(e.price_configurable for e in entries):
            console.print("[dim]* placeholder price — configure for your account[/dim]")

    _emit([e.model_dump() for e in entries], as_json, render)


# ---------------------------------------------------------------------- route
@app.command("route")
def route(
    complexity: Complexity = typer.Option(Complexity.standard, "--complexity"),
    risk: str = typer.Option("standard", "--risk"),
    role: str = typer.Option("implementer", "--role"),
    capability: list[str] | None = typer.Option(None, "--capability", "-c"),
    exclude_family: list[str] | None = typer.Option(None, "--exclude-family"),
    latency_target_ms: int | None = typer.Option(None, "--latency-target"),
    budget_remaining: float | None = typer.Option(None, "--budget-remaining"),
    tier: RoutingTier | None = typer.Option(None, "--tier", help="Force a routing tier."),
    escalate_from: str | None = typer.Option(None, "--escalate-from"),
    allow: list[str] | None = typer.Option(None, "--allow", help="Allowlist model ids."),
    benchmarks: Path | None = typer.Option(None, "--benchmarks", help="Benchmark SQLite path."),
    registry: Path | None = typer.Option(None, "--registry"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Route a task profile to a model and explain why."""
    reg = _load_registry(registry)
    profile = TaskProfile(
        complexity=complexity,
        risk=risk,
        role=role,
        required_capabilities=capability or [],
        exclude_families=exclude_family or [],
        latency_target_ms=latency_target_ms,
        budget_remaining_usd=budget_remaining,
        tier_override=tier,
        escalate_from=escalate_from,
    )
    bench = BenchmarkService(str(benchmarks)) if benchmarks else None
    try:
        decision = RoutingPolicy().route(profile, reg, benchmarks=bench, allowlist=allow)
    except RoutingError as exc:
        console.print(f"[red]routing failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    finally:
        if bench is not None:
            bench.close()
    _emit(
        decision.model_dump(mode="json"),
        as_json,
        lambda: console.print(
            f"[bold]{decision.model}[/bold] ({decision.provider}/{decision.family}) "
            f"tier={decision.tier.value} est=${decision.estimated_cost_per_1k * 1000:.2f}/1M\n"
            f"alternatives: {', '.join(decision.alternatives) or '-'}\n"
            f"reason: {decision.reason}"
        ),
    )


# ---------------------------------------------------------------------- import
_IMPORT_CHANGE = typer.Option("", "--change", help="Change id applied to every event.")
_IMPORT_TASK = typer.Option("", "--task", help="Task id applied to every event.")
_IMPORT_ROLE = typer.Option("", "--role", help="Agent role applied to every event.")
_IMPORT_TEAM = typer.Option("", "--team")
_IMPORT_APP = typer.Option("", "--app")
_IMPORT_USER = typer.Option("", "--user")
_IMPORT_REPO = typer.Option("", "--repo")
_IMPORT_ENV = typer.Option("", "--env")
_IMPORT_SESSION = typer.Option("", "--session")
_IMPORT_LEDGER = typer.Option(None, "--ledger", help=f"SQLite path (${LEDGER_ENV}).")
_IMPORT_REGISTRY = typer.Option(None, "--registry", help="Registry YAML used for pricing.")
_IMPORT_JSON = typer.Option(False, "--json")


def _telemetry_defaults(
    *,
    change_id: str,
    task_id: str,
    role: str,
    team: str,
    application: str,
    user: str,
    repository: str,
    environment: str,
    session_id: str,
    harness: str = "",
) -> TelemetryDefaults:
    return TelemetryDefaults(
        change_id=change_id,
        task_id=task_id,
        agent_role=role,
        team=team,
        application=application,
        user=user,
        repository=repository,
        environment=environment,
        session_id=session_id,
        harness=harness,
    )


def _record_imported(
    events: list[UsageEvent], ledger: Path | None, as_json: bool, source: str
) -> None:
    with UsageLedger(_ledger_path(ledger)) as led:
        before = led.count()
        offered = led.record_many(events)
        recorded = led.count() - before
    total = sum(e.cost_usd for e in events)
    summary = {
        "source": source,
        "events": offered,
        "recorded": recorded,
        "skipped_existing": offered - recorded,
        "cost_usd": round(total, 6),
        "models": sorted({e.model for e in events if e.model}),
        "event_ids": [e.event_id for e in events],
    }
    _emit(
        summary,
        as_json,
        lambda: console.print(
            f"imported {recorded} of {offered} {source} event(s) (${total:.6f}); "
            f"{offered - recorded} already present"
        ),
    )


@import_app.command("claude-code")
def import_claude_code(
    path: Path = typer.Argument(..., help="Claude Code session transcript (JSONL)."),
    change_id: str = _IMPORT_CHANGE,
    task_id: str = _IMPORT_TASK,
    role: str = _IMPORT_ROLE,
    team: str = _IMPORT_TEAM,
    application: str = _IMPORT_APP,
    user: str = _IMPORT_USER,
    repository: str = _IMPORT_REPO,
    environment: str = _IMPORT_ENV,
    session_id: str = _IMPORT_SESSION,
    no_dedupe: bool = typer.Option(False, "--no-dedupe", help="Keep streaming duplicates."),
    ledger: Path | None = _IMPORT_LEDGER,
    registry: Path | None = _IMPORT_REGISTRY,
    as_json: bool = _IMPORT_JSON,
) -> None:
    """Import a Claude Code session transcript (JSONL) into the ledger."""
    if not path.is_file():
        raise typer.BadParameter(f"{path} is not a file")
    defaults = _telemetry_defaults(
        change_id=change_id,
        task_id=task_id,
        role=role,
        team=team,
        application=application,
        user=user,
        repository=repository,
        environment=environment,
        session_id=session_id,
        harness="claude_code",
    )
    events = from_claude_code_jsonl(
        path, defaults=defaults, registry=_load_registry(registry), dedupe=not no_dedupe
    )
    _record_imported(events, ledger, as_json, "claude_code")


def _load_audit_entries(path: Path) -> list[Any]:
    """AGT audit entries from a JSON array, an ``AuditLog.export()`` dict or JSON lines."""
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if len(lines) > 1 and all(line.startswith("{") for line in lines):
        entries: list[Any] = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise typer.BadParameter(f"{path}: invalid JSON line: {exc}") from exc
        return entries
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"{path}: invalid JSON: {exc}") from exc
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        return list(data["entries"])
    if isinstance(data, dict) and "entry_id" in data:
        return [data]
    raise typer.BadParameter(f"{path}: expected a JSON array, {{'entries': [...]}} or JSON lines")


@import_app.command("agt-audit")
def import_agt_audit(
    path: Path = typer.Argument(..., help="AGT audit log (JSON array, export dict or JSONL)."),
    change_id: str = _IMPORT_CHANGE,
    task_id: str = _IMPORT_TASK,
    role: str = _IMPORT_ROLE,
    team: str = _IMPORT_TEAM,
    application: str = _IMPORT_APP,
    user: str = _IMPORT_USER,
    repository: str = _IMPORT_REPO,
    environment: str = _IMPORT_ENV,
    session_id: str = _IMPORT_SESSION,
    ledger: Path | None = _IMPORT_LEDGER,
    as_json: bool = _IMPORT_JSON,
) -> None:
    """Import AGT audit entries as tool-call usage events."""
    if not path.is_file():
        raise typer.BadParameter(f"{path} is not a file")
    defaults = _telemetry_defaults(
        change_id="",
        task_id=task_id,
        role=role,
        team=team,
        application=application,
        user=user,
        repository=repository,
        environment=environment,
        session_id=session_id,
    )
    entries = [e for e in _load_audit_entries(path) if isinstance(e, dict)]
    events = from_agt_audit(entries, defaults=defaults, change_id=change_id)
    _record_imported(events, ledger, as_json, "agt_audit")


def _parse_labels(values: list[str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise typer.BadParameter(f"label {item!r} must be key=value")
        key, value = item.split("=", 1)
        labels[key.strip()] = value.strip()
    return labels


@import_app.command("pyrit")
def import_pyrit(
    source: Path = typer.Argument(
        ..., help="PyRIT SQLite memory database, or a JSON file of message pieces."
    ),
    change_id: str = _IMPORT_CHANGE,
    task_id: str = _IMPORT_TASK,
    role: str = _IMPORT_ROLE,
    team: str = _IMPORT_TEAM,
    application: str = _IMPORT_APP,
    user: str = _IMPORT_USER,
    repository: str = _IMPORT_REPO,
    environment: str = _IMPORT_ENV,
    session_id: str = _IMPORT_SESSION,
    conversation_id: str | None = typer.Option(None, "--conversation", help="Filter by id."),
    label: list[str] = typer.Option([], "--label", help="Memory label filter key=value."),
    model: str = typer.Option("", "--model", help="Model for pieces that record none."),
    ledger: Path | None = _IMPORT_LEDGER,
    registry: Path | None = _IMPORT_REGISTRY,
    as_json: bool = _IMPORT_JSON,
) -> None:
    """Import PyRIT token usage (``token_usage_*`` piece metadata) into the ledger.

    A ``.json`` source is read as a list of message-piece objects (no PyRIT needed); any
    other path is opened as a PyRIT SQLite memory database (requires ``pyrit``).
    """
    if not source.is_file():
        raise typer.BadParameter(f"{source} is not a file")
    defaults = _telemetry_defaults(
        change_id=change_id,
        task_id=task_id,
        role=role,
        team=team,
        application=application,
        user=user,
        repository=repository,
        environment=environment,
        session_id=session_id,
        harness="pyrit",
    )
    reg = _load_registry(registry)
    if source.suffix.lower() == ".json":
        data = _load_json_list(source, "pieces")
        pieces = [p for p in data if isinstance(p, dict)]
        if conversation_id is not None:
            pieces = [p for p in pieces if str(p.get("conversation_id", "")) == conversation_id]
        events = from_pyrit_pieces(pieces, defaults=defaults, registry=reg, model=model)
    else:
        try:
            from pyrit.memory import SQLiteMemory
        except ImportError as exc:
            typer.echo(
                "error: pyrit is not installed; export the message pieces to JSON and import "
                "that file instead",
                err=True,
            )
            raise typer.Exit(code=2) from exc
        memory = SQLiteMemory(db_path=str(source), silent=True)
        try:
            events = from_pyrit_memory(
                memory,
                defaults=defaults,
                conversation_id=conversation_id,
                labels=_parse_labels(label) or None,
                registry=reg,
                model=model,
            )
        finally:
            dispose = getattr(memory, "dispose_engine", None)
            if callable(dispose):
                dispose()
    _record_imported(events, ledger, as_json, "pyrit")
