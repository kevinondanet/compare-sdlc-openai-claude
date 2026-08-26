"""``aisdlc run`` — governed multi-agent orchestration of a change package.

Commands: ``change`` (run every wave), ``task`` (one task), ``review`` (whole-change final
review) and ``status`` (task statuses and handoffs). Checkpoints are interactive
(``typer.confirm``) unless ``--yes`` approves everything or ``--non-interactive`` denies
everything (the fail-closed default when stdin is not a terminal).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

import typer

from aisdlc import ids
from aisdlc.cli.cmd_init import uncommitted_sources
from aisdlc.control_plane.ledger import UsageLedger
from aisdlc.control_plane.registry import ModelRegistry, RegistryLoadError
from aisdlc.orchestration.executor import (
    ActionChecker,
    Checkpoint,
    CheckpointOutcome,
    CheckpointRequest,
    Executor,
    ExecutorConfig,
    ExecutorError,
    LocalTierChecker,
    RunOutcome,
    RunReport,
    TaskReport,
    approve_all_checkpoints,
    deny_all_checkpoints,
)
from aisdlc.orchestration.handoff import HandoffStore
from aisdlc.orchestration.roles import AgentRole, default_tool_tier, orchestration_policy_spec
from aisdlc.orchestration.runner import (
    AgentRunner,
    ClaudeCodeRunner,
    DryRunRunner,
    LocalScriptRunner,
)
from aisdlc.orchestration.worktree import WorktreeError, WorktreeManager
from aisdlc.policy.org_policy import (
    OrgPolicy,
    PolicyLoadError,
    default_org_policy,
    find_org_policy,
    load_org_policy,
)
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ChangePackage

NAME = "run"
app = typer.Typer(
    help="Run change packages with governed, isolated agents (orchestration layer).",
    no_args_is_help=True,
)

LEDGER_ENV = "AISDLC_LEDGER"
DEFAULT_LEDGER = Path(".aisdlc") / "ledger.sqlite"
RUNNERS = ("dry", "script", "claude")

EXIT_FAILED = 1
EXIT_LOAD_ERROR = 2
EXIT_BLOCKED = 3
EXIT_SKIPPED = 4


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _package_dir(change: str, root: Path) -> Path:
    candidate = Path(change)
    if (candidate / pkgio.INTENT_FILE).is_file():
        return candidate.resolve()
    try:
        return pkgio.package_dir(root, change).resolve()
    except ids.InvalidIdError as exc:
        typer.echo(f"error: {exc} (pass a CHG-<slug> id or a change package directory)", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc


def _load_package(change: str, root: Path) -> ChangePackage:
    directory = _package_dir(change, root)
    try:
        return pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc


def _load_policy(root: Path, org_policy: Path | None) -> OrgPolicy:
    path = org_policy or find_org_policy(root)
    if path is None:
        return default_org_policy()
    try:
        return load_org_policy(path)
    except PolicyLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc


def _ledger_path(root: Path, value: Path | None) -> str:
    if value is not None:
        value.parent.mkdir(parents=True, exist_ok=True)
        return str(value)
    env = os.environ.get(LEDGER_ENV)
    if env:
        return env
    path = root / DEFAULT_LEDGER
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def _worktree_error(exc: WorktreeError) -> NoReturn:
    """Report a git/worktree failure (exit 2) with a hint for the common no-commit case."""
    message = str(exc)
    hint = ""
    if "Needed a single revision" in message or "HEAD" in message:
        hint = " (hint: the repository needs an initial commit before agents can run)"
    typer.echo(f"error: {message}{hint}", err=True)
    raise typer.Exit(code=EXIT_LOAD_ERROR) from exc


COMMIT_HINT = "git add -A && git commit -m 'baseline'"


def _refuse_uncommitted_sources(executor: Executor, allow_dirty: bool) -> None:
    """Exit 2 with an actionable message when the repository has uncommitted sources.

    Task worktrees are created from ``HEAD``; :func:`aisdlc.cli.cmd_init.uncommitted_sources`
    defines what counts (``changes/``, ``.aisdlc/`` and generated artefacts are exempt).
    """
    if allow_dirty:
        return
    dirty = uncommitted_sources(executor.repo_root)
    if not dirty:
        return
    shown = ", ".join(dirty[:5]) + (f" (+{len(dirty) - 5} more)" if len(dirty) > 5 else "")
    typer.echo(
        f"error: {len(dirty)} uncommitted file(s) in {executor.repo_root} would be missing "
        f"from the task worktrees, which start from HEAD: {shown}. Commit them first "
        f"({COMMIT_HINT}) or pass --allow-dirty to run against HEAD anyway.",
        err=True,
    )
    raise typer.Exit(code=EXIT_LOAD_ERROR)


def _registry(path: Path | None) -> ModelRegistry:
    try:
        return ModelRegistry.load(path) if path else ModelRegistry.default()
    except RegistryLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc


def _runner(kind: str, script_command: str | None, model: str | None) -> AgentRunner:
    if kind == "dry":
        return DryRunRunner()
    if kind == "script":
        if not script_command:
            typer.echo("error: --script-command is required with --runner script", err=True)
            raise typer.Exit(code=EXIT_LOAD_ERROR)
        return LocalScriptRunner(script_command)
    if kind == "claude":
        return ClaudeCodeRunner(executable=model or "claude")
    typer.echo(f"error: unknown runner {kind!r}; choose from {', '.join(RUNNERS)}", err=True)
    raise typer.Exit(code=EXIT_LOAD_ERROR)


def _interactive_checkpoint(request: CheckpointRequest) -> CheckpointOutcome:
    label = request.kind.value.replace("_", " ")
    prefix = f"[{label}]" + (f" {request.task_id}" if request.task_id else "")
    approved = typer.confirm(f"{prefix} {request.description} Approve?", default=False)
    approver = os.environ.get("USER") or os.environ.get("USERNAME") or "operator"
    return CheckpointOutcome(
        approved=approved,
        approver=approver if approved else "",
        reason="approved interactively" if approved else "denied interactively",
    )


def _checkpoint(yes: bool, non_interactive: bool) -> Checkpoint:
    if yes:
        return approve_all_checkpoints
    if non_interactive or not sys.stdin.isatty():
        return deny_all_checkpoints
    return _interactive_checkpoint


def _enforcer(
    executor: Executor, *, audit_log: Path | None, shadow: bool
) -> tuple[ActionChecker, str | None]:
    """AGT-backed enforcer when available, else the local tier checker (with a note)."""
    spec = orchestration_policy_spec(
        workspace_roots=[str(executor.worktrees.worktrees_dir), str(executor.repo_root)]
    )
    try:
        from aisdlc.governance.audit import AuditTrail
        from aisdlc.governance.enforce import PolicyEnforcer
        from aisdlc.governance.policy import GovernanceUnavailableError, render_policy_yaml

        try:
            sink = AuditTrail(audit_log, session_id=executor.change_id)
            enforcer = PolicyEnforcer(
                render_policy_yaml(spec, AgentRole.IMPLEMENTER.value),
                AgentRole.IMPLEMENTER.value,
                approval_handler=executor.approval_callback,
                approval_timeout_seconds=executor.policy.tool_tiers.approval_timeout_seconds,
                audit_sink=sink,
                shadow=shadow,
                tier_config=spec.effective_tier_config(),
            )
        except GovernanceUnavailableError as exc:
            return LocalTierChecker(default_tool_tier(AgentRole.IMPLEMENTER)), str(exc)
        return enforcer, None
    except ImportError as exc:  # pragma: no cover - defensive
        return LocalTierChecker(default_tool_tier(AgentRole.IMPLEMENTER)), str(exc)


def _build_executor(
    *,
    change: str,
    root: Path,
    runner_kind: str,
    script_command: str | None,
    model: str | None,
    max_parallel: int | None,
    max_review_rounds: int | None,
    yes: bool,
    non_interactive: bool,
    apply_back: bool,
    keep_worktrees: bool,
    final_review: bool,
    ledger: Path | None,
    org_policy: Path | None,
    registry: Path | None,
    environment: str,
    audit_log: Path | None,
    shadow: bool,
    ignore_duplicates: bool = False,
) -> tuple[Executor, list[str]]:
    notes: list[str] = []
    pkg = _load_package(change, root)
    policy = _load_policy(root, org_policy)
    config = ExecutorConfig(
        max_parallel=max_parallel,
        max_review_rounds=max_review_rounds,
        environment=environment,
        apply_back=apply_back,
        cleanup_worktrees=not keep_worktrees,
        final_review=final_review,
        ignore_duplicates=ignore_duplicates,
    )
    try:
        executor = Executor(
            pkg,
            policy,
            _runner(runner_kind, script_command, model),
            UsageLedger(_ledger_path(root, ledger)),
            registry=_registry(registry),
            checkpoint=_checkpoint(yes, non_interactive),
            config=config,
            repo_root=root.resolve(),
        )
    except (ExecutorError, WorktreeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc
    enforcer, note = _enforcer(executor, audit_log=audit_log, shadow=shadow)
    executor.enforcer = enforcer
    if note:
        notes.append(f"governance: AGT unavailable ({note}); using local tier ceiling checks")
    return executor, notes


def _exit_for(outcome: RunOutcome) -> int:
    return {
        RunOutcome.SUCCESS: 0,
        RunOutcome.FAILED: EXIT_FAILED,
        RunOutcome.BLOCKED: EXIT_BLOCKED,
        RunOutcome.SKIPPED: EXIT_SKIPPED,
    }[outcome]


def _print_task(task: TaskReport) -> None:
    detail = task.error or (
        f"rounds={task.review_rounds} model={task.implementer_model} "
        f"reviewer={task.reviewer_model} applied={task.applied_back}"
    )
    flag = " (resumed)" if task.resumed else ""
    typer.echo(f"  {task.task_id:<10} {task.status.value:<12}{flag} {detail}")


def _print_report(report: RunReport, notes: list[str], as_json: bool) -> None:
    if as_json:
        data: dict[str, Any] = report.model_dump(mode="json")
        data["notes"] = notes
        typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))
        return
    for note in notes:
        typer.echo(f"note: {note}", err=True)
    typer.echo(f"{report.change_id}: {report.outcome.value}")
    for task in report.tasks:
        _print_task(task)
    typer.echo(
        f"  usage: {report.usage.calls} call(s), {report.usage.input_tokens} in / "
        f"{report.usage.output_tokens} out tokens, ${report.usage.cost_usd:.4f}"
    )
    if report.final_review_id:
        verdict = report.final_review_verdict.value if report.final_review_verdict else "n/a"
        typer.echo(f"  final review: {report.final_review_id} {verdict}")
    if report.release_approved is not None:
        typer.echo(f"  release checkpoint: {'approved' if report.release_approved else 'denied'}")
    for message in report.messages:
        typer.echo(f"  {message}")
    typer.echo(f"  handoffs: {report.handoffs_written}")


# --------------------------------------------------------------------------------------
# shared options
# --------------------------------------------------------------------------------------

_ROOT = typer.Option(Path("."), "--root", help="Repository root (holds changes/).")
_RUNNER = typer.Option("dry", "--runner", help="Agent runner: dry | script | claude.")
_SCRIPT = typer.Option(None, "--script-command", help="Command for --runner script.")
_MODEL = typer.Option(None, "--claude-executable", help="Claude Code executable.")
_PARALLEL = typer.Option(None, "--max-parallel", min=1, help="Parallel agent bound.")
_ROUNDS = typer.Option(None, "--max-review-rounds", min=1, help="Fix-loop bound.")
_YES = typer.Option(False, "--yes", "-y", help="Approve every checkpoint.")
_NON_INTERACTIVE = typer.Option(
    False, "--non-interactive", help="Deny every checkpoint (default without a TTY)."
)
_APPLY = typer.Option(True, "--apply-back/--no-apply-back", help="Merge task branches back.")
_KEEP = typer.Option(False, "--keep-worktrees", help="Keep worktrees after success.")
_ALLOW_DIRTY = typer.Option(
    False,
    "--allow-dirty",
    help="Start even with uncommitted files outside changes/ (worktrees start from HEAD).",
)
_FINAL = typer.Option(True, "--final-review/--no-final-review", help="Whole-change review.")
_LEDGER = typer.Option(None, "--ledger", help="Usage ledger path ($AISDLC_LEDGER).")
_ORG = typer.Option(None, "--org-policy", help="Org policy YAML (auto-discovered).")
_REGISTRY = typer.Option(None, "--registry", help="Model registry YAML.")
_ENV = typer.Option("local", "--environment", help="Evidence environment label.")
_AUDIT = typer.Option(
    None,
    "--audit-log",
    help="HMAC audit log path (AGT). Recorded as given: an absolute path is verified at "
    "that path; a relative one is resolved by G4/G6 against the current working "
    "directory, then the repository root (never the evidence directory).",
)
_SHADOW = typer.Option(False, "--shadow", help="Evaluate governance without blocking.")
_JSON = typer.Option(False, "--json", help="Machine-readable output.")


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------


@app.command("change")
def run_change(
    change: str = typer.Argument(..., help="CHG-<slug> id or package directory."),
    root: Path = _ROOT,
    runner: str = _RUNNER,
    script_command: str | None = _SCRIPT,
    claude_executable: str | None = _MODEL,
    max_parallel: int | None = _PARALLEL,
    max_review_rounds: int | None = _ROUNDS,
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Skip completed tasks."),
    ignore_duplicates: bool = typer.Option(
        False, "--ignore-duplicates", help="Run even if identical inputs already ran."
    ),
    yes: bool = _YES,
    non_interactive: bool = _NON_INTERACTIVE,
    apply_back: bool = _APPLY,
    keep_worktrees: bool = _KEEP,
    allow_dirty: bool = _ALLOW_DIRTY,
    final_review: bool = _FINAL,
    ledger: Path | None = _LEDGER,
    org_policy: Path | None = _ORG,
    registry: Path | None = _REGISTRY,
    environment: str = _ENV,
    audit_log: Path | None = _AUDIT,
    shadow: bool = _SHADOW,
    as_json: bool = _JSON,
) -> None:
    """Run every wave of the change (exit 0 ok, 1 failed, 2 load error, 3 blocked, 4 dup).

    Refuses to start (exit 2) while sources outside ``changes/`` are uncommitted: the
    task worktrees are created from ``HEAD`` and would not contain them.
    """
    executor, notes = _build_executor(
        change=change,
        root=root,
        runner_kind=runner,
        script_command=script_command,
        model=claude_executable,
        max_parallel=max_parallel,
        max_review_rounds=max_review_rounds,
        yes=yes,
        non_interactive=non_interactive,
        apply_back=apply_back,
        keep_worktrees=keep_worktrees,
        final_review=final_review,
        ledger=ledger,
        org_policy=org_policy,
        registry=registry,
        environment=environment,
        audit_log=audit_log,
        shadow=shadow,
        ignore_duplicates=ignore_duplicates,
    )
    _refuse_uncommitted_sources(executor, allow_dirty)
    try:
        report = executor.run(resume=resume)
    except ExecutorError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_FAILED) from exc
    except WorktreeError as exc:
        _worktree_error(exc)
    _print_report(report, notes, as_json)
    code = _exit_for(report.outcome)
    if code:
        raise typer.Exit(code=code)


@app.command("task")
def run_task(
    task_id: str = typer.Argument(..., help="TASK-<nnn> id."),
    change: str = typer.Option(..., "--change", "-c", help="CHG-<slug> id or package dir."),
    root: Path = _ROOT,
    runner: str = _RUNNER,
    script_command: str | None = _SCRIPT,
    claude_executable: str | None = _MODEL,
    max_review_rounds: int | None = _ROUNDS,
    yes: bool = _YES,
    non_interactive: bool = _NON_INTERACTIVE,
    apply_back: bool = _APPLY,
    keep_worktrees: bool = _KEEP,
    allow_dirty: bool = _ALLOW_DIRTY,
    ledger: Path | None = _LEDGER,
    org_policy: Path | None = _ORG,
    registry: Path | None = _REGISTRY,
    environment: str = _ENV,
    audit_log: Path | None = _AUDIT,
    shadow: bool = _SHADOW,
    as_json: bool = _JSON,
) -> None:
    """Run a single task (worktree, implement, verify, review, apply-back).

    Like ``change``, refuses to start (exit 2) on uncommitted sources outside ``changes/``.
    """
    executor, notes = _build_executor(
        change=change,
        root=root,
        runner_kind=runner,
        script_command=script_command,
        model=claude_executable,
        max_parallel=1,
        max_review_rounds=max_review_rounds,
        yes=yes,
        non_interactive=non_interactive,
        apply_back=apply_back,
        keep_worktrees=keep_worktrees,
        final_review=False,
        ledger=ledger,
        org_policy=org_policy,
        registry=registry,
        environment=environment,
        audit_log=audit_log,
        shadow=shadow,
    )
    _refuse_uncommitted_sources(executor, allow_dirty)
    try:
        report = executor.run_task(task_id)
    except ExecutorError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc
    except WorktreeError as exc:
        _worktree_error(exc)
    if as_json:
        data: dict[str, Any] = report.model_dump(mode="json")
        data["notes"] = notes
        typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        for note in notes:
            typer.echo(f"note: {note}", err=True)
        typer.echo(f"{executor.change_id}:")
        _print_task(report)
    if report.status.value == "done":
        return
    raise typer.Exit(code=EXIT_BLOCKED if report.status.value == "blocked" else EXIT_FAILED)


@app.command("review")
def run_review(
    change: str = typer.Argument(..., help="CHG-<slug> id or package directory."),
    root: Path = _ROOT,
    runner: str = _RUNNER,
    script_command: str | None = _SCRIPT,
    claude_executable: str | None = _MODEL,
    base: str | None = typer.Option(None, "--base", help="Base commit (default: run start)."),
    ledger: Path | None = _LEDGER,
    org_policy: Path | None = _ORG,
    registry: Path | None = _REGISTRY,
    environment: str = _ENV,
    as_json: bool = _JSON,
) -> None:
    """Independent whole-change review of everything applied since the run base."""
    executor, notes = _build_executor(
        change=change,
        root=root,
        runner_kind=runner,
        script_command=script_command,
        model=claude_executable,
        max_parallel=1,
        max_review_rounds=None,
        yes=False,
        non_interactive=True,
        apply_back=False,
        keep_worktrees=True,
        final_review=True,
        ledger=ledger,
        org_policy=org_policy,
        registry=registry,
        environment=environment,
        audit_log=None,
        shadow=False,
    )
    try:
        review = executor.final_review(base_sha=base)
    except WorktreeError as exc:
        _worktree_error(exc)
    executor.save_package()
    if review is None:
        typer.echo("error: no reviewer could be routed (see handoffs)", err=True)
        raise typer.Exit(code=EXIT_BLOCKED)
    if as_json:
        data = review.evidence.model_dump(mode="json")
        data["notes"] = notes
        typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        for note in notes:
            typer.echo(f"note: {note}", err=True)
        ev = review.evidence
        typer.echo(
            f"{executor.change_id}: {ev.id} {ev.verdict.value} "
            f"({ev.reviewer_model_family} reviewing {ev.implementer_model_family or '?'}; "
            f"{len(ev.findings)} finding(s), {len(review.blocking)} blocking)"
        )
        for finding in ev.findings:
            mark = "!" if finding.is_grounded_blocking else ("~" if finding.grounded else "?")
            typer.echo(
                f"  {mark} {finding.id} {finding.severity.value} "
                f"{finding.file or '-'}:{finding.line or '-'} {finding.title}"
            )
    if not review.approved:
        raise typer.Exit(code=EXIT_FAILED)


@app.command("status")
def run_status(
    change: str = typer.Argument(..., help="CHG-<slug> id or package directory."),
    root: Path = _ROOT,
    as_json: bool = _JSON,
) -> None:
    """Task statuses and the handoff log of a change."""
    pkg = _load_package(change, root)
    assert pkg.root is not None
    store = HandoffStore(pkg.root)
    handoffs = store.load()
    completed = store.completed_tasks()
    worktrees: list[dict[str, str]] = []
    repo_root = pkg.root.parent.parent
    if (repo_root / ".git").exists():
        try:
            manager = WorktreeManager(repo_root)
            worktrees = [
                {"task_id": w.task_id, "branch": w.branch, "path": w.path}
                for w in manager.list_worktrees()
                if w.change_id == pkg.change_id
            ]
        except WorktreeError:
            worktrees = []
    summary: dict[str, Any] = {
        "change_id": pkg.change_id,
        "state": pkg.derive_state().value,
        "tasks": [
            {
                "id": t.id,
                "status": t.status.value,
                "wave": pkg.plan.wave_of(t.id) if pkg.plan else t.wave,
                "completed_handoff": t.id in completed,
            }
            for t in pkg.tasks
        ],
        "handoffs": [h.model_dump(mode="json") for h in handoffs],
        "worktrees": worktrees,
        "evidence": pkg.evidence.ids(),
    }
    if as_json:
        typer.echo(json.dumps(summary, indent=2, sort_keys=True, default=str))
        return
    typer.echo(f"{pkg.change_id}: {summary['state']}")
    for task in summary["tasks"]:
        done = " ✓" if task["completed_handoff"] else ""
        typer.echo(f"  {task['id']:<10} {task['status']:<12} wave={task['wave']}{done}")
    if worktrees:
        typer.echo("worktrees:")
        for wt in worktrees:
            typer.echo(f"  {wt['task_id']:<10} {wt['branch']} {wt['path']}")
    typer.echo("handoffs:")
    typer.echo("  " + store.summary().replace("\n", "\n  "))
