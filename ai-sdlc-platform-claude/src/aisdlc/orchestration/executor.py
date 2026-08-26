"""Wave execution with isolated worktrees, bounded fix loops, checkpoints and resumability.

:class:`Executor` is the only component that runs agents. For one change package it:

1. suppresses duplicate runs through the ledger's ``(source_hash, eval_config_hash)``
   register, asks for plan approval at a checkpoint, and derives waves from the plan or
   from task dependencies;
2. runs each wave's tasks with bounded parallelism (``max_parallel_agents``); per task it
   creates a worktree, routes the implementer through the control-plane
   :class:`~aisdlc.control_plane.routing.RoutingPolicy`, builds a narrow brief, checks the
   tier of every action it performs against the governance enforcer, runs the
   implementer, runs the task's verification command (captured as ``TestEvidence``), runs
   an independent review by a different model family, and loops fixes up to
   ``max_review_rounds``;
3. applies successful branches back onto the repository branch (a tier-3 action that
   stops at a checkpoint unless approved), writes handoffs after every step, records
   every run's usage in the ledger, re-runs every task's verification on the merged
   ``HEAD`` (post-merge verification), runs a whole-change final review, and writes
   ``evidence/tests.json``, ``evidence/reviews.json`` and ``evidence/cost.json`` through
   the schema APIs.

Budget: every agent run (implementer and reviewer, every round, plus the final review) is
admitted through the control-plane :class:`~aisdlc.control_plane.budget.BudgetPolicyEngine`
with the routing forecast (raised to the observed average cost of the change's earlier
runs) plus the forecasts of runs still in flight, so parallel tasks cannot overspend the
per-change and per-task budgets; ``require_approval`` decisions go to the ``budget``
checkpoint.

Evidence: while a change is in progress the canonical evidence files carry the working
records of every round (stamped with the worktree commit they were produced at, each with
a report file under ``evidence/logs/``). Once every task is applied back, verified on the
merged ``HEAD`` and finally reviewed, the evidence files are consolidated to the records
produced at ``HEAD``; superseded records are archived to
``evidence/logs/superseded-evidence.json`` (see :func:`load_superseded_evidence`).

Verification commands come from ``tasks.md`` (an agent-writable artifact), so they are
classified with the governance shell classifier before they run (tier >= 3 is refused),
governed as the classified action, and executed without a shell.

Runs are resumable: tasks with a successful ``task_done`` handoff (or ``done`` status in
``tasks.md``) are skipped, and a task whose apply-back was denied at the checkpoint resumes
directly at apply-back when its branch is unchanged since the approved review.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import threading
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.control_plane.benchmark import BenchmarkService
from aisdlc.control_plane.budget import (
    Budget,
    BudgetDecision,
    BudgetPolicyEngine,
    DecisionKind,
    Quotas,
    ScopeType,
)
from aisdlc.control_plane.ledger import UsageLedger
from aisdlc.control_plane.registry import ModelRegistry
from aisdlc.control_plane.routing import (
    Complexity,
    RoutingDecision,
    RoutingError,
    RoutingPolicy,
    RoutingTier,
    TaskProfile,
)
from aisdlc.governance.claude_code_plugin import classify_shell_command
from aisdlc.governance.enforce import ApprovalOutcome
from aisdlc.governance.tiers import RiskTier, TierConfig, ToolAction, classify_action
from aisdlc.orchestration.brief import DEFAULT_BRIEF_SHARE, AgentBrief, build_brief
from aisdlc.orchestration.handoff import (
    Handoff,
    HandoffStatus,
    HandoffStep,
    HandoffStore,
    inputs_hash,
)
from aisdlc.orchestration.review import IndependentReviewer, ReviewResult, whole_change_task
from aisdlc.orchestration.roles import AgentRole, default_complexity, default_tool_tier
from aisdlc.orchestration.runner import (
    AgentResult,
    AgentRunner,
    AgentUsage,
    LedgerUsageRecorder,
    RunStatus,
    UsageRecorder,
)
from aisdlc.orchestration.worktree import DiffSummary, WorktreeInfo, WorktreeManager, branch_name
from aisdlc.policy.org_policy import OrgPolicy
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    ChangePackage,
    EvidenceStatus,
    Finding,
    ModelTier,
    Plan,
    ReviewEvidence,
    ReviewVerdict,
    Task,
    TaskStatus,
    TestEvidence,
    Verification,
)

__all__ = [
    "ExecutorError",
    "CheckpointKind",
    "CheckpointRequest",
    "CheckpointOutcome",
    "Checkpoint",
    "deny_all_checkpoints",
    "approve_all_checkpoints",
    "ActionChecker",
    "LocalDecision",
    "LocalTierChecker",
    "UsageTotals",
    "TaskReport",
    "RunOutcome",
    "RunReport",
    "ExecutorConfig",
    "WaveSpec",
    "derive_waves",
    "check_wave_order",
    "router_from_policy",
    "budget_engine_from_policy",
    "registry_allowlist",
    "complexity_for",
    "shell_operators",
    "run_verification",
    "SUPERSEDED_EVIDENCE_FILE",
    "load_superseded_evidence",
    "source_hash_of",
    "Executor",
]


class ExecutorError(RuntimeError):
    """The run could not proceed."""


# --------------------------------------------------------------------------------------
# Checkpoints
# --------------------------------------------------------------------------------------


class CheckpointKind(StrEnum):
    """Human checkpoints (ARCHITECTURE.md §6)."""

    PLAN_APPROVAL = "plan_approval"
    TIER_ACTION = "tier_action"
    BUDGET = "budget"
    WAVE = "wave"
    RELEASE = "release"


class CheckpointRequest(BaseModel):
    """What the checkpoint callback is asked to approve."""

    model_config = ConfigDict(extra="forbid")

    kind: CheckpointKind
    change_id: str
    description: str
    task_id: str | None = None
    tier: int | None = None
    action_type: str | None = None
    resource: str | None = None
    wave: int | None = None
    forecast_usd: float | None = None
    remaining_usd: float | None = None


class CheckpointOutcome(BaseModel):
    """Checkpoint decision."""

    model_config = ConfigDict(extra="forbid")

    approved: bool
    approver: str = ""
    reason: str = ""


Checkpoint = Callable[[CheckpointRequest], "CheckpointOutcome | bool"]


def deny_all_checkpoints(request: CheckpointRequest) -> CheckpointOutcome:
    """Default for non-interactive runs: every checkpoint is denied."""
    return CheckpointOutcome(
        approved=False, reason=f"non-interactive run: {request.kind.value} checkpoint denied"
    )


def approve_all_checkpoints(request: CheckpointRequest) -> CheckpointOutcome:
    """Approve everything (tests / explicitly trusted automation)."""
    return CheckpointOutcome(approved=True, approver="auto", reason="auto-approved")


def _resolve_checkpoint(callback: Checkpoint, request: CheckpointRequest) -> CheckpointOutcome:
    try:
        outcome = callback(request)
    except Exception as exc:  # noqa: BLE001 - a broken checkpoint must deny, never crash
        return CheckpointOutcome(approved=False, reason=f"checkpoint error: {exc}")
    if isinstance(outcome, CheckpointOutcome):
        return outcome
    return CheckpointOutcome(
        approved=bool(outcome),
        approver="checkpoint" if outcome else "",
        reason="approved" if outcome else "denied",
    )


# --------------------------------------------------------------------------------------
# Governance checker protocol + local fallback
# --------------------------------------------------------------------------------------


class ActionDecision(Protocol):
    """Subset of an enforcement decision the executor relies on."""

    allowed: bool
    reason: str


class ActionChecker(Protocol):
    """A :class:`~aisdlc.governance.enforce.PolicyEnforcer`-compatible checker."""

    def check(self, action: ToolAction) -> ActionDecision:
        """Evaluate ``action``."""
        ...


class LocalDecision(BaseModel):
    """Decision of :class:`LocalTierChecker`."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str = ""
    action_type: str = ""
    resource: str = ""
    tier: int = 0


class LocalTierChecker:
    """Tier-ceiling checker used when the AGT-backed enforcer is unavailable.

    Allows any action at or below ``max_tier`` (tier 4 is always denied). Every decision
    is kept in :attr:`decisions` so tests and reports can inspect what was checked.
    """

    def __init__(self, max_tier: RiskTier | int = RiskTier.APPROVAL) -> None:
        self.max_tier = RiskTier.coerce(max_tier)
        self.decisions: list[LocalDecision] = []
        self._lock = threading.Lock()

    def check(self, action: ToolAction) -> LocalDecision:
        """Evaluate ``action`` against the ceiling."""
        tier = int(action.tier)
        allowed = tier <= int(self.max_tier) and tier < int(RiskTier.HUMAN_APPROVAL)
        reason = (
            f"tier {tier} within ceiling {int(self.max_tier)}"
            if allowed
            else f"tier {tier} exceeds ceiling {int(self.max_tier)}"
        )
        decision = LocalDecision(
            allowed=allowed,
            reason=reason,
            action_type=action.action_type,
            resource=action.resource,
            tier=tier,
        )
        with self._lock:
            self.decisions.append(decision)
        return decision


# --------------------------------------------------------------------------------------
# Reports and configuration
# --------------------------------------------------------------------------------------


class UsageTotals(BaseModel):
    """Aggregated usage."""

    model_config = ConfigDict(extra="forbid")

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0

    def add(self, usage: AgentUsage) -> None:
        """Add one run's usage."""
        self.calls += 1
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.cached_tokens += usage.cached_tokens
        self.cost_usd += usage.cost_usd
        self.latency_ms += usage.latency_ms

    def merge(self, other: UsageTotals) -> None:
        """Add another total."""
        self.calls += other.calls
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cached_tokens += other.cached_tokens
        self.cost_usd += other.cost_usd
        self.latency_ms += other.latency_ms


class TaskReport(BaseModel):
    """Per-task outcome."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    status: TaskStatus = TaskStatus.PENDING
    wave: int | None = None
    implementer_model: str = ""
    implementer_family: str = ""
    reviewer_model: str = ""
    reviewer_family: str = ""
    review_rounds: int = 0
    fix_attempts: int = 0
    verification_passed: bool | None = None
    worktree: str | None = None
    branch: str | None = None
    applied_back: bool = False
    evidence_ids: list[str] = Field(default_factory=list)
    error: str | None = None
    resumed: bool = False
    resumed_at_apply_back: bool = False
    usage: UsageTotals = Field(default_factory=UsageTotals)
    messages: list[str] = Field(default_factory=list)


class RunOutcome(StrEnum):
    """Overall run outcome."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class RunReport(BaseModel):
    """Result of :meth:`Executor.run`."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    outcome: RunOutcome
    tasks: list[TaskReport] = Field(default_factory=list)
    waves_executed: list[int] = Field(default_factory=list)
    usage: UsageTotals = Field(default_factory=UsageTotals)
    review_rounds: int = 0
    final_review_id: str | None = None
    final_review_verdict: ReviewVerdict | None = None
    post_merge_verified: bool | None = None
    post_merge_evidence_ids: list[str] = Field(default_factory=list)
    evidence_consolidated: bool = False
    release_approved: bool | None = None
    duplicate: bool = False
    handoffs_written: int = 0
    messages: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    source_hash: str = ""
    eval_config_hash: str = ""

    def task(self, task_id: str) -> TaskReport | None:
        """Report for one task."""
        return next((t for t in self.tasks if t.task_id == task_id), None)

    @property
    def resumed_tasks(self) -> list[str]:
        """Tasks skipped because they were already complete."""
        return [t.task_id for t in self.tasks if t.resumed]


class ExecutorConfig(BaseModel):
    """Run-time knobs (policy values win when a knob is ``None``)."""

    model_config = ConfigDict(extra="forbid")

    max_parallel: int | None = Field(default=None, ge=1)
    max_review_rounds: int | None = Field(default=None, ge=1)
    environment: str = "local"
    apply_back: bool = True
    apply_strategy: str = "merge"
    cleanup_worktrees: bool = True
    final_review: bool = True
    require_plan_approval: bool = True
    release_checkpoint: bool = True
    verification_timeout_seconds: float = Field(default=600.0, gt=0)
    base_ref: str | None = None
    worktrees_dir: str | None = None
    ledger_defaults: dict[str, str] = Field(default_factory=dict)
    session_id: str = ""
    brief_share: float = Field(default=DEFAULT_BRIEF_SHARE, gt=0, le=1)
    logs_dir: str = "evidence/logs"
    ignore_duplicates: bool = Field(
        default=False, description="Run even when the (source, eval-config) pair already ran."
    )
    allow_shell_verification: bool = Field(
        default=False,
        description="Run verification commands through a shell (pipes, &&, redirects). Off by "
        "default: commands are split with shlex and executed directly.",
    )
    post_merge_verification: bool = Field(
        default=True,
        description="Re-run every task's verification on the merged HEAD before the final "
        "review so test evidence exists at HEAD.",
    )
    keep_intermediate_evidence: bool = Field(
        default=False,
        description="Keep per-round worktree evidence in the canonical evidence files after a "
        "successful run instead of archiving it under evidence/logs/.",
    )


class WaveSpec(BaseModel):
    """A derived wave."""

    model_config = ConfigDict(extra="forbid")

    index: int
    tasks: list[Task]
    checkpoint: bool = False
    description: str = ""

    @property
    def task_ids(self) -> list[str]:
        """Ids in this wave."""
        return [t.id for t in self.tasks]


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _levels(tasks: Sequence[Task]) -> dict[str, int]:
    by_id = {t.id: t for t in tasks}
    level: dict[str, int] = {}
    visiting: set[str] = set()

    def visit(task_id: str) -> int:
        if task_id in level:
            return level[task_id]
        if task_id in visiting:
            raise ExecutorError(f"dependency cycle involving {task_id}")
        visiting.add(task_id)
        task = by_id[task_id]
        deps = [d for d in task.depends_on if d in by_id]
        value = 0 if not deps else 1 + max(visit(d) for d in deps)
        visiting.discard(task_id)
        level[task_id] = value
        return value

    for task in tasks:
        visit(task.id)
    return level


def check_wave_order(waves: Sequence[WaveSpec]) -> list[str]:
    """Dependency-order violations: every ``depends_on`` must sit in an earlier wave.

    Returns one message per violation (empty when the schedule is valid). Dependencies
    that are not scheduled at all are reported too, since a task cannot run before work
    that never runs.
    """
    wave_of: dict[str, int] = {}
    for wave in waves:
        for task in wave.tasks:
            wave_of[task.id] = wave.index
    problems: list[str] = []
    for wave in waves:
        for task in wave.tasks:
            for dep in task.depends_on:
                if dep not in wave_of:
                    problems.append(f"{task.id} depends on {dep}, which is not scheduled")
                elif wave_of[dep] >= wave.index:
                    problems.append(
                        f"{task.id} (wave {wave.index}) depends on {dep} "
                        f"(wave {wave_of[dep]}); dependencies must run in an earlier wave"
                    )
    return problems


def derive_waves(tasks: Sequence[Task], plan: Plan | None = None) -> list[WaveSpec]:
    """Derive execution waves.

    Precedence: waves declared in the plan (tasks the plan omits are appended in
    dependency order), then explicit ``task.wave`` values, then dependency levels
    (Kahn-style: a task runs one wave after its latest dependency). Cycles and schedules
    that place a task in the same wave as (or before) one of its dependencies raise
    :class:`ExecutorError` — the executor never runs a dependent concurrently with its
    dependency, whatever the plan says.
    """
    by_id = {t.id: t for t in tasks}
    waves: list[WaveSpec] = []
    scheduled: set[str] = set()
    if plan is not None and plan.waves:
        for wave in plan.waves:
            members = [by_id[tid] for tid in wave.task_ids if tid in by_id]
            scheduled.update(t.id for t in members)
            waves.append(
                WaveSpec(
                    index=wave.index,
                    tasks=members,
                    checkpoint=wave.checkpoint,
                    description=wave.description,
                )
            )
    leftover = [t for t in tasks if t.id not in scheduled]
    if leftover:
        next_index = (max(w.index for w in waves) + 1) if waves else 0
        if all(t.wave is not None for t in leftover) and not waves:
            groups: dict[int, list[Task]] = {}
            for task in leftover:
                assert task.wave is not None
                groups.setdefault(task.wave, []).append(task)
            for index in sorted(groups):
                waves.append(WaveSpec(index=index, tasks=groups[index]))
        else:
            levels = _levels(leftover)
            grouped: dict[int, list[Task]] = {}
            for task in leftover:
                grouped.setdefault(levels[task.id], []).append(task)
            for offset, level in enumerate(sorted(grouped)):
                waves.append(WaveSpec(index=next_index + offset, tasks=grouped[level]))
    waves.sort(key=lambda w: w.index)
    problems = check_wave_order(waves)
    if problems:
        raise ExecutorError("invalid wave order: " + "; ".join(problems))
    return waves


def router_from_policy(policy: OrgPolicy) -> RoutingPolicy:
    """Routing policy honouring the org policy's per-role tier caps."""
    caps: dict[str, str] = {}
    for role, tier in policy.models.max_tier_per_role.items():
        if tier.value in {"low", "standard", "high"}:
            caps[role] = tier.value
    return RoutingPolicy(max_tier_by_role=caps)  # type: ignore[arg-type]


def budget_engine_from_policy(
    policy: OrgPolicy, ledger: UsageLedger, change_id: str
) -> BudgetPolicyEngine:
    """Budget engine enforcing the org policy's per-change budget and execution quotas.

    The per-change budget is a ``change:<id>`` scope over the whole ledger history
    (window ``all``); a zero budget means unlimited. Quotas mirror ``cost_limits`` and the
    low/standard/high entries of ``models.max_tier_per_role``.
    """
    budgets: list[Budget] = []
    limit = policy.cost_limits.budgets.per_change_usd
    if limit > 0:
        budgets.append(
            Budget(scope_type=ScopeType.change, scope_id=change_id, limit_usd=limit, window="all")
        )
    tiers: dict[str, str] = {
        role: str(tier.value)
        for role, tier in policy.models.max_tier_per_role.items()
        if tier.value in {"low", "standard", "high"}
    }
    limits = policy.cost_limits
    quotas = Quotas(
        max_model_tier_by_role=tiers,
        max_agent_turns=limits.max_agent_turns,
        max_parallel_agents=limits.max_parallel_agents,
        max_review_rounds=limits.max_review_rounds,
        max_tool_calls=limits.max_tool_calls,
        context_ceiling_tokens=limits.context_ceiling_tokens,
    )
    return BudgetPolicyEngine(ledger, budgets=budgets, quotas=quotas)


def registry_allowlist(registry: ModelRegistry, policy: OrgPolicy) -> list[str] | None:
    """Model ids permitted by the policy allowlist (``None`` = everything)."""
    patterns = policy.models.allowlist
    if not patterns or "*" in patterns:
        return None
    return [
        e.model
        for e in registry.entries()
        if any(fnmatch(f"{e.provider}/{e.model}", p) or fnmatch(e.model, p) for p in patterns)
    ]


def complexity_for(task: Task, role: AgentRole) -> Complexity:
    """Routing complexity from the task's tier hint, else the role default."""
    hint = task.model_tier
    if hint is None:
        return default_complexity(role)
    if hint is ModelTier.LOW:
        return Complexity.low
    if hint is ModelTier.STANDARD:
        return Complexity.standard
    return Complexity.high


_COUNT_RE = {
    "passed": re.compile(r"(\d+) passed"),
    "failed": re.compile(r"(\d+) failed"),
    "skipped": re.compile(r"(\d+) skipped"),
}

_SHELL_PUNCTUATION = frozenset("();<>|&")


def shell_operators(command: str) -> list[str]:
    """Shell features in ``command`` that cannot be honoured without a shell.

    Returns the offending tokens (pipes, ``&&``/``||``/``;``, redirects, subshells,
    ``$`` expansions, backticks); an empty list means the command can be executed directly
    from its ``shlex``-split argv.
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError as exc:
        return [f"unparseable: {exc}"]
    found: list[str] = []
    for token in tokens:
        if token and set(token) <= _SHELL_PUNCTUATION:
            found.append(token)
        elif "`" in token or "$(" in token or re.search(r"\$\{?[A-Za-z_]", token):
            found.append(token)
    return found


def run_verification(
    verification: Verification,
    cwd: str | Path,
    *,
    evidence_id: str,
    timeout_seconds: float = 600.0,
    environment: str = "local",
    commit_sha: str = "",
    produced_by: str = "aisdlc.orchestration.executor",
    log_path: Path | None = None,
    report_uri: str | None = None,
    allow_shell: bool = False,
) -> tuple[TestEvidence, bool, str]:
    """Run a task's verification command; returns (evidence, passed, output).

    The command is split with :mod:`shlex` and executed **without a shell**; commands that
    need shell features (see :func:`shell_operators`) are refused — recorded as incomplete
    evidence with ``exit_code`` ``None`` — unless ``allow_shell`` is set. ``passed``
    honours ``expect_exit_code`` and ``expect_output_regex``. Counts are parsed from
    pytest-style summaries when present; otherwise the run itself counts as one
    passed/failed check.
    """
    started = datetime.now(UTC)
    exit_code: int | None = None
    output = ""
    argv: list[str] | str
    if allow_shell:
        argv = verification.command
    else:
        needs = shell_operators(verification.command)
        argv = shlex.split(verification.command) if not needs else []
        if needs:
            output = (
                f"[refused: verification command uses shell features {needs!r}; "
                "verification runs without a shell — move the logic into a script or set "
                "allow_shell_verification]"
            )
        elif not argv:
            output = "[refused: empty verification command]"
    if argv:
        try:
            proc = subprocess.run(
                argv,
                shell=allow_shell,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            exit_code = proc.returncode
            output = proc.stdout + (("\n" + proc.stderr) if proc.stderr else "")
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            output = f"{out}\n[timed out after {timeout_seconds:g}s]"
        except OSError as exc:
            output = f"[could not start verification command: {exc}]"
    finished = datetime.now(UTC)
    passed = exit_code == verification.expect_exit_code
    if passed and verification.expect_output_regex:
        passed = re.search(verification.expect_output_regex, output, re.MULTILINE) is not None
    counts = {
        k: (int(m.group(1)) if (m := rx.search(output)) else None) for k, rx in _COUNT_RE.items()
    }
    parsed = any(v is not None for v in counts.values())
    n_passed = counts["passed"] or 0 if parsed else (1 if passed else 0)
    n_failed = counts["failed"] or 0 if parsed else (0 if passed else 1)
    if parsed and not passed and n_failed == 0:
        n_failed = 1
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output, encoding="utf-8")
    evidence = TestEvidence(
        id=evidence_id,
        command=verification.command,
        exit_code=exit_code,
        passed=n_passed,
        failed=n_failed,
        skipped=counts["skipped"] or 0,
        commit_sha=commit_sha,
        environment=environment,
        produced_by=produced_by,
        started_at=started,
        finished_at=finished,
        report_uri=report_uri,
        status=EvidenceStatus.COMPLETE if exit_code is not None else EvidenceStatus.INCOMPLETE,
    )
    return evidence, passed, output


#: Archive of evidence records superseded by records produced at the merged ``HEAD``.
SUPERSEDED_EVIDENCE_FILE = "superseded-evidence.json"


def load_superseded_evidence(
    package_dir: str | Path, logs_dir: str = "evidence/logs"
) -> tuple[list[TestEvidence], list[ReviewEvidence]]:
    """Read the archive of working evidence that consolidation moved out of the package."""
    path = Path(package_dir) / logs_dir / SUPERSEDED_EVIDENCE_FILE
    if not path.is_file():
        return [], []
    data = pkgio.read_json(path)
    if not isinstance(data, dict):
        return [], []
    tests = [TestEvidence.model_validate(r) for r in data.get("tests", [])]
    reviews = [ReviewEvidence.model_validate(r) for r in data.get("reviews", [])]
    return tests, reviews


def _tail(text: str, lines: int = 40, chars: int = 4000) -> str:
    tail = "\n".join(text.strip().splitlines()[-lines:])
    return tail[-chars:]


_RUN_END_STATUS: dict[RunOutcome, HandoffStatus] = {
    RunOutcome.SUCCESS: HandoffStatus.SUCCESS,
    RunOutcome.FAILED: HandoffStatus.FAILED,
    RunOutcome.BLOCKED: HandoffStatus.BLOCKED,
    RunOutcome.SKIPPED: HandoffStatus.SKIPPED,
}


@dataclass
class _TaskWork:
    """Everything a task worker produces (merged into the package on the main thread)."""

    report: TaskReport
    tests: list[TestEvidence] = field(default_factory=list)
    reviews: list[ReviewEvidence] = field(default_factory=list)
    info: WorktreeInfo | None = None
    brief: AgentBrief | None = None
    brief_hash: str = ""
    head: str = ""


# --------------------------------------------------------------------------------------
# Executor
# --------------------------------------------------------------------------------------


class Executor:
    """Run a change package's tasks (ARCHITECTURE.md §6).

    Args:
        package: Loaded change package (``package.root`` must be set).
        policy: Effective/org policy (cost limits, model caps, allowlist).
        runner: Runner for implementer-role agents.
        ledger: Control-plane usage ledger.
        enforcer: Governance checker (``PolicyEnforcer`` or :class:`LocalTierChecker`).
        router: Routing policy (default derived from ``policy``).
        registry: Model registry (default: bundled registry).
        benchmarks: Optional benchmark service for routing.
        checkpoint: Checkpoint callback (default denies everything).
        worktrees: Worktree manager (default: ``<repo>/.aisdlc/worktrees``).
        config: Executor configuration.
        reviewer_runner: Runner for the reviewer role (default: ``runner``).
        recorder: Usage recorder used when a runner did not record its own usage.
        repo_root: Repository root (default: two levels above the package directory).
        budget_engine: Control-plane budget engine consulted before every agent run
            (default: :func:`budget_engine_from_policy`).
    """

    def __init__(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        runner: AgentRunner,
        ledger: UsageLedger,
        enforcer: ActionChecker | None = None,
        router: RoutingPolicy | None = None,
        *,
        registry: ModelRegistry | None = None,
        benchmarks: BenchmarkService | None = None,
        checkpoint: Checkpoint = deny_all_checkpoints,
        worktrees: WorktreeManager | None = None,
        config: ExecutorConfig | None = None,
        reviewer_runner: AgentRunner | None = None,
        recorder: UsageRecorder | None = None,
        repo_root: str | Path | None = None,
        budget_engine: BudgetPolicyEngine | None = None,
    ) -> None:
        if package.root is None:
            raise ExecutorError("package must be loaded from disk (package.root is None)")
        self.package = package
        self.policy = policy
        self.runner = runner
        self.reviewer_runner = reviewer_runner or runner
        self.ledger = ledger
        self.config = config or ExecutorConfig()
        self.registry = registry or ModelRegistry.default()
        self.benchmarks = benchmarks
        self.router = router or router_from_policy(policy)
        self.checkpoint = checkpoint
        self.enforcer: ActionChecker = enforcer or LocalTierChecker(
            default_tool_tier(AgentRole.IMPLEMENTER)
        )
        self.repo_root = (
            Path(repo_root).resolve()
            if repo_root is not None
            else package.root.resolve().parent.parent
        )
        self.worktrees = worktrees or WorktreeManager(
            self.repo_root, worktrees_dir=self.config.worktrees_dir
        )
        self.recorder: UsageRecorder = recorder or LedgerUsageRecorder(
            ledger,
            registry=self.registry,
            defaults=self.config.ledger_defaults,
            environment=self.config.environment,
            session_id=self.config.session_id,
        )
        self.handoffs = HandoffStore(package.root)
        self.reviewer = IndependentReviewer(
            self.reviewer_runner, environment=self.config.environment
        )
        self.tier_config = TierConfig(
            workspace_roots=[str(self.worktrees.worktrees_dir)],
        )
        self.allowlist = registry_allowlist(self.registry, policy)
        self.budget_engine = budget_engine or budget_engine_from_policy(
            policy, ledger, package.change_id
        )
        self._lock = threading.Lock()
        self._pending_checkpoint: CheckpointOutcome | None = None
        self._budget_remaining: float | None = None
        self._in_flight_usd: float = 0.0
        self._resume = True
        self._reserved_evidence: set[str] = set(self._historic_evidence_ids())
        self._reserved_findings: set[str] = set()

    # ------------------------------------------------------------------ properties
    @property
    def max_parallel(self) -> int:
        """Parallel agent bound."""
        return max(1, self.config.max_parallel or self.policy.cost_limits.max_parallel_agents)

    @property
    def max_review_rounds(self) -> int:
        """Bound on implement/verify/review rounds per task."""
        return max(1, self.config.max_review_rounds or self.policy.cost_limits.max_review_rounds)

    @property
    def change_id(self) -> str:
        """The change id."""
        return self.package.change_id

    @property
    def package_dir(self) -> Path:
        """Change package directory."""
        assert self.package.root is not None
        return self.package.root

    # ------------------------------------------------------------------ persistence
    def save_package(self) -> Path:
        """Persist the package without clobbering concurrent edits.

        The executor only *produces* state (task statuses, plan approval, evidence), so
        the save is guarded by the base fingerprint taken at load time; when a human or
        another agent edited authored artifacts meanwhile, the package is reloaded and
        only the produced state is reapplied
        (:func:`aisdlc.schema.package.save_produced_state`).
        """
        return pkgio.save_produced_state(self.package)

    # ------------------------------------------------------------------ governance
    def approval_callback(self, request: Any) -> ApprovalOutcome:
        """Approval handler for a ``PolicyEnforcer``: approves only what a checkpoint approved.

        Wire it as ``PolicyEnforcer(..., approval_handler=executor.approval_callback)``; the
        executor always asks its checkpoint before any tier >= 3 action reaches the
        enforcer, so this callback approves exactly those actions.
        """
        pending = self._pending_checkpoint
        if pending is not None and pending.approved:
            return ApprovalOutcome(
                approved=True,
                approver=pending.approver or "checkpoint",
                reason=pending.reason or "approved at orchestration checkpoint",
            )
        return ApprovalOutcome(approved=False, reason="no orchestration checkpoint approval")

    def _govern(
        self,
        action_type: str,
        resource: str,
        *,
        task_id: str | None,
        in_worktree: bool,
        description: str,
        tool_name: str = "aisdlc.orchestration",
    ) -> tuple[bool, str, ToolAction]:
        """Checkpoint (tier >= 3) then policy-check an action the executor performs."""
        action = classify_action(
            tool_name, action_type, resource, config=self.tier_config, in_worktree=in_worktree
        )
        approval: CheckpointOutcome | None = None
        if int(action.tier) >= int(RiskTier.APPROVAL):
            approval = _resolve_checkpoint(
                self.checkpoint,
                CheckpointRequest(
                    kind=CheckpointKind.TIER_ACTION,
                    change_id=self.change_id,
                    task_id=task_id,
                    description=description,
                    tier=int(action.tier),
                    action_type=action_type,
                    resource=resource,
                ),
            )
            self.handoffs.write(
                HandoffStep.CHECKPOINT,
                task_id=task_id,
                status=HandoffStatus.APPROVED if approval.approved else HandoffStatus.DENIED,
                inputs=inputs_hash(action_type, resource),
                outputs={
                    "kind": CheckpointKind.TIER_ACTION.value,
                    "tier": int(action.tier),
                    "action_type": action_type,
                    "resource": resource,
                    "approver": approval.approver,
                    "reason": approval.reason,
                },
            )
            if not approval.approved:
                return (
                    False,
                    f"checkpoint denied tier {int(action.tier)} {action_type}: {approval.reason}",
                    action,
                )
        with self._lock:
            self._pending_checkpoint = approval
            try:
                decision = self.enforcer.check(action)
            except Exception as exc:  # noqa: BLE001 - enforcement errors fail closed
                return False, f"governance error for {action_type}: {exc}", action
            finally:
                self._pending_checkpoint = None
        if not decision.allowed:
            return False, f"policy denied {action_type} on {resource}: {decision.reason}", action
        return True, decision.reason, action

    # ------------------------------------------------------------------ routing
    def _route(
        self,
        role: AgentRole,
        task: Task,
        *,
        exclude_families: Iterable[str] = (),
        escalate_from: str | None = None,
    ) -> RoutingDecision:
        tier_override: RoutingTier | None = None
        if (
            role is AgentRole.REVIEWER
            and self.policy.models.independent_review_requires_different_family
        ):
            tier_override = RoutingTier.independent_review
        if escalate_from and self.policy.models.escalation_allowed:
            tier_override = RoutingTier.escalation
        profile = TaskProfile(
            complexity=complexity_for(task, role),
            risk=self.package.intent.risk_class.value,
            role=role.value,
            exclude_families=sorted(set(exclude_families)),
            tier_override=tier_override,
            escalate_from=escalate_from,
            budget_remaining_usd=self._budget_remaining,
        )
        return self.router.route(profile, self.registry, self.benchmarks, allowlist=self.allowlist)

    def _refresh_budget(self) -> None:
        with self._lock:
            self._refresh_budget_locked()

    def _refresh_budget_locked(self) -> None:
        spent = self.ledger.total_cost({"change_id": self.change_id})
        limit = self.policy.cost_limits.budgets.per_change_usd
        remaining = max(0.0, limit - spent - self._in_flight_usd) if limit > 0 else None
        self._budget_remaining = remaining

    def _forecast_locked(self, routing: RoutingDecision) -> float:
        """Forecast for one run: the routing estimate, raised to the observed average."""
        forecast = max(0.0, float(routing.estimated_task_cost_usd))
        costs = [
            e.cost_usd for e in self.ledger.query({"change_id": self.change_id}) if e.cost_usd > 0
        ]
        if costs:
            forecast = max(forecast, sum(costs) / len(costs))
        return forecast

    def _admit(
        self,
        role: AgentRole,
        routing: RoutingDecision,
        *,
        task_id: str | None,
        round_no: int,
        context_tokens: int | None = None,
    ) -> tuple[bool, str, float]:
        """Admit one agent run through the budget engine; returns (ok, reason, forecast).

        The forecast covers this run plus every run still in flight, so parallel workers
        cannot jointly overspend. ``require_approval`` decisions go to the ``budget``
        checkpoint. On admission the forecast is reserved until :meth:`_release`.
        """
        with self._lock:
            forecast = self._forecast_locked(routing)
            tier = routing.tier.value if routing.tier.value in {"low", "standard", "high"} else None
            try:
                decision = self.budget_engine.check(
                    [f"change:{self.change_id}"],
                    forecast + self._in_flight_usd,
                    role.value,
                    tier,
                    parallel_agents=self.max_parallel,
                    review_rounds=round_no,
                    context_tokens=context_tokens,
                )
            except Exception as exc:  # noqa: BLE001 - budget errors fail closed
                return False, f"budget check failed closed: {exc}", 0.0
            task_reason = self._task_budget_reason_locked(task_id, forecast)
            if task_reason:
                decision = BudgetDecision(
                    decision=DecisionKind.deny,
                    reason=task_reason,
                    forecast_cost_usd=forecast,
                    remaining_usd=decision.remaining_usd,
                )
        if decision.decision is DecisionKind.deny:
            self._write_budget_handoff(task_id, round_no, role, decision, approved=False)
            return False, f"budget denied {role.value} run: {decision.reason}", 0.0
        if decision.decision is DecisionKind.require_approval:
            outcome = _resolve_checkpoint(
                self.checkpoint,
                CheckpointRequest(
                    kind=CheckpointKind.BUDGET,
                    change_id=self.change_id,
                    task_id=task_id,
                    description=(
                        f"{role.value} run (round {round_no}) needs budget approval: "
                        f"{decision.reason}"
                    ),
                    forecast_usd=forecast,
                    remaining_usd=decision.remaining_usd,
                ),
            )
            self._write_budget_handoff(
                task_id, round_no, role, decision, approved=outcome.approved, outcome=outcome
            )
            if not outcome.approved:
                return (
                    False,
                    f"budget checkpoint denied {role.value} run: {decision.reason} "
                    f"({outcome.reason})",
                    0.0,
                )
        with self._lock:
            self._in_flight_usd += forecast
            self._refresh_budget_locked()
        return True, decision.reason, forecast

    def _task_budget_reason_locked(self, task_id: str | None, forecast: float) -> str:
        limit = self.policy.cost_limits.budgets.per_task_usd
        if not task_id or limit <= 0:
            return ""
        spent = self.ledger.total_cost({"change_id": self.change_id, "task_id": task_id})
        if spent + forecast > limit + 1e-9:
            return (
                f"task:{task_id}: spent ${spent:.2f} + forecast ${forecast:.2f} exceeds the "
                f"per-task budget ${limit:.2f}"
            )
        return ""

    def _release(self, forecast: float) -> None:
        """Release a reservation taken by :meth:`_admit` and refresh the remaining budget."""
        with self._lock:
            self._in_flight_usd = max(0.0, self._in_flight_usd - forecast)
            self._refresh_budget_locked()

    def _write_budget_handoff(
        self,
        task_id: str | None,
        round_no: int,
        role: AgentRole,
        decision: BudgetDecision,
        *,
        approved: bool,
        outcome: CheckpointOutcome | None = None,
    ) -> None:
        self.handoffs.write(
            HandoffStep.CHECKPOINT,
            task_id=task_id,
            round=round_no,
            status=HandoffStatus.APPROVED if approved else HandoffStatus.DENIED,
            inputs=inputs_hash(role.value, round_no, decision.forecast_cost_usd),
            outputs={
                "kind": CheckpointKind.BUDGET.value,
                "role": role.value,
                "decision": decision.decision.value,
                "reason": decision.reason,
                "forecast_usd": decision.forecast_cost_usd,
                "remaining_usd": decision.remaining_usd,
                "approver": outcome.approver if outcome else "",
                "checkpoint_reason": outcome.reason if outcome else "",
            },
        )

    # ------------------------------------------------------------------ ids
    def _historic_evidence_ids(self) -> set[str]:
        """Evidence ids referenced by handoffs or archived, so they are never reused."""
        found: set[str] = set()
        for handoff in self.handoffs.load():
            single = handoff.outputs.get("evidence_id")
            if isinstance(single, str) and single:
                found.add(single)
            many = handoff.outputs.get("evidence_ids")
            if isinstance(many, list):
                found.update(str(v) for v in many if v)
        tests, reviews = load_superseded_evidence(self.package_dir, self.config.logs_dir)
        found.update(r.id for r in [*tests, *reviews])
        return found

    def _next_evidence_id(self, kind: str) -> str:
        with self._lock:
            existing = [*self.package.evidence.ids(), *self._reserved_evidence]
            new = ids.next_id("EVD", existing, evidence_kind=kind)
            self._reserved_evidence.add(new)
            return new

    def _assign_finding_ids(self, evidence: ReviewEvidence) -> ReviewEvidence:
        with self._lock:
            existing = [f.id for r in self.package.evidence.reviews for f in r.findings] + list(
                self._reserved_findings
            )
            renumbered: list[Finding] = []
            for finding in evidence.findings:
                fid = ids.next_id("FND", existing)
                existing.append(fid)
                self._reserved_findings.add(fid)
                renumbered.append(finding.model_copy(update={"id": fid}))
            return evidence.model_copy(update={"findings": renumbered})

    # ------------------------------------------------------------------ usage
    def _record(self, brief: AgentBrief, result: AgentResult) -> AgentResult:
        """Record usage unless the runner already did; price the result for the report."""
        if result.ledger_event_id is None:
            event_id = self.recorder.record(brief, result)
            result = result.model_copy(update={"ledger_event_id": event_id})
        if result.usage.cost_usd <= 0:
            build = getattr(self.recorder, "build_event", None)
            if callable(build):
                priced = build(brief, result)
                usage = result.usage.model_copy(update={"cost_usd": float(priced.cost_usd)})
                result = result.model_copy(update={"usage": usage})
        return result

    # ------------------------------------------------------------------ run
    def run(self, resume: bool = True) -> RunReport:
        """Execute every wave; see the module docstring for the full pipeline."""
        started = datetime.now(UTC)
        pkg = self.package
        source_hash = source_hash_of(pkg)
        eval_config_hash = inputs_hash(
            self.policy.model_dump(mode="json"),
            getattr(self.runner, "name", type(self.runner).__name__),
            # metadata-only knobs do not change what a run evaluates
            self.config.model_dump(
                mode="json", exclude={"ignore_duplicates", "session_id", "ledger_defaults"}
            ),
            sorted(self.registry.models()),
        )
        report = RunReport(
            change_id=self.change_id,
            outcome=RunOutcome.SUCCESS,
            started_at=started,
            source_hash=source_hash,
            eval_config_hash=eval_config_hash,
        )
        dup = self.ledger.suppress_duplicate(
            source_hash, eval_config_hash, change_id=self.change_id, kind="orchestration"
        )
        if dup.duplicate:
            report.duplicate = True
            if not resume and not self.config.ignore_duplicates:
                report.outcome = RunOutcome.SKIPPED
                report.messages.append(
                    f"duplicate run suppressed (prior run {dup.prior_run_id} at {dup.prior_ts})"
                )
                return self._finish(report)
            report.messages.append("identical inputs already ran; resuming incomplete tasks only")

        base_sha = self.worktrees.rev_parse(self.config.base_ref or "HEAD")
        first_start = self.handoffs.latest(HandoffStep.RUN_START)
        run_base = (
            str(first_start.outputs.get("base_sha") or base_sha)
            if (resume and first_start is not None)
            else base_sha
        )
        self.handoffs.write(
            HandoffStep.RUN_START,
            inputs=inputs_hash(source_hash, eval_config_hash),
            outputs={"base_sha": run_base, "resume": resume, "runner": report_runner(self.runner)},
        )

        self._resume = resume
        try:
            waves = derive_waves(pkg.tasks, pkg.plan)
        except ExecutorError as exc:
            report.outcome = RunOutcome.BLOCKED
            report.messages.append(f"plan rejected: {exc}")
            return self._finish(report)

        if not self._plan_approval(report, resume):
            return self._finish(report)

        if not pkg.tasks:
            report.messages.append("no tasks to run")
            return self._finish(report)

        completed = self._completed_tasks(resume)
        failed_or_blocked: set[str] = set()
        stop = False
        for wave in waves:
            if stop:
                break
            todo: list[Task] = []
            for task in wave.tasks:
                if task.id in completed:
                    report.tasks.append(
                        TaskReport(
                            task_id=task.id, status=TaskStatus.DONE, wave=wave.index, resumed=True
                        )
                    )
                    continue
                if task.status is TaskStatus.SKIPPED:
                    report.tasks.append(
                        TaskReport(task_id=task.id, status=TaskStatus.SKIPPED, wave=wave.index)
                    )
                    continue
                blocked_by = [d for d in task.depends_on if d in failed_or_blocked]
                if blocked_by:
                    tr = TaskReport(
                        task_id=task.id,
                        status=TaskStatus.BLOCKED,
                        wave=wave.index,
                        error=f"dependencies not completed: {', '.join(blocked_by)}",
                    )
                    report.tasks.append(tr)
                    failed_or_blocked.add(task.id)
                    self._set_task_status(task.id, TaskStatus.BLOCKED)
                    continue
                todo.append(task)
            if not todo:
                continue
            report.waves_executed.append(wave.index)
            self._refresh_budget()
            works = self._run_wave(todo, wave.index)
            for work in works:
                tr = work.report
                if tr.status is TaskStatus.DONE and self.config.apply_back:
                    self._apply_back(work)
                self._merge_work(work)
                report.tasks.append(tr)
                report.usage.merge(tr.usage)
                report.review_rounds += tr.review_rounds
                if tr.status is TaskStatus.DONE:
                    completed.add(tr.task_id)
                else:
                    failed_or_blocked.add(tr.task_id)
                    if tr.status is TaskStatus.BLOCKED:
                        stop = True
            self.save_package()
            self.handoffs.write(
                HandoffStep.WAVE,
                wave=wave.index,
                status=HandoffStatus.SUCCESS
                if all(w.report.status is TaskStatus.DONE for w in works)
                else HandoffStatus.FAILED,
                inputs=inputs_hash(wave.task_ids),
                outputs={"tasks": {w.report.task_id: w.report.status.value for w in works}},
            )
            if wave.checkpoint and not stop:
                outcome = _resolve_checkpoint(
                    self.checkpoint,
                    CheckpointRequest(
                        kind=CheckpointKind.WAVE,
                        change_id=self.change_id,
                        description=f"wave {wave.index} finished; continue to the next wave?",
                        wave=wave.index,
                    ),
                )
                self.handoffs.write(
                    HandoffStep.CHECKPOINT,
                    wave=wave.index,
                    status=HandoffStatus.APPROVED if outcome.approved else HandoffStatus.DENIED,
                    outputs={"kind": CheckpointKind.WAVE.value, "reason": outcome.reason},
                )
                if not outcome.approved:
                    report.messages.append(
                        f"stopped at wave {wave.index} checkpoint: {outcome.reason}"
                    )
                    report.outcome = RunOutcome.BLOCKED
                    stop = True

        statuses = {t.status for t in report.tasks}
        if report.outcome is RunOutcome.SUCCESS:
            if TaskStatus.FAILED in statuses:
                report.outcome = RunOutcome.FAILED
            elif TaskStatus.BLOCKED in statuses:
                report.outcome = RunOutcome.BLOCKED

        finished = {TaskStatus.DONE, TaskStatus.SKIPPED}
        all_done = (
            report.outcome is RunOutcome.SUCCESS
            and bool(pkg.tasks)
            and all(t.status in finished for t in pkg.tasks)
        )
        already_reviewed = (
            not report.waves_executed
            and (prior := self.handoffs.latest(HandoffStep.FINAL_REVIEW)) is not None
            and prior.status is HandoffStatus.SUCCESS
        )
        if already_reviewed and prior is not None:
            report.final_review_id = str(prior.outputs.get("evidence_id") or "") or None
            report.final_review_verdict = ReviewVerdict.APPROVED
            report.messages.append("final review already approved; not repeated")
        if (
            all_done
            and not already_reviewed
            and self.config.apply_back
            and self.config.post_merge_verification
        ):
            report.post_merge_verified = self._post_merge_verification(report)
            if not report.post_merge_verified:
                report.outcome = RunOutcome.FAILED
                report.messages.append("post-merge verification failed on the merged HEAD")
        if (
            all_done
            and not already_reviewed
            and report.outcome is RunOutcome.SUCCESS
            and self.config.final_review
            and self.config.apply_back
        ):
            review = self.final_review(base_sha=run_base, task_reports=report.tasks)
            if review is None:
                report.outcome = RunOutcome.BLOCKED
                report.messages.append("final review could not run (see final_review handoff)")
            else:
                report.final_review_id = review.evidence.id
                report.final_review_verdict = review.evidence.verdict
                report.usage.add(review.result.usage)
                report.review_rounds += 1
                if not review.approved:
                    report.outcome = RunOutcome.FAILED
                    report.messages.append(
                        f"final review {review.evidence.verdict.value}: "
                        f"{len(review.blocking)} grounded blocking finding(s)"
                    )
        if (
            report.outcome is RunOutcome.SUCCESS
            and all_done
            and self.config.apply_back
            and not self.config.keep_intermediate_evidence
        ):
            report.evidence_consolidated = self._consolidate_evidence(report)
        if report.outcome is RunOutcome.SUCCESS and all_done and self.config.release_checkpoint:
            outcome = _resolve_checkpoint(
                self.checkpoint,
                CheckpointRequest(
                    kind=CheckpointKind.RELEASE,
                    change_id=self.change_id,
                    description="all tasks done and reviewed; approve for release gating?",
                ),
            )
            report.release_approved = outcome.approved
            self.handoffs.write(
                HandoffStep.RELEASE,
                status=HandoffStatus.APPROVED if outcome.approved else HandoffStatus.DENIED,
                outputs={"approver": outcome.approver, "reason": outcome.reason},
            )
        return self._finish(report)

    def run_change(self, resume: bool = True) -> RunReport:
        """Alias of :meth:`run` under the name used in ARCHITECTURE.md §6."""
        return self.run(resume=resume)

    def _finish(self, report: RunReport) -> RunReport:
        report.finished_at = datetime.now(UTC)
        self._write_cost_evidence()
        self.save_package()
        self.handoffs.write(
            HandoffStep.RUN_END,
            status=_RUN_END_STATUS[report.outcome],
            inputs=inputs_hash(report.source_hash, report.eval_config_hash),
            outputs={
                "outcome": report.outcome.value,
                "tasks": {t.task_id: t.status.value for t in report.tasks},
            },
            usage=report.usage.model_dump(mode="json"),
        )
        report.handoffs_written = len(self.handoffs.load())
        return report

    # ------------------------------------------------------------------ plan approval
    def _plan_approval(self, report: RunReport, resume: bool) -> bool:
        pkg = self.package
        if not self.config.require_plan_approval:
            return True
        if pkg.plan is not None and pkg.plan.approved_by:
            return True
        if resume and self.handoffs.plan_approved() is not None:
            return True
        outcome = _resolve_checkpoint(
            self.checkpoint,
            CheckpointRequest(
                kind=CheckpointKind.PLAN_APPROVAL,
                change_id=self.change_id,
                description=(
                    f"approve the plan for {self.change_id} "
                    f"({len(pkg.tasks)} task(s), {len(pkg.plan.waves) if pkg.plan else 0} wave(s))?"
                ),
            ),
        )
        self.handoffs.write(
            HandoffStep.PLAN_APPROVAL,
            status=HandoffStatus.APPROVED if outcome.approved else HandoffStatus.DENIED,
            inputs=inputs_hash([t.id for t in pkg.tasks]),
            outputs={"approver": outcome.approver, "reason": outcome.reason},
        )
        if not outcome.approved:
            report.outcome = RunOutcome.BLOCKED
            report.messages.append(f"plan approval denied: {outcome.reason}")
            return False
        plan = pkg.plan or Plan()
        pkg.plan = plan.model_copy(
            update={
                "approved_by": outcome.approver or "checkpoint",
                "approved_at": datetime.now(UTC),
            }
        )
        self.save_package()
        return True

    def _completed_tasks(self, resume: bool) -> set[str]:
        """Tasks to skip: ``done`` in ``tasks.md`` or a successful ``task_done`` handoff.

        A non-resumed run reruns everything (task statuses are re-derived from the run).
        """
        if not resume:
            return set()
        done = {t.id for t in self.package.tasks if t.status is TaskStatus.DONE}
        return done | self.handoffs.completed_tasks()

    # ------------------------------------------------------------------ waves
    def _run_wave(self, tasks: list[Task], wave_index: int) -> list[_TaskWork]:
        workers = min(self.max_parallel, len(tasks))
        results: dict[str, _TaskWork] = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="aisdlc-task") as pool:
            futures: dict[Future[_TaskWork], Task] = {
                pool.submit(self._task_pipeline, task, wave_index): task for task in tasks
            }
            for future in as_completed(futures):
                task = futures[future]
                try:
                    results[task.id] = future.result()
                except Exception as exc:  # noqa: BLE001 - one task must not kill the wave
                    results[task.id] = _TaskWork(
                        report=TaskReport(
                            task_id=task.id,
                            status=TaskStatus.FAILED,
                            wave=wave_index,
                            error=f"executor error: {exc}",
                        )
                    )
                    self.handoffs.write(
                        HandoffStep.TASK_FAILED,
                        task_id=task.id,
                        status=HandoffStatus.FAILED,
                        wave=wave_index,
                        notes=str(exc)[:500],
                    )
        return [results[t.id] for t in tasks]

    def _set_task_status(self, task_id: str, status: TaskStatus) -> None:
        for task in self.package.tasks:
            if task.id == task_id:
                task.status = status

    def _merge_work(self, work: _TaskWork) -> None:
        pkg = self.package
        pkg.evidence.tests.extend(work.tests)
        pkg.evidence.reviews.extend(work.reviews)
        self._set_task_status(work.report.task_id, work.report.status)

    # ------------------------------------------------------------------ per task
    def run_task(
        self, task_id: str, *, apply_back: bool | None = None, resume: bool = True
    ) -> TaskReport:
        """Run one task end to end (worktree, implement, verify, review, apply-back).

        With ``resume`` a task whose apply-back was denied earlier and whose branch is
        unchanged resumes at apply-back instead of being re-implemented.
        """
        task = self.package.task(task_id)
        if task is None:
            raise ExecutorError(f"unknown task {task_id}")
        self._resume = resume
        self._refresh_budget()
        wave = self.package.plan.wave_of(task_id) if self.package.plan else task.wave
        work = self._task_pipeline(task, wave)
        do_apply = self.config.apply_back if apply_back is None else apply_back
        if work.report.status is TaskStatus.DONE and do_apply:
            self._apply_back(work)
        self._merge_work(work)
        self._write_cost_evidence()
        self.save_package()
        return work.report

    def _task_pipeline(self, task: Task, wave_index: int | None) -> _TaskWork:
        report = TaskReport(task_id=task.id, status=TaskStatus.IN_PROGRESS, wave=wave_index)
        work = _TaskWork(report=report)
        pkg = self.package

        if self._resume:
            pending = self._pending_apply_back(task.id)
            if pending is not None:
                return self._resume_apply_back(work, pending)

        try:
            info = self.worktrees.create(self.change_id, task.id, base=self.config.base_ref)
        except Exception as exc:  # noqa: BLE001
            return self._fail(work, TaskStatus.FAILED, f"worktree creation failed: {exc}")
        work.info = info
        report.worktree = info.path
        report.branch = info.branch

        try:
            impl_routing = self._route(AgentRole.IMPLEMENTER, task)
            reviewer_routing = self._route(
                AgentRole.REVIEWER, task, exclude_families=[impl_routing.family]
            )
        except RoutingError as exc:
            return self._fail(work, TaskStatus.BLOCKED, f"routing failed: {exc}")
        report.implementer_model = impl_routing.model
        report.implementer_family = impl_routing.family
        report.reviewer_model = reviewer_routing.model
        report.reviewer_family = reviewer_routing.family
        self.handoffs.write(
            HandoffStep.ROUTE,
            task_id=task.id,
            wave=wave_index,
            inputs=inputs_hash(task.model_dump(mode="json"), pkg.intent.risk_class.value),
            outputs={
                "implementer": impl_routing.model_dump(mode="json"),
                "reviewer": reviewer_routing.model_dump(mode="json"),
            },
        )

        ok, reason, _ = self._govern(
            "write",
            info.path,
            task_id=task.id,
            in_worktree=True,
            description=f"{task.id}: implementer writes inside worktree {info.path}",
        )
        if not ok:
            return self._fail(work, TaskStatus.BLOCKED, reason)

        feedback: list[str] = []
        previous_findings: list[Finding] = []
        last_reviewed_head: str | None = None
        ceiling = self.policy.cost_limits.context_ceiling_tokens
        final_status: TaskStatus | None = None
        error: str | None = None

        for round_no in range(1, self.max_review_rounds + 1):
            brief = build_brief(
                pkg,
                task,
                role=AgentRole.IMPLEMENTER,
                routing=impl_routing,
                worktree=info.path,
                context=feedback,
                context_ceiling_tokens=ceiling,
                brief_share=self.config.brief_share,
                round=round_no,
            )
            work.brief = brief
            work.brief_hash = brief.content_hash()
            step = HandoffStep.IMPLEMENT if round_no == 1 else HandoffStep.FIX
            self.handoffs.write(
                HandoffStep.BRIEF,
                task_id=task.id,
                wave=wave_index,
                round=round_no,
                inputs=brief.content_hash(),
                outputs={"tokens": brief.estimated_tokens, "warnings": brief.warnings},
            )
            ok, reason, forecast = self._admit(
                AgentRole.IMPLEMENTER,
                impl_routing,
                task_id=task.id,
                round_no=round_no,
                context_tokens=brief.estimated_tokens,
            )
            if not ok:
                final_status, error = TaskStatus.BLOCKED, reason
                break
            try:
                result = self._record(brief, self.runner.run(brief))
            finally:
                self._release(forecast)
            report.usage.add(result.usage)
            self.handoffs.write(
                step,
                task_id=task.id,
                wave=wave_index,
                round=round_no,
                status=HandoffStatus(result.status.value),
                inputs=brief.content_hash(),
                outputs={
                    "summary": result.summary,
                    "files_changed": result.files_changed,
                    "model": result.usage.model or impl_routing.model,
                },
                usage=result.usage.model_dump(mode="json"),
            )
            if result.status is RunStatus.BLOCKED:
                final_status, error = TaskStatus.BLOCKED, f"implementer blocked: {result.summary}"
                break
            if result.status is RunStatus.FAILED:
                report.fix_attempts += 1
                feedback = [f"Round {round_no}: the implementer run failed: {result.summary}"]
                error = f"implementer failed: {result.summary}"
                continue

            ok, reason, _ = self._govern(
                "git_commit",
                info.path,
                task_id=task.id,
                in_worktree=True,
                description=f"{task.id}: commit round {round_no} in worktree",
            )
            if not ok:
                final_status, error = TaskStatus.BLOCKED, reason
                break
            commit = self.worktrees.commit_all(info, f"{task.id}: {task.title} (round {round_no})")
            head = commit or self.worktrees.head_sha(info.path)
            work.head = head

            if task.verification is not None:
                ok, reason = self._govern_verification(task, in_worktree=True)
                if not ok:
                    final_status, error = TaskStatus.BLOCKED, reason
                    break
                evidence_id = self._next_evidence_id("tests")
                rel_log = f"{self.config.logs_dir}/{task.id}-r{round_no}.log"
                evidence, passed, output = run_verification(
                    task.verification,
                    info.path,
                    evidence_id=evidence_id,
                    timeout_seconds=self.config.verification_timeout_seconds,
                    environment=self.config.environment,
                    commit_sha=head,
                    log_path=self.package_dir / rel_log,
                    report_uri=rel_log,
                    allow_shell=self.config.allow_shell_verification,
                )
                work.tests.append(evidence)
                report.evidence_ids.append(evidence.id)
                report.verification_passed = passed
                self.handoffs.write(
                    HandoffStep.VERIFY,
                    task_id=task.id,
                    wave=wave_index,
                    round=round_no,
                    status=HandoffStatus.SUCCESS if passed else HandoffStatus.FAILED,
                    inputs=inputs_hash(task.verification.model_dump(), head),
                    outputs={
                        "evidence_id": evidence.id,
                        "exit_code": evidence.exit_code,
                        "passed": passed,
                        "log": rel_log,
                        "head": head,
                    },
                )
                if not passed:
                    report.fix_attempts += 1
                    feedback = [
                        f"Round {round_no}: verification `{task.verification.command}` failed "
                        f"(exit {evidence.exit_code}, expected "
                        f"{task.verification.expect_exit_code}). "
                        f"Output tail:\n```\n{_tail(output)}\n```\nFix the implementation so the "
                        "verification passes."
                    ]
                    error = f"verification failed (exit {evidence.exit_code})"
                    continue

            scope: list[str] | None = None
            diff = self.worktrees.diff(info)
            if last_reviewed_head is not None:
                changed = self.worktrees.diff_between(last_reviewed_head, head, cwd=info.path)
                scope = changed.file_paths or None
                if scope:
                    diff = self.worktrees.diff(info, paths=scope)
            ok, reason, forecast = self._admit(
                AgentRole.REVIEWER, reviewer_routing, task_id=task.id, round_no=round_no
            )
            if not ok:
                final_status, error = TaskStatus.BLOCKED, reason
                break
            try:
                review = self._review_task(
                    brief,
                    diff,
                    routing=reviewer_routing,
                    implementer_family=impl_routing.family,
                    round_no=round_no,
                    scope=scope,
                    previous_findings=previous_findings,
                )
            finally:
                self._release(forecast)
            report.usage.add(review.result.usage)
            report.review_rounds += 1
            work.reviews.append(review.evidence)
            report.evidence_ids.append(review.evidence.id)
            self.handoffs.write(
                HandoffStep.REVIEW,
                task_id=task.id,
                wave=wave_index,
                round=round_no,
                status=HandoffStatus.SUCCESS if review.approved else HandoffStatus.FAILED,
                inputs=review.brief_hash,
                outputs={
                    "evidence_id": review.evidence.id,
                    "verdict": review.evidence.verdict.value,
                    "findings": len(review.evidence.findings),
                    "blocking": [f.id for f in review.blocking],
                    "scope": review.scope,
                    "reviewer_family": review.evidence.reviewer_model_family,
                    "head": diff.head,
                    "report": review.evidence.report_uri,
                },
                usage=review.result.usage.model_dump(mode="json"),
            )
            last_reviewed_head = diff.head
            if review.approved:
                final_status, error = TaskStatus.DONE, None
                break
            report.fix_attempts += 1
            previous_findings = review.blocking
            if review.evidence.is_complete:
                lines = [
                    f"- {f.id} [{f.severity.value}] {f.file}:{f.line} {f.title}: {f.detail}"
                    for f in review.blocking
                ]
                feedback = [
                    f"Round {round_no}: independent review requested changes. Address every "
                    "blocking finding below:\n" + "\n".join(lines)
                ]
                error = f"review requested changes ({len(review.blocking)} blocking finding(s))"
            else:
                feedback = [f"Round {round_no}: review incomplete: {review.evidence.produced_by}"]
                error = "review incomplete"

        if final_status is None:
            final_status = TaskStatus.FAILED
            error = f"max review rounds ({self.max_review_rounds}) exhausted: {error}"
        if final_status is TaskStatus.DONE:
            report.status = TaskStatus.DONE
            report.error = None
            return work
        return self._fail(work, final_status, error or "task failed")

    def _review_task(
        self,
        brief: AgentBrief,
        diff: DiffSummary,
        *,
        routing: RoutingDecision,
        implementer_family: str,
        round_no: int,
        scope: list[str] | None,
        previous_findings: Sequence[Finding],
    ) -> ReviewResult:
        """Run one independent review and write its report under ``evidence/logs``."""
        evidence_id = self._next_evidence_id("reviews")
        report_uri = f"{self.config.logs_dir}/{evidence_id}.json"
        review = self.reviewer.review(
            brief,
            diff,
            routing=routing,
            implementer_family=implementer_family,
            evidence_id=evidence_id,
            round=round_no,
            scope=scope,
            previous_findings=previous_findings,
            report_uri=report_uri,
        )
        reviewer_brief = brief.model_copy(
            update={"role": AgentRole.REVIEWER, "routing": routing, "round": round_no}
        )
        result = self._record(reviewer_brief, review.result)
        evidence = self._assign_finding_ids(review.evidence)
        review = review.model_copy(update={"evidence": evidence, "result": result})
        self._write_review_report(review, diff, report_uri)
        return review

    def _write_review_report(self, review: ReviewResult, diff: DiffSummary, rel: str) -> None:
        """Durable reviewer output: evidence, raw findings/verdict, runner output, diff refs."""
        result = review.result
        document = {
            "evidence": review.evidence.model_dump(mode="json"),
            "brief_hash": review.brief_hash,
            "scope": review.scope,
            "diff": {"base": diff.base, "head": diff.head, "files": diff.file_paths},
            "result": {
                "status": result.status.value,
                "summary": result.summary,
                "verdict": result.verdict,
                "findings": result.findings,
                "runner": result.runner,
                "exit_code": result.exit_code,
                "ledger_event_id": result.ledger_event_id,
                "usage": result.usage.model_dump(mode="json"),
                "raw_output": result.raw_output,
            },
        }
        pkgio.write_json(self.package_dir / rel, document)

    def _govern_verification(self, task: Task, *, in_worktree: bool) -> tuple[bool, str]:
        """Classify a task's verification command and govern it as the classified action.

        ``tasks.md`` is writable by agents, so the command is never trusted as a generic
        tier-2 ``execute``: it is classified with the governance shell classifier (highest
        tier wins) and refused outright at tier >= 3 before the enforcer is consulted.
        """
        assert task.verification is not None
        command = task.verification.command
        mapped = classify_shell_command(command)
        action = classify_action(
            "aisdlc.orchestration",
            mapped.action_type,
            mapped.resource or command,
            {"command": command, "_reason": mapped.reason},
            config=self.tier_config,
            in_worktree=in_worktree,
        )
        if int(action.tier) >= int(RiskTier.APPROVAL):
            return (
                False,
                f"verification command `{command}` classified as tier {int(action.tier)} "
                f"{mapped.action_type} ({mapped.reason}); verification must be a local "
                "tier <= 2 command",
            )
        ok, reason, _ = self._govern(
            mapped.action_type,
            mapped.resource or command,
            task_id=task.id,
            in_worktree=in_worktree,
            description=f"{task.id}: run verification `{command}` ({mapped.action_type})",
        )
        return ok, reason

    def _fail(self, work: _TaskWork, status: TaskStatus, error: str) -> _TaskWork:
        work.report.status = status
        work.report.error = error
        self.handoffs.write(
            HandoffStep.TASK_FAILED,
            task_id=work.report.task_id,
            wave=work.report.wave,
            status=HandoffStatus.BLOCKED if status is TaskStatus.BLOCKED else HandoffStatus.FAILED,
            outputs={"error": error, "rounds": work.report.review_rounds},
            usage=work.report.usage.model_dump(mode="json"),
            notes=error[:200],
        )
        return work

    # ------------------------------------------------------------------ apply back
    def _apply_back(self, work: _TaskWork) -> None:
        """Merge the task branch onto the repository branch (tier-3; checkpointed)."""
        report = work.report
        info = work.info
        if info is None:
            return
        target = self.worktrees.current_branch()
        ok, reason, _ = self._govern(
            "modify_shared_state",
            f"branch:{target}",
            task_id=report.task_id,
            in_worktree=False,
            description=(
                f"{report.task_id}: apply branch {info.branch} back onto {target} "
                f"({self.config.apply_strategy})"
            ),
        )
        if not ok:
            report.status = TaskStatus.BLOCKED
            report.error = reason
            report.messages.append("worktree kept for later apply-back")
            head = work.head or self.worktrees.head_sha(info.path)
            self.handoffs.write(
                HandoffStep.APPLY_BACK,
                task_id=report.task_id,
                wave=report.wave,
                status=HandoffStatus.BLOCKED,
                inputs=inputs_hash(info.branch, target),
                outputs={
                    "branch": info.branch,
                    "target": target,
                    "reason": reason,
                    "head": head,
                    "verified": report.verification_passed is not False,
                    "brief_hash": work.brief_hash,
                    "evidence_ids": report.evidence_ids,
                    "review_rounds": report.review_rounds,
                    "fix_attempts": report.fix_attempts,
                    "implementer_model": report.implementer_model,
                    "implementer_family": report.implementer_family,
                    "reviewer_model": report.reviewer_model,
                    "reviewer_family": report.reviewer_family,
                },
                usage=report.usage.model_dump(mode="json"),
                notes="resumable: branch is verified and approved; apply-back pending",
            )
            return
        result = self.worktrees.apply_back(
            info, strategy=self.config.apply_strategy, message=f"{report.task_id}: apply back"
        )
        self.handoffs.write(
            HandoffStep.APPLY_BACK,
            task_id=report.task_id,
            wave=report.wave,
            status=HandoffStatus.SUCCESS if result.ok else HandoffStatus.FAILED,
            inputs=inputs_hash(info.branch, target),
            outputs=result.model_dump(mode="json"),
        )
        if not result.ok:
            report.status = TaskStatus.FAILED
            report.error = f"apply-back failed: {result.message}" + (
                f" (conflicts: {', '.join(result.conflicts)})" if result.conflicts else ""
            )
            return
        report.applied_back = True
        self.handoffs.write(
            HandoffStep.TASK_DONE,
            task_id=report.task_id,
            wave=report.wave,
            status=HandoffStatus.SUCCESS,
            inputs=work.brief_hash or (work.brief.content_hash() if work.brief else ""),
            outputs={
                "commit": result.commit,
                "branch": info.branch,
                "head": work.head,
                "evidence_ids": report.evidence_ids,
                "review_rounds": report.review_rounds,
                "resumed_at_apply_back": report.resumed_at_apply_back,
            },
            usage=report.usage.model_dump(mode="json"),
        )
        if self.config.cleanup_worktrees:
            try:
                self.worktrees.remove(info)
            except Exception as exc:  # noqa: BLE001 - cleanup is best effort
                report.messages.append(f"worktree cleanup failed: {exc}")

    def _pending_apply_back(self, task_id: str) -> Handoff | None:
        """The task's blocked ``apply_back`` handoff when its branch is still at that head.

        A task resumes at apply-back only if its last decisive handoff is a blocked
        apply-back that recorded a verified, approved head and the task branch still
        points at that head (nothing was re-implemented or edited since).
        """
        decisive = {
            HandoffStep.APPLY_BACK,
            HandoffStep.TASK_DONE,
            HandoffStep.TASK_FAILED,
            HandoffStep.IMPLEMENT,
            HandoffStep.FIX,
        }
        last: Handoff | None = None
        for handoff in self.handoffs.for_task(task_id):
            if handoff.step in decisive:
                last = handoff
        if (
            last is None
            or last.step is not HandoffStep.APPLY_BACK
            or last.status is not HandoffStatus.BLOCKED
        ):
            return None
        head = str(last.outputs.get("head") or "")
        if not head or not last.outputs.get("verified", False):
            return None
        branch = branch_name(self.change_id, task_id)
        if not self.worktrees.branch_exists(branch):
            return None
        try:
            current = self.worktrees.rev_parse(branch)
        except Exception:  # noqa: BLE001 - unreadable branch: re-run the pipeline
            return None
        return last if current == head else None

    def _resume_apply_back(self, work: _TaskWork, pending: Handoff) -> _TaskWork:
        """Rebuild the task work from the blocked apply-back handoff (no agent runs)."""
        report = work.report
        outputs = pending.outputs
        try:
            info = self.worktrees.create(self.change_id, report.task_id, base=self.config.base_ref)
        except Exception as exc:  # noqa: BLE001
            return self._fail(work, TaskStatus.FAILED, f"worktree creation failed: {exc}")
        work.info = info
        work.head = str(outputs.get("head") or "")
        work.brief_hash = str(outputs.get("brief_hash") or "")
        report.worktree = info.path
        report.branch = info.branch
        report.status = TaskStatus.DONE
        report.error = None
        report.resumed_at_apply_back = True
        report.verification_passed = True
        report.evidence_ids = [str(v) for v in outputs.get("evidence_ids", []) if v]
        report.review_rounds = int(outputs.get("review_rounds") or 0)
        report.fix_attempts = int(outputs.get("fix_attempts") or 0)
        report.implementer_model = str(outputs.get("implementer_model") or "")
        report.implementer_family = str(outputs.get("implementer_family") or "")
        report.reviewer_model = str(outputs.get("reviewer_model") or "")
        report.reviewer_family = str(outputs.get("reviewer_family") or "")
        report.messages.append(
            f"resumed at apply-back: branch {info.branch} already verified and approved at "
            f"{work.head[:12]} (handoff {pending.seq:04d})"
        )
        return work

    # ------------------------------------------------------------------ post-merge verification
    def _post_merge_verification(self, report: RunReport) -> bool:
        """Re-run every task's verification on the merged ``HEAD`` (evidence at HEAD).

        Returns ``True`` when every verification passed (or no task has one). Each run is
        governed like an in-worktree verification and recorded as ``TestEvidence`` with
        ``commit_sha`` = HEAD and a ``merged_verify`` handoff.
        """
        head = self.worktrees.head_sha()
        all_ok = True
        for task in self.package.tasks:
            if task.verification is None or task.status is TaskStatus.SKIPPED:
                continue
            ok, reason = self._govern_verification(task, in_worktree=False)
            if not ok:
                self.handoffs.write(
                    HandoffStep.MERGED_VERIFY,
                    task_id=task.id,
                    status=HandoffStatus.BLOCKED,
                    outputs={"commit": head, "reason": reason},
                    notes=reason[:200],
                )
                report.messages.append(f"{task.id}: post-merge verification refused: {reason}")
                all_ok = False
                continue
            evidence_id = self._next_evidence_id("tests")
            rel_log = f"{self.config.logs_dir}/{task.id}-merged.log"
            evidence, passed, _ = run_verification(
                task.verification,
                self.repo_root,
                evidence_id=evidence_id,
                timeout_seconds=self.config.verification_timeout_seconds,
                environment=self.config.environment,
                commit_sha=head,
                produced_by="aisdlc.orchestration.executor:post-merge",
                log_path=self.package_dir / rel_log,
                report_uri=rel_log,
                allow_shell=self.config.allow_shell_verification,
            )
            self.package.evidence.tests.append(evidence)
            report.post_merge_evidence_ids.append(evidence.id)
            task_report = report.task(task.id)
            if task_report is not None:
                task_report.evidence_ids.append(evidence.id)
            self.handoffs.write(
                HandoffStep.MERGED_VERIFY,
                task_id=task.id,
                status=HandoffStatus.SUCCESS if passed else HandoffStatus.FAILED,
                inputs=inputs_hash(task.verification.model_dump(), head),
                outputs={
                    "evidence_id": evidence.id,
                    "exit_code": evidence.exit_code,
                    "passed": passed,
                    "log": rel_log,
                    "commit": head,
                },
            )
            if not passed:
                report.messages.append(
                    f"{task.id}: verification failed on merged HEAD (exit {evidence.exit_code})"
                )
                all_ok = False
        self.package.save()
        return all_ok

    # ------------------------------------------------------------------ evidence consolidation
    def _consolidate_evidence(self, report: RunReport) -> bool:
        """Keep only evidence produced at ``HEAD``; archive the rest under ``evidence/logs``.

        Runs after a fully successful run so the canonical evidence files describe the
        merged ``HEAD`` (post-merge test evidence, final review, cost). Superseded records
        stay readable through :func:`load_superseded_evidence` and keep their ids reserved.
        """
        head = self.worktrees.head_sha()
        evidence = self.package.evidence
        keep_tests = [r for r in evidence.tests if r.commit_sha == head]
        keep_reviews = [r for r in evidence.reviews if r.commit_sha == head]
        old_tests = [r for r in evidence.tests if r.commit_sha != head]
        old_reviews = [r for r in evidence.reviews if r.commit_sha != head]
        if not old_tests and not old_reviews:
            return False
        if not keep_reviews and self.config.final_review:
            report.messages.append("evidence not consolidated: no review evidence at HEAD")
            return False
        path = self.package_dir / self.config.logs_dir / SUPERSEDED_EVIDENCE_FILE
        archived_tests, archived_reviews = load_superseded_evidence(
            self.package_dir, self.config.logs_dir
        )
        known = {r.id for r in [*archived_tests, *archived_reviews]}
        archived_tests.extend(r for r in old_tests if r.id not in known)
        archived_reviews.extend(r for r in old_reviews if r.id not in known)
        pkgio.write_json(
            path,
            {
                "head": head,
                "archived_at": datetime.now(UTC).isoformat(),
                "tests": [r.model_dump(mode="json") for r in archived_tests],
                "reviews": [r.model_dump(mode="json") for r in archived_reviews],
            },
        )
        evidence.tests = keep_tests
        evidence.reviews = keep_reviews
        self._reserved_evidence.update(r.id for r in [*old_tests, *old_reviews])
        report.messages.append(
            f"evidence consolidated at {head[:12]}: {len(old_tests)} test and "
            f"{len(old_reviews)} review record(s) archived to "
            f"{self.config.logs_dir}/{SUPERSEDED_EVIDENCE_FILE}"
        )
        return True

    # ------------------------------------------------------------------ final review
    def final_review(
        self,
        *,
        base_sha: str | None = None,
        task_reports: Sequence[TaskReport] = (),
    ) -> ReviewResult | None:
        """Whole-branch review of everything applied since ``base_sha`` (default run start)."""
        pkg = self.package
        base = base_sha
        if base is None:
            first = self.handoffs.latest(HandoffStep.RUN_START)
            base = str(first.outputs.get("base_sha")) if first is not None else None
        if base is None:
            base = self.worktrees.rev_parse(self.config.base_ref or "HEAD")
        diff = self.worktrees.diff_between(base, "HEAD")
        families = {t.implementer_family for t in task_reports if t.implementer_family}
        if not families:
            families = {
                r.implementer_model_family
                for r in pkg.evidence.reviews
                if r.implementer_model_family
            }
        synthetic = whole_change_task(
            pkg.change_id, pkg.intent.title, [t.id for t in pkg.tasks]
        ).model_copy(update={"requirement_ids": [r.id for r in pkg.requirements]})
        try:
            routing = self._route(AgentRole.REVIEWER, synthetic, exclude_families=families)
        except RoutingError as exc:
            self.handoffs.write(
                HandoffStep.FINAL_REVIEW, status=HandoffStatus.BLOCKED, notes=str(exc)[:200]
            )
            return None
        brief = build_brief(
            pkg,
            synthetic,
            role=AgentRole.REVIEWER,
            routing=routing,
            worktree=str(self.repo_root),
            context_ceiling_tokens=self.policy.cost_limits.context_ceiling_tokens,
            brief_share=self.config.brief_share,
        )
        implementer_family = ",".join(sorted(families)) if families else ""
        ok, reason, forecast = self._admit(AgentRole.REVIEWER, routing, task_id=None, round_no=1)
        if not ok:
            self.handoffs.write(
                HandoffStep.FINAL_REVIEW, status=HandoffStatus.BLOCKED, notes=reason[:200]
            )
            return None
        try:
            review = self._review_task(
                brief,
                diff,
                routing=routing,
                implementer_family=implementer_family,
                round_no=1,
                scope=None,
                previous_findings=[],
            )
        finally:
            self._release(forecast)
        pkg.evidence.reviews.append(review.evidence)
        self.handoffs.write(
            HandoffStep.FINAL_REVIEW,
            status=HandoffStatus.SUCCESS if review.approved else HandoffStatus.FAILED,
            inputs=review.brief_hash,
            outputs={
                "evidence_id": review.evidence.id,
                "verdict": review.evidence.verdict.value,
                "base": diff.base,
                "head": diff.head,
                "files": diff.file_paths,
                "blocking": [f.id for f in review.blocking],
            },
            usage=review.result.usage.model_dump(mode="json"),
        )
        return review

    # ------------------------------------------------------------------ cost evidence
    def _write_cost_evidence(self) -> None:
        limit = self.policy.cost_limits.budgets.per_change_usd
        head = ""
        try:
            head = self.worktrees.head_sha()
        except Exception:  # noqa: BLE001 - evidence must still be written
            head = ""
        self.package.evidence.cost = self.ledger.cost_evidence(
            self.change_id,
            budget_usd=limit if limit > 0 else None,
            commit_sha=head,
            environment=self.config.environment,
            produced_by="aisdlc.orchestration.executor",
        )


def source_hash_of(pkg: ChangePackage) -> str:
    """Hash of the authored inputs of a run (task statuses and approvals excluded).

    Two runs over the same intent, requirements, assumptions, decisions, interfaces, plan
    waves and task definitions share a source hash, so the ledger's duplicate register
    can suppress re-evaluating identical inputs.
    """
    tasks = [t.model_dump(mode="json", exclude={"status"}) for t in pkg.tasks]
    plan = (
        pkg.plan.model_dump(mode="json", exclude={"approved_by", "approved_at"})
        if pkg.plan
        else None
    )
    return inputs_hash(
        pkg.intent.model_dump(mode="json", exclude={"created_at"}),
        [r.model_dump(mode="json") for r in pkg.requirements],
        [a.model_dump(mode="json") for a in pkg.assumptions],
        [q.model_dump(mode="json") for q in pkg.open_questions],
        [d.model_dump(mode="json") for d in pkg.decisions],
        [i.model_dump(mode="json") for i in pkg.interfaces],
        plan,
        tasks,
    )


def report_runner(runner: AgentRunner) -> str:
    """Name of a runner for handoffs."""
    return str(getattr(runner, "name", type(runner).__name__))
