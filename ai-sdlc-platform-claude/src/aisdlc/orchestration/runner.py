"""Agent runners: the only place in the platform that executes an agent.

* :class:`AgentRunner` — protocol ``run(brief) -> AgentResult``.
* :class:`DryRunRunner` — deterministic; writes a marker file into the worktree so a
  verification such as ``test -f TASK-001.dryrun`` passes, and supports scripted
  outcomes per ``role:task`` to exercise fix loops and review blocking in tests.
* :class:`LocalScriptRunner` — runs a configured command with the brief on stdin and in
  the environment, parsing the last JSON result line of its stdout.
* :class:`ClaudeCodeRunner` — builds a ``claude -p --output-format json`` command with an
  ``--allowedTools`` list derived from the brief's tool tier (bare ``Bash`` is never
  granted: only prefix-scoped patterns for the commands a tier legitimately needs, plus
  the task's own verification command when it classifies at tier <= 2), runs it with
  ``--permission-mode default`` and a generated ``--settings`` file whose ``PreToolUse``
  hook routes every tool call through the platform policy enforcer (``aisdlc governance
  hook --max-tier <brief tier>``), feeds the brief as the prompt (stdin), runs it in the
  worktree and parses usage from the JSON result. The permission mode is capped by the
  brief's tool tier (``acceptEdits`` only at tier >= 1 inside a worktree) and the hooks
  can only be switched off for tier-0 (read-only) briefs. The executable is resolved at
  run time; a missing executable yields a ``blocked`` result.

Every runner records usage through an injected :class:`UsageRecorder`
(:class:`LedgerUsageRecorder` writes :class:`~aisdlc.control_plane.ledger.UsageEvent`
rows to the control-plane ledger).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.control_plane.pricing import cost_usd
from aisdlc.control_plane.registry import ModelRegistry
from aisdlc.governance.claude_code_plugin import (
    DEFAULT_HOOK_COMMAND,
    build_platform_hooks,
    classify_shell_command,
)
from aisdlc.governance.tiers import RiskTier, TierConfig, classify_action
from aisdlc.orchestration.brief import AgentBrief, brief_to_json
from aisdlc.orchestration.roles import AgentRole

__all__ = [
    "RunStatus",
    "AgentUsage",
    "AgentResult",
    "AgentRunner",
    "UsageRecorder",
    "NullRecorder",
    "LedgerUsageRecorder",
    "ScriptedOutcome",
    "DryRunRunner",
    "LocalScriptRunner",
    "ClaudeCodeRunner",
    "TIER_TOOLS",
    "DISALLOWED_TOOLS",
    "FORBIDDEN_PERMISSION_MODES",
    "EDIT_PERMISSION_MODES",
    "PERMISSION_MODES",
    "allowed_tools_for_tier",
    "effective_permission_mode",
    "verification_tool_pattern",
    "parse_result_line",
    "parse_claude_output",
    "git_changed_files",
]


class RunStatus(StrEnum):
    """Outcome of an agent run."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


class AgentUsage(BaseModel):
    """Usage reported by a runner (``UsageEvent``-like)."""

    model_config = ConfigDict(extra="forbid")

    model: str = ""
    provider: str = ""
    family: str = ""
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cached_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    reasoning_tokens: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    turns: int = Field(default=0, ge=0)
    session_id: str = ""

    @property
    def total_tokens(self) -> int:
        """All tokens."""
        return (
            self.input_tokens
            + self.output_tokens
            + self.cached_tokens
            + self.cache_write_tokens
            + self.reasoning_tokens
        )


class AgentResult(BaseModel):
    """What a runner returns."""

    model_config = ConfigDict(extra="forbid")

    status: RunStatus
    summary: str = ""
    files_changed: list[str] = Field(default_factory=list)
    evidence_paths: list[str] = Field(default_factory=list)
    usage: AgentUsage = Field(default_factory=AgentUsage)
    tool_calls: int = Field(default=0, ge=0)
    findings: list[dict[str, Any]] = Field(
        default_factory=list, description="Reviewer output before grounding."
    )
    verdict: str | None = None
    raw_output: str = ""
    exit_code: int | None = None
    runner: str = ""
    ledger_event_id: str | None = None

    @property
    def succeeded(self) -> bool:
        """True for ``success``."""
        return self.status is RunStatus.SUCCESS


@runtime_checkable
class AgentRunner(Protocol):
    """Executes one brief."""

    name: str

    def run(self, brief: AgentBrief) -> AgentResult:
        """Run the agent described by ``brief``."""
        ...


class UsageRecorder(Protocol):
    """Records a run's usage (to the ledger, or nowhere)."""

    def record(self, brief: AgentBrief, result: AgentResult) -> str | None:
        """Record usage; returns the ledger event id when one was written."""
        ...


class NullRecorder:
    """Discards usage."""

    def record(self, brief: AgentBrief, result: AgentResult) -> str | None:
        """No-op."""
        return None


class LedgerUsageRecorder:
    """Writes one :class:`UsageEvent` per run to a :class:`UsageLedger` (thread-safe).

    Cost is taken from the runner when it reports one, otherwise priced through the
    registry when the model is known.
    """

    def __init__(
        self,
        ledger: UsageLedger,
        *,
        registry: ModelRegistry | None = None,
        defaults: Mapping[str, Any] | None = None,
        source: str = "platform",
        harness: str = "",
        environment: str = "",
        session_id: str = "",
    ) -> None:
        self.ledger = ledger
        self.registry = registry
        self.defaults = dict(defaults or {})
        self.source = source
        self.harness = harness
        self.environment = environment
        self.session_id = session_id
        self.events: list[str] = []
        self._lock = threading.Lock()

    def build_event(self, brief: AgentBrief, result: AgentResult) -> UsageEvent:
        """Build the event without recording it."""
        usage = result.usage
        model = usage.model or brief.model
        provider = usage.provider or (brief.routing.provider if brief.routing else "")
        cost = usage.cost_usd
        if cost <= 0 and self.registry is not None and model in self.registry:
            cost = cost_usd(
                self.registry.get(model),
                usage.input_tokens,
                usage.output_tokens,
                usage.cached_tokens,
                usage.reasoning_tokens,
                cache_write_tokens=usage.cache_write_tokens,
            )
        fields: dict[str, Any] = {
            **self.defaults,
            "change_id": brief.change_id,
            "task_id": brief.task.id,
            "agent_role": brief.role.value,
            "harness": self.harness or result.runner,
            "provider": provider,
            "model": model,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cached_tokens": usage.cached_tokens,
            "cache_write_tokens": usage.cache_write_tokens,
            "reasoning_tokens": usage.reasoning_tokens,
            "tool_calls": max(usage.tool_calls, result.tool_calls),
            "latency_ms": usage.latency_ms,
            "cost_usd": max(0.0, cost),
            "cache_hit": usage.cached_tokens > 0,
            "source": self.source,
            "environment": self.environment,
            "routing_tier": brief.routing.tier.value if brief.routing else "",
            "session_id": self.session_id or usage.session_id,
            "escalated": bool(brief.routing and brief.routing.tier.value == "escalation"),
            "turn": usage.turns or None,
            "review_round": brief.round,
            "success": result.status is RunStatus.SUCCESS,
        }
        return UsageEvent(**fields)

    def record(self, brief: AgentBrief, result: AgentResult) -> str | None:
        """Record the event; returns its id."""
        event = self.build_event(brief, result)
        with self._lock:
            event_id = self.ledger.record(event)
            self.events.append(event_id)
        return event_id


# --------------------------------------------------------------------------------------
# Result parsing helpers
# --------------------------------------------------------------------------------------


def parse_result_line(text: str) -> dict[str, Any] | None:
    """Return the last line of ``text`` that is a JSON object with a ``status`` key."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and "status" in data:
            return data
    return None


def _status_from(value: Any, default: RunStatus) -> RunStatus:
    try:
        return RunStatus(str(value).lower())
    except ValueError:
        return default


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value:
        return [value]
    return []


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(v) for v in value if isinstance(v, dict)]
    return []


def git_changed_files(directory: str | Path | None) -> list[str]:
    """Files changed in a git working tree (tracked + untracked); empty if not a repo."""
    if directory is None or shutil.which("git") is None:
        return []
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=str(directory),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    files: list[str] = []
    for line in proc.stdout.splitlines():
        if len(line) > 3:
            files.append(line[3:].split(" -> ")[-1].strip())
    return files


def _apply_contract(result: AgentResult, data: dict[str, Any] | None) -> AgentResult:
    """Fold a parsed output-contract object into ``result``."""
    if data is None:
        return result
    update: dict[str, Any] = {"status": _status_from(data.get("status"), result.status)}
    if isinstance(data.get("summary"), str):
        update["summary"] = data["summary"]
    if data.get("files_changed") is not None:
        update["files_changed"] = _str_list(data.get("files_changed"))
    if data.get("evidence_paths") is not None:
        update["evidence_paths"] = _str_list(data.get("evidence_paths"))
    if data.get("findings") is not None:
        update["findings"] = _dict_list(data.get("findings"))
    if isinstance(data.get("verdict"), str):
        update["verdict"] = data["verdict"]
    return result.model_copy(update=update)


# --------------------------------------------------------------------------------------
# Dry run
# --------------------------------------------------------------------------------------


class ScriptedOutcome(BaseModel):
    """One scripted result for :class:`DryRunRunner`."""

    model_config = ConfigDict(extra="forbid")

    status: RunStatus = RunStatus.SUCCESS
    summary: str = ""
    files_changed: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    verdict: str | None = None
    write_marker: bool = True
    marker_content: str | None = None
    usage: AgentUsage | None = None


ScriptSpec = Mapping[str, Sequence[ScriptedOutcome | RunStatus | str | Mapping[str, Any]]]


def _coerce_outcome(item: ScriptedOutcome | RunStatus | str | Mapping[str, Any]) -> ScriptedOutcome:
    if isinstance(item, ScriptedOutcome):
        return item
    if isinstance(item, RunStatus):
        return ScriptedOutcome(status=item, write_marker=item is RunStatus.SUCCESS)
    if isinstance(item, str):
        status = RunStatus(item)
        return ScriptedOutcome(status=status, write_marker=status is RunStatus.SUCCESS)
    return ScriptedOutcome.model_validate(dict(item))


class DryRunRunner:
    """Deterministic runner for tests and rehearsals.

    Args:
        recorder: Usage recorder.
        script: Scripted outcomes keyed by ``"<role>:<task_id>"``, ``"<task_id>"``,
            ``"<role>:*"`` or ``"*"``; each key maps to a sequence consumed in order (the
            last outcome repeats once exhausted). Unscripted runs succeed.
        marker_suffix: Marker file written to the worktree as ``<task_id><suffix>``.
        delay_seconds: Sleep per run (lets tests observe parallelism).
        default_usage: Usage reported for unscripted runs.
    """

    name = "dry-run"

    def __init__(
        self,
        recorder: UsageRecorder | None = None,
        *,
        script: ScriptSpec | None = None,
        marker_suffix: str = ".dryrun",
        delay_seconds: float = 0.0,
        default_usage: AgentUsage | None = None,
        model: str = "dry-run-model",
    ) -> None:
        self.recorder: UsageRecorder = recorder or NullRecorder()
        self.marker_suffix = marker_suffix
        self.delay_seconds = delay_seconds
        self.model = model
        self.default_usage = default_usage or AgentUsage(
            input_tokens=1000, output_tokens=200, latency_ms=50.0
        )
        self._script: dict[str, list[ScriptedOutcome]] = {
            key: [_coerce_outcome(item) for item in items] for key, items in (script or {}).items()
        }
        self._cursor: dict[str, int] = {}
        self.calls: list[tuple[str, str, int]] = []
        self.briefs: list[AgentBrief] = []
        self.peak_concurrency = 0
        self._active = 0
        self._lock = threading.Lock()

    def _next_outcome(self, brief: AgentBrief) -> ScriptedOutcome:
        keys = (
            f"{brief.role.value}:{brief.task.id}",
            brief.task.id if brief.role is AgentRole.IMPLEMENTER else "",
            f"{brief.role.value}:*",
            "*",
        )
        for key in keys:
            if key and key in self._script and self._script[key]:
                items = self._script[key]
                index = self._cursor.get(key, 0)
                self._cursor[key] = index + 1
                return items[min(index, len(items) - 1)]
        return ScriptedOutcome(write_marker=brief.role is AgentRole.IMPLEMENTER)

    def marker_path(self, brief: AgentBrief) -> Path | None:
        """Marker file for the brief's task inside its worktree."""
        if not brief.worktree:
            return None
        return Path(brief.worktree) / f"{brief.task.id}{self.marker_suffix}"

    def run(self, brief: AgentBrief) -> AgentResult:
        """Return the scripted (or default successful) outcome."""
        with self._lock:
            self._active += 1
            self.peak_concurrency = max(self.peak_concurrency, self._active)
            outcome = self._next_outcome(brief)
            self.calls.append((brief.role.value, brief.task.id, brief.round))
            self.briefs.append(brief)
        try:
            if self.delay_seconds > 0:
                time.sleep(self.delay_seconds)
            files = list(outcome.files_changed)
            marker = self.marker_path(brief)
            if outcome.write_marker and marker is not None and brief.role is AgentRole.IMPLEMENTER:
                marker.parent.mkdir(parents=True, exist_ok=True)
                content = outcome.marker_content
                if content is None:
                    content = f"{brief.content_hash()}\nround={brief.round}\n"
                marker.write_text(content, encoding="utf-8")
                files.append(marker.name)
            usage = (outcome.usage or self.default_usage).model_copy()
            if not usage.model:
                usage.model = brief.model or self.model
            if not usage.provider and brief.routing is not None:
                usage.provider = brief.routing.provider
            if not usage.family and brief.routing is not None:
                usage.family = brief.routing.family
            summary = outcome.summary or (
                f"dry-run {brief.role.value} for {brief.task.id} round {brief.round}: "
                f"{outcome.status.value}"
            )
            result = AgentResult(
                status=outcome.status,
                summary=summary,
                files_changed=files,
                usage=usage,
                tool_calls=usage.tool_calls,
                findings=list(outcome.findings),
                verdict=outcome.verdict,
                runner=self.name,
            )
            event_id = self.recorder.record(brief, result)
            return result.model_copy(update={"ledger_event_id": event_id})
        finally:
            with self._lock:
                self._active -= 1


# --------------------------------------------------------------------------------------
# Local script
# --------------------------------------------------------------------------------------


def _brief_env(brief: AgentBrief) -> dict[str, str]:
    return {
        "AISDLC_CHANGE_ID": brief.change_id,
        "AISDLC_TASK_ID": brief.task.id,
        "AISDLC_ROLE": brief.role.value,
        "AISDLC_ROUND": str(brief.round),
        "AISDLC_WORKTREE": brief.worktree or "",
        "AISDLC_MODEL": brief.model,
        "AISDLC_TOOL_TIER": str(int(brief.allowed_tool_tier)),
        "AISDLC_VERIFY_COMMAND": brief.verification.command if brief.verification else "",
        "AISDLC_BRIEF_JSON": brief_to_json(brief),
    }


class LocalScriptRunner:
    """Run a configured command with the brief on stdin and ``AISDLC_*`` in the environment.

    The command must print, as its last line, a JSON object following the brief's output
    contract (``{"status": ..., "summary": ..., "files_changed": [...]}``). A non-zero
    exit without a result line is ``failed``; a missing executable is ``blocked``.
    """

    name = "local-script"

    def __init__(
        self,
        command: Sequence[str] | str,
        *,
        recorder: UsageRecorder | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float = 600.0,
        model: str = "",
        provider: str = "",
    ) -> None:
        self.command: list[str] | str = list(command) if not isinstance(command, str) else command
        self.recorder: UsageRecorder = recorder or NullRecorder()
        self.env = dict(env or {})
        self.timeout_seconds = timeout_seconds
        self.model = model
        self.provider = provider

    def run(self, brief: AgentBrief) -> AgentResult:
        """Execute the command and parse its result line."""
        env = {**os.environ, **self.env, **_brief_env(brief)}
        cwd = brief.worktree or None
        started = time.monotonic()
        try:
            proc = subprocess.run(
                self.command,
                input=brief.render_markdown(),
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=isinstance(self.command, str),
                check=False,
            )
        except FileNotFoundError as exc:
            result = AgentResult(
                status=RunStatus.BLOCKED, summary=f"command not found: {exc}", runner=self.name
            )
            return result.model_copy(
                update={"ledger_event_id": self.recorder.record(brief, result)}
            )
        except subprocess.TimeoutExpired:
            result = AgentResult(
                status=RunStatus.FAILED,
                summary=f"command timed out after {self.timeout_seconds:g}s",
                runner=self.name,
            )
            return result.model_copy(
                update={"ledger_event_id": self.recorder.record(brief, result)}
            )
        latency = (time.monotonic() - started) * 1000.0
        data = parse_result_line(proc.stdout)
        base_status = RunStatus.SUCCESS if proc.returncode == 0 else RunStatus.FAILED
        usage = AgentUsage(
            model=self.model or brief.model, provider=self.provider, latency_ms=latency
        )
        if data is not None and isinstance(data.get("usage"), dict):
            raw = {k: v for k, v in data["usage"].items() if k in AgentUsage.model_fields}
            usage = usage.model_copy(update=raw)
        result = AgentResult(
            status=base_status,
            summary=(proc.stdout.strip().splitlines() or [""])[-1][:500],
            usage=usage,
            raw_output=proc.stdout + (("\n" + proc.stderr) if proc.stderr else ""),
            exit_code=proc.returncode,
            runner=self.name,
        )
        result = _apply_contract(result, data)
        if data is None and proc.returncode != 0:
            result = result.model_copy(
                update={"summary": f"exit {proc.returncode} without a result line"}
            )
        if not result.files_changed:
            result = result.model_copy(update={"files_changed": git_changed_files(cwd)})
        return result.model_copy(update={"ledger_event_id": self.recorder.record(brief, result)})


# --------------------------------------------------------------------------------------
# Claude Code
# --------------------------------------------------------------------------------------

#: Claude Code tools granted per risk tier (cumulative). ``Bash`` is never granted bare:
#: every shell grant is a prefix-scoped ``Bash(<prefix>:*)`` pattern for the commands the
#: tier legitimately needs; everything else goes through the PreToolUse governance hook.
TIER_TOOLS: dict[int, list[str]] = {
    0: [
        "Read",
        "Grep",
        "Glob",
        "LS",
        "Bash(ls:*)",
        "Bash(git status:*)",
        "Bash(git diff:*)",
        "Bash(git log:*)",
    ],
    1: ["Write", "Edit", "MultiEdit", "NotebookEdit"],
    2: [
        "Bash(pytest:*)",
        "Bash(python -m pytest:*)",
        "Bash(ruff:*)",
        "Bash(mypy:*)",
        "Bash(npm test:*)",
        "Bash(npm run build:*)",
        "Bash(make:*)",
        "Bash(cargo test:*)",
        "Bash(go test:*)",
        "Bash(git add:*)",
        "Bash(git commit:*)",
    ],
    3: ["Bash(git push:*)", "Bash(gh pr create:*)"],
    4: [],
}

#: Tools never granted to a governed agent (egress is governed by the MCP gateway/policy).
DISALLOWED_TOOLS: tuple[str, ...] = ("WebFetch", "WebSearch")

#: ``--permission-mode`` values that would bypass the governance hook; never accepted.
FORBIDDEN_PERMISSION_MODES: frozenset[str] = frozenset({"bypassPermissions", "dontAsk"})

#: ``--permission-mode`` values that auto-approve file edits. Only meaningful for briefs
#: that may write (tier >= 1) and only inside an isolated worktree; a tier-0 (read-only)
#: brief must run with ``default`` so every write goes through the permission prompt.
EDIT_PERMISSION_MODES: frozenset[str] = frozenset({"acceptEdits"})

#: Every ``--permission-mode`` value the runner accepts (``None`` omits the flag).
PERMISSION_MODES: frozenset[str] = frozenset({"default", "plan"} | EDIT_PERMISSION_MODES)

#: Bare grants that hand the agent an ungoverned shell; never emitted, even via ``extra``.
_BARE_SHELL_GRANTS: frozenset[str] = frozenset(
    {"Bash", "Bash(*)", "Bash(:*)", "Shell", "PowerShell"}
)


def allowed_tools_for_tier(tier: RiskTier | int, *, extra: Sequence[str] = ()) -> list[str]:
    """Cumulative Claude Code tool allowlist for ``tier`` (tier 4 grants nothing extra).

    Bare shell grants (``Bash``) are dropped from ``extra`` as well; scope them with a
    ``Bash(<prefix>:*)`` pattern instead.
    """
    level = int(RiskTier.coerce(tier))
    tools: list[str] = []
    for t in range(0, min(level, 3) + 1):
        tools.extend(TIER_TOOLS.get(t, []))
    for item in extra:
        if item in _BARE_SHELL_GRANTS:
            continue
        if item not in tools:
            tools.append(item)
    return tools


def effective_permission_mode(permission_mode: str | None, brief: AgentBrief) -> str | None:
    """The ``--permission-mode`` a session for ``brief`` may run with.

    The configured mode is capped by the brief's allowed tool tier: an edit-accepting mode
    (:data:`EDIT_PERMISSION_MODES`) is only valid for a brief at tier >= 1 that runs inside
    a worktree. Because the runner's default mode is ``default`` — which never needs
    capping — an edit-accepting mode can only arrive through explicit configuration, and a
    mismatch with the brief is therefore an error rather than a silent downgrade: a
    ``ValueError`` is raised, so a runner configured with ``acceptEdits`` cannot be handed
    a read-only brief by accident. ``None`` and ``default``/``plan`` pass through.
    """
    if permission_mode is None:
        return None
    if permission_mode in FORBIDDEN_PERMISSION_MODES:
        raise ValueError(f"permission_mode {permission_mode!r} bypasses governance; use 'default'")
    if permission_mode not in PERMISSION_MODES:
        raise ValueError(
            f"permission_mode {permission_mode!r} is not supported; use one of "
            f"{sorted(PERMISSION_MODES)}"
        )
    if permission_mode in EDIT_PERMISSION_MODES:
        tier = int(brief.allowed_tool_tier)
        if tier < int(RiskTier.AUTOMATIC_AUDIT):
            raise ValueError(
                f"permission_mode {permission_mode!r} is not allowed for a tier-{tier} "
                f"(read-only) brief; run role {brief.role.value!r} with 'default'"
            )
        if not brief.worktree:
            raise ValueError(
                f"permission_mode {permission_mode!r} requires the brief to run inside an "
                "isolated worktree (brief.worktree is unset)"
            )
    return permission_mode


def verification_tool_pattern(brief: AgentBrief, *, config: TierConfig | None = None) -> str | None:
    """Exact ``Bash(<command>)`` grant for the brief's verification command, if safe.

    The command comes from ``tasks.md`` (agent-writable), so it is classified with the
    governance shell classifier first; anything at tier 3 or above, or above the brief's
    own tool tier, gets no grant (the agent may still request it and the hook decides).
    """
    if brief.verification is None or not brief.verification.command.strip():
        return None
    command = brief.verification.command.strip()
    mapped = classify_shell_command(command)
    action = classify_action(
        "Bash", mapped.action_type, mapped.resource or command, config=config, in_worktree=True
    )
    if int(action.tier) >= int(RiskTier.APPROVAL) or int(action.tier) > int(
        brief.allowed_tool_tier
    ):
        return None
    return f"Bash({command})"


def parse_claude_output(text: str) -> dict[str, Any] | None:
    """Parse ``claude --output-format json`` output into the final result object.

    Accepts a single JSON object, a JSON array of events (last ``type == result`` wins)
    or JSON lines.
    """
    stripped = text.strip()
    if not stripped:
        return None
    data: Any
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        found: dict[str, Any] | None = None
        for line in stripped.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and (obj.get("type") == "result" or found is None):
                found = dict(obj)
        return found
    if isinstance(data, list):
        results = [dict(d) for d in data if isinstance(d, dict) and d.get("type") == "result"]
        if results:
            return results[-1]
        dicts = [dict(d) for d in data if isinstance(d, dict)]
        return dicts[-1] if dicts else None
    return dict(data) if isinstance(data, dict) else None


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


class ClaudeCodeRunner:
    """Run ``claude -p`` in the worktree with a governed tool allowlist.

    Args:
        executable: The Claude Code binary (resolved on ``PATH`` at run time).
        recorder: Usage recorder.
        extra_allowed_tools: Tools granted in addition to the tier-derived list (bare
            shell grants are ignored).
        permission_mode: ``--permission-mode`` value (``None`` omits the flag). Defaults to
            ``default`` so the governance hook's deny/ask decisions are honoured;
            ``bypassPermissions``/``dontAsk`` are refused. ``acceptEdits`` is capped by the
            brief: it is only valid for tier >= 1 briefs running inside a worktree, and
            :meth:`build_command` raises ``ValueError`` for a tier-0 brief (see
            :func:`effective_permission_mode`).
        max_turns: ``--max-turns`` value (``None`` omits the flag).
        timeout_seconds: Subprocess timeout.
        env: Extra environment variables.
        extra_args: Additional CLI arguments appended verbatim.
        which: Executable resolver (injectable for tests).
        governance_hooks: Generate a ``--settings`` file wiring the platform PreToolUse /
            PostToolUse hooks (``aisdlc governance hook --max-tier <brief tier>``) for the
            brief's role. ``False`` is only honoured for tier-0 (read-only) briefs;
            :meth:`build_command` raises ``ValueError`` for any brief that may write or
            execute, because the hook is what enforces the tier ceiling there.
        hook_command: Command the hooks invoke.
        policy_path: Policy YAML the hook loads (default: the role's template policy).
        workspace_roots: Extra workspace roots passed to the hook (the brief's worktree is
            always included).
        audit_log: Signed audit log the hook appends to.
        settings_dir: Where hook settings files are written (default: a private temp dir).
    """

    name = "claude-code"

    def __init__(
        self,
        *,
        executable: str = "claude",
        recorder: UsageRecorder | None = None,
        extra_allowed_tools: Sequence[str] = (),
        permission_mode: str | None = "default",
        max_turns: int | None = None,
        timeout_seconds: float = 1800.0,
        env: Mapping[str, str] | None = None,
        extra_args: Sequence[str] = (),
        which: Callable[[str], str | None] = shutil.which,
        governance_hooks: bool = True,
        hook_command: str = DEFAULT_HOOK_COMMAND,
        policy_path: str | None = None,
        workspace_roots: Sequence[str] = (),
        audit_log: str | None = None,
        settings_dir: str | Path | None = None,
        tier_config: TierConfig | None = None,
    ) -> None:
        if permission_mode in FORBIDDEN_PERMISSION_MODES:
            raise ValueError(
                f"permission_mode {permission_mode!r} bypasses governance; use 'default'"
            )
        if permission_mode is not None and permission_mode not in PERMISSION_MODES:
            raise ValueError(
                f"permission_mode {permission_mode!r} is not supported; use one of "
                f"{sorted(PERMISSION_MODES)}"
            )
        self.executable = executable
        self.recorder: UsageRecorder = recorder or NullRecorder()
        self.extra_allowed_tools = list(extra_allowed_tools)
        self.permission_mode = permission_mode
        self.max_turns = max_turns
        self.timeout_seconds = timeout_seconds
        self.env = dict(env or {})
        self.extra_args = list(extra_args)
        self._which = which
        self.governance_hooks = governance_hooks
        self.hook_command = hook_command
        self.policy_path = policy_path
        self.workspace_roots = [str(r) for r in workspace_roots]
        self.audit_log = audit_log
        self._settings_dir = Path(settings_dir) if settings_dir is not None else None
        self.tier_config = tier_config
        self._lock = threading.Lock()

    @property
    def settings_dir(self) -> Path:
        """Directory holding the generated hook settings files (created on first use)."""
        with self._lock:
            if self._settings_dir is None:
                self._settings_dir = Path(tempfile.mkdtemp(prefix="aisdlc-claude-"))
            self._settings_dir.mkdir(parents=True, exist_ok=True)
            return self._settings_dir

    def allowed_tools(self, brief: AgentBrief) -> list[str]:
        """Tool allowlist for the brief's tier plus its (safe) verification command."""
        extra = list(self.extra_allowed_tools)
        pattern = verification_tool_pattern(brief, config=self.tier_config)
        if pattern is not None:
            extra.append(pattern)
        return allowed_tools_for_tier(brief.allowed_tool_tier, extra=extra)

    def hook_settings(self, brief: AgentBrief) -> dict[str, Any]:
        """Claude Code settings block wiring the platform governance hooks for ``brief``."""
        roots = list(self.workspace_roots)
        if brief.worktree and brief.worktree not in roots:
            roots.append(brief.worktree)
        return build_platform_hooks(
            role=brief.role.value,
            policy_path=self.policy_path,
            command=self.hook_command,
            workspace_roots=roots,
            audit_log=self.audit_log,
            max_tier=brief.allowed_tool_tier,
        )

    def permission_mode_for(self, brief: AgentBrief) -> str | None:
        """The permission mode ``brief`` runs with (configured mode capped by its tier)."""
        return effective_permission_mode(self.permission_mode, brief)

    def hooks_required(self, brief: AgentBrief) -> bool:
        """Whether the governance hooks must be wired for ``brief``.

        Hooks are mandatory for every brief that may write or execute (tier >= 1); only a
        tier-0 (read-only) brief may run without them.
        """
        return int(brief.allowed_tool_tier) >= int(RiskTier.AUTOMATIC_AUDIT)

    def hook_settings_path(self, brief: AgentBrief) -> Path:
        """Write the hook settings for ``brief`` and return the file to pass as ``--settings``."""
        settings = self.hook_settings(brief)
        stem = f"settings.hooks.{brief.role.value}.{brief.task.id}.{brief.round}"
        path = self.settings_dir / f"{stem}.json"
        path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        return path

    def build_command(self, brief: AgentBrief, *, executable: str | None = None) -> list[str]:
        """The full ``claude`` argv for ``brief`` (prompt is passed on stdin).

        With ``governance_hooks`` the hook settings file is (re)written as a side effect.
        Raises ``ValueError`` when the configured permission mode is not allowed for the
        brief's tier or when ``governance_hooks=False`` for a brief above tier 0.
        """
        permission_mode = self.permission_mode_for(brief)
        if not self.governance_hooks and self.hooks_required(brief):
            raise ValueError(
                f"governance_hooks=False is only allowed for tier-0 (read-only) briefs; "
                f"role {brief.role.value!r} runs at tier {int(brief.allowed_tool_tier)}, "
                "where the PreToolUse hook is what enforces the tier ceiling"
            )
        cmd = [executable or self.executable, "-p", "--output-format", "json"]
        if brief.model:
            cmd += ["--model", brief.model]
        cmd += ["--allowedTools", ",".join(self.allowed_tools(brief))]
        cmd += ["--disallowedTools", ",".join(DISALLOWED_TOOLS)]
        if permission_mode:
            cmd += ["--permission-mode", permission_mode]
        if self.governance_hooks:
            cmd += ["--settings", str(self.hook_settings_path(brief))]
        if self.max_turns is not None:
            cmd += ["--max-turns", str(self.max_turns)]
        cmd += self.extra_args
        return cmd

    @staticmethod
    def parse_usage(data: dict[str, Any], *, brief: AgentBrief, latency_ms: float) -> AgentUsage:
        """Extract usage/cost from a Claude Code JSON result."""
        usage_raw = data.get("usage")
        raw: dict[str, Any] = dict(usage_raw) if isinstance(usage_raw, dict) else {}
        model = brief.model
        model_usage = data.get("modelUsage")
        if not model and isinstance(model_usage, dict) and model_usage:
            model = str(next(iter(model_usage)))
        return AgentUsage(
            model=model,
            provider=brief.routing.provider if brief.routing else "anthropic",
            family=brief.routing.family if brief.routing else "claude",
            input_tokens=_int(raw.get("input_tokens")),
            output_tokens=_int(raw.get("output_tokens")),
            cached_tokens=_int(raw.get("cache_read_input_tokens")),
            cache_write_tokens=_int(raw.get("cache_creation_input_tokens")),
            latency_ms=float(data.get("duration_ms") or latency_ms),
            cost_usd=max(0.0, float(data.get("total_cost_usd") or 0.0)),
            turns=_int(data.get("num_turns")),
            session_id=str(data.get("session_id") or ""),
        )

    def run(self, brief: AgentBrief) -> AgentResult:
        """Execute Claude Code for ``brief``."""
        resolved = self._which(self.executable)
        if resolved is None:
            result = AgentResult(
                status=RunStatus.BLOCKED,
                summary=f"claude executable {self.executable!r} not found on PATH",
                runner=self.name,
            )
            return result.model_copy(
                update={"ledger_event_id": self.recorder.record(brief, result)}
            )
        cmd = self.build_command(brief, executable=resolved)
        env = {**os.environ, **self.env, **_brief_env(brief)}
        cwd = brief.worktree or None
        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=brief.render_markdown(),
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = AgentResult(
                status=RunStatus.FAILED,
                summary=f"claude timed out after {self.timeout_seconds:g}s",
                runner=self.name,
            )
            return result.model_copy(
                update={"ledger_event_id": self.recorder.record(brief, result)}
            )
        except OSError as exc:
            result = AgentResult(
                status=RunStatus.BLOCKED, summary=f"could not start claude: {exc}", runner=self.name
            )
            return result.model_copy(
                update={"ledger_event_id": self.recorder.record(brief, result)}
            )
        latency = (time.monotonic() - started) * 1000.0
        data = parse_claude_output(proc.stdout)
        raw_output = proc.stdout + (("\n" + proc.stderr) if proc.stderr else "")
        if data is None:
            result = AgentResult(
                status=RunStatus.FAILED,
                summary=f"claude exited {proc.returncode} without a JSON result",
                usage=AgentUsage(model=brief.model, latency_ms=latency),
                raw_output=raw_output,
                exit_code=proc.returncode,
                runner=self.name,
            )
            return result.model_copy(
                update={"ledger_event_id": self.recorder.record(brief, result)}
            )
        usage = self.parse_usage(data, brief=brief, latency_ms=latency)
        text = data.get("result") if isinstance(data.get("result"), str) else ""
        is_error = bool(data.get("is_error")) or proc.returncode != 0
        status = RunStatus.FAILED if is_error else RunStatus.SUCCESS
        result = AgentResult(
            status=status,
            summary=(text or str(data.get("subtype") or "")).strip()[:500],
            usage=usage,
            tool_calls=usage.tool_calls,
            raw_output=raw_output,
            exit_code=proc.returncode,
            runner=self.name,
        )
        result = _apply_contract(result, parse_result_line(text or ""))
        if is_error and result.status is RunStatus.SUCCESS:
            result = result.model_copy(update={"status": RunStatus.FAILED})
        if not result.files_changed:
            result = result.model_copy(update={"files_changed": git_changed_files(cwd)})
        return result.model_copy(update={"ledger_event_id": self.recorder.record(brief, result)})
