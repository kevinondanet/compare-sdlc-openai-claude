"""BudgetPolicyEngine: budgets, quotas, tier caps, exceptions and per-agent windows.

Budgets are scoped (application / team / environment / change / user) and evaluated
against the :class:`~aisdlc.control_plane.ledger.UsageLedger` over a rolling window.
Quotas are hard limits on agent turns, parallel agents, review rounds, tool calls and
context size; ``approval_threshold_usd`` turns large single forecasts into
``require_approval`` decisions. Approved exceptions (with expiry) can raise a scope's
limit. Per-agent rolling windows delegate to AGT's ``BudgetTracker`` when importable and
fall back to an equivalent in-process tracker otherwise.
"""

from __future__ import annotations

import re
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aisdlc.control_plane.ledger import UsageLedger

_TIER_ORDER: dict[str, int] = {"low": 0, "standard": 1, "high": 2}
_WINDOW_RE = re.compile(r"^(\d+)([smhdw])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_window(window: str) -> timedelta | None:
    """Parse ``'30d'``/``'12h'``/``'1w'`` into a timedelta; ``'all'``/``''`` -> None."""
    w = window.strip().lower()
    if w in {"", "all", "none", "lifetime"}:
        return None
    m = _WINDOW_RE.match(w)
    if not m:
        raise ValueError(f"invalid window {window!r}; expected e.g. '1h', '30d', 'all'")
    return timedelta(seconds=int(m.group(1)) * _UNIT_SECONDS[m.group(2)])


class ScopeType(StrEnum):
    """Budget scope kinds."""

    application = "application"
    team = "team"
    environment = "environment"
    change = "change"
    user = "user"


_SCOPE_FIELD: dict[ScopeType, str] = {
    ScopeType.application: "application",
    ScopeType.team: "team",
    ScopeType.environment: "environment",
    ScopeType.change: "change_id",
    ScopeType.user: "user",
}


class BudgetScope(BaseModel):
    """A concrete scope instance, e.g. ``application:payments``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_type: ScopeType
    scope_id: str = Field(min_length=1)

    @property
    def key(self) -> str:
        """``<type>:<id>`` form."""
        return f"{self.scope_type.value}:{self.scope_id}"

    @classmethod
    def parse(cls, text: str) -> BudgetScope:
        """Parse ``'team:platform'`` into a scope."""
        if ":" not in text:
            raise ValueError(f"scope must be '<type>:<id>', got {text!r}")
        t, i = text.split(":", 1)
        return cls(scope_type=ScopeType(t.strip()), scope_id=i.strip())

    @property
    def ledger_filter(self) -> dict[str, str]:
        """Ledger filter matching events in this scope."""
        return {_SCOPE_FIELD[self.scope_type]: self.scope_id}


class Budget(BaseModel):
    """Spending limit for one scope over a rolling window."""

    model_config = ConfigDict(extra="forbid")

    scope_type: ScopeType
    scope_id: str = Field(min_length=1)
    limit_usd: float = Field(gt=0)
    window: str = Field(default="30d", description="Rolling window, e.g. 24h, 30d, all")
    soft_limit_ratio: float = Field(
        default=0.8, gt=0, le=1, description="Above this fraction of the limit -> approval"
    )

    @field_validator("window")
    @classmethod
    def _check_window(cls, value: str) -> str:
        parse_window(value)
        return value

    @property
    def scope(self) -> BudgetScope:
        """Scope this budget applies to."""
        return BudgetScope(scope_type=self.scope_type, scope_id=self.scope_id)


class Quotas(BaseModel):
    """Hard limits applied to every check; ``None`` disables a quota."""

    model_config = ConfigDict(extra="forbid")

    max_model_tier_by_role: dict[str, str] = Field(default_factory=dict)
    max_agent_turns: int | None = Field(default=None, ge=0)
    max_parallel_agents: int | None = Field(default=None, ge=0)
    max_review_rounds: int | None = Field(default=None, ge=0)
    max_tool_calls: int | None = Field(default=None, ge=0)
    context_ceiling_tokens: int | None = Field(default=None, ge=0)
    approval_threshold_usd: float | None = Field(default=None, ge=0)

    @field_validator("max_model_tier_by_role")
    @classmethod
    def _tiers(cls, value: dict[str, str]) -> dict[str, str]:
        for role, tier in value.items():
            if tier not in _TIER_ORDER:
                raise ValueError(f"unknown tier {tier!r} for role {role!r}")
        return value


class BudgetException(BaseModel):
    """An approved, time-boxed exception raising a scope's limit."""

    model_config = ConfigDict(extra="forbid")

    exception_id: str = Field(default_factory=lambda: f"EXC-{uuid.uuid4().hex[:8]}")
    scope_type: ScopeType
    scope_id: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    expires_at: datetime
    extra_limit_usd: float | None = Field(
        default=None, ge=0, description="Additional headroom; None means unlimited"
    )
    reason: str = ""

    @field_validator("expires_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    def active(self, now: datetime) -> bool:
        """True while not expired."""
        return now < self.expires_at


class ExceptionRegister:
    """In-memory register of approved budget exceptions."""

    def __init__(self, exceptions: Iterable[BudgetException] = ()) -> None:
        self._items: dict[str, BudgetException] = {}
        for e in exceptions:
            self.add(e)

    def add(self, exc: BudgetException) -> BudgetException:
        """Register (or replace) an exception."""
        self._items[exc.exception_id] = exc
        return exc

    def get(self, exception_id: str) -> BudgetException | None:
        """Look up by id."""
        return self._items.get(exception_id)

    def revoke(self, exception_id: str) -> bool:
        """Remove an exception; True if it existed."""
        return self._items.pop(exception_id, None) is not None

    def all(self) -> list[BudgetException]:
        """Every registered exception."""
        return list(self._items.values())

    def active_for(self, scope: BudgetScope, now: datetime) -> list[BudgetException]:
        """Unexpired exceptions for ``scope``."""
        return [
            e
            for e in self._items.values()
            if e.scope_type == scope.scope_type and e.scope_id == scope.scope_id and e.active(now)
        ]


class DecisionKind(StrEnum):
    """Budget decision outcomes."""

    allow = "allow"
    require_approval = "require_approval"
    deny = "deny"


class ScopeStatus(BaseModel):
    """Per-scope evaluation detail."""

    model_config = ConfigDict(extra="forbid")

    scope: str
    limit_usd: float
    effective_limit_usd: float | None
    spent_usd: float
    forecast_usd: float
    remaining_usd: float | None
    hard_breach: bool
    soft_breach: bool
    exceptions: list[str] = Field(default_factory=list)


class BudgetDecision(BaseModel):
    """Result of :meth:`BudgetPolicyEngine.check`."""

    model_config = ConfigDict(extra="forbid")

    decision: DecisionKind
    reason: str
    remaining_usd: float | None = None
    breached_scopes: list[str] = Field(default_factory=list)
    soft_breached_scopes: list[str] = Field(default_factory=list)
    quota_violations: list[str] = Field(default_factory=list)
    applied_exceptions: list[str] = Field(default_factory=list)
    forecast_cost_usd: float = 0.0
    scopes: list[ScopeStatus] = Field(default_factory=list)

    @property
    def allowed(self) -> bool:
        """True only for ``allow``."""
        return self.decision is DecisionKind.allow


class AgentWindowDecision(BaseModel):
    """Result of a per-agent rolling-window check."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str = ""
    tokens_remaining: int = 0
    cost_remaining_usd: float = 0.0
    backend: str = "local"


class AgentWindowTracker(Protocol):
    """Per-agent rolling window of tokens and cost."""

    @property
    def backend(self) -> str:
        """Implementation name (``agt`` or ``local``)."""

    def record_usage(self, agent_id: str, tokens: int, cost_usd: float = 0.0) -> None:
        """Record consumption."""

    def check(self, agent_id: str, estimated_tokens: int = 0) -> AgentWindowDecision:
        """Check whether ``estimated_tokens`` more fit in the window."""


class LocalAgentWindowTracker:
    """Pure-Python rolling window tracker (fallback when AGT is unavailable)."""

    backend = "local"

    def __init__(
        self,
        *,
        max_tokens: int = 100_000,
        max_cost_usd: float = 10.0,
        window: str = "1h",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_tokens = max_tokens
        self.max_cost_usd = max_cost_usd
        delta = parse_window(window)
        self.window_seconds = delta.total_seconds() if delta else float("inf")
        self._clock = clock
        self._usage: dict[str, deque[tuple[float, int, float]]] = {}

    def _prune(self, agent_id: str) -> deque[tuple[float, int, float]]:
        q = self._usage.setdefault(agent_id, deque())
        cutoff = self._clock() - self.window_seconds
        while q and q[0][0] < cutoff:
            q.popleft()
        return q

    def record_usage(self, agent_id: str, tokens: int, cost_usd: float = 0.0) -> None:
        """Record consumption at the current clock time."""
        self._prune(agent_id).append((self._clock(), tokens, cost_usd))

    def usage(self, agent_id: str) -> tuple[int, float]:
        """(tokens, cost) consumed within the window."""
        q = self._prune(agent_id)
        return sum(t for _, t, _ in q), sum(c for _, _, c in q)

    def check(self, agent_id: str, estimated_tokens: int = 0) -> AgentWindowDecision:
        """Rolling-window check."""
        tokens, cost = self.usage(agent_id)
        tokens_remaining = max(0, self.max_tokens - tokens)
        cost_remaining = max(0.0, self.max_cost_usd - cost)
        if tokens + estimated_tokens > self.max_tokens:
            return AgentWindowDecision(
                allowed=False,
                reason=(
                    f"agent {agent_id} token window exceeded "
                    f"({tokens}+{estimated_tokens} > {self.max_tokens})"
                ),
                tokens_remaining=tokens_remaining,
                cost_remaining_usd=cost_remaining,
            )
        if cost >= self.max_cost_usd:
            return AgentWindowDecision(
                allowed=False,
                reason=(
                    f"agent {agent_id} cost window exceeded "
                    f"(${cost:.4f} >= ${self.max_cost_usd:.2f})"
                ),
                tokens_remaining=tokens_remaining,
                cost_remaining_usd=0.0,
            )
        return AgentWindowDecision(
            allowed=True,
            reason="within window",
            tokens_remaining=tokens_remaining,
            cost_remaining_usd=cost_remaining,
        )


class AgtAgentWindowTracker:
    """Adapter over ``agentmesh.governance.budget.BudgetTracker`` (AGT)."""

    backend = "agt"

    def __init__(self, tracker: Any) -> None:
        self._tracker = tracker

    def record_usage(self, agent_id: str, tokens: int, cost_usd: float = 0.0) -> None:
        """Delegate to AGT."""
        self._tracker.record_usage(agent_id, tokens, cost_usd)

    def check(self, agent_id: str, estimated_tokens: int = 0) -> AgentWindowDecision:
        """Delegate to AGT and translate its decision."""
        d = self._tracker.check_budget(agent_id, estimated_tokens)
        return AgentWindowDecision(
            allowed=bool(getattr(d, "allowed", False)),
            reason=str(getattr(d, "reason", "")),
            tokens_remaining=int(getattr(d, "tokens_remaining", 0) or 0),
            cost_remaining_usd=float(getattr(d, "cost_remaining", 0.0) or 0.0),
            backend="agt",
        )


def make_agent_tracker(
    *,
    max_tokens: int = 100_000,
    max_cost_usd: float = 10.0,
    window: str = "1h",
    prefer_agt: bool = True,
) -> AgentWindowTracker:
    """Build a per-agent window tracker, using AGT when importable and preferred."""
    parse_window(window)
    if prefer_agt:
        try:
            from agentmesh.governance.budget import BudgetConfig, BudgetTracker
        except Exception:  # pragma: no cover - depends on environment
            pass
        else:
            cfg = BudgetConfig(max_tokens=max_tokens, max_cost_usd=max_cost_usd, window=window)
            return AgtAgentWindowTracker(BudgetTracker(cfg))
    return LocalAgentWindowTracker(max_tokens=max_tokens, max_cost_usd=max_cost_usd, window=window)


ScopesInput = Iterable[BudgetScope | str] | dict[str, str]


def normalize_scopes(scopes: ScopesInput) -> list[BudgetScope]:
    """Accept ``[BudgetScope]``, ``['team:x']`` or ``{'team': 'x'}`` and return scopes."""
    if isinstance(scopes, dict):
        return [BudgetScope(scope_type=ScopeType(k), scope_id=v) for k, v in scopes.items()]
    out: list[BudgetScope] = []
    for s in scopes:
        out.append(s if isinstance(s, BudgetScope) else BudgetScope.parse(s))
    return out


class BudgetPolicyEngine:
    """Evaluate budgets, quotas and exceptions against the ledger."""

    def __init__(
        self,
        ledger: UsageLedger,
        *,
        budgets: Iterable[Budget] = (),
        quotas: Quotas | None = None,
        exceptions: ExceptionRegister | None = None,
        clock: Callable[[], datetime] | None = None,
        agent_tracker: AgentWindowTracker | None = None,
    ) -> None:
        self.ledger = ledger
        self._budgets: dict[str, Budget] = {}
        for b in budgets:
            self.add_budget(b)
        self.quotas = quotas or Quotas()
        self.exceptions = exceptions or ExceptionRegister()
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self.agent_tracker = agent_tracker

    # ------------------------------------------------------------------ config
    def add_budget(self, budget: Budget) -> None:
        """Add or replace the budget for a scope."""
        self._budgets[budget.scope.key] = budget

    def remove_budget(self, scope: BudgetScope | str) -> bool:
        """Remove a scope's budget; True if it existed."""
        key = scope.key if isinstance(scope, BudgetScope) else BudgetScope.parse(scope).key
        return self._budgets.pop(key, None) is not None

    @property
    def budgets(self) -> list[Budget]:
        """Configured budgets."""
        return list(self._budgets.values())

    def budget_for(self, scope: BudgetScope) -> Budget | None:
        """Budget configured for ``scope`` if any."""
        return self._budgets.get(scope.key)

    # ------------------------------------------------------------------ evaluation
    def spent(self, budget: Budget, *, now: datetime | None = None) -> float:
        """USD spent in ``budget``'s scope within its window."""
        now = now or self._clock()
        delta = parse_window(budget.window)
        since = (now - delta) if delta else None
        return self.ledger.total_cost(budget.scope.ledger_filter, since=since, until=now)

    def tier_allowed(self, role: str | None, requested_tier: str | None) -> tuple[bool, str]:
        """Check the requested model tier against ``max_model_tier_by_role``."""
        if not role or not requested_tier:
            return True, ""
        cap = self.quotas.max_model_tier_by_role.get(role)
        if cap is None:
            return True, ""
        req = _TIER_ORDER.get(requested_tier)
        if req is None:
            # Non-model tiers (independent_review/escalation) are governed elsewhere.
            return True, ""
        if req > _TIER_ORDER[cap]:
            return (
                False,
                f"role {role!r} may use at most tier {cap!r}; requested {requested_tier!r}",
            )
        return True, ""

    def quota_violations(
        self,
        *,
        role: str | None = None,
        requested_tier: str | None = None,
        agent_turns: int | None = None,
        parallel_agents: int | None = None,
        review_rounds: int | None = None,
        tool_calls: int | None = None,
        context_tokens: int | None = None,
    ) -> list[str]:
        """List every quota the request would violate (empty when compliant)."""
        out: list[str] = []
        ok, why = self.tier_allowed(role, requested_tier)
        if not ok:
            out.append(why)
        q = self.quotas
        checks: list[tuple[str, int | None, int | None]] = [
            ("agent turns", agent_turns, q.max_agent_turns),
            ("parallel agents", parallel_agents, q.max_parallel_agents),
            ("review rounds", review_rounds, q.max_review_rounds),
            ("tool calls", tool_calls, q.max_tool_calls),
            ("context tokens", context_tokens, q.context_ceiling_tokens),
        ]
        for label, value, limit in checks:
            if value is not None and limit is not None and value > limit:
                out.append(f"{label} {value} exceed quota {limit}")
        return out

    def check(
        self,
        scopes: ScopesInput,
        forecast_cost_usd: float,
        role: str | None = None,
        requested_tier: str | None = None,
        *,
        agent_turns: int | None = None,
        parallel_agents: int | None = None,
        review_rounds: int | None = None,
        tool_calls: int | None = None,
        context_tokens: int | None = None,
        now: datetime | None = None,
    ) -> BudgetDecision:
        """Decide allow / require_approval / deny for a forecast spend.

        Hard breaches and quota violations deny; soft-limit breaches and forecasts above
        ``approval_threshold_usd`` require approval; otherwise allow. Scopes without a
        configured budget are unconstrained.
        """
        if forecast_cost_usd < 0:
            raise ValueError("forecast_cost_usd must be >= 0")
        now = now or self._clock()
        scope_list = normalize_scopes(scopes)
        violations = self.quota_violations(
            role=role,
            requested_tier=requested_tier,
            agent_turns=agent_turns,
            parallel_agents=parallel_agents,
            review_rounds=review_rounds,
            tool_calls=tool_calls,
            context_tokens=context_tokens,
        )
        statuses: list[ScopeStatus] = []
        applied: list[str] = []
        for scope in scope_list:
            budget = self._budgets.get(scope.key)
            if budget is None:
                continue
            spent = self.spent(budget, now=now)
            active = self.exceptions.active_for(scope, now)
            effective: float | None = budget.limit_usd
            for exc in active:
                applied.append(exc.exception_id)
                if exc.extra_limit_usd is None:
                    effective = None
                elif effective is not None:
                    effective += exc.extra_limit_usd
            projected = spent + forecast_cost_usd
            hard = effective is not None and projected > effective + 1e-9
            soft = (
                effective is not None
                and not hard
                and projected > budget.soft_limit_ratio * effective + 1e-9
            )
            remaining = None if effective is None else max(0.0, effective - spent)
            statuses.append(
                ScopeStatus(
                    scope=scope.key,
                    limit_usd=budget.limit_usd,
                    effective_limit_usd=effective,
                    spent_usd=round(spent, 10),
                    forecast_usd=forecast_cost_usd,
                    remaining_usd=remaining,
                    hard_breach=hard,
                    soft_breach=soft,
                    exceptions=[e.exception_id for e in active],
                )
            )
        breached = [s.scope for s in statuses if s.hard_breach]
        soft_breached = [s.scope for s in statuses if s.soft_breach]
        remaining_values = [s.remaining_usd for s in statuses if s.remaining_usd is not None]
        remaining = min(remaining_values) if remaining_values else None

        reasons: list[str] = []
        if violations:
            decision = DecisionKind.deny
            reasons.extend(violations)
        elif breached:
            decision = DecisionKind.deny
            for s in statuses:
                if s.hard_breach:
                    reasons.append(
                        f"{s.scope}: spent ${s.spent_usd:.2f} + forecast ${s.forecast_usd:.2f} "
                        f"exceeds limit ${s.effective_limit_usd:.2f}"
                    )
        elif soft_breached or (
            self.quotas.approval_threshold_usd is not None
            and forecast_cost_usd > self.quotas.approval_threshold_usd
        ):
            decision = DecisionKind.require_approval
            for s in statuses:
                if s.soft_breach:
                    reasons.append(
                        f"{s.scope}: projected ${s.spent_usd + s.forecast_usd:.2f} above soft "
                        f"limit ({s.remaining_usd:.2f} remaining of {s.effective_limit_usd:.2f})"
                    )
            if (
                self.quotas.approval_threshold_usd is not None
                and forecast_cost_usd > self.quotas.approval_threshold_usd
            ):
                reasons.append(
                    f"forecast ${forecast_cost_usd:.2f} exceeds approval threshold "
                    f"${self.quotas.approval_threshold_usd:.2f}"
                )
        else:
            decision = DecisionKind.allow
            if statuses:
                reasons.append("within budget for " + ", ".join(s.scope for s in statuses))
            else:
                reasons.append("no budget configured for the requested scopes")
        if applied:
            reasons.append("exceptions applied: " + ", ".join(sorted(set(applied))))
        return BudgetDecision(
            decision=decision,
            reason="; ".join(reasons),
            remaining_usd=remaining,
            breached_scopes=breached,
            soft_breached_scopes=soft_breached,
            quota_violations=violations,
            applied_exceptions=sorted(set(applied)),
            forecast_cost_usd=forecast_cost_usd,
            scopes=statuses,
        )

    # ------------------------------------------------------------------ per-agent windows
    def check_agent(self, agent_id: str, estimated_tokens: int = 0) -> AgentWindowDecision:
        """Per-agent rolling-window check (allowed when no tracker is configured)."""
        if self.agent_tracker is None:
            return AgentWindowDecision(allowed=True, reason="no agent tracker configured")
        return self.agent_tracker.check(agent_id, estimated_tokens)

    def record_agent_usage(self, agent_id: str, tokens: int, cost_usd: float = 0.0) -> None:
        """Feed per-agent consumption to the tracker (no-op without one)."""
        if self.agent_tracker is not None:
            self.agent_tracker.record_usage(agent_id, tokens, cost_usd)
