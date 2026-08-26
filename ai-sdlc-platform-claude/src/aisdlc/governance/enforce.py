"""Policy enforcement for tool actions, built on the AGT ``PolicyEngine`` and approvals.

:class:`PolicyEnforcer` evaluates a classified :class:`ToolAction` against the loaded
tier policies with ``PolicyEngine.evaluate(agent_did, context)`` and turns the result
into an :class:`EnforcementDecision`:

* ``allow``            -> allowed
* ``log`` / ``warn``   -> allowed, always audited (AGT reports ``allowed=False`` for these
  informational actions; the platform interprets them as "allow with audit")
* ``require_approval`` -> routed to the approval handler; no handler, a timeout or an
  error denies (AGT ``AutoRejectApproval`` / ``CallbackApproval`` deny-on-timeout)
* ``deny``             -> denied

Every tier >= 1 decision and every denial is written to the :class:`AuditTrail`.
:func:`govern_callable` wraps AGT ``govern()`` for callables; shadow mode records what
*would* happen without blocking tier 0-3 — tier-4 denials are enforced even in shadow mode
(:func:`shadow_enforces`). :class:`DeferredApproval` hands tier-3 decisions to a human
outside the process (the Claude Code permission prompt) and audits them as pending.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from aisdlc.governance.audit import AuditTrail
from aisdlc.governance.policy import agt_governance, load_policy_engine
from aisdlc.governance.tiers import RiskTier, TierConfig, ToolAction, classify_action

if TYPE_CHECKING:
    _DeniedBase = Exception
else:  # pragma: no cover - import branch depends on the optional extra
    try:
        from agentmesh.governance import GovernanceDenied as _DeniedBase
    except ImportError:
        _DeniedBase = Exception

#: Policy actions the platform treats as "execute, but audit".
PERMISSIVE_ACTIONS: frozenset[str] = frozenset({"allow", "log", "warn"})


class EnforcementDecision(BaseModel):
    """Outcome of enforcing a tool action.

    Attributes:
        allowed: Final verdict (after approvals).
        action: The classified tool action.
        tier: Risk tier of the action.
        policy_action: Final policy action (``allow``/``deny``/``log``/``warn``).
        matched_rule: Name of the winning AGT rule.
        policy_name: Name of the policy containing the rule.
        reason: Human-readable explanation.
        approver: Identity that approved/rejected when an approval was requested.
        approval_requested: Whether the policy asked for approval.
        audit_entry_id: Id of the audit entry written for this decision.
        agent_id: Role/agent the decision was evaluated for.
        shadow: ``True`` when evaluated in shadow (dry-run) mode: never enforced.
    """

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    action: ToolAction
    tier: RiskTier
    policy_action: str
    matched_rule: str | None = None
    policy_name: str | None = None
    reason: str = ""
    approver: str | None = None
    approval_requested: bool = False
    audit_entry_id: str | None = None
    agent_id: str
    shadow: bool = False


class PlatformDenied(_DeniedBase):
    """Raised when a governed action is denied. Subclasses AGT ``GovernanceDenied`` when
    the toolkit is installed, so ``except GovernanceDenied`` also catches it."""

    def __init__(self, decision: EnforcementDecision, policy_decision: Any = None) -> None:
        self.decision = decision
        self.policy_decision = policy_decision
        Exception.__init__(
            self,
            f"Action denied by policy rule '{decision.matched_rule}': {decision.reason}",
        )


@dataclass
class ApprovalRequestInfo:
    """Platform view of an approval request (no AGT types)."""

    action: ToolAction
    rule_name: str
    policy_name: str
    agent_id: str
    approvers: list[str] = field(default_factory=list)
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ApprovalOutcome:
    """Platform view of an approval decision."""

    approved: bool
    approver: str = ""
    reason: str = ""


ApprovalCallback = Callable[[ApprovalRequestInfo], "ApprovalOutcome | bool"]

#: Approver prefix for decisions that were not taken in-process but handed to a human
#: outside the enforcer (the Claude Code permission prompt). Such decisions are audited as
#: ``approval_pending`` rather than ``denied``.
DEFERRED_APPROVER_PREFIX = "deferred:"


class DeferredApproval:
    """AGT-compatible approval handler that defers tier-3 decisions to an external human.

    It never approves: the action stays blocked in-process (fail closed), but the decision
    is reported as *pending* (``policy_action == "require_approval"``, approver
    ``deferred:<channel>``) so the audit trail records an open approval instead of a
    denial. The hook CLI uses it because Claude Code shows the human its own permission
    prompt; the tool only runs (and ``PostToolUse`` fires) when the human approves.
    """

    def __init__(self, channel: str = "claude-code") -> None:
        self.channel = channel
        self.approver = f"{DEFERRED_APPROVER_PREFIX}{channel}"

    def request_approval(self, request: Any) -> Any:
        """AGT ``ApprovalHandler`` protocol method."""
        gov = agt_governance()
        return gov.ApprovalDecision(
            approved=False,
            approver=self.approver,
            reason=f"approval deferred to the {self.channel} permission prompt",
        )


class _RecordingHandler:
    """AGT-compatible approval handler that fails closed and remembers the last outcome.

    Wraps either an AGT ``ApprovalHandler`` (anything with ``request_approval``), a plain
    platform callback (wrapped in ``CallbackApproval`` with deny-on-timeout) or nothing
    (``AutoRejectApproval``).
    """

    def __init__(self, handler: Any, timeout_seconds: float) -> None:
        gov = agt_governance()
        self._local = threading.local()
        if handler is None:
            self._inner = gov.AutoRejectApproval(
                reason="No approval handler configured — tier 3 action auto-rejected"
            )
        elif hasattr(handler, "request_approval"):
            self._inner = handler
        elif callable(handler):
            self._inner = gov.CallbackApproval(
                callback=self._bridge(handler),
                timeout_seconds=timeout_seconds,
                on_timeout="deny",
            )
        else:
            raise TypeError("approval_handler must be an ApprovalHandler, a callable or None")

    def _bridge(self, callback: ApprovalCallback) -> Callable[[Any], Any]:
        gov = agt_governance()

        def _call(request: Any) -> Any:
            info = ApprovalRequestInfo(
                action=_tool_action_from_context(request.context),
                rule_name=request.rule_name,
                policy_name=request.policy_name,
                agent_id=request.agent_id,
                approvers=list(request.approvers),
                requested_at=request.requested_at,
            )
            outcome = callback(info)
            if isinstance(outcome, bool):
                outcome = ApprovalOutcome(
                    approved=outcome, approver="callback", reason="rule-based decision"
                )
            return gov.ApprovalDecision(
                approved=outcome.approved, approver=outcome.approver, reason=outcome.reason
            )

        return _call

    def request_approval(self, request: Any) -> Any:
        """AGT ``ApprovalHandler`` protocol method."""
        decision = self._inner.request_approval(request)
        self._local.last = decision
        return decision

    @property
    def last(self) -> Any | None:
        """Last approval decision made on this thread (``None`` if none)."""
        return getattr(self._local, "last", None)

    def reset(self) -> None:
        """Forget the last decision on this thread."""
        self._local.last = None


def _tool_action_from_context(context: dict[str, Any]) -> ToolAction:
    call = context.get("call")
    if isinstance(call, dict) and isinstance(call.get("tool_action"), ToolAction):
        found: ToolAction = call["tool_action"]
        return found
    action = context.get("action", {})
    if not isinstance(action, dict):
        action = {"type": str(action)}
    return ToolAction(
        tool_name=str(action.get("tool_name", "unknown")),
        action_type=str(action.get("type", "unknown")),
        resource=str(action.get("resource", "")),
        parameters=dict(action.get("parameters") or {}),
        tier=RiskTier.coerce(action.get("tier", RiskTier.APPROVAL)),
        scope=action.get("scope", "execute"),
        in_worktree=bool(action.get("in_worktree", False)),
    )


class PolicyEnforcer:
    """Enforce tier policies for one agent/role.

    Args:
        policy: A policy YAML path, YAML text, AGT ``Policy`` object, or an iterable of
            those (loaded into one engine).
        agent_id: The role/agent id policies are evaluated for (e.g. ``implementer``).
        approval_handler: AGT ``ApprovalHandler``, platform callback or ``None`` (deny).
        approval_timeout_seconds: Deny-on-timeout budget for callback approvals.
        audit_sink: Trail to record decisions in (an in-memory trail is created if omitted).
        shadow: Dry-run mode: decisions are evaluated and audited but never enforced.
        tier_config: Project tier overrides used by :meth:`classify`.
    """

    def __init__(
        self,
        policy: str | Path | Any | Iterable[str | Path | Any],
        agent_id: str,
        *,
        approval_handler: Any | None = None,
        approval_timeout_seconds: float = 300.0,
        audit_sink: AuditTrail | None = None,
        shadow: bool = False,
        tier_config: TierConfig | None = None,
        conflict_strategy: str = "priority_first_match",
    ) -> None:
        self._sources = _normalise_sources(policy)
        self._engine = load_policy_engine(self._sources, conflict_strategy=conflict_strategy)
        self.agent_id = agent_id
        self.shadow = shadow
        self.tier_config = tier_config or TierConfig()
        self._approvals = _RecordingHandler(approval_handler, approval_timeout_seconds)
        self._audit = audit_sink or AuditTrail()

    @property
    def engine(self) -> Any:
        """The AGT ``PolicyEngine`` (for inspection)."""
        return self._engine

    @property
    def audit(self) -> AuditTrail:
        """The audit trail decisions are recorded in."""
        return self._audit

    @property
    def policy_sources(self) -> list[Any]:
        """Sources the engine was loaded from."""
        return list(self._sources)

    @property
    def defers_approval(self) -> bool:
        """Whether tier-3 approvals go to an external human (:class:`DeferredApproval`)."""
        return isinstance(self._approvals._inner, DeferredApproval)  # noqa: SLF001

    def classify(
        self,
        tool_name: str,
        action_type: str,
        resource: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> ToolAction:
        """Classify a raw tool call with this enforcer's tier configuration."""
        return classify_action(
            tool_name, action_type, resource, parameters, config=self.tier_config
        )

    def check(self, action: ToolAction) -> EnforcementDecision:
        """Evaluate ``action`` (requesting approval when required) and audit the result.

        Never raises for policy reasons; see :meth:`enforce` for the raising variant.
        """
        context = action.to_context()
        context["call"] = {"tool_action": action}
        raw = self._engine.evaluate(self.agent_id, context, stage="pre_tool")
        policy_action = str(raw.action)
        allowed = bool(raw.allowed) or policy_action in PERMISSIVE_ACTIONS
        approver: str | None = None
        approval_requested = policy_action == "require_approval"
        reason = str(raw.reason or "")

        if approval_requested and not self.shadow:
            gov = agt_governance()
            request = gov.ApprovalRequest(
                action=action.action_type,
                rule_name=raw.matched_rule or "",
                policy_name=raw.policy_name or "",
                agent_id=self.agent_id,
                context=context,
                approvers=list(raw.approvers),
            )
            outcome = self._approvals.request_approval(request)
            approver = str(outcome.approver or "") or None
            allowed = bool(outcome.approved)
            if allowed:
                policy_action = "allow"
                reason = f"Approved by {outcome.approver or 'unknown'}: {outcome.reason or reason}"
            elif (approver or "").startswith(DEFERRED_APPROVER_PREFIX):
                # Still blocked here, but the decision is pending on an external human:
                # keep ``require_approval`` so the audit outcome is approval_pending.
                policy_action = "require_approval"
                reason = f"Approval pending ({approver}): {outcome.reason or reason}"
            else:
                policy_action = "deny"
                reason = (
                    f"Approval rejected by {outcome.approver or 'unknown'}: "
                    f"{outcome.reason or reason}"
                )
        elif approval_requested:
            allowed = False
            reason = f"[shadow] would require approval from {list(raw.approvers) or 'policy'}"

        decision = EnforcementDecision(
            allowed=allowed,
            action=action,
            tier=action.tier,
            policy_action=policy_action,
            matched_rule=raw.matched_rule,
            policy_name=raw.policy_name,
            reason=reason,
            approver=approver,
            approval_requested=approval_requested,
            agent_id=self.agent_id,
            shadow=self.shadow,
        )
        return self._audited(decision)

    def enforce(self, action: ToolAction) -> EnforcementDecision:
        """Like :meth:`check` but raises :class:`PlatformDenied` unless allowed.

        Shadow mode lets tier 0-3 denials through (recorded only); tier-4 denials — deploy,
        secrets, IAM, data deletion, unlisted egress — are enforced even in shadow mode.
        """
        decision = self.check(action)
        if not decision.allowed and shadow_enforces(decision, self.shadow):
            raise PlatformDenied(decision)
        return decision

    def govern_callable(
        self, fn: Callable[..., Any], *, action: ToolAction | Callable[..., ToolAction]
    ) -> Callable[..., Any]:
        """Wrap ``fn`` with AGT ``govern()`` using this enforcer's policy and settings."""
        if len(self._sources) != 1:
            raise ValueError("govern_callable needs an enforcer loaded from exactly one policy")
        return govern_callable(
            fn,
            policy=self._sources[0],
            agent_id=self.agent_id,
            action=action,
            approval_handler=self._approvals,
            audit_sink=self._audit,
            shadow=self.shadow,
        )

    def _audited(self, decision: EnforcementDecision) -> EnforcementDecision:
        if decision.tier.requires_audit or not decision.allowed or decision.approval_requested:
            entry_id = self._audit.record(decision, decision.action)
            return decision.model_copy(update={"audit_entry_id": entry_id})
        return decision


class _LogPassthroughError(Exception):
    """Internal: AGT would deny an informational ``log``/``warn`` rule; call through."""

    def __init__(self, decision: Any) -> None:
        self.decision = decision
        super().__init__("log passthrough")


class GovernedTool:
    """A callable governed by AGT ``govern()`` with platform classification and audit."""

    def __init__(
        self,
        fn: Callable[..., Any],
        *,
        policy: str | Path | Any,
        agent_id: str,
        action: ToolAction | Callable[..., ToolAction],
        approval_handler: Any | None = None,
        approval_timeout_seconds: float = 300.0,
        audit_sink: AuditTrail | None = None,
        shadow: bool = False,
    ) -> None:
        gov = agt_governance()
        self._fn = fn
        self._action = action
        self.agent_id = agent_id
        self.shadow = shadow
        self._audit = audit_sink or AuditTrail()
        if isinstance(approval_handler, _RecordingHandler):
            self._approvals = approval_handler
        else:
            self._approvals = _RecordingHandler(approval_handler, approval_timeout_seconds)
        policy_source = str(policy) if isinstance(policy, Path) else policy
        self._governed = gov.govern(
            self._invoke,
            policy=policy_source,
            agent_id=agent_id,
            audit=False,
            approval_handler=self._approvals,
            conflict_strategy="priority_first_match",
            on_deny=self._on_deny,
        )
        self.__name__ = getattr(fn, "__name__", "governed")
        self.__doc__ = getattr(fn, "__doc__", None)
        self.last_decision: EnforcementDecision | None = None

    @property
    def engine(self) -> Any:
        """The AGT ``PolicyEngine`` created by ``govern()``."""
        return self._governed.engine

    @staticmethod
    def _invoke(**kwargs: Any) -> Any:
        call = kwargs["call"]
        return call["fn"](*call["args"], **call["kwargs"])

    @staticmethod
    def _on_deny(decision: Any) -> Any:
        if str(decision.action) in PERMISSIVE_ACTIONS:
            raise _LogPassthroughError(decision)
        raise _AgtDeniedError(decision)

    def resolve_action(self, *args: Any, **kwargs: Any) -> ToolAction:
        """The :class:`ToolAction` for a call with these arguments."""
        if isinstance(self._action, ToolAction):
            return self._action
        return self._action(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        tool_action = self.resolve_action(*args, **kwargs)
        context = tool_action.to_context()
        payload = {"fn": self._fn, "args": args, "kwargs": kwargs, "tool_action": tool_action}
        raw = self._governed.engine.evaluate(self.agent_id, dict(context), stage="pre_tool")
        self._approvals.reset()
        allowed = True
        policy_action = str(raw.action)
        reason = str(raw.reason or "")
        result: Any = None
        denied: _AgtDeniedError | None = None
        if self.shadow:
            # Dry run: record without blocking (tier-4 denials stay enforced) and never
            # wait on an approval handler.
            allowed = bool(raw.allowed) or policy_action in PERMISSIVE_ACTIONS
            if policy_action == "require_approval":
                reason = f"[shadow] would require approval from {list(raw.approvers) or 'policy'}"
            decision = EnforcementDecision(
                allowed=allowed,
                action=tool_action,
                tier=tool_action.tier,
                policy_action=policy_action,
                matched_rule=raw.matched_rule,
                policy_name=raw.policy_name,
                reason=reason,
                approval_requested=policy_action == "require_approval",
                agent_id=self.agent_id,
                shadow=True,
            )
            entry_id = self._audit.record(decision, tool_action)
            self.last_decision = decision.model_copy(update={"audit_entry_id": entry_id})
            if not allowed and shadow_enforces(decision, True):
                raise PlatformDenied(self.last_decision, raw)
            return self._fn(*args, **kwargs)
        try:
            result = self._governed(action=context["action"], call=payload)
            if policy_action == "require_approval":
                policy_action = "allow"
        except _LogPassthroughError:
            result = self._fn(*args, **kwargs)
        except _AgtDeniedError as exc:
            denied = exc
            allowed = False
            policy_action = "deny"
            reason = str(exc.decision.reason or reason)
        approval = self._approvals.last
        decision = EnforcementDecision(
            allowed=allowed,
            action=tool_action,
            tier=tool_action.tier,
            policy_action=policy_action,
            matched_rule=raw.matched_rule,
            policy_name=raw.policy_name,
            reason=reason,
            approver=(str(approval.approver) or None) if approval is not None else None,
            approval_requested=str(raw.action) == "require_approval",
            agent_id=self.agent_id,
            shadow=self.shadow,
        )
        if decision.tier.requires_audit or not decision.allowed or decision.approval_requested:
            entry_id = self._audit.record(decision, tool_action)
            decision = decision.model_copy(update={"audit_entry_id": entry_id})
        self.last_decision = decision
        if denied is not None:
            raise PlatformDenied(decision, denied.decision) from None
        return result


class _AgtDeniedError(Exception):
    """Internal: carries the AGT ``PolicyDecision`` out of ``on_deny``."""

    def __init__(self, decision: Any) -> None:
        self.decision = decision
        super().__init__("denied")


def govern_callable(
    fn: Callable[..., Any],
    *,
    policy: str | Path | Any,
    agent_id: str,
    action: ToolAction | Callable[..., ToolAction],
    approval_handler: Any | None = None,
    approval_timeout_seconds: float = 300.0,
    audit_sink: AuditTrail | None = None,
    shadow: bool = False,
) -> GovernedTool:
    """Wrap ``fn`` with AGT ``govern()``.

    ``action`` is either a fixed :class:`ToolAction` or a factory called with the same
    arguments as ``fn`` to classify each call. Denials raise :class:`PlatformDenied`
    (unless ``shadow``); ``log``/``warn`` rules call through; approvals go to
    ``approval_handler`` with deny-on-timeout and deny-when-missing semantics.
    """
    return GovernedTool(
        fn,
        policy=policy,
        agent_id=agent_id,
        action=action,
        approval_handler=approval_handler,
        approval_timeout_seconds=approval_timeout_seconds,
        audit_sink=audit_sink,
        shadow=shadow,
    )


def shadow_enforces(decision: EnforcementDecision, shadow: bool) -> bool:
    """Whether a non-allowed ``decision`` must still be enforced given ``shadow`` mode.

    Shadow mode is a dry run for tier 0-3; tier 4 (human approval required: deploy,
    secrets, IAM, delete data, unlisted egress) has no dry run and is always enforced.
    """
    return not shadow or decision.tier >= RiskTier.HUMAN_APPROVAL


def _normalise_sources(policy: Any) -> list[Any]:
    if isinstance(policy, (str, Path)):
        return [policy]
    if isinstance(policy, Iterable) and not hasattr(policy, "rules"):
        return list(policy)
    return [policy]
