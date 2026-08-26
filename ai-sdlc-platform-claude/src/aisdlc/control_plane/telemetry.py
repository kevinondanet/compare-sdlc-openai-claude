"""Telemetry importers: external usage records -> :class:`UsageEvent`.

Sources:

* PyRIT memory message pieces (``prompt_metadata`` ``token_usage_*`` keys, optional).
* Claude Code session JSONL (``message.usage`` + ``message.model``).
* AGT audit entries (privileged tool calls).
* OpenTelemetry-style spans carrying GenAI semantic-convention attributes (no otel
  dependency; any object with ``name``/``attributes``/timestamps is accepted).

None of the importers require the source library to be installed; PyRIT and AGT objects
are consumed by duck typing so tests run without them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.control_plane.pricing import PriceTable, cost_usd
from aisdlc.control_plane.registry import ModelRegistry

PYRIT_TOKEN_PREFIX = "token_usage_"


class TelemetryDefaults(BaseModel):
    """Attribution applied to every imported event unless the record carries its own."""

    model_config = ConfigDict(extra="forbid")

    team: str = ""
    application: str = ""
    user: str = ""
    repository: str = ""
    change_id: str = ""
    task_id: str = ""
    agent_role: str = ""
    harness: str = ""
    environment: str = ""
    session_id: str = ""
    prompt_version: str = ""


def _int(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return max(0, int(value))
    try:
        return max(0, int(float(str(value))))
    except ValueError:
        return 0


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        # Accept seconds, milliseconds or nanoseconds since the epoch.
        v = float(value)
        if v > 1e17:
            v /= 1e9
        elif v > 1e11:
            v /= 1e3
        return datetime.fromtimestamp(v, tz=UTC)
    if isinstance(value, str) and value:
        text = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(tz=UTC)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return datetime.now(tz=UTC)


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _provider_for(model: str, registry: ModelRegistry | None, fallback: str = "") -> str:
    if registry is not None and model in registry:
        return registry.get(model).provider
    if fallback:
        return fallback
    lowered = model.lower()
    if lowered.startswith("claude"):
        return "anthropic"
    if lowered.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    return ""


def compute_cost(
    registry: ModelRegistry | None,
    model: str,
    *,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
    reasoning_tokens: int = 0,
    cache_write_tokens: int = 0,
    price_table: PriceTable | None = None,
) -> float:
    """Cost from the registry price (0.0 when the model is unknown)."""
    if registry is None or model not in registry:
        return 0.0
    return cost_usd(
        registry.get(model),
        input_tokens,
        output_tokens,
        cached_tokens,
        reasoning_tokens,
        cache_write_tokens=cache_write_tokens,
        price_table=price_table,
    )


def _base_kwargs(defaults: TelemetryDefaults) -> dict[str, Any]:
    return defaults.model_dump()


# ---------------------------------------------------------------------- PyRIT
def _pyrit_tokens(metadata: dict[str, Any]) -> dict[str, int] | None:
    """Extract token counts from a PyRIT ``prompt_metadata`` dict; None if absent."""
    keys = {
        "input_tokens": ("token_usage_input_tokens", "input_tokens"),
        "output_tokens": ("token_usage_output_tokens", "output_tokens"),
        "cached_tokens": ("token_usage_cached_tokens", "cached_tokens"),
        "reasoning_tokens": ("token_usage_reasoning_tokens", "reasoning_tokens"),
    }
    found = False
    out: dict[str, int] = {}
    for field, candidates in keys.items():
        val = None
        for k in candidates:
            if k in metadata:
                val = metadata[k]
                found = found or field in ("input_tokens", "output_tokens")
                break
        out[field] = _int(val)
    return out if found else None


def from_pyrit_pieces(
    pieces: Iterable[Any],
    *,
    defaults: TelemetryDefaults | None = None,
    registry: ModelRegistry | None = None,
    model: str = "",
    provider: str = "",
    price_table: PriceTable | None = None,
) -> list[UsageEvent]:
    """Convert PyRIT message pieces (objects or dicts) into usage events.

    Only pieces whose ``prompt_metadata`` carries token counts produce events. The model is
    taken from ``prompt_metadata['model']`` when present, else ``model``.
    """
    defaults = defaults or TelemetryDefaults()
    events: list[UsageEvent] = []
    for piece in pieces:
        metadata = _get(piece, "prompt_metadata", None) or {}
        if not isinstance(metadata, dict):
            continue
        tokens = _pyrit_tokens(metadata)
        if tokens is None:
            continue
        piece_model = str(metadata.get("model") or model or "")
        cost = _float(metadata.get("token_usage_cost"))
        if cost is None:
            cost = compute_cost(registry, piece_model, price_table=price_table, **tokens)
        conv = _get(piece, "conversation_id", "") or ""
        kwargs = _base_kwargs(defaults)
        kwargs.update(
            ts=_ts(_get(piece, "timestamp", None)),
            provider=_provider_for(piece_model, registry, provider),
            model=piece_model,
            session_id=str(conv) or defaults.session_id,
            source="pyrit",
            cost_usd=max(0.0, cost),
            cache_hit=tokens["cached_tokens"] > 0,
            **tokens,
        )
        if not kwargs["agent_role"]:
            kwargs["agent_role"] = "security_tester"
        events.append(UsageEvent(**kwargs))
    return events


def from_pyrit_memory(
    memory: Any,
    *,
    change_id: str = "",
    defaults: TelemetryDefaults | None = None,
    conversation_id: str | None = None,
    labels: dict[str, str] | None = None,
    registry: ModelRegistry | None = None,
    model: str = "",
    price_table: PriceTable | None = None,
) -> list[UsageEvent]:
    """Read message pieces from a PyRIT memory instance and convert them.

    ``memory`` must expose ``get_message_pieces(**filters)`` (PyRIT ``MemoryInterface``);
    any object with that method works, so PyRIT itself need not be installed.
    """
    defaults = defaults or TelemetryDefaults()
    if change_id:
        defaults = defaults.model_copy(update={"change_id": change_id})
    getter = getattr(memory, "get_message_pieces", None)
    if getter is None:
        raise TypeError("memory must provide get_message_pieces(...)")
    filters: dict[str, Any] = {}
    if conversation_id is not None:
        filters["conversation_id"] = conversation_id
    if labels is not None:
        filters["labels"] = labels
    pieces = getter(**filters)
    return from_pyrit_pieces(
        pieces, defaults=defaults, registry=registry, model=model, price_table=price_table
    )


# ---------------------------------------------------------------------- Claude Code
def _claude_code_event(
    record: dict[str, Any],
    defaults: TelemetryDefaults,
    registry: ModelRegistry | None,
    price_table: PriceTable | None,
) -> UsageEvent | None:
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    usage = message.get("usage")
    if not isinstance(usage, dict):
        return None
    model = str(message.get("model") or record.get("model") or "")
    input_tokens = _int(usage.get("input_tokens"))
    output_tokens = _int(usage.get("output_tokens"))
    cached = _int(usage.get("cache_read_input_tokens"))
    cache_write = _int(usage.get("cache_creation_input_tokens"))
    content = message.get("content")
    tool_calls = 0
    if isinstance(content, list):
        tool_calls = sum(
            1
            for c in content
            if isinstance(c, dict) and c.get("type") in {"tool_use", "server_tool_use"}
        )
    cost = _float(record.get("costUSD"))
    if cost is None:
        cost = compute_cost(
            registry,
            model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached,
            cache_write_tokens=cache_write,
            price_table=price_table,
        )
    kwargs = _base_kwargs(defaults)
    kwargs.update(
        ts=_ts(record.get("timestamp")),
        harness=defaults.harness or "claude_code",
        provider=_provider_for(model, registry, "anthropic"),
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached,
        cache_write_tokens=cache_write,
        tool_calls=tool_calls,
        cost_usd=cost,
        cache_hit=cached > 0,
        source="claude_code",
        session_id=str(record.get("sessionId") or record.get("session_id") or defaults.session_id),
    )
    if not kwargs["repository"] and record.get("cwd"):
        kwargs["repository"] = str(record["cwd"])
    if not kwargs["user"] and record.get("userType"):
        kwargs["user"] = str(record["userType"])
    if record.get("version"):
        kwargs["prompt_version"] = kwargs["prompt_version"] or str(record["version"])
    # Claude reports thinking tokens inside output_tokens (billed as output), so
    # reasoning_tokens stays 0 to avoid double counting.
    return UsageEvent(**kwargs)


def from_claude_code_jsonl(
    path: str | Path,
    *,
    defaults: TelemetryDefaults | None = None,
    registry: ModelRegistry | None = None,
    price_table: PriceTable | None = None,
    dedupe: bool = True,
) -> list[UsageEvent]:
    """Parse a Claude Code session transcript (JSONL) into usage events.

    Streaming writes one line per content block with the same ``requestId``/message id
    and identical usage; with ``dedupe`` those collapse to one event, keeping the union
    of tool calls.
    """
    defaults = defaults or TelemetryDefaults()
    p = Path(path)
    events: list[UsageEvent] = []
    seen: dict[str, int] = {}
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            ev = _claude_code_event(record, defaults, registry, price_table)
            if ev is None:
                continue
            msg = record.get("message") if isinstance(record.get("message"), dict) else {}
            key = str(record.get("requestId") or (msg or {}).get("id") or "")
            if dedupe and key:
                if key in seen:
                    prior = events[seen[key]]
                    if ev.tool_calls > prior.tool_calls or ev.output_tokens > prior.output_tokens:
                        events[seen[key]] = prior.model_copy(
                            update={
                                "tool_calls": max(prior.tool_calls, ev.tool_calls),
                                "output_tokens": max(prior.output_tokens, ev.output_tokens),
                                "cost_usd": max(prior.cost_usd, ev.cost_usd),
                            }
                        )
                    continue
                seen[key] = len(events)
            events.append(ev)
    return events


# ---------------------------------------------------------------------- AGT audit
def from_agt_audit(
    entries: Iterable[Any],
    *,
    defaults: TelemetryDefaults | None = None,
    change_id: str = "",
) -> list[UsageEvent]:
    """Convert AGT ``AuditEntry`` objects (or dicts) into tool-call usage events.

    Each entry becomes one event with ``tool_calls=1``; latency comes from
    ``issued_at``/``completed_at`` when both are present.
    """
    defaults = defaults or TelemetryDefaults()
    if change_id:
        defaults = defaults.model_copy(update={"change_id": change_id})
    events: list[UsageEvent] = []
    for entry in entries:
        action = str(_get(entry, "action", "") or "")
        agent = str(_get(entry, "agent_did", "") or "")
        issued = _get(entry, "issued_at", None)
        completed = _get(entry, "completed_at", None)
        latency = 0.0
        if issued is not None and completed is not None:
            latency = max(0.0, (_ts(completed) - _ts(issued)).total_seconds() * 1000.0)
        data = _get(entry, "data", None)
        data = data if isinstance(data, dict) else {}
        outcome = str(_get(entry, "outcome", "") or "")
        kwargs = _base_kwargs(defaults)
        kwargs.update(
            event_id=str(_get(entry, "entry_id", "") or "") or UsageEvent().event_id,
            ts=_ts(_get(entry, "timestamp", None)),
            agent_role=defaults.agent_role or agent,
            provider="agt",
            model=f"tool:{action}" if action else "tool",
            tool_calls=1,
            latency_ms=latency,
            cost_usd=max(0.0, _float(data.get("cost_usd")) or 0.0),
            source="agt_audit",
            session_id=str(_get(entry, "session_id", "") or defaults.session_id),
            environment=defaults.environment or str(_get(entry, "environment", "") or ""),
            success=None if not outcome else outcome.lower() in {"success", "allowed", "ok"},
        )
        if not kwargs["task_id"] and data.get("task_id"):
            kwargs["task_id"] = str(data["task_id"])
        if not kwargs["change_id"] and data.get("change_id"):
            kwargs["change_id"] = str(data["change_id"])
        events.append(UsageEvent(**kwargs))
    return events


# ---------------------------------------------------------------------- OpenTelemetry-style hook
class SpanData(BaseModel):
    """Minimal span shape (subset of the OTel span) understood by the exporter."""

    model_config = ConfigDict(extra="forbid")

    name: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    start_time_unix_nano: int | None = None
    end_time_unix_nano: int | None = None
    status: str = "ok"
    trace_id: str = ""
    span_id: str = ""

    @classmethod
    def from_object(cls, span: Any) -> SpanData:
        """Build from any span-like object (``opentelemetry.sdk.trace.ReadableSpan`` etc.)."""
        if isinstance(span, SpanData):
            return span
        if isinstance(span, dict):
            return cls.model_validate(
                {
                    "name": span.get("name", ""),
                    "attributes": dict(span.get("attributes") or {}),
                    "start_time_unix_nano": span.get(
                        "start_time_unix_nano", span.get("start_time")
                    ),
                    "end_time_unix_nano": span.get("end_time_unix_nano", span.get("end_time")),
                    "status": str(span.get("status", "ok")),
                    "trace_id": str(span.get("trace_id", "")),
                    "span_id": str(span.get("span_id", "")),
                }
            )
        attrs = getattr(span, "attributes", None) or {}
        ctx = getattr(span, "context", None) or getattr(span, "get_span_context", lambda: None)()
        trace_id = getattr(ctx, "trace_id", "") if ctx is not None else ""
        span_id = getattr(ctx, "span_id", "") if ctx is not None else ""
        status = getattr(span, "status", "ok")
        status_text = getattr(status, "status_code", status)
        return cls(
            name=str(getattr(span, "name", "") or ""),
            attributes=dict(attrs),
            start_time_unix_nano=getattr(span, "start_time", None),
            end_time_unix_nano=getattr(span, "end_time", None),
            status=str(getattr(status_text, "name", status_text)).lower(),
            trace_id=format(trace_id, "032x") if isinstance(trace_id, int) else str(trace_id),
            span_id=format(span_id, "016x") if isinstance(span_id, int) else str(span_id),
        )


class SpanHook(Protocol):
    """Callback interface compatible with an OTel ``SpanProcessor.on_end``."""

    def on_end(self, span: Any) -> None:
        """Called once per finished span."""


_ATTR_ALIASES: dict[str, tuple[str, ...]] = {
    "model": ("gen_ai.response.model", "gen_ai.request.model", "llm.model", "model"),
    "provider": ("gen_ai.provider.name", "gen_ai.system", "llm.provider"),
    "input_tokens": (
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.prompt_tokens",
        "llm.usage.prompt_tokens",
    ),
    "output_tokens": (
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.completion_tokens",
        "llm.usage.completion_tokens",
    ),
    "cached_tokens": ("gen_ai.usage.cache_read_input_tokens", "gen_ai.usage.cached_tokens"),
    "cache_write_tokens": ("gen_ai.usage.cache_creation_input_tokens",),
    "reasoning_tokens": ("gen_ai.usage.reasoning_tokens",),
    "tool_calls": ("gen_ai.tool.calls", "aisdlc.tool_calls"),
    "cost_usd": ("gen_ai.usage.cost", "aisdlc.cost_usd"),
    "agent_role": ("aisdlc.agent_role", "gen_ai.agent.name"),
    "change_id": ("aisdlc.change_id",),
    "task_id": ("aisdlc.task_id",),
    "team": ("aisdlc.team",),
    "application": ("aisdlc.application", "service.name"),
    "user": ("aisdlc.user", "enduser.id"),
    "repository": ("aisdlc.repository",),
    "harness": ("aisdlc.harness",),
    "environment": ("aisdlc.environment", "deployment.environment"),
    "prompt_version": ("aisdlc.prompt_version", "gen_ai.prompt.version"),
    "session_id": ("aisdlc.session_id", "gen_ai.conversation.id", "session.id"),
    "routing_tier": ("aisdlc.routing_tier",),
    "escalated": ("aisdlc.escalated",),
}


def _attr(attrs: dict[str, Any], key: str) -> Any:
    for name in _ATTR_ALIASES[key]:
        if name in attrs and attrs[name] is not None:
            return attrs[name]
    return None


def span_to_event(
    span: Any,
    *,
    defaults: TelemetryDefaults | None = None,
    registry: ModelRegistry | None = None,
    price_table: PriceTable | None = None,
) -> UsageEvent | None:
    """Convert a GenAI-instrumented span to a usage event (None if it carries no usage)."""
    defaults = defaults or TelemetryDefaults()
    data = SpanData.from_object(span)
    attrs = data.attributes
    model = _attr(attrs, "model")
    has_tokens = any(_attr(attrs, k) is not None for k in ("input_tokens", "output_tokens"))
    tool_calls = _int(_attr(attrs, "tool_calls"))
    if model is None and not has_tokens and tool_calls == 0:
        return None
    model_s = str(model or "")
    input_tokens = _int(_attr(attrs, "input_tokens"))
    output_tokens = _int(_attr(attrs, "output_tokens"))
    cached = _int(_attr(attrs, "cached_tokens"))
    cache_write = _int(_attr(attrs, "cache_write_tokens"))
    reasoning = _int(_attr(attrs, "reasoning_tokens"))
    cost = _float(_attr(attrs, "cost_usd"))
    if cost is None:
        cost = compute_cost(
            registry,
            model_s,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached,
            reasoning_tokens=reasoning,
            cache_write_tokens=cache_write,
            price_table=price_table,
        )
    latency = 0.0
    if data.start_time_unix_nano is not None and data.end_time_unix_nano is not None:
        latency = max(0.0, (data.end_time_unix_nano - data.start_time_unix_nano) / 1e6)
    kwargs = _base_kwargs(defaults)
    for field in (
        "agent_role",
        "change_id",
        "task_id",
        "team",
        "application",
        "user",
        "repository",
        "harness",
        "environment",
        "prompt_version",
        "session_id",
    ):
        val = _attr(attrs, field)
        if val is not None and str(val):
            kwargs[field] = str(val)
    ts = (
        datetime.fromtimestamp(data.end_time_unix_nano / 1e9, tz=UTC)
        if data.end_time_unix_nano
        else datetime.now(tz=UTC)
    )
    kwargs.update(
        ts=ts,
        provider=_provider_for(model_s, registry, str(_attr(attrs, "provider") or "")),
        model=model_s,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached,
        cache_write_tokens=cache_write,
        reasoning_tokens=reasoning,
        tool_calls=tool_calls,
        latency_ms=latency,
        cost_usd=max(0.0, cost),
        cache_hit=cached > 0,
        source="otel",
        routing_tier=str(_attr(attrs, "routing_tier") or ""),
        escalated=bool(_attr(attrs, "escalated") or False),
        success=None if data.status in {"unset", ""} else data.status not in {"error", "failed"},
    )
    return UsageEvent(**kwargs)


class LedgerSpanExporter:
    """Span hook that writes GenAI spans straight into a :class:`UsageLedger`.

    Usable as an OTel ``SpanProcessor`` (``on_end``) or a ``SpanExporter`` (``export``).
    """

    def __init__(
        self,
        ledger: UsageLedger,
        *,
        defaults: TelemetryDefaults | None = None,
        registry: ModelRegistry | None = None,
        price_table: PriceTable | None = None,
    ) -> None:
        self.ledger = ledger
        self.defaults = defaults or TelemetryDefaults()
        self.registry = registry
        self.price_table = price_table
        self.exported = 0
        self.skipped = 0

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        """No-op (SpanProcessor compatibility)."""

    def on_end(self, span: Any) -> None:
        """Record the span if it carries usage."""
        ev = span_to_event(
            span, defaults=self.defaults, registry=self.registry, price_table=self.price_table
        )
        if ev is None:
            self.skipped += 1
            return
        self.ledger.record(ev)
        self.exported += 1

    def export(self, spans: Iterable[Any]) -> int:
        """Record a batch of spans; returns the number written."""
        before = self.exported
        for s in spans:
            self.on_end(s)
        return self.exported - before

    def shutdown(self) -> None:
        """No-op (SpanExporter compatibility)."""

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """No-op (SpanExporter compatibility)."""
        return True
