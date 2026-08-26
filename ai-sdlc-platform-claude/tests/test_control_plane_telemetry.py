"""Tests for control_plane.telemetry and control_plane.kpis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aisdlc.control_plane.benchmark import BenchmarkCategory, BenchmarkResult, BenchmarkService
from aisdlc.control_plane.kpis import Outcomes, compute_kpis
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.control_plane.registry import ModelEntry, ModelRegistry
from aisdlc.control_plane.telemetry import (
    LedgerSpanExporter,
    SpanData,
    TelemetryDefaults,
    from_agt_audit,
    from_claude_code_jsonl,
    from_pyrit_memory,
    from_pyrit_pieces,
    span_to_event,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def _entry(**overrides: object) -> ModelEntry:
    base: dict[str, object] = {
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "family": "claude",
        "capabilities": ["code"],
        "context_limit": 1_000_000,
        "price_in_per_1m": 2.0,
        "price_out_per_1m": 10.0,
        "price_cached_per_1m": 0.2,
        "price_cache_write_per_1m": 2.5,
        "approved_use_cases": ["*"],
        "default_tier": "standard",
    }
    base.update(overrides)
    return ModelEntry.model_validate(base)


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry(
        [
            _entry(),
            _entry(
                model="claude-opus-5",
                default_tier="high",
                price_in_per_1m=5,
                price_out_per_1m=25,
                price_cached_per_1m=0.5,
                price_cache_write_per_1m=6.25,
            ),
            _entry(
                model="claude-haiku-4-5-20251001",
                default_tier="low",
                price_in_per_1m=1,
                price_out_per_1m=5,
                price_cached_per_1m=0.1,
                price_cache_write_per_1m=1.25,
            ),
        ]
    )


DEFAULTS = TelemetryDefaults(team="core", application="payments", change_id="CHG-a")


# ---------------------------------------------------------------------------- PyRIT
@dataclass
class FakePiece:
    role: str
    prompt_metadata: dict[str, Any] = field(default_factory=dict)
    conversation_id: str = "conv-1"
    timestamp: datetime = NOW


class FakeMemory:
    def __init__(self, pieces: list[FakePiece]) -> None:
        self.pieces = pieces
        self.calls: list[dict[str, Any]] = []

    def get_message_pieces(self, **filters: Any) -> list[FakePiece]:
        self.calls.append(filters)
        conv = filters.get("conversation_id")
        return [p for p in self.pieces if conv is None or p.conversation_id == conv]


def test_from_pyrit_pieces_reads_token_usage_keys(registry: ModelRegistry) -> None:
    pieces = [
        FakePiece(role="user"),  # no usage -> ignored
        FakePiece(
            role="assistant",
            prompt_metadata={
                "token_usage_input_tokens": "1000",
                "token_usage_output_tokens": 500,
                "token_usage_cached_tokens": 200,
                "token_usage_reasoning_tokens": 0,
                "finish_reason": "stop",
            },
        ),
        FakePiece(
            role="assistant",
            prompt_metadata={"input_tokens": 10, "output_tokens": 5, "model": "claude-opus-5"},
            conversation_id="conv-2",
        ),
        FakePiece(
            role="assistant",
            prompt_metadata={
                "token_usage_cost": "0.5",
                "token_usage_input_tokens": 1,
                "token_usage_output_tokens": 1,
            },
        ),
    ]
    events = from_pyrit_pieces(
        pieces, defaults=DEFAULTS, registry=registry, model="claude-sonnet-5"
    )
    assert len(events) == 3
    first = events[0]
    assert first.source == "pyrit"
    assert first.model == "claude-sonnet-5" and first.provider == "anthropic"
    assert (first.input_tokens, first.output_tokens, first.cached_tokens) == (1000, 500, 200)
    assert first.cache_hit is True
    assert first.cost_usd == pytest.approx(0.002 + 0.005 + 0.00004)
    assert first.session_id == "conv-1"
    assert first.change_id == "CHG-a" and first.team == "core"
    assert first.agent_role == "security_tester"
    assert events[1].model == "claude-opus-5" and events[1].session_id == "conv-2"
    assert events[1].cost_usd == pytest.approx(10 * 5 / 1e6 + 5 * 25 / 1e6)
    # Provider-reported cost wins over computed cost.
    assert events[2].cost_usd == 0.5


def test_from_pyrit_memory_filters_by_conversation(registry: ModelRegistry) -> None:
    mem = FakeMemory(
        [
            FakePiece("assistant", {"token_usage_input_tokens": 1, "token_usage_output_tokens": 1}),
            FakePiece(
                "assistant",
                {"token_usage_input_tokens": 1, "token_usage_output_tokens": 1},
                conversation_id="other",
            ),
        ]
    )
    events = from_pyrit_memory(
        mem, change_id="CHG-z", conversation_id="conv-1", registry=registry, model="claude-sonnet-5"
    )
    assert len(events) == 1
    assert events[0].change_id == "CHG-z"
    assert mem.calls == [{"conversation_id": "conv-1"}]
    assert len(from_pyrit_memory(mem, model="x")) == 2
    with pytest.raises(TypeError):
        from_pyrit_memory(object())


@pytest.mark.integration
def test_from_pyrit_memory_real_pieces() -> None:
    pytest.importorskip("pyrit")
    from pyrit.models import MessagePiece

    piece = MessagePiece(
        role="assistant",
        original_value="hello",
        conversation_id="c1",
        prompt_metadata={"token_usage_input_tokens": 12, "token_usage_output_tokens": 3},
    )
    events = from_pyrit_pieces([piece], model="claude-sonnet-5")
    assert len(events) == 1
    assert events[0].input_tokens == 12 and events[0].output_tokens == 3
    assert events[0].session_id == "c1"


# ---------------------------------------------------------------------------- Claude Code
def _cc_line(**kw: Any) -> str:
    rec: dict[str, Any] = {
        "type": "assistant",
        "timestamp": "2026-08-25T12:00:00.000Z",
        "requestId": "req_1",
        "sessionId": "sess-1",
        "cwd": "/repo",
        "version": "2.1.0",
        "message": {
            "id": "msg_1",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 100,
                "cache_read_input_tokens": 5000,
                "cache_creation_input_tokens": 2000,
                "output_tokens_details": {"thinking_tokens": 40},
            },
        },
    }
    for key, value in kw.items():
        if key in rec["message"]:
            rec["message"][key] = value
        else:
            rec[key] = value
    return json.dumps(rec)


def test_from_claude_code_jsonl(tmp_path: Path, registry: ModelRegistry) -> None:
    path = tmp_path / "session.jsonl"
    lines = [
        json.dumps({"type": "user", "message": {"role": "user", "content": "hello"}}),
        _cc_line(),
        # Streaming duplicate of the same request with a tool_use block.
        _cc_line(content=[{"type": "tool_use", "name": "Read", "input": {}}]),
        "not json",
        "",
        _cc_line(
            requestId="req_2",
            id="msg_2",
            model="claude-opus-5",
            usage={
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
        ),
        json.dumps({"type": "summary", "summary": "x"}),
    ]
    path.write_text("\n".join(lines) + "\n")
    events = from_claude_code_jsonl(path, defaults=DEFAULTS, registry=registry)
    assert len(events) == 2
    first, second = events
    assert first.source == "claude_code" and first.harness == "claude_code"
    assert first.model == "claude-sonnet-5" and first.provider == "anthropic"
    assert (first.input_tokens, first.output_tokens) == (10, 100)
    assert first.cached_tokens == 5000 and first.cache_write_tokens == 2000
    assert first.cache_hit is True
    assert first.tool_calls == 1  # merged from the streaming duplicate
    assert first.session_id == "sess-1" and first.repository == "/repo"
    assert first.change_id == "CHG-a"
    assert first.ts == NOW
    assert first.reasoning_tokens == 0  # thinking is inside output_tokens; never double billed
    expected = (10 * 2 + 100 * 10 + 5000 * 0.2 + 2000 * 2.5) / 1e6
    assert first.cost_usd == pytest.approx(expected)
    assert second.model == "claude-opus-5" and second.cache_hit is False
    # Without dedupe both streaming lines survive.
    assert len(from_claude_code_jsonl(path, dedupe=False)) == 3
    # Unknown model -> zero cost, no crash.
    assert from_claude_code_jsonl(path)[0].cost_usd == 0.0


# ---------------------------------------------------------------------------- AGT audit
@dataclass
class FakeAuditEntry:
    entry_id: str
    timestamp: datetime
    event_type: str
    agent_did: str
    action: str
    resource: str | None = None
    data: dict[str, Any] | None = None
    outcome: str = "success"
    issued_at: datetime | None = None
    completed_at: datetime | None = None
    session_id: str = "s1"
    environment: str = "ci"


def test_from_agt_audit() -> None:
    entries = [
        FakeAuditEntry(
            entry_id="e1",
            timestamp=NOW,
            event_type="tool_call",
            agent_did="did:agent:implementer",
            action="write_file",
            data={"task_id": "TASK-002", "cost_usd": 0.25},
            issued_at=NOW,
            completed_at=NOW + timedelta(milliseconds=150),
        ),
        {
            "entry_id": "e2",
            "timestamp": NOW.isoformat(),
            "agent_did": "did:agent:reviewer",
            "action": "run_tests",
            "outcome": "denied",
        },
    ]
    events = from_agt_audit(entries, defaults=DEFAULTS, change_id="CHG-q")
    assert [e.event_id for e in events] == ["e1", "e2"]
    e1, e2 = events
    assert e1.source == "agt_audit" and e1.provider == "agt"
    assert e1.model == "tool:write_file" and e1.tool_calls == 1
    assert e1.latency_ms == pytest.approx(150.0)
    assert e1.agent_role == "did:agent:implementer"
    assert e1.task_id == "TASK-002" and e1.change_id == "CHG-q"
    assert e1.cost_usd == 0.25 and e1.success is True
    assert e1.environment == "ci" and e1.session_id == "s1"
    assert e2.success is False and e2.latency_ms == 0.0
    assert e2.model == "tool:run_tests"


@pytest.mark.integration
def test_from_agt_audit_real_entries() -> None:
    pytest.importorskip("agentmesh.governance")
    from agentmesh.governance import AuditLog

    log = AuditLog()
    entry = log.log("tool_call", "did:agent:x", "read_file", resource="README.md")
    events = from_agt_audit([entry], defaults=DEFAULTS)
    assert len(events) == 1
    assert events[0].model == "tool:read_file"
    assert events[0].tool_calls == 1


# ---------------------------------------------------------------------------- OTel spans
def test_span_to_event_genai_attributes(registry: ModelRegistry) -> None:
    start = int(NOW.timestamp() * 1e9)
    span = SpanData(
        name="chat claude-sonnet-5",
        attributes={
            "gen_ai.request.model": "claude-sonnet-5",
            "gen_ai.provider.name": "anthropic",
            "gen_ai.usage.input_tokens": 1000,
            "gen_ai.usage.output_tokens": 100,
            "gen_ai.usage.cache_read_input_tokens": 400,
            "aisdlc.change_id": "CHG-span",
            "aisdlc.agent_role": "reviewer",
            "aisdlc.routing_tier": "independent_review",
            "aisdlc.tool_calls": 2,
        },
        start_time_unix_nano=start,
        end_time_unix_nano=start + 250_000_000,
        status="ok",
    )
    ev = span_to_event(span, defaults=DEFAULTS, registry=registry)
    assert ev is not None
    assert ev.source == "otel"
    assert ev.model == "claude-sonnet-5" and ev.provider == "anthropic"
    assert ev.input_tokens == 1000 and ev.cached_tokens == 400 and ev.cache_hit
    assert ev.latency_ms == pytest.approx(250.0)
    assert ev.change_id == "CHG-span" and ev.team == "core"
    assert ev.agent_role == "reviewer" and ev.routing_tier == "independent_review"
    assert ev.tool_calls == 2
    assert ev.ts == NOW + timedelta(milliseconds=250)
    assert ev.cost_usd == pytest.approx((1000 * 2 + 100 * 10 + 400 * 0.2) / 1e6)
    assert ev.success is True


def test_span_to_event_ignores_non_genai_spans_and_accepts_objects() -> None:
    assert span_to_event(SpanData(name="db.query", attributes={"db.system": "sqlite"})) is None

    class Ctx:
        trace_id = 0xABC
        span_id = 0x12

    class Status:
        status_code = "ERROR"

    class ObjSpan:
        name = "llm"
        attributes = {
            "gen_ai.usage.prompt_tokens": 5,
            "gen_ai.usage.completion_tokens": 7,
            "gen_ai.system": "openai",
            "gen_ai.request.model": "gpt-5",
        }
        start_time = 1_000_000_000
        end_time = 1_500_000_000
        status = Status()

        def get_span_context(self) -> Ctx:
            return Ctx()

    data = SpanData.from_object(ObjSpan())
    assert data.trace_id == format(0xABC, "032x") and data.status == "error"
    ev = span_to_event(ObjSpan())
    assert ev is not None
    assert (ev.input_tokens, ev.output_tokens, ev.provider) == (5, 7, "openai")
    assert ev.success is False
    dict_span = {
        "name": "x",
        "attributes": {"gen_ai.request.model": "m", "gen_ai.usage.input_tokens": 1},
    }
    assert span_to_event(dict_span) is not None


def test_ledger_span_exporter_writes_to_ledger() -> None:
    ledger = UsageLedger()
    exporter = LedgerSpanExporter(ledger, defaults=DEFAULTS)
    spans = [
        SpanData(
            name="a", attributes={"gen_ai.request.model": "m", "gen_ai.usage.input_tokens": 1}
        ),
        SpanData(name="db", attributes={}),
    ]
    assert exporter.export(spans) == 1
    exporter.on_end(spans[0])
    assert exporter.exported == 2 and exporter.skipped == 1
    assert ledger.count() == 2
    assert exporter.force_flush() is True
    exporter.shutdown()


# ---------------------------------------------------------------------------- KPIs
def _ev(**kw: object) -> UsageEvent:
    base: dict[str, object] = {
        "ts": NOW,
        "change_id": "CHG-a",
        "agent_role": "implementer",
        "model": "claude-sonnet-5",
        "provider": "anthropic",
        "input_tokens": 1000,
        "output_tokens": 100,
        "latency_ms": 100.0,
        "cost_usd": 1.0,
    }
    base.update(kw)
    return UsageEvent.model_validate(base)


def test_compute_kpis_full(registry: ModelRegistry) -> None:
    ledger = UsageLedger()
    ledger.record_many(
        [
            _ev(event_id="1", turn=1, cache_hit=True, cached_tokens=500),
            _ev(
                event_id="2",
                turn=2,
                escalated=True,
                model="claude-opus-5",
                cost_usd=4.0,
                latency_ms=400.0,
            ),
            _ev(
                event_id="3",
                agent_role="reviewer",
                review_round=1,
                model="claude-opus-5",
                cost_usd=2.0,
                latency_ms=200.0,
            ),
            _ev(event_id="4", agent_role="reviewer", review_round=2, cost_usd=1.0),
            _ev(
                event_id="5",
                model="tool:write_file",
                provider="agt",
                tool_calls=3,
                cost_usd=0.0,
                input_tokens=0,
                output_tokens=0,
            ),
        ]
    )
    bench = BenchmarkService()
    bench.store_many(
        [
            BenchmarkResult(
                benchmark_id="BM-swe-1",
                category=BenchmarkCategory.quality,
                model="claude-opus-5",
                metric="pass",
                value=0.80,
                sample_size=10,
            ),
            BenchmarkResult(
                benchmark_id="BM-swe-1",
                category=BenchmarkCategory.quality,
                model="claude-sonnet-5",
                metric="pass",
                value=0.80,
                sample_size=10,
            ),
            BenchmarkResult(
                benchmark_id="BM-rev-1",
                category=BenchmarkCategory.review_precision,
                model="claude-opus-5",
                metric="precision",
                value=0.9,
                sample_size=10,
            ),
            BenchmarkResult(
                benchmark_id="BM-rev-1",
                category=BenchmarkCategory.review_precision,
                model="claude-sonnet-5",
                metric="precision",
                value=0.5,
                sample_size=10,
            ),
        ]
    )
    outcomes = Outcomes(
        accepted_requirements=4,
        merged_changes=2,
        defects_found=8,
        vulns_found=1,
        benchmarks_passed=16,
        accepted_tasks=5,
        successful_runs=2,
    )
    rep = compute_kpis(ledger, outcomes, benchmarks=bench, registry=registry)
    assert rep.calls == 5 and rep.model_calls == 4
    assert rep.total_cost_usd == pytest.approx(8.0)
    assert rep.cost_per_accepted_requirement == pytest.approx(2.0)
    assert rep.cost_per_merged_change == pytest.approx(4.0)
    assert rep.cost_per_defect_found == pytest.approx(1.0)
    assert rep.cost_per_vuln_found == pytest.approx(8.0)
    assert rep.cost_per_passing_benchmark == pytest.approx(0.5)
    assert rep.total_tokens == 4 * 1100 + 500
    assert rep.tokens_per_accepted_task == pytest.approx(rep.total_tokens / 5)
    assert rep.escalation_rate == pytest.approx(0.25)
    assert rep.cache_hit_rate == pytest.approx(0.25)
    assert rep.cached_token_share == pytest.approx(500 / 4500)
    assert rep.latency_p50_ms == 100.0 and rep.latency_p95_ms == 400.0
    assert rep.turns_per_success == pytest.approx(1.0)  # 2 recorded turns / 2 successes
    assert rep.review_rounds_per_merge == pytest.approx(1.0)  # 2 distinct rounds / 2 merges
    assert rep.tool_calls_per_accepted_change == pytest.approx(1.5)
    # Two high-tier calls (opus): the implementer one could have been served by sonnet
    # (equal quality score); the reviewer one could not (0.5 < 0.9).
    assert rep.high_tier_calls == 2 and rep.high_tier_assessed_calls == 2
    assert rep.high_tier_servable_by_lower_share == pytest.approx(0.5)
    assert rep.high_tier_servable_savings_usd > 0
    # Tolerance makes the reviewer call servable too.
    loose = compute_kpis(ledger, outcomes, benchmarks=bench, registry=registry, score_tolerance=0.5)
    assert loose.high_tier_servable_by_lower_share == pytest.approx(1.0)


def test_compute_kpis_handles_empty_and_missing_data(registry: ModelRegistry) -> None:
    ledger = UsageLedger()
    rep = compute_kpis(ledger, Outcomes())
    assert rep.calls == 0
    assert rep.cost_per_accepted_requirement is None
    assert rep.escalation_rate is None and rep.cache_hit_rate is None
    assert rep.high_tier_servable_by_lower_share is None
    assert "no usage events in window" in rep.notes
    ledger.record(_ev(model="claude-opus-5", agent_role="reviewer"))
    no_bench = compute_kpis(ledger, Outcomes(merged_changes=1), registry=registry)
    assert no_bench.high_tier_calls == 1 and no_bench.high_tier_servable_by_lower_share is None
    assert any("no benchmark service" in n for n in no_bench.notes)
    assert any("estimated from reviewer calls" in n for n in no_bench.notes)
    # Benchmarks present but no score for the high-tier model -> unassessed.
    bench = BenchmarkService()
    bench.store(
        BenchmarkResult(
            benchmark_id="BM-x-1",
            category=BenchmarkCategory.review_precision,
            model="claude-sonnet-5",
            metric="p",
            value=0.9,
        )
    )
    partial = compute_kpis(ledger, Outcomes(), benchmarks=bench, registry=registry)
    assert partial.high_tier_assessed_calls == 0
    assert any("no benchmark score" in n for n in partial.notes)


def test_compute_kpis_window_and_filters() -> None:
    ledger = UsageLedger()
    ledger.record(_ev(event_id="old", ts=NOW - timedelta(days=10), cost_usd=100))
    ledger.record(_ev(event_id="new", cost_usd=1, change_id="CHG-b"))
    rep = compute_kpis(ledger, Outcomes(merged_changes=1), since=NOW - timedelta(days=1))
    assert rep.total_cost_usd == 1.0
    rep2 = compute_kpis(ledger, Outcomes(merged_changes=1), filters={"change_id": "CHG-a"})
    assert rep2.total_cost_usd == 100.0
    assert rep2.since is None
    assert Outcomes(merged_changes=3).effective_accepted_changes == 3
    assert Outcomes(merged_changes=3, accepted_changes=1).effective_accepted_changes == 1
