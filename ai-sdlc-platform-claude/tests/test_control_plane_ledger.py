"""Tests for control_plane.ledger and control_plane.budget."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aisdlc.control_plane.budget import (
    AgtAgentWindowTracker,
    Budget,
    BudgetException,
    BudgetPolicyEngine,
    BudgetScope,
    DecisionKind,
    ExceptionRegister,
    LocalAgentWindowTracker,
    Quotas,
    ScopeType,
    make_agent_tracker,
    normalize_scopes,
    parse_window,
)
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger, percentile

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def _ev(**kw: object) -> UsageEvent:
    base: dict[str, object] = {
        "ts": NOW,
        "team": "core",
        "application": "payments",
        "user": "kevin",
        "change_id": "CHG-a",
        "task_id": "TASK-001",
        "agent_role": "implementer",
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "input_tokens": 1000,
        "output_tokens": 200,
        "latency_ms": 100.0,
        "cost_usd": 0.01,
    }
    base.update(kw)
    return UsageEvent.model_validate(base)


@pytest.fixture
def ledger() -> UsageLedger:
    return UsageLedger(":memory:")


# ---------------------------------------------------------------------------- ledger
def test_record_and_query_round_trip(ledger: UsageLedger) -> None:
    ev = _ev(
        cached_tokens=50,
        cache_hit=True,
        escalated=True,
        turn=3,
        review_round=1,
        success=True,
        routing_tier="standard",
        source_hash="s",
        eval_config_hash="e",
    )
    assert ledger.record(ev) == ev.event_id
    got = ledger.query({"change_id": "CHG-a"})
    assert len(got) == 1
    assert got[0] == ev
    assert got[0].ts.tzinfo is not None
    assert got[0].total_tokens == 1250


def test_record_is_idempotent_by_event_id(ledger: UsageLedger) -> None:
    ev = _ev()
    ledger.record(ev)
    ledger.record(ev)
    assert ledger.count() == 1


def test_query_filters_since_until_and_lists(ledger: UsageLedger) -> None:
    ledger.record_many(
        [
            _ev(event_id="1", ts=NOW - timedelta(hours=2), model="a"),
            _ev(event_id="2", ts=NOW - timedelta(hours=1), model="b"),
            _ev(event_id="3", ts=NOW, model="c", cache_hit=True),
        ]
    )
    assert [e.event_id for e in ledger.query()] == ["1", "2", "3"]
    assert [e.event_id for e in ledger.query(newest_first=True, limit=1)] == ["3"]
    assert [e.event_id for e in ledger.query(since=NOW - timedelta(minutes=90))] == ["2", "3"]
    assert [e.event_id for e in ledger.query(until=NOW - timedelta(minutes=90))] == ["1"]
    assert [e.event_id for e in ledger.query({"model": ["a", "c"]})] == ["1", "3"]
    assert [e.event_id for e in ledger.query({"cache_hit": True})] == ["3"]
    assert ledger.query({"model": []}) == []
    with pytest.raises(ValueError):
        ledger.query({"not_a_field": 1})


def test_summarize_groups_and_percentiles(ledger: UsageLedger) -> None:
    for i, lat in enumerate([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]):
        ledger.record(
            _ev(
                event_id=str(i),
                model="m1" if i % 2 else "m2",
                latency_ms=float(lat),
                cost_usd=0.5,
                cache_hit=(i % 2 == 0),
                tool_calls=1,
            )
        )
    total = ledger.totals()
    assert total.calls == 10
    assert total.cost_usd == pytest.approx(5.0)
    assert total.input_tokens == 10_000 and total.output_tokens == 2000
    assert total.total_tokens == 12_000
    assert total.tool_calls == 10
    assert total.latency_p50_ms == 50.0
    assert total.latency_p95_ms == 100.0
    assert total.cache_hit_rate == 0.5
    assert total.first_ts == NOW and total.last_ts == NOW
    by_model = ledger.summarize(["model"])
    assert [s.group for s in by_model] == [{"model": "m1"}, {"model": "m2"}]
    assert all(s.calls == 5 for s in by_model)
    multi = ledger.summarize(["agent_role", "model"], filters={"model": "m1"})
    assert multi[0].group == {"agent_role": "implementer", "model": "m1"}
    with pytest.raises(ValueError):
        ledger.summarize(["cost_usd"])


def test_summarize_empty_returns_zero_totals(ledger: UsageLedger) -> None:
    assert ledger.totals().calls == 0
    assert ledger.summarize(["model"]) == []
    assert ledger.total_cost() == 0.0


def test_percentile_helper() -> None:
    assert percentile([], 50) == 0.0
    assert percentile([5.0], 95) == 5.0
    assert percentile([1, 2, 3, 4], 50) == 2.0
    assert percentile([1, 2, 3, 4], 100) == 4.0
    assert percentile([3, 1, 2], 0) == 1.0
    with pytest.raises(ValueError):
        percentile([1.0], 101)


def test_export_change_cost_evidence(ledger: UsageLedger) -> None:
    ledger.record_many(
        [
            _ev(event_id="a", ts=NOW - timedelta(minutes=5), agent_role="implementer"),
            _ev(
                event_id="b",
                agent_role="reviewer",
                model="gpt-5",
                provider="openai",
                escalated=True,
                cost_usd=0.5,
            ),
            _ev(event_id="other", change_id="CHG-other"),
        ]
    )
    doc = ledger.export_change("CHG-a")
    assert doc["id"] == "EVD-cost-001"
    assert doc["kind"] == "cost"
    assert doc["status"] == "complete"
    assert doc["events"] == 2
    assert doc["totals"]["cost_usd"] == pytest.approx(0.51)
    assert doc["started_at"] < doc["finished_at"]
    assert {row["group"]["model"] for row in doc["by_model"]} == {"claude-sonnet-5", "gpt-5"}
    assert {row["group"]["agent_role"] for row in doc["by_role"]} == {"implementer", "reviewer"}
    assert doc["escalations"] == 1
    # No events -> incomplete evidence (fails closed).
    assert ledger.export_change("CHG-none")["status"] == "incomplete"
    ledger.record(_ev(event_id="x", change_id="CHG-bad", model="", tool_calls=0))
    assert ledger.export_change("CHG-bad")["status"] == "incomplete"


def test_duplicate_run_suppression(ledger: UsageLedger) -> None:
    first = ledger.suppress_duplicate("src123", "cfg456", change_id="CHG-a", kind="pyrit")
    assert first.duplicate is False
    assert first.prior_run_id
    second = ledger.suppress_duplicate("src123", "cfg456")
    assert second.duplicate is True
    assert second.prior_run_id == first.prior_run_id
    assert second.prior_change_id == "CHG-a"
    assert second.prior_ts is not None
    # A different eval config is a different run.
    assert ledger.check_duplicate("src123", "cfg999").duplicate is False
    assert ledger.register_run("src123", "cfg456") == first.prior_run_id
    assert ledger.forget_run("src123", "cfg456") is True
    assert ledger.forget_run("src123", "cfg456") is False
    assert ledger.check_duplicate("src123", "cfg456").duplicate is False


def test_ledger_persists_on_disk(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    with UsageLedger(str(path)) as led:
        led.record(_ev())
    with UsageLedger(str(path)) as led:
        assert led.count() == 1


def test_usage_event_rejects_extra_and_negative() -> None:
    with pytest.raises(ValueError):
        UsageEvent.model_validate({"bogus": 1})
    with pytest.raises(ValueError):
        UsageEvent(input_tokens=-1)


# ---------------------------------------------------------------------------- budget
def test_parse_window() -> None:
    assert parse_window("1h") == timedelta(hours=1)
    assert parse_window("30d") == timedelta(days=30)
    assert parse_window("2w") == timedelta(weeks=2)
    assert parse_window("all") is None
    with pytest.raises(ValueError):
        parse_window("fortnight")


def test_scope_parsing_and_normalisation() -> None:
    s = BudgetScope.parse("application:payments")
    assert s.scope_type is ScopeType.application and s.key == "application:payments"
    assert s.ledger_filter == {"application": "payments"}
    assert BudgetScope.parse("change:CHG-a").ledger_filter == {"change_id": "CHG-a"}
    assert [x.key for x in normalize_scopes({"team": "core", "user": "kevin"})] == [
        "team:core",
        "user:kevin",
    ]
    assert normalize_scopes(["team:core", s]) == [BudgetScope.parse("team:core"), s]
    with pytest.raises(ValueError):
        BudgetScope.parse("nocolon")


def _engine(ledger: UsageLedger, **kw: object) -> BudgetPolicyEngine:
    return BudgetPolicyEngine(ledger, clock=lambda: NOW, **kw)  # type: ignore[arg-type]


def test_budget_allow_soft_and_hard(ledger: UsageLedger) -> None:
    ledger.record(_ev(cost_usd=5.0))
    engine = _engine(
        ledger,
        budgets=[Budget(scope_type=ScopeType.application, scope_id="payments", limit_usd=10)],
    )
    ok = engine.check(["application:payments"], forecast_cost_usd=1.0)
    assert ok.decision is DecisionKind.allow and ok.allowed
    assert ok.remaining_usd == pytest.approx(5.0)
    assert "within budget" in ok.reason
    soft = engine.check(["application:payments"], forecast_cost_usd=3.5)  # 8.5 > 8.0 soft
    assert soft.decision is DecisionKind.require_approval
    assert soft.soft_breached_scopes == ["application:payments"]
    hard = engine.check(["application:payments"], forecast_cost_usd=6.0)
    assert hard.decision is DecisionKind.deny
    assert hard.breached_scopes == ["application:payments"]
    assert "exceeds limit" in hard.reason
    assert hard.scopes[0].spent_usd == pytest.approx(5.0)


def test_budget_window_excludes_old_spend(ledger: UsageLedger) -> None:
    ledger.record(_ev(event_id="old", ts=NOW - timedelta(days=40), cost_usd=100))
    ledger.record(_ev(event_id="new", cost_usd=1))
    engine = _engine(
        ledger,
        budgets=[
            Budget(scope_type=ScopeType.team, scope_id="core", limit_usd=10, window="30d"),
            Budget(scope_type=ScopeType.user, scope_id="kevin", limit_usd=10, window="all"),
        ],
    )
    assert engine.check(["team:core"], 1.0).decision is DecisionKind.allow
    assert engine.check(["user:kevin"], 1.0).decision is DecisionKind.deny


def test_multiple_scopes_and_unbudgeted_scope(ledger: UsageLedger) -> None:
    ledger.record(_ev(cost_usd=9.0))
    engine = _engine(
        ledger,
        budgets=[
            Budget(scope_type=ScopeType.application, scope_id="payments", limit_usd=1000),
            Budget(scope_type=ScopeType.change, scope_id="CHG-a", limit_usd=10),
        ],
    )
    d = engine.check(["application:payments", "change:CHG-a", "team:nobody"], 0.5)
    assert d.decision is DecisionKind.require_approval
    assert d.remaining_usd == pytest.approx(1.0)  # min across scopes
    assert len(d.scopes) == 2
    none = engine.check(["team:nobody"], 5.0)
    assert none.decision is DecisionKind.allow
    assert none.remaining_usd is None
    assert "no budget configured" in none.reason


def test_quotas_deny(ledger: UsageLedger) -> None:
    engine = _engine(
        ledger,
        quotas=Quotas(
            max_model_tier_by_role={"verifier": "low"},
            max_agent_turns=10,
            max_parallel_agents=4,
            max_review_rounds=3,
            max_tool_calls=100,
            context_ceiling_tokens=200_000,
        ),
    )
    d = engine.check([], 0.1, role="verifier", requested_tier="high")
    assert d.decision is DecisionKind.deny
    assert "may use at most tier 'low'" in d.reason
    assert engine.check([], 0.1, role="verifier", requested_tier="low").allowed
    assert engine.check([], 0.1, role="implementer", requested_tier="high").allowed
    # Non-model tiers are not capped here.
    assert engine.check([], 0.1, role="verifier", requested_tier="independent_review").allowed
    d2 = engine.check(
        [],
        0.1,
        agent_turns=11,
        parallel_agents=5,
        review_rounds=4,
        tool_calls=101,
        context_tokens=300_000,
    )
    assert d2.decision is DecisionKind.deny
    assert len(d2.quota_violations) == 5
    assert engine.check([], 0.1, agent_turns=10, parallel_agents=4).allowed


def test_approval_threshold(ledger: UsageLedger) -> None:
    engine = _engine(ledger, quotas=Quotas(approval_threshold_usd=5.0))
    assert engine.check([], 4.99).decision is DecisionKind.allow
    d = engine.check([], 5.01)
    assert d.decision is DecisionKind.require_approval
    assert "approval threshold" in d.reason


def test_exceptions_raise_limits_and_expire(ledger: UsageLedger) -> None:
    ledger.record(_ev(cost_usd=9.0))
    reg = ExceptionRegister()
    exc = reg.add(
        BudgetException(
            scope_type=ScopeType.application,
            scope_id="payments",
            approved_by="cto",
            expires_at=NOW + timedelta(days=1),
            extra_limit_usd=20.0,
            reason="launch week",
        )
    )
    engine = _engine(
        ledger,
        budgets=[Budget(scope_type=ScopeType.application, scope_id="payments", limit_usd=10)],
        exceptions=reg,
    )
    d = engine.check(["application:payments"], 5.0)
    assert d.decision is DecisionKind.allow
    assert d.applied_exceptions == [exc.exception_id]
    assert d.remaining_usd == pytest.approx(21.0)
    # Expired -> back to deny.
    late = engine.check(["application:payments"], 5.0, now=NOW + timedelta(days=2))
    assert late.decision is DecisionKind.deny and late.applied_exceptions == []
    # Unlimited exception.
    reg.add(
        BudgetException(
            exception_id="EXC-unlimited",
            scope_type=ScopeType.application,
            scope_id="payments",
            approved_by="cto",
            expires_at=NOW + timedelta(hours=1),
        )
    )
    unlimited = engine.check(["application:payments"], 10_000)
    assert unlimited.decision is DecisionKind.allow
    assert unlimited.remaining_usd is None
    assert reg.revoke("EXC-unlimited") and reg.get("EXC-unlimited") is None
    assert len(reg.all()) == 1
    assert engine.check(["application:payments"], 10_000).decision is DecisionKind.deny


def test_budget_management(ledger: UsageLedger) -> None:
    engine = _engine(ledger)
    b = Budget(scope_type=ScopeType.team, scope_id="core", limit_usd=5)
    engine.add_budget(b)
    assert engine.budgets == [b]
    assert engine.budget_for(BudgetScope.parse("team:core")) == b
    assert engine.remove_budget("team:core") is True
    assert engine.remove_budget("team:core") is False
    with pytest.raises(ValueError):
        engine.check([], -1)
    with pytest.raises(ValueError):
        Budget(scope_type=ScopeType.team, scope_id="x", limit_usd=1, window="soon")
    with pytest.raises(ValueError):
        Quotas(max_model_tier_by_role={"r": "ultra"})


def test_local_agent_window_tracker() -> None:
    clock = [0.0]
    tracker = LocalAgentWindowTracker(
        max_tokens=1000, max_cost_usd=1.0, window="1h", clock=lambda: clock[0]
    )
    assert tracker.check("a", 500).allowed
    tracker.record_usage("a", 800, 0.5)
    denied = tracker.check("a", 300)
    assert not denied.allowed and denied.tokens_remaining == 200
    tracker.record_usage("a", 0, 0.6)
    assert not tracker.check("a", 0).allowed  # cost exceeded
    clock[0] = 3601.0  # window rolled over
    assert tracker.check("a", 300).allowed
    assert tracker.usage("a") == (0, 0.0)


def test_engine_agent_delegation(ledger: UsageLedger) -> None:
    engine = _engine(ledger)
    assert engine.check_agent("x", 10).allowed  # no tracker configured
    engine.agent_tracker = LocalAgentWindowTracker(max_tokens=10)
    engine.record_agent_usage("x", 8, 0.0)
    assert not engine.check_agent("x", 5).allowed
    assert engine.check_agent("y", 5).allowed


def test_make_agent_tracker_falls_back_without_agt(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("agentmesh"):
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    tracker = make_agent_tracker(max_tokens=10, window="1h")
    assert isinstance(tracker, LocalAgentWindowTracker)
    assert tracker.backend == "local"
    assert make_agent_tracker(prefer_agt=False).backend == "local"


@pytest.mark.integration
def test_make_agent_tracker_uses_agt_when_available() -> None:
    pytest.importorskip("agentmesh.governance.budget")
    tracker = make_agent_tracker(max_tokens=100, max_cost_usd=1.0, window="1h")
    assert isinstance(tracker, AgtAgentWindowTracker)
    assert tracker.check("agent", 10).allowed
    tracker.record_usage("agent", 95, 0.1)
    d = tracker.check("agent", 10)
    assert d.backend == "agt"
    assert not d.allowed
