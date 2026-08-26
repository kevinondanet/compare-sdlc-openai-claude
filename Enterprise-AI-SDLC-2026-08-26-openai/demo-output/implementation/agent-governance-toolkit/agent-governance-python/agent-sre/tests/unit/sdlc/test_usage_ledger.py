from __future__ import annotations

import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Literal

import pytest

import agent_sre.sdlc.usage_ledger as usage_ledger_module
from agent_sre.sdlc.model_registry import (
    ModelIdentity,
    ModelPrice,
    PriceCatalog,
    TokenUsage,
)
from agent_sre.sdlc.usage_ledger import (
    BudgetDefinition,
    BudgetExceededError,
    BudgetScope,
    IdempotencyConflictError,
    LedgerError,
    PathSafetyError,
    PromptIdentity,
    ReservationRequest,
    UnknownBudgetCostError,
    UsageAttribution,
    UsageEvent,
    UsageLedger,
    usage_event_set_digest,
)

NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)


@pytest.fixture
def model_identity() -> ModelIdentity:
    return ModelIdentity(
        provider="azure-openai",
        provider_family="openai",
        model="gpt-control",
        version="2026-08-01",
        deployment="production-us",
    )


@pytest.fixture
def attribution() -> UsageAttribution:
    return UsageAttribution(
        organization_id="org-1",
        team_id="team-platform",
        application_id="control-plane",
        user_id="user-7",
        environment="production",
        repository="agent-governance-toolkit",
        change_id="change-42",
        task_id="task-route",
    )


@pytest.fixture
def prices(model_identity: ModelIdentity) -> PriceCatalog:
    return PriceCatalog(
        [
            ModelPrice(
                identity=model_identity,
                effective_from=NOW - timedelta(days=30),
                effective_to=None,
                input_per_million=Decimal("1.25"),
                output_per_million=Decimal("10"),
                cached_input_per_million=Decimal("0.25"),
                reasoning_per_million=Decimal("15"),
                provenance="finance/approved-price-table:2026-08",
            )
        ]
    )


@pytest.fixture
def unit_prices(model_identity: ModelIdentity) -> PriceCatalog:
    return PriceCatalog(
        [
            ModelPrice(
                identity=model_identity,
                effective_from=NOW - timedelta(days=30),
                effective_to=None,
                input_per_million=Decimal("1"),
                output_per_million=Decimal("1"),
                cached_input_per_million=Decimal("1"),
                reasoning_per_million=Decimal("1"),
                provenance="finance/unit-price",
            )
        ]
    )


@pytest.fixture
def ledger(tmp_path: Path) -> UsageLedger:
    return UsageLedger(tmp_path / "state" / "usage.sqlite3", allowed_root=tmp_path)


def usage_event(
    *,
    event_id: str,
    attribution: UsageAttribution,
    model: ModelIdentity,
    usage: TokenUsage,
    outcome: Literal["accepted", "rejected", "failed", "unknown"] = "accepted",
) -> UsageEvent:
    return UsageEvent(
        event_id=event_id,
        occurred_at=NOW,
        attribution=attribution,
        model=model,
        prompt=PromptIdentity(
            prompt_id="implementation",
            version="3",
            digest="sha256:0123456789abcdef",
        ),
        usage=usage,
        latency_ms=250,
        tool_calls=2,
        turns=3,
        outcome=outcome,
        metadata={"release_gate": "G4"},
    )


def reservation(
    reservation_id: str,
    amount: str,
    attribution: UsageAttribution,
) -> ReservationRequest:
    return ReservationRequest(
        reservation_id=reservation_id,
        attribution=attribution,
        amount_usd=Decimal(amount),
        reserved_at=NOW,
        expires_at=NOW + timedelta(hours=2),
    )


def organization_budget(*, limit: str = "1") -> BudgetDefinition:
    return BudgetDefinition(
        budget_id="org-august",
        scope=BudgetScope.ORGANIZATION,
        scope_value="org-1",
        period_start=NOW - timedelta(days=1),
        period_end=NOW + timedelta(days=7),
        limit_usd=Decimal(limit),
    )


def test_usage_is_exact_idempotent_append_only_and_rolls_up(
    tmp_path: Path,
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    prices: PriceCatalog,
) -> None:
    event = usage_event(
        event_id="usage-1",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(
            input_tokens=100_000,
            output_tokens=200_000,
            cached_input_tokens=400_000,
            reasoning_tokens=300_000,
        ),
    )

    first = ledger.append_usage(event, prices=prices)
    replay = ledger.append_usage(event, prices=prices)

    assert first == replay
    assert first.cost_usd == Decimal("6.725")
    rollup = ledger.rollup(
        start=NOW - timedelta(minutes=1),
        end=NOW + timedelta(minutes=1),
        group_by=("organization_id", "model_version"),
    )
    assert len(rollup) == 1
    assert rollup[0].group == (
        ("organization_id", "org-1"),
        ("model_version", "2026-08-01"),
    )
    assert rollup[0].event_count == 1
    assert rollup[0].event_set_digest == usage_event_set_digest((event.event_id,))
    assert rollup[0].known_cost_usd == Decimal("6.725")
    assert rollup[0].cache_hit_rate == Decimal("0.8")
    assert rollup[0].cost_per_accepted_task_usd == Decimal("6.725")

    database_path = tmp_path / "state" / "usage.sqlite3"
    with (
        sqlite3.connect(database_path) as connection,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        connection.execute("DELETE FROM usage_events WHERE event_id = ?", (event.event_id,))


def test_rollup_digest_binds_exact_event_set_independent_of_order(
    tmp_path: Path,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    first = UsageLedger(tmp_path / "first" / "usage.sqlite3", allowed_root=tmp_path)
    second = UsageLedger(tmp_path / "second" / "usage.sqlite3", allowed_root=tmp_path)
    for event_id in ("event-b", "event-a"):
        first.append_usage(
            usage_event(
                event_id=event_id,
                attribution=attribution,
                model=model_identity,
                usage=TokenUsage(input_tokens=10),
            ),
            prices=unit_prices,
        )
    for event_id in ("event-a", "event-c"):
        second.append_usage(
            usage_event(
                event_id=event_id,
                attribution=attribution,
                model=model_identity,
                usage=TokenUsage(input_tokens=10),
            ),
            prices=unit_prices,
        )

    first_rollup = first.rollup(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1))[0]
    second_rollup = second.rollup(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1))[
        0
    ]
    assert first_rollup.event_count == second_rollup.event_count == 2
    assert first_rollup.known_cost_usd == second_rollup.known_cost_usd
    assert first_rollup.event_set_digest == usage_event_set_digest(("event-a", "event-b"))
    assert first_rollup.event_set_digest == usage_event_set_digest(("event-b", "event-a"))
    assert second_rollup.event_set_digest == usage_event_set_digest(("event-a", "event-c"))
    assert first_rollup.event_set_digest != second_rollup.event_set_digest


def test_reusing_event_id_with_different_facts_is_a_conflict(
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    event = usage_event(
        event_id="usage-conflict",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(input_tokens=10),
    )
    ledger.append_usage(event, prices=unit_prices)

    with pytest.raises(IdempotencyConflictError):
        ledger.append_usage(
            replace(event, usage=TokenUsage(input_tokens=11)),
            prices=unit_prices,
        )


def test_usage_rejects_untyped_nested_facts_and_duplicate_metadata(
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
) -> None:
    with pytest.raises(LedgerError, match="usage must be a TokenUsage"):
        UsageEvent(
            event_id="invalid-nested",
            occurred_at=NOW,
            attribution=attribution,
            model=model_identity,
            prompt=PromptIdentity(prompt_id="p", version="1", digest="digest"),
            usage={"input_tokens": 1},  # type: ignore[arg-type]
        )

    with pytest.raises(LedgerError, match="metadata keys must be unique"):
        UsageEvent(
            event_id="duplicate-metadata",
            occurred_at=NOW,
            attribution=attribution,
            model=model_identity,
            prompt=PromptIdentity(prompt_id="p", version="1", digest="digest"),
            usage=TokenUsage(input_tokens=1),
            metadata=(("source", "one"), ("source", "two")),
        )


def test_concurrent_duplicate_writes_create_one_event(
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    event = usage_event(
        event_id="usage-concurrent",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(input_tokens=25_000),
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        stored = list(
            executor.map(
                lambda _: ledger.append_usage(event, prices=unit_prices),
                range(24),
            )
        )

    assert len({item.row_id for item in stored}) == 1
    rollup = ledger.rollup(
        start=NOW - timedelta(minutes=1),
        end=NOW + timedelta(minutes=1),
    )
    assert rollup[0].event_count == 1


def test_database_path_must_stay_within_allowed_root(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside" / "usage.sqlite3"

    with pytest.raises(PathSafetyError):
        UsageLedger(outside, allowed_root=allowed_root)


def test_usage_ledger_accepts_symlinked_ancestor_not_symlinked_root(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    root = real_parent / "ledger-root"
    root.mkdir()
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(real_parent, target_is_directory=True)
    aliased_root = parent_alias / "ledger-root"

    ledger = UsageLedger(
        aliased_root / "state" / "usage.sqlite3",
        allowed_root=aliased_root,
    )
    assert ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1)) == ()

    root_alias = tmp_path / "root-alias"
    root_alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(PathSafetyError, match="allowed_root"):
        UsageLedger(root_alias / "usage.sqlite3", allowed_root=root_alias)


@pytest.mark.parametrize("suffix", ["", "-journal", "-wal", "-shm"])
def test_usage_ledger_rejects_database_and_companion_symlinks_on_every_connect(
    tmp_path: Path,
    suffix: str,
) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    database = root / "usage.sqlite3"
    ledger = UsageLedger(database, allowed_root=root)
    attacked = Path(f"{database}{suffix}")
    if suffix and attacked.exists():
        attacked.unlink()
    target = root / f"target{suffix or '-database'}"
    if suffix == "":
        database.rename(target)
    else:
        target.touch()
    attacked.symlink_to(target)

    with pytest.raises(PathSafetyError, match="regular files|symbolic link"):
        ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1))


def test_usage_ledger_rejects_nonregular_companion(tmp_path: Path) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    database = root / "usage.sqlite3"
    ledger = UsageLedger(database, allowed_root=root)
    companion = Path(f"{database}-journal")
    companion.mkdir()

    with pytest.raises(PathSafetyError, match="regular files"):
        ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1))


def test_usage_ledger_rejects_root_replacement_after_construction(tmp_path: Path) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    ledger = UsageLedger(root / "usage.sqlite3", allowed_root=root)
    displaced = tmp_path / "displaced-root"
    root.rename(displaced)
    root.mkdir()

    with pytest.raises(PathSafetyError, match="allowed_root changed"):
        ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1))


def test_usage_ledger_closes_connection_when_database_swaps_during_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    database = root / "usage.sqlite3"
    ledger = UsageLedger(database, allowed_root=root)
    replacement = root / "replacement.sqlite3"
    shutil.copy2(database, replacement)
    displaced = root / "displaced.sqlite3"
    real_connect = sqlite3.connect
    opened: list[sqlite3.Connection] = []

    def racing_connect(
        database_arg: str,
        timeout: float = 5.0,
        isolation_level: Literal["DEFERRED", "EXCLUSIVE", "IMMEDIATE"] | None = None,
    ) -> sqlite3.Connection:
        database.rename(displaced)
        replacement.rename(database)
        connection = real_connect(
            database_arg,
            timeout=timeout,
            isolation_level=isolation_level,
        )
        opened.append(connection)
        return connection

    monkeypatch.setattr(usage_ledger_module.sqlite3, "connect", racing_connect)
    with pytest.raises(PathSafetyError, match="database file changed"):
        ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1))
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_usage_ledger_rejects_valid_older_database_snapshot_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    database = root / "usage.sqlite3"
    snapshot = root / "older.sqlite3"
    ledger = UsageLedger(database, allowed_root=root)
    with sqlite3.connect(database) as source, sqlite3.connect(snapshot) as destination:
        source.backup(destination)
    ledger.add_budget(organization_budget())
    snapshot.replace(database)

    with pytest.raises(PathSafetyError, match="database file changed"):
        ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1))


def test_usage_ledger_rejects_intermediate_directory_replacement(tmp_path: Path) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    state = root / "state"
    database = state / "usage.sqlite3"
    ledger = UsageLedger(database, allowed_root=root)
    displaced = root / "displaced-state"
    state.rename(displaced)
    state.mkdir()
    shutil.copy2(displaced / database.name, database)

    with pytest.raises(PathSafetyError, match="database parent changed"):
        ledger.rollup(start=NOW, end=NOW + timedelta(seconds=1))


def test_budget_boundary_and_reserve_reconcile_semantics(
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    ledger.add_budget(organization_budget())
    ledger.reserve(reservation("reserve-1", "0.8", attribution))

    with pytest.raises(BudgetExceededError) as exc_info:
        ledger.reserve(reservation("over-boundary", "0.200001", attribution))
    assert exc_info.value.budget_ids == ("org-august",)

    ledger.reserve(reservation("exact-boundary", "0.2", attribution))
    actual = usage_event(
        event_id="actual-reserve-1",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(input_tokens=500_000),
    )
    result = ledger.reconcile("reserve-1", actual, prices=unit_prices)

    assert result.actual_usd == Decimal("0.5")
    assert result.reserved_usd == Decimal("0.8")
    assert result.variance_usd == Decimal("-0.3")
    assert result.breached_budget_ids == ()
    assert ledger.reconcile("reserve-1", actual, prices=unit_prices) == result

    ledger.reserve(reservation("new-exact-boundary", "0.3", attribution))
    with pytest.raises(BudgetExceededError):
        ledger.reserve(reservation("new-over-boundary", "0.000001", attribution))


def test_reconcile_records_actual_overspend_and_blocks_future_reservations(
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    ledger.add_budget(organization_budget(limit="0.5"))
    ledger.reserve(reservation("forecast", "0.5", attribution))
    actual = usage_event(
        event_id="actual-overspend",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(input_tokens=800_000),
    )

    result = ledger.reconcile("forecast", actual, prices=unit_prices)

    assert result.actual_usd == Decimal("0.8")
    assert result.variance_usd == Decimal("0.3")
    assert result.breached_budget_ids == ("org-august",)
    with pytest.raises(BudgetExceededError):
        ledger.reserve(reservation("post-overspend", "0.01", attribution))


def test_reconcile_retry_returns_original_persisted_breach_set(
    tmp_path: Path,
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    ledger.add_budget(organization_budget(limit="1"))
    ledger.reserve(reservation("stable-result", "0.1", attribution))
    actual = usage_event(
        event_id="stable-result-actual",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(input_tokens=100_000),
    )
    first = ledger.reconcile("stable-result", actual, prices=unit_prices)
    assert first.breached_budget_ids == ()

    ledger.append_usage(
        usage_event(
            event_id="later-usage",
            attribution=attribution,
            model=model_identity,
            usage=TokenUsage(input_tokens=950_000),
        ),
        prices=unit_prices,
    )
    retried = ledger.reconcile("stable-result", actual, prices=unit_prices)
    assert retried == first

    with sqlite3.connect(tmp_path / "state" / "usage.sqlite3") as connection:
        stored = connection.execute(
            "SELECT breached_budget_ids_json FROM budget_reconciliations "
            "WHERE reservation_id = 'stable-result'"
        ).fetchone()
        assert stored == ("[]",)


def test_usage_ledger_migrates_legacy_reconciliation_schema(tmp_path: Path) -> None:
    root = tmp_path / "ledger-root"
    root.mkdir()
    database = root / "usage.sqlite3"
    legacy_schema = usage_ledger_module._SCHEMA.replace(
        "    breached_budget_ids_json TEXT NOT NULL DEFAULT '[]',\n",
        "",
    )
    assert legacy_schema != usage_ledger_module._SCHEMA
    with sqlite3.connect(database) as connection:
        connection.executescript(legacy_schema)

    UsageLedger(database, allowed_root=root)

    with sqlite3.connect(database) as connection:
        columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(budget_reconciliations)")
        }
    assert columns["breached_budget_ids_json"][3] == 1
    assert columns["breached_budget_ids_json"][4] == "'[]'"


def test_reconcile_rejects_usage_outside_the_reserved_window(
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
    unit_prices: PriceCatalog,
) -> None:
    ledger.add_budget(organization_budget())
    ledger.reserve(reservation("short-lived", "0.1", attribution))
    event = replace(
        usage_event(
            event_id="too-late",
            attribution=attribution,
            model=model_identity,
            usage=TokenUsage(input_tokens=1),
        ),
        occurred_at=NOW + timedelta(hours=2),
    )

    with pytest.raises(LedgerError, match="reservation window"):
        ledger.reconcile("short-lived", event, prices=unit_prices)


def test_budget_checks_fail_closed_when_prior_usage_is_unpriced(
    ledger: UsageLedger,
    attribution: UsageAttribution,
    model_identity: ModelIdentity,
) -> None:
    ledger.add_budget(organization_budget())
    event = usage_event(
        event_id="unpriced",
        attribution=attribution,
        model=model_identity,
        usage=TokenUsage(input_tokens=1),
    )
    ledger.append_usage(event, prices=PriceCatalog(), require_cost=False)

    with pytest.raises(UnknownBudgetCostError):
        ledger.reserve(reservation("cannot-price-budget", "0.1", attribution))
