from __future__ import annotations

import hashlib
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Literal

import pytest

import agent_sre.sdlc.control_plane as control_plane_module
from agent_sre.sdlc.canonical import load_json_strict
from agent_sre.sdlc.control_plane import (
    ControlPlaneCatalog,
    ControlPlaneClosedError,
    ControlPlaneIntegrityError,
    ControlPlanePathError,
    ControlPlaneSchemaError,
    DuplicatePromptError,
    RegisteredPrompt,
)
from agent_sre.sdlc.model_registry import (
    DuplicateModelError,
    ModelCapabilities,
    ModelIdentity,
    ModelPrice,
    ModelTier,
    PriceOverlapError,
    RegisteredModel,
    TokenUsage,
)
from agent_sre.sdlc.routing import (
    BenchmarkConflictError,
    BenchmarkRecord,
    NoRouteError,
    RoutingRequest,
)
from agent_sre.sdlc.usage_ledger import PromptIdentity

NOW = datetime(2026, 8, 25, 12, 34, 56, 123456, tzinfo=UTC)


def registered_model(*, context_tokens: int = 64_000) -> RegisteredModel:
    return RegisteredModel(
        identity=ModelIdentity(
            provider="azure-openai",
            provider_family="openai",
            model="gpt-control",
            version="2026-08-01",
            deployment="control-prod",
        ),
        capabilities=ModelCapabilities(
            tier=ModelTier.STANDARD,
            max_context_tokens=context_tokens,
            capabilities=frozenset({"json", "reasoning"}),
            allowed_tools=frozenset({"read_file"}),
            allowed_risk_levels=frozenset({"medium", "high"}),
            allowed_use_cases=frozenset({"implementation", "independent_review"}),
        ),
    )


def model_price(model: RegisteredModel, *, amount: str = "1.2300") -> ModelPrice:
    return ModelPrice(
        identity=model.identity,
        effective_from=NOW - timedelta(days=30),
        effective_to=None,
        input_per_million=Decimal(amount),
        output_per_million=Decimal("2.5000"),
        cached_input_per_million=Decimal("0.2500"),
        reasoning_per_million=Decimal("4.7500"),
        provenance="finance/catalog:sha256:abc",
    )


def benchmark(model: RegisteredModel, *, quality: str = "0.9100") -> BenchmarkRecord:
    return BenchmarkRecord(
        benchmark_id="benchmark-control-v1",
        identity=model.identity,
        task_type="code-change",
        quality_score=Decimal(quality),
        latency_ms=Decimal("450.00"),
        measured_at=NOW - timedelta(days=1),
        valid_until=NOW + timedelta(days=10),
        provenance="eval-suite:v1/dataset:sha256:def",
        sample_size=250,
    )


def routing_request() -> RoutingRequest:
    return RoutingRequest(
        task_type="code-change",
        use_case="implementation",
        risk_level="medium",
        context_tokens=4_000,
        estimated_usage=TokenUsage(input_tokens=1_000_000),
        as_of=NOW,
        max_benchmark_age=timedelta(days=30),
        required_capabilities=frozenset({"json"}),
        required_tools=frozenset({"read_file"}),
        min_quality=Decimal("0.90"),
        max_latency_ms=Decimal("500"),
    )


def registered_prompt(*, provenance: str = "prompt-catalog:sha256:abc") -> RegisteredPrompt:
    return RegisteredPrompt(
        identity=PromptIdentity(
            prompt_id="implementation",
            version="3",
            digest="sha256:0123456789abcdef",
        ),
        provenance=provenance,
    )


def test_prompt_registry_public_exports() -> None:
    import agent_sre.sdlc as sdlc

    assert sdlc.RegisteredPrompt is RegisteredPrompt
    assert sdlc.DuplicatePromptError is DuplicatePromptError
    assert sdlc.PromptRegistry.__module__ == "agent_sre.sdlc.control_plane"


def test_reopen_hydrates_exact_facts_and_routes(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "control-plane.sqlite3"
    model = registered_model()
    price = model_price(model)
    record = benchmark(model)

    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        assert catalog.register_model(model) == model
        assert catalog.register_model(model) == model
        assert catalog.add_price(price) == price
        assert catalog.add_price(price) == price
        assert catalog.add_benchmark(record) == record
        assert catalog.add_benchmark(record) == record

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        hydrated_model = reopened.model_registry().get(model.identity)
        hydrated_price = reopened.price_catalog().get(model.identity, at=NOW)
        hydrated_benchmark = reopened.benchmark_registry().latest_fresh(
            model.identity,
            task_type="code-change",
            at=NOW,
            max_age=timedelta(days=30),
        )

        assert hydrated_model == model
        assert hydrated_price == price
        assert hydrated_price is not None
        assert hydrated_price.input_per_million.as_tuple() == Decimal("1.2300").as_tuple()
        assert hydrated_price.effective_from == price.effective_from
        assert hydrated_price.effective_from.tzinfo is UTC
        assert hydrated_benchmark == record
        assert hydrated_benchmark is not None
        assert hydrated_benchmark.quality_score.as_tuple() == Decimal("0.9100").as_tuple()

        decision = reopened.model_router().route(routing_request())
        assert decision.model == model
        assert decision.benchmark == record
        assert decision.estimated_cost_usd == Decimal("1.2300")

    with pytest.raises(ControlPlaneClosedError):
        reopened.model_registry()


def test_reopen_rejects_conflicting_model_and_benchmark_facts(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "control-plane.sqlite3"
    model = registered_model()
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.add_benchmark(benchmark(model))

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        with pytest.raises(DuplicateModelError):
            reopened.register_model(registered_model(context_tokens=32_000))
        with pytest.raises(BenchmarkConflictError):
            reopened.add_benchmark(benchmark(model, quality="0.9200"))


def test_price_periods_remain_non_overlapping_across_reopen(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "control-plane.sqlite3"
    model = registered_model()
    january = ModelPrice(
        identity=model.identity,
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=datetime(2026, 2, 1, tzinfo=UTC),
        input_per_million=Decimal("1.00"),
        output_per_million=Decimal("2.00"),
        provenance="finance/january",
    )
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.add_price(january)

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        with pytest.raises(PriceOverlapError):
            reopened.add_price(
                ModelPrice(
                    identity=model.identity,
                    effective_from=datetime(2026, 1, 15, tzinfo=UTC),
                    effective_to=datetime(2026, 2, 15, tzinfo=UTC),
                    input_per_million=Decimal("3.00"),
                    output_per_million=Decimal("4.00"),
                    provenance="finance/conflict",
                )
            )
        with pytest.raises(PriceOverlapError):
            reopened.add_price(
                ModelPrice(
                    identity=model.identity,
                    effective_from=january.effective_from,
                    effective_to=january.effective_to,
                    input_per_million=Decimal("9.00"),
                    output_per_million=Decimal("9.00"),
                    provenance="finance/reused-identity",
                )
            )


def test_path_safety_rejects_escape_uri_directory_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(ControlPlanePathError):
        ControlPlaneCatalog(outside / "catalog.sqlite3", allowed_root=root)
    with pytest.raises(ControlPlanePathError):
        ControlPlaneCatalog(":memory:", allowed_root=root)
    with pytest.raises(ControlPlanePathError):
        ControlPlaneCatalog("file:catalog.sqlite3", allowed_root=root)
    with pytest.raises(ControlPlanePathError):
        ControlPlaneCatalog(root, allowed_root=root)

    target = outside / "target.sqlite3"
    target.touch()
    database_link = root / "database-link.sqlite3"
    database_link.symlink_to(target)
    with pytest.raises(ControlPlanePathError):
        ControlPlaneCatalog(database_link, allowed_root=root)

    linked_directory = root / "linked-directory"
    linked_directory.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ControlPlanePathError):
        ControlPlaneCatalog(linked_directory / "catalog.sqlite3", allowed_root=root)


def test_catalog_rejects_allowed_root_replacement_after_construction(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    catalog = ControlPlaneCatalog(root / "catalog.sqlite3", allowed_root=root)
    moved_root = tmp_path / "moved-catalog-root"
    root.rename(moved_root)
    root.mkdir()

    with pytest.raises(ControlPlanePathError, match="allowed_root changed"):
        catalog.model_registry()


def test_catalog_accepts_symlinked_ancestor_but_rejects_symlinks_below_root(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    root = real_parent / "catalog-root"
    root.mkdir()
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(real_parent, target_is_directory=True)
    aliased_root = parent_alias / "catalog-root"

    with ControlPlaneCatalog(
        aliased_root / "state" / "catalog.sqlite3",
        allowed_root=aliased_root,
    ) as catalog:
        assert catalog.model_registry().list_models() == ()

    root_alias = tmp_path / "root-alias"
    root_alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ControlPlanePathError, match="allowed_root"):
        ControlPlaneCatalog(root_alias / "catalog.sqlite3", allowed_root=root_alias)


@pytest.mark.parametrize("suffix", ["", "-journal", "-wal", "-shm"])
def test_catalog_rejects_database_and_companion_symlinks_after_open(
    tmp_path: Path,
    suffix: str,
) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    catalog = ControlPlaneCatalog(database, allowed_root=root)
    attacked = Path(f"{database}{suffix}")
    if suffix and attacked.exists():
        attacked.unlink()
    target = root / f"target{suffix or '-database'}"
    if suffix == "":
        database.rename(target)
    else:
        target.touch()
    attacked.symlink_to(target)

    with pytest.raises(ControlPlanePathError, match="regular files|symbolic link"):
        catalog.model_registry()


def test_catalog_closes_connection_when_database_is_swapped_during_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    catalog = ControlPlaneCatalog(database, allowed_root=root)
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

    monkeypatch.setattr(control_plane_module.sqlite3, "connect", racing_connect)
    with pytest.raises(ControlPlanePathError, match="database file changed"):
        catalog.model_registry()
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_catalog_rejects_valid_older_database_snapshot_replacement(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    snapshot = root / "older.sqlite3"
    catalog = ControlPlaneCatalog(database, allowed_root=root)
    model = registered_model()
    catalog.register_model(model)
    with sqlite3.connect(database) as source, sqlite3.connect(snapshot) as destination:
        source.backup(destination)
    catalog.disable_model(model.identity)
    snapshot.replace(database)

    with pytest.raises(ControlPlanePathError, match="database file changed"):
        catalog.model_registry()


def test_catalog_rejects_intermediate_directory_replacement(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    state = root / "state"
    database = state / "catalog.sqlite3"
    catalog = ControlPlaneCatalog(database, allowed_root=root)
    displaced = root / "displaced-state"
    state.rename(displaced)
    state.mkdir()
    shutil.copy2(displaced / database.name, database)

    with pytest.raises(ControlPlanePathError, match="database parent changed"):
        catalog.model_registry()


def test_model_state_transitions_survive_reopen_and_control_routing(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    model = registered_model()
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.add_price(model_price(model))
        catalog.add_benchmark(benchmark(model))
        assert catalog.disable_model(model.identity).enabled is False
        assert catalog.disable_model(model.identity).enabled is False

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        effective = reopened.model_registry().get(model.identity)
        assert effective is not None and effective.enabled is False
        with pytest.raises(NoRouteError) as exc_info:
            reopened.model_router().route(routing_request())
        assert "disabled" in exc_info.value.diagnostics[model.identity.canonical_id]
        assert reopened.enable_model(model.identity).enabled is True

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        assert reopened.model_router().route(routing_request()).model.enabled is True
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM model_state_transitions").fetchone() == (2,)
        base = connection.execute("SELECT payload_json FROM registered_models").fetchone()
        assert base is not None and load_json_strict(base[0])["enabled"] is True


def test_model_state_transition_tampering_is_detected(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    model = registered_model()
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.disable_model(model.identity)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_state_transitions_no_update")
        connection.execute(
            "UPDATE model_state_transitions SET prior_payload_hash = ?",
            ("0" * 64,),
        )
    with (
        ControlPlaneCatalog(database, allowed_root=root) as reopened,
        pytest.raises(ControlPlaneIntegrityError, match="chain index"),
    ):
        reopened.model_registry()


def test_open_ended_price_can_be_superseded_without_mutating_original(
    tmp_path: Path,
) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    model = registered_model()
    original = ModelPrice(
        identity=model.identity,
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
        input_per_million=Decimal("1.0000"),
        output_per_million=Decimal("2.0000"),
        provenance="finance/first",
    )
    successor = ModelPrice(
        identity=model.identity,
        effective_from=datetime(2026, 2, 1, tzinfo=UTC),
        effective_to=None,
        input_per_million=Decimal("3.0000"),
        output_per_million=Decimal("4.0000"),
        provenance="finance/revision",
    )
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.add_price(original)
        assert catalog.add_price(successor) == successor
        assert catalog.add_price(successor) == successor

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        effective_prices = reopened.price_catalog()
        january = effective_prices.get(model.identity, at=datetime(2026, 1, 15, tzinfo=UTC))
        february = effective_prices.get(model.identity, at=datetime(2026, 2, 1, tzinfo=UTC))
        assert january is not None
        assert january.effective_to == successor.effective_from
        assert january.input_per_million.as_tuple() == Decimal("1.0000").as_tuple()
        assert february == successor

    with sqlite3.connect(database) as connection:
        original_row = connection.execute(
            "SELECT effective_to, payload_json FROM model_prices WHERE effective_from = ?",
            (original.effective_from.isoformat(timespec="microseconds"),),
        ).fetchone()
        assert original_row is not None
        assert original_row[0] is None
        assert load_json_strict(original_row[1])["effective_to"] is None
        assert connection.execute("SELECT COUNT(*) FROM price_supersessions").fetchone() == (1,)


def test_price_supersession_tampering_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    model = registered_model()
    first = model_price(model)
    second = ModelPrice(
        identity=model.identity,
        effective_from=NOW - timedelta(days=1),
        effective_to=None,
        input_per_million=Decimal("2"),
        output_per_million=Decimal("3"),
        provenance="finance/revision",
    )
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.add_price(first)
        catalog.add_price(second)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER price_supersessions_no_update")
        connection.execute(
            "UPDATE price_supersessions SET successor_payload_hash = ?",
            ("f" * 64,),
        )
    with (
        ControlPlaneCatalog(database, allowed_root=root) as reopened,
        pytest.raises(ControlPlaneIntegrityError, match="index disagrees"),
    ):
        reopened.price_catalog()


def test_missing_price_supersession_fact_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    model = registered_model()
    first = model_price(model)
    second = ModelPrice(
        identity=model.identity,
        effective_from=NOW - timedelta(days=1),
        effective_to=None,
        input_per_million=Decimal("2"),
        output_per_million=Decimal("3"),
        provenance="finance/revision",
    )
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)
        catalog.add_price(first)
        catalog.add_price(second)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER price_supersessions_no_delete")
        connection.execute("DELETE FROM price_supersessions")
    with (
        ControlPlaneCatalog(database, allowed_root=root) as reopened,
        pytest.raises(ControlPlaneIntegrityError, match="effective price periods overlap"),
    ):
        reopened.price_catalog()


def test_prompt_registry_is_idempotent_stateful_and_integrity_checked(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    prompt = registered_prompt()
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        assert catalog.register_prompt(prompt) == prompt
        assert catalog.register_prompt(prompt) == prompt
        with pytest.raises(DuplicatePromptError):
            catalog.register_prompt(registered_prompt(provenance="other-source"))
        assert catalog.get_prompt(prompt.identity) == prompt
        assert catalog.disable_prompt(prompt.identity).enabled is False
        assert catalog.disable_prompt(prompt.identity).enabled is False

    with ControlPlaneCatalog(database, allowed_root=root) as reopened:
        disabled = reopened.prompt_registry().get(prompt.identity)
        assert disabled is not None and disabled.enabled is False
        assert reopened.get_prompt(prompt.identity) is None
        assert reopened.get_prompt(prompt.identity, enabled_only=False) == disabled
        assert reopened.enable_prompt(prompt.identity).enabled is True

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM registered_prompts").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM prompt_state_transitions").fetchone() == (
            2,
        )
        connection.execute("DROP TRIGGER prompt_state_transitions_no_update")
        connection.execute(
            "UPDATE prompt_state_transitions SET prior_payload_hash = ? WHERE sequence = 2",
            ("0" * 64,),
        )
    with (
        ControlPlaneCatalog(database, allowed_root=root) as reopened,
        pytest.raises(ControlPlaneIntegrityError, match="chain index"),
    ):
        reopened.prompt_registry()


@pytest.mark.parametrize("legacy_version", [1, 2])
def test_catalog_migrates_legacy_schema_to_prompt_aware_v3(
    tmp_path: Path,
    legacy_version: int,
) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "catalog.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for statement in control_plane_module._SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_versions (version, applied_at) VALUES (1, ?)",
            (NOW.isoformat(timespec="microseconds"),),
        )
        if legacy_version == 2:
            for statement in control_plane_module._SCHEMA_V2_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_versions (version, applied_at) VALUES (2, ?)",
                (NOW.isoformat(timespec="microseconds"),),
            )
        connection.execute(f"PRAGMA user_version = {legacy_version}")

    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        assert catalog.prompt_registry().list_prompts() == ()
        catalog.register_prompt(registered_prompt())
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (3,)
        versions = connection.execute(
            "SELECT version FROM schema_versions ORDER BY version"
        ).fetchall()
        assert versions == [(1,), (2,), (3,)]


def test_schema_version_and_append_only_hashes_are_enforced(tmp_path: Path) -> None:
    root = tmp_path / "catalog-root"
    root.mkdir()
    database = root / "control-plane.sqlite3"
    model = registered_model()
    with ControlPlaneCatalog(database, allowed_root=root) as catalog:
        catalog.register_model(model)

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT payload_json, payload_hash FROM registered_models"
        ).fetchone()
        assert row is not None
        payload_json, payload_hash = row
        assert load_json_strict(payload_json)["schema"] == "agt.control-plane/model/v1"
        assert hashlib.sha256(payload_json.encode("utf-8")).hexdigest() == payload_hash
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE registered_models SET payload_hash = 'tampered'")

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 99")
    with pytest.raises(ControlPlaneSchemaError, match="unsupported"):
        ControlPlaneCatalog(database, allowed_root=root)
