from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from agent_sre.sdlc.model_registry import (
    DuplicateModelError,
    ModelCapabilities,
    ModelIdentity,
    ModelPrice,
    ModelRegistry,
    ModelTier,
    PriceCatalog,
    PriceOverlapError,
    RegisteredModel,
    RegistryError,
    TokenUsage,
    UnknownPriceError,
)


def identity(*, version: str = "2026-01", deployment: str = "primary") -> ModelIdentity:
    return ModelIdentity(
        provider="azure-openai",
        provider_family="openai",
        model="gpt-control",
        version=version,
        deployment=deployment,
    )


def capabilities(*, context: int = 128_000) -> ModelCapabilities:
    return ModelCapabilities(
        tier=ModelTier.STANDARD,
        max_context_tokens=context,
        capabilities=frozenset({"json", "reasoning", "tools"}),
        allowed_tools=frozenset({"search", "read_file"}),
        allowed_risk_levels=frozenset({"low", "medium"}),
        allowed_use_cases=frozenset({"implementation", "review"}),
    )


def test_identity_is_immutable_and_includes_version_and_deployment() -> None:
    first = identity()
    assert first != identity(version="2026-02")
    assert first != identity(deployment="secondary")
    with pytest.raises(FrozenInstanceError):
        first.model = "changed"  # type: ignore[misc]


def test_registry_is_idempotent_but_rejects_conflicting_facts() -> None:
    registered = RegisteredModel(identity=identity(), capabilities=capabilities())
    registry = ModelRegistry([registered])

    assert registry.register(registered) is registered
    with pytest.raises(DuplicateModelError):
        registry.register(
            RegisteredModel(identity=registered.identity, capabilities=capabilities(context=32_000))
        )


def test_capability_limits_reject_non_integer_values() -> None:
    with pytest.raises(RegistryError, match="positive integer"):
        capabilities(context=128_000.5)  # type: ignore[arg-type]


def test_price_effective_dates_use_half_open_intervals() -> None:
    model = identity()
    january = ModelPrice(
        identity=model,
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=datetime(2026, 2, 1, tzinfo=UTC),
        input_per_million=Decimal("1"),
        output_per_million=Decimal("2"),
        provenance="finance/price-table-v1",
    )
    february = ModelPrice(
        identity=model,
        effective_from=datetime(2026, 2, 1, tzinfo=UTC),
        effective_to=None,
        input_per_million=Decimal("1.5"),
        output_per_million=Decimal("2.5"),
        provenance="finance/price-table-v2",
    )
    catalog = PriceCatalog([january, february])

    assert catalog.get(model, at=datetime(2026, 1, 31, 23, 59, tzinfo=UTC)) == january
    assert catalog.get(model, at=datetime(2026, 2, 1, tzinfo=UTC)) == february

    with pytest.raises(PriceOverlapError):
        catalog.add(
            ModelPrice(
                identity=model,
                effective_from=datetime(2026, 1, 15, tzinfo=UTC),
                effective_to=datetime(2026, 2, 15, tzinfo=UTC),
                input_per_million=Decimal("9"),
                output_per_million=Decimal("9"),
                provenance="conflicting-source",
            )
        )


def test_cost_calculation_is_exact_decimal_across_all_buckets() -> None:
    price = ModelPrice(
        identity=identity(),
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=None,
        input_per_million=Decimal("1.25"),
        output_per_million=Decimal("10"),
        cached_input_per_million=Decimal("0.25"),
        reasoning_per_million=Decimal("15"),
        provenance="finance/exact",
    )
    usage = TokenUsage(
        input_tokens=100_000,
        output_tokens=200_000,
        cached_input_tokens=400_000,
        reasoning_tokens=300_000,
    )

    assert price.calculate(usage) == Decimal("6.725")


def test_unknown_usage_bucket_fails_closed_when_cost_required() -> None:
    model = identity()
    catalog = PriceCatalog(
        [
            ModelPrice(
                identity=model,
                effective_from=datetime(2026, 1, 1, tzinfo=UTC),
                effective_to=None,
                input_per_million=Decimal("1"),
                output_per_million=Decimal("2"),
                provenance="finance/no-reasoning-price",
            )
        ]
    )
    usage = TokenUsage(reasoning_tokens=10)

    with pytest.raises(UnknownPriceError):
        catalog.calculate(model, usage=usage, at=datetime(2026, 1, 2, tzinfo=UTC))
    cost, price = catalog.calculate(
        model,
        usage=usage,
        at=datetime(2026, 1, 2, tzinfo=UTC),
        required=False,
    )
    assert cost is None
    assert price is not None
