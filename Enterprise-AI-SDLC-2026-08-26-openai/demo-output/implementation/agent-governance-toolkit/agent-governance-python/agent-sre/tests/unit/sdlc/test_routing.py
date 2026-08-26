from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from agent_sre.sdlc.model_registry import (
    ModelCapabilities,
    ModelIdentity,
    ModelPrice,
    ModelRegistry,
    ModelTier,
    PriceCatalog,
    RegisteredModel,
    TokenUsage,
)
from agent_sre.sdlc.routing import (
    BenchmarkRecord,
    BenchmarkRegistry,
    ModelRouter,
    NoRouteError,
    RoutingRequest,
)

NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)


def model(
    name: str,
    *,
    provider: str,
    family: str,
    tier: ModelTier = ModelTier.STANDARD,
    tools: frozenset[str] = frozenset({"search"}),
) -> RegisteredModel:
    return RegisteredModel(
        identity=ModelIdentity(
            provider=provider,
            provider_family=family,
            model=name,
            version="2026-08",
            deployment=f"{name}-prod",
        ),
        capabilities=ModelCapabilities(
            tier=tier,
            max_context_tokens=64_000,
            capabilities=frozenset({"json", "tools"}),
            allowed_tools=tools,
            allowed_risk_levels=frozenset({"medium", "high"}),
            allowed_use_cases=frozenset({"implementation", "independent_review"}),
        ),
    )


def benchmark(item: RegisteredModel, *, age_days: int = 1, quality: str = "0.9") -> BenchmarkRecord:
    return BenchmarkRecord(
        benchmark_id=f"bench-{item.identity.model}-{age_days}-{quality}",
        identity=item.identity,
        task_type="code-change",
        quality_score=Decimal(quality),
        latency_ms=Decimal("500"),
        measured_at=NOW - timedelta(days=age_days),
        valid_until=NOW + timedelta(days=10),
        provenance="eval-suite:v3/dataset:sha256:abc",
        sample_size=100,
    )


def price(item: RegisteredModel, amount: str) -> ModelPrice:
    return ModelPrice(
        identity=item.identity,
        effective_from=NOW - timedelta(days=30),
        effective_to=None,
        input_per_million=Decimal(amount),
        output_per_million=Decimal(amount),
        cached_input_per_million=Decimal(amount),
        reasoning_per_million=Decimal(amount),
        provenance="finance:v4",
    )


def request(**overrides: object) -> RoutingRequest:
    values: dict[str, object] = {
        "task_type": "code-change",
        "use_case": "implementation",
        "risk_level": "medium",
        "context_tokens": 10_000,
        "estimated_usage": TokenUsage(input_tokens=500_000, output_tokens=500_000),
        "as_of": NOW,
        "max_benchmark_age": timedelta(days=30),
        "max_tier": ModelTier.HIGH,
        "required_capabilities": frozenset({"json", "tools"}),
        "required_tools": frozenset({"search"}),
        "min_quality": Decimal("0.8"),
        "max_latency_ms": Decimal("1000"),
        "require_known_cost": True,
    }
    values.update(overrides)
    return RoutingRequest(**values)  # type: ignore[arg-type]


def router_for(
    items: list[RegisteredModel],
    *,
    records: list[BenchmarkRecord] | None = None,
    prices: list[ModelPrice] | None = None,
) -> ModelRouter:
    return ModelRouter(
        models=ModelRegistry(items),
        benchmarks=BenchmarkRegistry(
            [benchmark(item) for item in items] if records is None else records
        ),
        prices=PriceCatalog([price(item, "1") for item in items] if prices is None else prices),
    )


def test_router_selects_cheapest_qualifying_fresh_benchmark() -> None:
    cheap = model("cheap", provider="azure-a", family="openai")
    expensive = model("expensive", provider="azure-b", family="anthropic")
    router = router_for(
        [cheap, expensive],
        records=[benchmark(cheap, quality="0.85"), benchmark(expensive, quality="0.99")],
        prices=[price(cheap, "1"), price(expensive, "4")],
    )

    decision = router.route(request())

    assert decision.model == cheap
    assert decision.estimated_cost_usd == Decimal("1")
    assert decision.qualifying_models == 2


def test_router_fails_when_no_model_satisfies_tool_and_context_constraints() -> None:
    item = model("bounded", provider="provider", family="family", tools=frozenset())
    router = router_for([item])

    with pytest.raises(NoRouteError) as exc_info:
        router.route(request(context_tokens=100_000, required_tools=frozenset({"shell"})))

    reasons = next(iter(exc_info.value.diagnostics.values()))
    assert "context_limit_exceeded" in reasons
    assert "tool_not_allowed" in reasons


def test_stale_benchmark_is_not_routable() -> None:
    item = model("stale", provider="provider", family="family")
    router = router_for([item], records=[benchmark(item, age_days=60)])

    with pytest.raises(NoRouteError) as exc_info:
        router.route(request(max_benchmark_age=timedelta(days=30)))

    assert "fresh_benchmark_missing" in next(iter(exc_info.value.diagnostics.values()))


def test_independent_review_requires_different_provider_family() -> None:
    original = model("author", provider="azure-author", family="openai")
    same_family = model("same-family", provider="azure-review", family="openai")
    independent = model("independent", provider="other", family="anthropic")
    router = router_for(
        [same_family, independent],
        prices=[price(same_family, "0.1"), price(independent, "2")],
    )

    decision = router.route(
        request(
            use_case="independent_review",
            independent_review_of=original.identity,
        )
    )

    assert decision.model == independent


def test_unknown_price_fails_closed_and_budget_boundary_is_inclusive() -> None:
    item = model("priced", provider="provider", family="family")
    no_price_router = router_for([item], prices=[])
    with pytest.raises(NoRouteError) as exc_info:
        no_price_router.route(request())
    assert "price_unknown" in next(iter(exc_info.value.diagnostics.values()))

    priced_router = router_for([item], prices=[price(item, "1")])
    assert priced_router.route(request(max_estimated_cost_usd=Decimal("1"))).model == item
    with pytest.raises(NoRouteError):
        priced_router.route(request(max_estimated_cost_usd=Decimal("0.999999")))
