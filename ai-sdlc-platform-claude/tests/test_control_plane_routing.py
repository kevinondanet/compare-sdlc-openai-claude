"""Tests for control_plane.routing and control_plane.benchmark."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aisdlc.control_plane.benchmark import BenchmarkCategory, BenchmarkResult, BenchmarkService
from aisdlc.control_plane.registry import ModelEntry, ModelRegistry
from aisdlc.control_plane.routing import (
    Complexity,
    RoutingError,
    RoutingPolicy,
    RoutingTier,
    TaskProfile,
)


def _entry(**overrides: object) -> ModelEntry:
    base: dict[str, object] = {
        "provider": "anthropic",
        "model": "sonnet",
        "family": "claude",
        "capabilities": ["code", "tools"],
        "context_limit": 200_000,
        "price_in_per_1m": 3.0,
        "price_out_per_1m": 15.0,
        "price_cached_per_1m": 0.3,
        "approved_use_cases": ["*"],
        "default_tier": "standard",
        "typical_latency_ms": 3000,
    }
    base.update(overrides)
    return ModelEntry.model_validate(base)


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry(
        [
            _entry(
                model="haiku",
                default_tier="low",
                price_in_per_1m=1,
                price_out_per_1m=5,
                price_cached_per_1m=0.1,
                typical_latency_ms=800,
                capabilities=["code", "fast"],
            ),
            _entry(model="sonnet"),
            _entry(
                model="opus",
                default_tier="high",
                price_in_per_1m=15,
                price_out_per_1m=75,
                price_cached_per_1m=1.5,
                typical_latency_ms=8000,
                capabilities=["code", "tools", "vision"],
            ),
            _entry(
                provider="openai",
                model="gpt-mini",
                family="gpt",
                default_tier="standard",
                price_in_per_1m=0.4,
                price_out_per_1m=1.6,
                price_cached_per_1m=0.1,
                typical_latency_ms=2500,
            ),
            _entry(
                provider="openai",
                model="gpt-big",
                family="gpt",
                default_tier="high",
                price_in_per_1m=5,
                price_out_per_1m=20,
                price_cached_per_1m=0.5,
                typical_latency_ms=6000,
                capabilities=["code", "tools", "vision"],
            ),
            _entry(
                provider="meta",
                model="llama",
                family="llama",
                default_tier="standard",
                price_in_per_1m=0.2,
                price_out_per_1m=0.6,
                price_cached_per_1m=0.2,
                approved_use_cases=["reviewer", "verifier"],
                typical_latency_ms=4000,
            ),
        ]
    )


@pytest.fixture
def policy() -> RoutingPolicy:
    return RoutingPolicy()


# ---------------------------------------------------------------------------- tiers
def test_complexity_maps_to_tier(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    low = policy.route(TaskProfile(complexity=Complexity.low), registry)
    std = policy.route(TaskProfile(complexity=Complexity.standard), registry)
    high = policy.route(TaskProfile(complexity=Complexity.high), registry)
    assert low.tier is RoutingTier.low and low.model == "haiku"
    assert std.tier is RoutingTier.standard
    assert high.tier is RoutingTier.high
    assert registry.get(std.model).default_tier == "standard"
    assert registry.get(high.model).default_tier == "high"
    assert "complexity=high -> tier high" in high.reason


def test_default_ranking_is_price_based_not_reputation(
    registry: ModelRegistry, policy: RoutingPolicy
) -> None:
    d = policy.route(TaskProfile(complexity=Complexity.standard, role="implementer"), registry)
    # llama is not approved for implementer, so the cheapest approved standard model wins.
    assert d.model == "gpt-mini"
    assert "ranked by registry price/latency" in d.reason
    assert d.benchmark_backed is False
    assert d.alternatives and d.alternatives[0] == "sonnet"
    assert d.estimated_cost_per_1k > 0
    assert d.estimated_task_cost_usd == pytest.approx(d.estimated_cost_per_1k * 20)


def test_risk_raises_floor(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    d = policy.route(TaskProfile(complexity=Complexity.low, risk="high"), registry)
    assert d.tier is RoutingTier.standard
    assert "risk=high raises floor to standard" in d.reason
    d2 = policy.route(TaskProfile(complexity=Complexity.low, risk="critical"), registry)
    assert d2.tier is RoutingTier.high


def test_role_cap_limits_tier(registry: ModelRegistry) -> None:
    policy = RoutingPolicy(max_tier_by_role={"verifier": "low"})
    d = policy.route(TaskProfile(complexity=Complexity.high, role="verifier"), registry)
    assert d.tier is RoutingTier.low
    assert "capped at low" in d.reason


def test_required_capabilities_filter(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    d = policy.route(TaskProfile(required_capabilities=["vision"]), registry)
    assert d.model in {"opus", "gpt-big"}
    assert "no candidate at tier standard" in d.reason
    with pytest.raises(RoutingError):
        policy.route(TaskProfile(required_capabilities=["telepathy"]), registry)


def test_allowlist_restricts(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    d = policy.route(TaskProfile(), registry, allowlist=["sonnet", "opus"])
    assert d.model == "sonnet"
    with pytest.raises(RoutingError):
        policy.route(TaskProfile(), registry, allowlist=["nothing"])


def test_latency_target_prefers_fast_models(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    d = policy.route(TaskProfile(complexity=Complexity.standard, latency_target_ms=2600), registry)
    assert d.model == "gpt-mini"  # only standard-tier model under 2.6s
    d2 = policy.route(TaskProfile(complexity=Complexity.high, latency_target_ms=100), registry)
    assert "no candidate meets latency target" in d2.reason


def test_budget_pressure_downgrades(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    rich = policy.route(TaskProfile(complexity=Complexity.high, budget_remaining_usd=100), registry)
    assert rich.tier is RoutingTier.high
    poor = policy.route(
        TaskProfile(complexity=Complexity.high, budget_remaining_usd=0.001), registry
    )
    assert poor.tier is RoutingTier.low
    assert "downgraded to" in poor.reason


# ---------------------------------------------------------------------------- independent review
def test_independent_review_picks_different_family(
    registry: ModelRegistry, policy: RoutingPolicy
) -> None:
    d = policy.route(
        TaskProfile(
            role="reviewer",
            tier_override=RoutingTier.independent_review,
            exclude_families=["claude"],
        ),
        registry,
    )
    assert d.tier is RoutingTier.independent_review
    assert d.family != "claude"
    assert "excludes families ['claude']" in d.reason
    # High risk requires a high-tier reviewer from another family.
    d2 = policy.route(
        TaskProfile(
            role="reviewer",
            risk="high",
            tier_override=RoutingTier.independent_review,
            exclude_families=["claude"],
        ),
        registry,
    )
    assert d2.model == "gpt-big"


def test_independent_review_requires_exclusions(
    registry: ModelRegistry, policy: RoutingPolicy
) -> None:
    with pytest.raises(RoutingError):
        policy.route(TaskProfile(tier_override=RoutingTier.independent_review), registry)


def test_independent_review_fails_when_only_one_family(policy: RoutingPolicy) -> None:
    reg = ModelRegistry([_entry(model="a"), _entry(model="b", default_tier="high")])
    with pytest.raises(RoutingError):
        policy.route(
            TaskProfile(tier_override=RoutingTier.independent_review, exclude_families=["claude"]),
            reg,
        )


# ---------------------------------------------------------------------------- escalation
def test_escalation_picks_higher_tier_or_other_provider(
    registry: ModelRegistry, policy: RoutingPolicy
) -> None:
    d = policy.route(
        TaskProfile(tier_override=RoutingTier.escalation, escalate_from="sonnet"), registry
    )
    assert d.tier is RoutingTier.escalation
    assert d.model != "sonnet"
    entry = registry.get(d.model)
    assert entry.default_tier == "high" or entry.provider != "anthropic"
    assert "escalating from sonnet" in d.reason
    # From the top model of a provider, escalation must switch provider.
    d2 = policy.route(
        TaskProfile(tier_override=RoutingTier.escalation, escalate_from="opus"), registry
    )
    assert registry.get(d2.model).provider != "anthropic"


def test_escalation_requires_source_and_path(policy: RoutingPolicy) -> None:
    reg = ModelRegistry([_entry(model="only", default_tier="high")])
    with pytest.raises(RoutingError):
        policy.route(TaskProfile(tier_override=RoutingTier.escalation), reg)
    with pytest.raises(RoutingError):
        policy.route(TaskProfile(tier_override=RoutingTier.escalation, escalate_from="only"), reg)


# ---------------------------------------------------------------------------- benchmark-driven
def _bm(
    model: str,
    value: float,
    category: BenchmarkCategory = BenchmarkCategory.quality,
    cost: float = 0.0,
    n: int = 10,
    **kw: object,
) -> BenchmarkResult:
    return BenchmarkResult(
        benchmark_id="BM-swe-lite-1.0",
        category=category,
        model=model,
        metric="pass_rate",
        value=value,
        cost_usd=cost,
        sample_size=n,
        **kw,  # type: ignore[arg-type]
    )


def test_benchmark_scores_override_price_ranking(
    registry: ModelRegistry, policy: RoutingPolicy
) -> None:
    bench = BenchmarkService()
    # gpt-mini is cheapest but scores badly; sonnet scores very well.
    bench.store(_bm("gpt-mini", 0.10))
    bench.store(_bm("sonnet", 0.90))
    d = policy.route(TaskProfile(role="implementer"), registry, benchmarks=bench)
    assert d.model == "sonnet"
    assert d.benchmark_backed is True
    assert d.benchmark_category is BenchmarkCategory.quality
    assert d.benchmark_score == pytest.approx(0.9)
    assert "ranked by observed quality benchmark score per dollar" in d.reason
    # Models without data rank after models with data.
    assert d.alternatives[0] == "gpt-mini"


def test_benchmark_category_follows_role(registry: ModelRegistry, policy: RoutingPolicy) -> None:
    bench = BenchmarkService()
    bench.store(_bm("llama", 0.95, BenchmarkCategory.review_precision))
    bench.store(_bm("gpt-mini", 0.95, BenchmarkCategory.quality))  # wrong category for reviewer
    d = policy.route(TaskProfile(role="reviewer"), registry, benchmarks=bench)
    assert d.model == "llama"
    assert d.benchmark_category is BenchmarkCategory.review_precision


def test_min_samples_gate(registry: ModelRegistry) -> None:
    bench = BenchmarkService()
    bench.store(_bm("sonnet", 0.99, n=2))
    policy = RoutingPolicy(min_benchmark_samples=5)
    d = policy.route(TaskProfile(), registry, benchmarks=bench)
    assert d.benchmark_backed is False
    assert "no benchmark data" in d.reason


# ---------------------------------------------------------------------------- BenchmarkService
def test_benchmark_service_store_query_and_scores(tmp_path: Path) -> None:
    svc = BenchmarkService(str(tmp_path / "bm.sqlite"))
    old = datetime.now(tz=UTC) - timedelta(days=2)
    svc.store_many(
        [
            _bm("a", 0.5, cost=1.0, n=10),
            _bm("a", 0.95, cost=1.0, n=30),
            _bm("b", 0.8, cost=0.5, n=10, ts=old),
            _bm("c", 0.3, BenchmarkCategory.security, higher_is_better=False, n=10),
        ]
    )
    assert svc.count() == 4
    assert len(svc.query(category="quality")) == 3
    assert len(svc.query(model="a")) == 2
    assert len(svc.query(since=datetime.now(tz=UTC) - timedelta(days=1))) == 3
    assert svc.query(limit=1)[0].model in {"a", "c"}  # newest first
    scores = svc.scores(BenchmarkCategory.quality)
    assert scores["a"].score == pytest.approx((0.5 * 10 + 0.95 * 30) / 40)
    assert scores["a"].total_samples == 40 and scores["a"].results == 2
    assert scores["b"].score_per_dollar == pytest.approx(0.8 / 0.5)
    # lower-is-better metrics are folded to higher-is-better
    assert svc.scores(BenchmarkCategory.security)["c"].score == pytest.approx(0.7)
    assert svc.scores("quality", min_samples=20).keys() == {"a"}
    assert svc.scores("quality", models=["b"]).keys() == {"b"}
    best = svc.best_for("quality")
    assert best is not None and best.model == "a"
    best_value = svc.best_for("quality", by="score_per_dollar")
    assert best_value is not None and best_value.model == "b"
    assert svc.best_for(BenchmarkCategory.cost_performance) is None
    with pytest.raises(ValueError):
        svc.best_for("quality", by="reputation")
    svc.close()
    # Persisted on disk.
    again = BenchmarkService(str(tmp_path / "bm.sqlite"))
    assert again.count() == 4
    again.close()


def test_benchmark_id_validated() -> None:
    with pytest.raises(ValueError):
        BenchmarkResult(
            benchmark_id="not-an-id",
            category=BenchmarkCategory.quality,
            model="x",
            metric="m",
            value=1.0,
        )


def test_task_profile_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError):
        TaskProfile.model_validate({"complexity": "low", "bogus": 1})


# ---------------------------------------------------------------------------- role caps on
# independent review / escalation (review finding: caps were bypassed by tier overrides)
def test_role_cap_applies_to_independent_review() -> None:
    from aisdlc.control_plane.registry import ModelRegistry as _Registry

    registry = _Registry.default()
    profile = TaskProfile(
        role="reviewer",
        risk="high",
        exclude_families=["claude"],
        tier_override=RoutingTier.independent_review,
    )
    # cap at standard: the high-risk floor (high) is lowered to the cap, never exceeded
    d = RoutingPolicy(max_tier_by_role={"reviewer": "standard"}).route(profile, registry)
    assert registry.get(d.model).default_tier == "standard"
    assert d.tier is RoutingTier.independent_review
    assert "the cap wins" in d.reason
    # no reviewer-approved model at tier low -> fail closed instead of picking a high model
    with pytest.raises(RoutingError, match="role cap"):
        RoutingPolicy(max_tier_by_role={"reviewer": "low"}).route(profile, registry)
    # uncapped: high-risk independent review still picks a high-tier model
    d2 = RoutingPolicy().route(profile, registry)
    assert registry.get(d2.model).default_tier == "high"


def test_role_cap_applies_to_escalation() -> None:
    from aisdlc.control_plane.registry import ModelRegistry as _Registry

    registry = _Registry.default()
    profile = TaskProfile(
        role="reviewer", tier_override=RoutingTier.escalation, escalate_from="gpt-5-mini"
    )
    d = RoutingPolicy(max_tier_by_role={"reviewer": "standard"}).route(profile, registry)
    assert registry.get(d.model).default_tier == "standard" and d.model != "gpt-5-mini"
    assert "capped at standard" in d.reason
    with pytest.raises(RoutingError, match="role cap"):
        RoutingPolicy(max_tier_by_role={"reviewer": "low"}).route(profile, registry)


def test_nearest_tier_fallback_never_exceeds_role_cap() -> None:
    from aisdlc.control_plane.registry import ModelRegistry as _Registry

    registry = _Registry.default()
    # every reviewer-approved model is standard or high; a low cap cannot be honoured
    with pytest.raises(RoutingError, match="exceeds the role cap"):
        RoutingPolicy(max_tier_by_role={"reviewer": "low"}).route(
            TaskProfile(role="reviewer", risk="high", exclude_families=["claude"]), registry
        )
