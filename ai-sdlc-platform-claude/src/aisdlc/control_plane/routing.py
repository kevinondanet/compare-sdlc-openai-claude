"""RoutingPolicy: choose a model for a task from the registry, benchmarks and budget.

Selection order:

1. Decide the *tier* (low / standard / high / independent_review / escalation) from the
   task profile: complexity, risk, role caps, budget pressure and explicit overrides.
2. Build the candidate pool from the registry: capability match, allowlist, excluded
   families (independent review), approved use cases, context and latency constraints.
3. Rank the pool. When a :class:`~aisdlc.control_plane.benchmark.BenchmarkService` holds
   scores for the relevant category, candidates are ranked by **observed score per dollar**
   (then score); otherwise by registry defaults (cheapest blended price that satisfies the
   latency target). Reputation never enters the ranking.

Every decision carries a human-readable ``reason`` explaining the tier and ranking basis.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.benchmark import BenchmarkCategory, BenchmarkService, ModelScore
from aisdlc.control_plane.pricing import PriceTable, blended_cost_per_1k
from aisdlc.control_plane.registry import ModelEntry, ModelRegistry, ModelTier


class Complexity(StrEnum):
    """Task complexity as judged by the planner."""

    low = "low"
    standard = "standard"
    high = "high"


class RoutingTier(StrEnum):
    """Routing tiers (ARCHITECTURE.md §5)."""

    low = "low"
    standard = "standard"
    high = "high"
    independent_review = "independent_review"
    escalation = "escalation"


_TIER_ORDER: dict[str, int] = {"low": 0, "standard": 1, "high": 2}
_ORDER_TIER: dict[int, ModelTier] = {0: "low", 1: "standard", 2: "high"}

HIGH_RISK_CLASSES: frozenset[str] = frozenset({"high", "critical", "ai_agent"})

_COMPLEXITY_TIER: dict[Complexity, ModelTier] = {
    Complexity.low: "low",
    Complexity.standard: "standard",
    Complexity.high: "high",
}

ROLE_BENCHMARK_CATEGORY: dict[str, BenchmarkCategory] = {
    "planner": BenchmarkCategory.quality,
    "plan_checker": BenchmarkCategory.quality,
    "implementer": BenchmarkCategory.quality,
    "reviewer": BenchmarkCategory.review_precision,
    "verifier": BenchmarkCategory.test_generation,
    "uat": BenchmarkCategory.test_generation,
    "security": BenchmarkCategory.security,
    "security_tester": BenchmarkCategory.security,
}


class RoutingError(RuntimeError):
    """No model satisfies the task profile under the current registry/allowlist."""


class TaskProfile(BaseModel):
    """What the task needs from a model."""

    model_config = ConfigDict(extra="forbid")

    complexity: Complexity = Complexity.standard
    risk: str = Field(default="standard", description="RiskClass name, e.g. low|standard|high")
    required_capabilities: list[str] = Field(default_factory=list)
    latency_target_ms: int | None = Field(default=None, gt=0)
    budget_remaining_usd: float | None = None
    role: str = "implementer"
    exclude_families: list[str] = Field(default_factory=list)
    tier_override: RoutingTier | None = None
    escalate_from: str | None = Field(
        default=None, description="Model id that failed; used by the escalation tier"
    )
    min_context_tokens: int | None = Field(default=None, gt=0)
    benchmark_category: BenchmarkCategory | None = None
    expected_tokens: int = Field(default=20_000, gt=0, description="Used for cost forecasts")


class RoutingDecision(BaseModel):
    """Outcome of :meth:`RoutingPolicy.route`."""

    model_config = ConfigDict(extra="forbid")

    model: str
    provider: str
    family: str
    tier: RoutingTier
    reason: str
    alternatives: list[str] = Field(default_factory=list)
    estimated_cost_per_1k: float
    estimated_task_cost_usd: float
    benchmark_category: BenchmarkCategory | None = None
    benchmark_score: float | None = None
    benchmark_backed: bool = False


class RoutingPolicy(BaseModel):
    """Configurable routing rules."""

    model_config = ConfigDict(extra="forbid")

    max_tier_by_role: dict[str, ModelTier] = Field(
        default_factory=dict, description="Cap on the model tier a role may use"
    )
    min_tier_for_high_risk: ModelTier = "standard"
    min_tier_for_critical: ModelTier = "high"
    budget_downgrade_ratio: float = Field(
        default=2.0,
        gt=0,
        description="Downgrade the tier when budget_remaining < ratio * forecast task cost",
    )
    strict_use_cases: bool = Field(
        default=False,
        description="Fail (instead of widening the pool) when no model approves the role",
    )
    min_benchmark_samples: int = Field(default=1, ge=1)
    input_share: float = Field(default=0.8, ge=0, le=1)
    cache_hit_ratio: float = Field(default=0.0, ge=0, le=1)
    price_table: PriceTable | None = None

    # ------------------------------------------------------------------ helpers
    def _cost_per_1k(self, entry: ModelEntry) -> float:
        return blended_cost_per_1k(
            entry,
            input_share=self.input_share,
            cache_hit_ratio=self.cache_hit_ratio,
            price_table=self.price_table,
        )

    def _task_cost(self, entry: ModelEntry, profile: TaskProfile) -> float:
        return self._cost_per_1k(entry) * profile.expected_tokens / 1000.0

    def _base_tier(self, profile: TaskProfile, notes: list[str]) -> ModelTier:
        tier: ModelTier = _COMPLEXITY_TIER[profile.complexity]
        notes.append(f"complexity={profile.complexity.value} -> tier {tier}")
        floor: ModelTier
        if profile.risk == "critical":
            floor = self.min_tier_for_critical
        elif profile.risk in HIGH_RISK_CLASSES:
            floor = self.min_tier_for_high_risk
        else:
            floor = "low"
        if _TIER_ORDER[floor] > _TIER_ORDER[tier]:
            notes.append(f"risk={profile.risk} raises floor to {floor}")
            tier = floor
        cap = self.max_tier_by_role.get(profile.role)
        if cap is not None and _TIER_ORDER[cap] < _TIER_ORDER[tier]:
            notes.append(f"role={profile.role} capped at {cap}")
            tier = cap
        return tier

    @staticmethod
    def _tier_for(entry: ModelEntry) -> int:
        return _TIER_ORDER[entry.default_tier]

    def _role_cap(self, profile: TaskProfile) -> int | None:
        """Numeric ``max_tier_by_role`` cap for the profile's role (``None`` = uncapped)."""
        cap = self.max_tier_by_role.get(profile.role)
        return None if cap is None else _TIER_ORDER[cap]

    def _apply_cap(
        self, pool: list[ModelEntry], cap: int | None, profile: TaskProfile, what: str
    ) -> list[ModelEntry]:
        """Drop candidates above the role cap; fail closed when nothing is left."""
        if cap is None:
            return pool
        within = [e for e in pool if self._tier_for(e) <= cap]
        if not within:
            raise RoutingError(
                f"no {what} candidate within the role cap: role {profile.role!r} may use at "
                f"most tier {_ORDER_TIER[cap]} "
                f"(exclude_families={sorted(profile.exclude_families)})"
            )
        return within

    def _pool(
        self,
        profile: TaskProfile,
        registry: ModelRegistry,
        allowlist: Iterable[str] | None,
        notes: list[str],
    ) -> list[ModelEntry]:
        allow = list(allowlist) if allowlist is not None else None
        base = registry.filter(
            capabilities=profile.required_capabilities,
            allowlist=allow,
            exclude_families=profile.exclude_families,
            min_context=profile.min_context_tokens,
        )
        if not base:
            raise RoutingError(
                "no registry model satisfies capabilities="
                f"{profile.required_capabilities} exclude_families={profile.exclude_families}"
                f" allowlist={'*' if allow is None else sorted(allow)}"
            )
        approved = [e for e in base if e.supports_use_case(profile.role)]
        if approved:
            return approved
        if self.strict_use_cases:
            raise RoutingError(f"no model lists role {profile.role!r} in approved_use_cases")
        notes.append(f"no model approves role {profile.role!r}; using capability match only")
        return base

    def _rank(
        self,
        pool: list[ModelEntry],
        profile: TaskProfile,
        benchmarks: BenchmarkService | None,
        notes: list[str],
    ) -> tuple[list[ModelEntry], BenchmarkCategory | None, dict[str, ModelScore]]:
        """Rank ``pool`` best-first; returns (ranked, category, scores)."""
        # Latency preference: models within target come first.
        if profile.latency_target_ms is not None:
            within = [e for e in pool if e.typical_latency_ms <= profile.latency_target_ms]
            if within:
                if len(within) < len(pool):
                    notes.append(
                        f"{len(pool) - len(within)} candidate(s) exceed latency target "
                        f"{profile.latency_target_ms}ms and were deprioritised"
                    )
                pool = within + [e for e in pool if e not in within]
            else:
                notes.append(
                    f"no candidate meets latency target {profile.latency_target_ms}ms; "
                    "ignoring the target"
                )
        category = profile.benchmark_category or ROLE_BENCHMARK_CATEGORY.get(profile.role)
        scores: dict[str, ModelScore] = {}
        if benchmarks is not None and category is not None:
            scores = benchmarks.scores(
                category,
                min_samples=self.min_benchmark_samples,
                models=[e.model for e in pool],
            )
        lat_target = profile.latency_target_ms

        def within_latency(e: ModelEntry) -> int:
            return 0 if lat_target is None or e.typical_latency_ms <= lat_target else 1

        if scores:
            notes.append(
                f"ranked by observed {category.value if category else ''} benchmark score per "
                f"dollar ({len(scores)} of {len(pool)} candidates have data)"
            )

            def bench_key(e: ModelEntry) -> tuple[int, int, float, float, float]:
                s = scores.get(e.model)
                if s is None:
                    return (within_latency(e), 1, 0.0, 0.0, -self._cost_per_1k(e))
                cost = self._cost_per_1k(e)
                spd = s.score / cost if cost > 0 else s.score
                return (within_latency(e), 0, -spd, -s.score, -cost)

            return sorted(pool, key=bench_key), category, scores
        notes.append("no benchmark data for this category; ranked by registry price/latency")

        def default_key(e: ModelEntry) -> tuple[int, float, int]:
            return (within_latency(e), self._cost_per_1k(e), e.typical_latency_ms)

        return sorted(pool, key=default_key), category, scores

    # ------------------------------------------------------------------ route
    def route(
        self,
        profile: TaskProfile,
        registry: ModelRegistry,
        benchmarks: BenchmarkService | None = None,
        allowlist: Iterable[str] | None = None,
    ) -> RoutingDecision:
        """Select a model for ``profile``.

        Raises :class:`RoutingError` when nothing in the registry fits.
        """
        notes: list[str] = []
        tier = profile.tier_override or RoutingTier(self._base_tier(profile, notes))
        if profile.tier_override is not None:
            notes.append(f"tier override -> {tier.value}")
        if tier is RoutingTier.independent_review and not profile.exclude_families:
            raise RoutingError("independent_review requires exclude_families (implementer family)")
        if tier is RoutingTier.escalation and not profile.escalate_from:
            raise RoutingError("escalation requires escalate_from (the model that failed)")

        pool = self._pool(profile, registry, allowlist, notes)

        # Tier-specific narrowing.
        model_tier: int
        cap = self._role_cap(profile)
        if tier is RoutingTier.independent_review:
            floor = 2 if profile.risk in HIGH_RISK_CLASSES else 1
            notes.append(
                f"independent review excludes families {sorted(profile.exclude_families)}; "
                f"requires model tier >= {_ORDER_TIER[floor]}"
            )
            if cap is not None and cap < floor:
                notes.append(
                    f"role={profile.role} capped at {_ORDER_TIER[cap]} (below the "
                    f"independent-review floor {_ORDER_TIER[floor]}); the cap wins"
                )
                floor = cap
            pool = self._apply_cap(pool, cap, profile, "independent-review")
            narrowed = [e for e in pool if self._tier_for(e) >= floor]
            pool = narrowed or pool
            model_tier = floor
        elif tier is RoutingTier.escalation:
            assert profile.escalate_from is not None
            prev = (
                registry.get(profile.escalate_from) if profile.escalate_from in registry else None
            )
            prev_tier = self._tier_for(prev) if prev is not None else -1
            prev_provider = prev.provider if prev is not None else ""
            higher = [
                e
                for e in pool
                if e.model != profile.escalate_from
                and (self._tier_for(e) > prev_tier or e.provider != prev_provider)
            ]
            if not higher:
                raise RoutingError(
                    f"no escalation path from {profile.escalate_from!r}: nothing higher-tier "
                    "or from another provider is available"
                )
            notes.append(
                f"escalating from {profile.escalate_from} (tier {prev_tier}): candidates must be "
                "higher tier or a different provider"
            )
            if cap is not None:
                notes.append(f"role={profile.role} capped at {_ORDER_TIER[cap]}")
            pool = self._apply_cap(higher, cap, profile, "escalation")
            model_tier = max(self._tier_for(e) for e in pool)
        else:
            model_tier = _TIER_ORDER[tier.value]
            # Budget pressure downgrades the tier before candidate selection.
            if profile.budget_remaining_usd is not None and model_tier > 0:
                exemplar = self._cheapest_at_tier(pool, model_tier)
                if exemplar is not None:
                    forecast = self._task_cost(exemplar, profile)
                    while (
                        model_tier > 0
                        and profile.budget_remaining_usd < self.budget_downgrade_ratio * forecast
                    ):
                        model_tier -= 1
                        notes.append(
                            f"budget remaining ${profile.budget_remaining_usd:.2f} < "
                            f"{self.budget_downgrade_ratio:g}x forecast ${forecast:.2f}; "
                            f"downgraded to {_ORDER_TIER[model_tier]}"
                        )
                        nxt = self._cheapest_at_tier(pool, model_tier)
                        if nxt is None:
                            break
                        forecast = self._task_cost(nxt, profile)
            exact = [e for e in pool if self._tier_for(e) == model_tier]
            if exact:
                pool = exact
            else:
                # Fall to the nearest tier (prefer lower, then higher).
                ordered = sorted(
                    pool, key=lambda e: (abs(self._tier_for(e) - model_tier), self._tier_for(e))
                )
                nearest = self._tier_for(ordered[0])
                if cap is not None and nearest > cap:
                    raise RoutingError(
                        f"no candidate at tier {_ORDER_TIER[model_tier]} and the nearest tier "
                        f"{_ORDER_TIER[nearest]} exceeds the role cap {_ORDER_TIER[cap]} for "
                        f"role {profile.role!r}"
                    )
                notes.append(
                    f"no candidate at tier {_ORDER_TIER[model_tier]}; using nearest tier "
                    f"{_ORDER_TIER[nearest]}"
                )
                pool = [e for e in pool if self._tier_for(e) == nearest]
            tier = RoutingTier(_ORDER_TIER[model_tier]) if tier.value in _TIER_ORDER else tier

        ranked, category, scores = self._rank(pool, profile, benchmarks, notes)
        chosen = ranked[0]
        score = scores.get(chosen.model)
        if score is not None:
            notes.append(
                f"{chosen.model}: score={score.score:.3f} over {score.total_samples} samples"
            )
        else:
            notes.append(
                f"{chosen.model}: ${self._cost_per_1k(chosen) * 1000:.2f}/1M blended, "
                f"~{chosen.typical_latency_ms}ms"
            )
        if chosen.price_configurable:
            notes.append("price for the chosen model is a placeholder; configure it")
        return RoutingDecision(
            model=chosen.model,
            provider=chosen.provider,
            family=chosen.family,
            tier=tier,
            reason="; ".join(notes),
            alternatives=[e.model for e in ranked[1:4]],
            estimated_cost_per_1k=self._cost_per_1k(chosen),
            estimated_task_cost_usd=round(self._task_cost(chosen, profile), 6),
            benchmark_category=category if scores else None,
            benchmark_score=score.score if score else None,
            benchmark_backed=score is not None,
        )

    def _cheapest_at_tier(self, pool: list[ModelEntry], tier: int) -> ModelEntry | None:
        at = [e for e in pool if self._tier_for(e) == tier]
        if not at:
            return None
        return min(at, key=self._cost_per_1k)
