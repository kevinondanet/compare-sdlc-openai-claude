"""KPI computation from the usage ledger plus delivery outcomes (ARCHITECTURE.md §5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.benchmark import BenchmarkCategory, BenchmarkService
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger, percentile
from aisdlc.control_plane.pricing import blended_cost_per_1k
from aisdlc.control_plane.registry import ModelRegistry
from aisdlc.control_plane.routing import ROLE_BENCHMARK_CATEGORY

_TIER_ORDER: dict[str, int] = {"low": 0, "standard": 1, "high": 2}


class Outcomes(BaseModel):
    """Delivery outcomes for the KPI window (from change packages / gates)."""

    model_config = ConfigDict(extra="forbid")

    accepted_requirements: int = Field(default=0, ge=0)
    merged_changes: int = Field(default=0, ge=0)
    defects_found: int = Field(default=0, ge=0)
    vulns_found: int = Field(default=0, ge=0)
    benchmarks_passed: int = Field(default=0, ge=0)
    accepted_tasks: int = Field(default=0, ge=0)
    successful_runs: int = Field(default=0, ge=0)
    accepted_changes: int | None = Field(
        default=None, ge=0, description="Defaults to merged_changes when unset"
    )

    @property
    def effective_accepted_changes(self) -> int:
        """``accepted_changes`` or ``merged_changes``."""
        return self.merged_changes if self.accepted_changes is None else self.accepted_changes


class KpiReport(BaseModel):
    """All control-plane KPIs. ``None`` means the denominator was zero / data unavailable."""

    model_config = ConfigDict(extra="forbid")

    since: datetime | None = None
    until: datetime | None = None
    calls: int = 0
    model_calls: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    cost_per_accepted_requirement: float | None = None
    cost_per_merged_change: float | None = None
    cost_per_defect_found: float | None = None
    cost_per_vuln_found: float | None = None
    cost_per_passing_benchmark: float | None = None
    tokens_per_accepted_task: float | None = None
    escalation_rate: float | None = None
    cache_hit_rate: float | None = None
    cached_token_share: float | None = None
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    turns_per_success: float | None = None
    review_rounds_per_merge: float | None = None
    tool_calls_per_accepted_change: float | None = None
    high_tier_calls: int = 0
    high_tier_assessed_calls: int = 0
    high_tier_servable_by_lower_share: float | None = None
    high_tier_servable_savings_usd: float = 0.0
    notes: list[str] = Field(default_factory=list)


def _ratio(numerator: float, denominator: float) -> float | None:
    return (numerator / denominator) if denominator else None


def _event_tier(ev: UsageEvent, registry: ModelRegistry | None) -> int | None:
    if ev.routing_tier in _TIER_ORDER:
        return _TIER_ORDER[ev.routing_tier]
    if ev.routing_tier == "escalation":
        return 2
    if registry is not None and ev.model in registry:
        return _TIER_ORDER[registry.get(ev.model).default_tier]
    return None


def _high_tier_analysis(
    model_events: list[UsageEvent],
    *,
    benchmarks: BenchmarkService | None,
    registry: ModelRegistry | None,
    min_samples: int,
    score_tolerance: float,
    notes: list[str],
) -> tuple[int, int, float | None, float]:
    """Return (high_calls, assessed_calls, servable_share, savings_usd)."""
    high = [ev for ev in model_events if _event_tier(ev, registry) == 2]
    if not high:
        return 0, 0, None, 0.0
    if benchmarks is None:
        notes.append("high-tier servability not assessed: no benchmark service provided")
        return len(high), 0, None, 0.0
    score_cache: dict[BenchmarkCategory, dict[str, Any]] = {}
    assessed = 0
    servable = 0
    savings = 0.0
    for ev in high:
        category = ROLE_BENCHMARK_CATEGORY.get(ev.agent_role, BenchmarkCategory.quality)
        if category not in score_cache:
            score_cache[category] = benchmarks.scores(category, min_samples=min_samples)
        scores = score_cache[category]
        own = scores.get(ev.model)
        if own is None:
            continue
        own_cost = (
            blended_cost_per_1k(registry.get(ev.model))
            if registry is not None and ev.model in registry
            else None
        )
        assessed += 1
        best_saving = 0.0
        found = False
        for other, ms in scores.items():
            if other == ev.model:
                continue
            if registry is not None and other in registry:
                other_tier = _TIER_ORDER[registry.get(other).default_tier]
                if other_tier >= 2:
                    continue
                other_cost: float | None = blended_cost_per_1k(registry.get(other))
            else:
                # Without registry tiers, "lower" means observed cheaper on the benchmark.
                if own.mean_cost_usd <= 0 or ms.mean_cost_usd >= own.mean_cost_usd:
                    continue
                other_cost = None
            if ms.score + score_tolerance >= own.score:
                found = True
                if own_cost and other_cost is not None and own_cost > 0:
                    best_saving = max(best_saving, ev.cost_usd * (1 - other_cost / own_cost))
        if found:
            servable += 1
            savings += best_saving
    if assessed < len(high):
        notes.append(
            f"{len(high) - assessed} high-tier call(s) had no benchmark score for their model"
        )
    share = _ratio(servable, assessed)
    return len(high), assessed, share, round(savings, 6)


def compute_kpis(
    ledger: UsageLedger,
    outcomes: Outcomes,
    *,
    benchmarks: BenchmarkService | None = None,
    registry: ModelRegistry | None = None,
    filters: dict[str, Any] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    min_samples: int = 1,
    score_tolerance: float = 0.0,
) -> KpiReport:
    """Compute every KPI over the ledger events matching ``filters``/``since``/``until``.

    ``score_tolerance`` lets a lower-tier model count as "could have served" when its
    observed benchmark score is within that margin of the high-tier model's score.
    """
    events = ledger.query(filters, since=since, until=until)
    notes: list[str] = []
    model_events = [ev for ev in events if ev.model and not ev.model.startswith("tool")]
    total_cost = round(sum(ev.cost_usd for ev in events), 10)
    total_tokens = sum(ev.total_tokens for ev in events)
    calls = len(events)
    model_calls = len(model_events)
    prompt_tokens = sum(ev.input_tokens + ev.cached_tokens for ev in model_events)
    cached_tokens = sum(ev.cached_tokens for ev in model_events)
    tool_calls = sum(ev.tool_calls for ev in events)
    escalations = sum(1 for ev in model_events if ev.escalated or ev.routing_tier == "escalation")
    latencies = [ev.latency_ms for ev in model_events]

    review_events = [ev for ev in model_events if ev.agent_role == "reviewer"]
    rounds_keys = {
        (ev.change_id, ev.review_round) for ev in review_events if ev.review_round is not None
    }
    review_rounds = len(rounds_keys) if rounds_keys else len(review_events)
    if review_events and not rounds_keys:
        notes.append("review rounds estimated from reviewer calls (no review_round recorded)")

    turns = sum(1 for ev in model_events if ev.turn is not None) or model_calls

    high_calls, assessed, share, savings = _high_tier_analysis(
        model_events,
        benchmarks=benchmarks,
        registry=registry,
        min_samples=min_samples,
        score_tolerance=score_tolerance,
        notes=notes,
    )
    if not events:
        notes.append("no usage events in window")

    return KpiReport(
        since=since,
        until=until,
        calls=calls,
        model_calls=model_calls,
        total_tokens=total_tokens,
        total_cost_usd=total_cost,
        cost_per_accepted_requirement=_ratio(total_cost, outcomes.accepted_requirements),
        cost_per_merged_change=_ratio(total_cost, outcomes.merged_changes),
        cost_per_defect_found=_ratio(total_cost, outcomes.defects_found),
        cost_per_vuln_found=_ratio(total_cost, outcomes.vulns_found),
        cost_per_passing_benchmark=_ratio(total_cost, outcomes.benchmarks_passed),
        tokens_per_accepted_task=_ratio(total_tokens, outcomes.accepted_tasks),
        escalation_rate=_ratio(escalations, model_calls),
        cache_hit_rate=_ratio(sum(1 for ev in model_events if ev.cache_hit), model_calls),
        cached_token_share=_ratio(cached_tokens, prompt_tokens),
        latency_p50_ms=percentile(latencies, 50),
        latency_p95_ms=percentile(latencies, 95),
        turns_per_success=_ratio(turns, outcomes.successful_runs),
        review_rounds_per_merge=_ratio(review_rounds, outcomes.merged_changes),
        tool_calls_per_accepted_change=_ratio(tool_calls, outcomes.effective_accepted_changes),
        high_tier_calls=high_calls,
        high_tier_assessed_calls=assessed,
        high_tier_servable_by_lower_share=share,
        high_tier_servable_savings_usd=savings,
        notes=notes,
    )
