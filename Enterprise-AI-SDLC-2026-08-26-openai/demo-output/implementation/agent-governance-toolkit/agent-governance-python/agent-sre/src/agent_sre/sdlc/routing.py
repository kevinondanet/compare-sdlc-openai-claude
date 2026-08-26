# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmark-driven, policy-constrained model routing."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Iterable

from agent_sre.sdlc.model_registry import (
    ModelIdentity,
    ModelPrice,
    ModelRegistry,
    ModelTier,
    PriceCatalog,
    RegisteredModel,
    TokenUsage,
    UnknownPriceError,
)


class RoutingError(ValueError):
    """Base error for routing configuration and selection."""


class BenchmarkConflictError(RoutingError):
    """Raised when a benchmark id is reused for different immutable facts."""


class NoRouteError(RoutingError):
    """Raised when no model satisfies every routing constraint."""

    def __init__(self, diagnostics: dict[str, tuple[str, ...]]) -> None:
        self.diagnostics = diagnostics
        detail = "; ".join(
            f"{model_id}: {', '.join(reasons)}" for model_id, reasons in sorted(diagnostics.items())
        )
        super().__init__(f"no qualifying model route ({detail or 'registry is empty'})")


def _nonempty(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RoutingError(f"{field_name} must be a non-empty string")
    return value.strip()


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RoutingError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _decimal(value: Decimal | str | int, *, field_name: str) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise RoutingError(f"{field_name} must be a decimal") from exc
    if not result.is_finite():
        raise RoutingError(f"{field_name} must be finite")
    return result


@dataclass(frozen=True, slots=True)
class BenchmarkRecord:
    """Immutable observed quality and latency for one model/task combination."""

    benchmark_id: str
    identity: ModelIdentity
    task_type: str
    quality_score: Decimal
    latency_ms: Decimal
    measured_at: datetime
    valid_until: datetime | None
    provenance: str
    sample_size: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "benchmark_id", _nonempty(self.benchmark_id, field_name="benchmark_id")
        )
        object.__setattr__(self, "task_type", _nonempty(self.task_type, field_name="task_type"))
        quality = _decimal(self.quality_score, field_name="quality_score")
        if not Decimal("0") <= quality <= Decimal("1"):
            raise RoutingError("quality_score must be between 0 and 1")
        object.__setattr__(self, "quality_score", quality)
        latency = _decimal(self.latency_ms, field_name="latency_ms")
        if latency < 0:
            raise RoutingError("latency_ms must be non-negative")
        object.__setattr__(self, "latency_ms", latency)
        object.__setattr__(self, "measured_at", _utc(self.measured_at, field_name="measured_at"))
        if self.valid_until is not None:
            end = _utc(self.valid_until, field_name="valid_until")
            if end <= self.measured_at:
                raise RoutingError("valid_until must be after measured_at")
            object.__setattr__(self, "valid_until", end)
        object.__setattr__(self, "provenance", _nonempty(self.provenance, field_name="provenance"))
        if (
            isinstance(self.sample_size, bool)
            or not isinstance(self.sample_size, int)
            or self.sample_size <= 0
        ):
            raise RoutingError("sample_size must be a positive integer")

    def is_fresh(self, *, at: datetime, max_age: timedelta) -> bool:
        """Return whether the record was available and fresh at *at*."""

        when = _utc(at, field_name="at")
        return (
            self.measured_at <= when
            and when - self.measured_at <= max_age
            and (self.valid_until is None or when < self.valid_until)
        )


class BenchmarkRegistry:
    """Thread-safe append-only collection of immutable benchmark records."""

    def __init__(self, records: Iterable[BenchmarkRecord] = ()) -> None:
        self._records: dict[str, BenchmarkRecord] = {}
        self._lock = threading.RLock()
        for record in records:
            self.add(record)

    def add(self, record: BenchmarkRecord) -> BenchmarkRecord:
        """Append a benchmark idempotently and reject id reuse with changed facts."""

        if not isinstance(record, BenchmarkRecord):
            raise RoutingError("record must be a BenchmarkRecord")
        with self._lock:
            existing = self._records.get(record.benchmark_id)
            if existing is None:
                self._records[record.benchmark_id] = record
                return record
            if existing != record:
                raise BenchmarkConflictError(
                    f"benchmark id {record.benchmark_id!r} already identifies different facts"
                )
            return existing

    def latest_fresh(
        self,
        identity: ModelIdentity,
        *,
        task_type: str,
        at: datetime,
        max_age: timedelta,
    ) -> BenchmarkRecord | None:
        """Return the newest benchmark satisfying provenance-time freshness."""

        if max_age <= timedelta(0):
            raise RoutingError("max_age must be positive")
        task = _nonempty(task_type, field_name="task_type")
        with self._lock:
            candidates = [
                record
                for record in self._records.values()
                if record.identity == identity
                and record.task_type == task
                and record.is_fresh(at=at, max_age=max_age)
            ]
        return max(candidates, key=lambda item: (item.measured_at, item.benchmark_id), default=None)


@dataclass(frozen=True, slots=True)
class RoutingRequest:
    """Every constraint needed to select a model without ambient policy state."""

    task_type: str
    use_case: str
    risk_level: str
    context_tokens: int
    estimated_usage: TokenUsage
    as_of: datetime
    max_benchmark_age: timedelta
    max_tier: ModelTier = ModelTier.HIGH
    required_capabilities: frozenset[str] = field(default_factory=frozenset)
    required_tools: frozenset[str] = field(default_factory=frozenset)
    min_quality: Decimal = Decimal("0")
    max_latency_ms: Decimal | None = None
    max_estimated_cost_usd: Decimal | None = None
    require_known_cost: bool = True
    independent_review_of: ModelIdentity | None = None

    def __post_init__(self) -> None:
        for name in ("task_type", "use_case", "risk_level"):
            object.__setattr__(self, name, _nonempty(getattr(self, name), field_name=name))
        if (
            isinstance(self.context_tokens, bool)
            or not isinstance(self.context_tokens, int)
            or self.context_tokens < 0
        ):
            raise RoutingError("context_tokens must be a non-negative integer")
        object.__setattr__(self, "as_of", _utc(self.as_of, field_name="as_of"))
        if self.max_benchmark_age <= timedelta(0):
            raise RoutingError("max_benchmark_age must be positive")
        if not isinstance(self.max_tier, ModelTier):
            raise RoutingError("max_tier must be a ModelTier")
        for name in ("required_capabilities", "required_tools"):
            values = frozenset(
                _nonempty(item, field_name=f"{name} item") for item in getattr(self, name)
            )
            object.__setattr__(self, name, values)
        quality = _decimal(self.min_quality, field_name="min_quality")
        if not Decimal("0") <= quality <= Decimal("1"):
            raise RoutingError("min_quality must be between 0 and 1")
        object.__setattr__(self, "min_quality", quality)
        for name in ("max_latency_ms", "max_estimated_cost_usd"):
            value = getattr(self, name)
            if value is not None:
                parsed = _decimal(value, field_name=name)
                if parsed < 0:
                    raise RoutingError(f"{name} must be non-negative")
                object.__setattr__(self, name, parsed)


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    """Selected model and the benchmark/price evidence that justified it."""

    model: RegisteredModel
    benchmark: BenchmarkRecord
    estimated_cost_usd: Decimal | None
    price: ModelPrice | None
    qualifying_models: int


@dataclass(frozen=True, slots=True)
class _Candidate:
    model: RegisteredModel
    benchmark: BenchmarkRecord
    cost: Decimal | None
    price: ModelPrice | None


class ModelRouter:
    """Choose the cheapest model that satisfies policy and fresh benchmark evidence."""

    def __init__(
        self,
        *,
        models: ModelRegistry,
        prices: PriceCatalog,
        benchmarks: BenchmarkRegistry,
    ) -> None:
        self._models = models
        self._prices = prices
        self._benchmarks = benchmarks

    @staticmethod
    def _allowlisted(value: str, allowlist: frozenset[str]) -> bool:
        return "*" in allowlist or value in allowlist

    def route(self, request: RoutingRequest) -> RoutingDecision:
        """Return a deterministic cheapest qualifying route or raise ``NoRouteError``."""

        if not isinstance(request, RoutingRequest):
            raise RoutingError("request must be a RoutingRequest")

        diagnostics: dict[str, tuple[str, ...]] = {}
        candidates: list[_Candidate] = []
        cost_required = request.require_known_cost or request.max_estimated_cost_usd is not None

        for model in self._models.list_models(enabled_only=False):
            reasons: list[str] = []
            identity = model.identity
            capabilities = model.capabilities

            if not model.enabled:
                reasons.append("disabled")
            if capabilities.tier > request.max_tier:
                reasons.append("tier_exceeds_maximum")
            if request.context_tokens > capabilities.max_context_tokens:
                reasons.append("context_limit_exceeded")
            if not request.required_capabilities <= capabilities.capabilities:
                reasons.append("missing_capability")
            if not capabilities.permits_tools(request.required_tools):
                reasons.append("tool_not_allowed")
            if not self._allowlisted(request.risk_level, capabilities.allowed_risk_levels):
                reasons.append("risk_not_allowed")
            if not self._allowlisted(request.use_case, capabilities.allowed_use_cases):
                reasons.append("use_case_not_allowed")
            if (
                request.independent_review_of is not None
                and identity.provider_family == request.independent_review_of.provider_family
            ):
                reasons.append("review_provider_family_not_independent")

            benchmark = self._benchmarks.latest_fresh(
                identity,
                task_type=request.task_type,
                at=request.as_of,
                max_age=request.max_benchmark_age,
            )
            if benchmark is None:
                reasons.append("fresh_benchmark_missing")
            else:
                if benchmark.quality_score < request.min_quality:
                    reasons.append("quality_below_minimum")
                if (
                    request.max_latency_ms is not None
                    and benchmark.latency_ms > request.max_latency_ms
                ):
                    reasons.append("latency_exceeds_maximum")

            price = self._prices.get(identity, at=request.as_of)
            cost: Decimal | None = None
            if price is None:
                if cost_required:
                    reasons.append("price_unknown")
            else:
                try:
                    cost = price.calculate(request.estimated_usage)
                except UnknownPriceError:
                    if cost_required:
                        reasons.append("price_unknown_for_usage_bucket")
                if (
                    cost is not None
                    and request.max_estimated_cost_usd is not None
                    and cost > request.max_estimated_cost_usd
                ):
                    reasons.append("estimated_cost_exceeds_budget")

            if reasons or benchmark is None:
                diagnostics[identity.canonical_id] = tuple(reasons)
                continue
            candidates.append(_Candidate(model=model, benchmark=benchmark, cost=cost, price=price))

        if not candidates:
            raise NoRouteError(diagnostics)

        candidates.sort(
            key=lambda candidate: (
                candidate.cost is None,
                candidate.cost if candidate.cost is not None else Decimal("Infinity"),
                -candidate.benchmark.quality_score,
                candidate.benchmark.latency_ms,
                candidate.model.identity,
            )
        )
        selected = candidates[0]
        return RoutingDecision(
            model=selected.model,
            benchmark=selected.benchmark,
            estimated_cost_usd=selected.cost,
            price=selected.price,
            qualifying_models=len(candidates),
        )


__all__ = [
    "BenchmarkConflictError",
    "BenchmarkRecord",
    "BenchmarkRegistry",
    "ModelRouter",
    "NoRouteError",
    "RoutingDecision",
    "RoutingError",
    "RoutingRequest",
]
