# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Model identity, capability, and effective-dated price registry primitives.

The registry deliberately separates immutable model facts from routing policy.  A
deployment is identified by provider, provider family, model, version, and deployment
name.  Prices are effective-dated and use :class:`~decimal.Decimal` end to end so the
usage ledger never has to reconstruct cost from binary floating-point values.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from typing import Iterable


class RegistryError(ValueError):
    """Base error for invalid or conflicting registry state."""


class DuplicateModelError(RegistryError):
    """Raised when one immutable model identity is registered with different facts."""


class PriceOverlapError(RegistryError):
    """Raised when two price records overlap for one model identity."""


class UnknownPriceError(RegistryError):
    """Raised when an operation requires a price that is not known."""


class ModelTier(IntEnum):
    """Ordered model tiers used by maximum-tier routing constraints."""

    LOW = 0
    STANDARD = 1
    HIGH = 2


def _nonempty(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{field_name} must be a non-empty string")
    return value.strip()


def _aware_utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RegistryError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _nonnegative_decimal(value: Decimal | str | int, *, field_name: str) -> Decimal:
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise RegistryError(f"{field_name} must be a decimal value") from exc
    if not parsed.is_finite() or parsed < 0:
        raise RegistryError(f"{field_name} must be finite and non-negative")
    return parsed


@dataclass(frozen=True, slots=True, order=True)
class ModelIdentity:
    """Immutable provider/model/version/deployment identity.

    ``provider_family`` is explicit rather than inferred from a provider name.  Routing
    can therefore enforce an independent-review family boundary even when two provider
    accounts expose similarly named deployments.
    """

    provider: str
    provider_family: str
    model: str
    version: str
    deployment: str

    def __post_init__(self) -> None:
        for name in ("provider", "provider_family", "model", "version", "deployment"):
            object.__setattr__(self, name, _nonempty(getattr(self, name), field_name=name))

    @property
    def canonical_id(self) -> str:
        """Return a stable, human-readable identity key."""

        return "/".join(
            (self.provider, self.provider_family, self.model, self.version, self.deployment)
        )


@dataclass(frozen=True, slots=True)
class ModelCapabilities:
    """Immutable allowlists and capacity facts used to qualify a model."""

    tier: ModelTier
    max_context_tokens: int
    capabilities: frozenset[str] = field(default_factory=frozenset)
    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_risk_levels: frozenset[str] = field(default_factory=frozenset)
    allowed_use_cases: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if isinstance(self.tier, bool) or not isinstance(self.tier, ModelTier):
            raise RegistryError("tier must be a ModelTier")
        if (
            isinstance(self.max_context_tokens, bool)
            or not isinstance(self.max_context_tokens, int)
            or self.max_context_tokens <= 0
        ):
            raise RegistryError("max_context_tokens must be a positive integer")
        for name in ("capabilities", "allowed_tools", "allowed_risk_levels", "allowed_use_cases"):
            values = frozenset(
                _nonempty(item, field_name=f"{name} item") for item in getattr(self, name)
            )
            object.__setattr__(self, name, values)
        if not self.allowed_risk_levels:
            raise RegistryError("allowed_risk_levels must not be empty")
        if not self.allowed_use_cases:
            raise RegistryError("allowed_use_cases must not be empty")

    def permits_tools(self, required_tools: frozenset[str]) -> bool:
        """Return whether every requested tool is explicitly allowed."""

        return (
            not required_tools or "*" in self.allowed_tools or required_tools <= self.allowed_tools
        )


@dataclass(frozen=True, slots=True)
class RegisteredModel:
    """An immutable routable model deployment."""

    identity: ModelIdentity
    capabilities: ModelCapabilities
    enabled: bool = True


class ModelRegistry:
    """Thread-safe in-memory registry of immutable model deployment facts."""

    def __init__(self, models: Iterable[RegisteredModel] = ()) -> None:
        self._models: dict[ModelIdentity, RegisteredModel] = {}
        self._lock = threading.RLock()
        for model in models:
            self.register(model)

    def register(self, model: RegisteredModel) -> RegisteredModel:
        """Register *model* idempotently, rejecting conflicting immutable facts."""

        if not isinstance(model, RegisteredModel):
            raise RegistryError("model must be a RegisteredModel")
        with self._lock:
            existing = self._models.get(model.identity)
            if existing is None:
                self._models[model.identity] = model
                return model
            if existing != model:
                raise DuplicateModelError(
                    f"model identity {model.identity.canonical_id!r} is already registered with different facts"
                )
            return existing

    def get(self, identity: ModelIdentity) -> RegisteredModel | None:
        """Return a registered model or ``None``."""

        with self._lock:
            return self._models.get(identity)

    def list_models(self, *, enabled_only: bool = True) -> tuple[RegisteredModel, ...]:
        """Return models in deterministic identity order."""

        with self._lock:
            models = [model for model in self._models.values() if model.enabled or not enabled_only]
        return tuple(sorted(models, key=lambda item: item.identity))


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Mutually exclusive token buckets used for exact price calculation."""

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens", "cached_input_tokens", "reasoning_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RegistryError(f"{name} must be a non-negative integer")

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cached_input_tokens
            + self.reasoning_tokens
        )


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """Effective-dated USD prices per one million tokens.

    The four token buckets are treated as mutually exclusive.  A missing optional
    cache or reasoning rate is only an error when corresponding usage is non-zero.
    """

    identity: ModelIdentity
    effective_from: datetime
    effective_to: datetime | None
    input_per_million: Decimal
    output_per_million: Decimal
    cached_input_per_million: Decimal | None = None
    reasoning_per_million: Decimal | None = None
    provenance: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "effective_from",
            _aware_utc(self.effective_from, field_name="effective_from"),
        )
        if self.effective_to is not None:
            end = _aware_utc(self.effective_to, field_name="effective_to")
            if end <= self.effective_from:
                raise RegistryError("effective_to must be after effective_from")
            object.__setattr__(self, "effective_to", end)
        for name in ("input_per_million", "output_per_million"):
            object.__setattr__(
                self,
                name,
                _nonnegative_decimal(getattr(self, name), field_name=name),
            )
        for name in ("cached_input_per_million", "reasoning_per_million"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _nonnegative_decimal(value, field_name=name))
        object.__setattr__(self, "provenance", _nonempty(self.provenance, field_name="provenance"))

    def applies_at(self, at: datetime) -> bool:
        """Return whether this price applies at the supplied instant."""

        when = _aware_utc(at, field_name="at")
        return self.effective_from <= when and (
            self.effective_to is None or when < self.effective_to
        )

    def calculate(self, usage: TokenUsage) -> Decimal:
        """Calculate exact USD cost for *usage*, failing on an unknown required bucket."""

        rates: tuple[tuple[str, int, Decimal | None], ...] = (
            ("input", usage.input_tokens, self.input_per_million),
            ("output", usage.output_tokens, self.output_per_million),
            ("cached_input", usage.cached_input_tokens, self.cached_input_per_million),
            ("reasoning", usage.reasoning_tokens, self.reasoning_per_million),
        )
        total = Decimal("0")
        million = Decimal(1_000_000)
        for bucket, tokens, rate in rates:
            if tokens == 0:
                continue
            if rate is None:
                raise UnknownPriceError(
                    f"{bucket} price is unknown for {self.identity.canonical_id!r}"
                )
            total += Decimal(tokens) * rate / million
        return total


class PriceCatalog:
    """Thread-safe, non-overlapping effective-dated model price catalog."""

    def __init__(self, prices: Iterable[ModelPrice] = ()) -> None:
        self._prices: dict[ModelIdentity, list[ModelPrice]] = {}
        self._lock = threading.RLock()
        for price in prices:
            self.add(price)

    @staticmethod
    def _overlaps(left: ModelPrice, right: ModelPrice) -> bool:
        left_end = left.effective_to or datetime.max.replace(tzinfo=UTC)
        right_end = right.effective_to or datetime.max.replace(tzinfo=UTC)
        return left.effective_from < right_end and right.effective_from < left_end

    def add(self, price: ModelPrice) -> ModelPrice:
        """Add a price idempotently, rejecting ambiguous effective periods."""

        if not isinstance(price, ModelPrice):
            raise RegistryError("price must be a ModelPrice")
        with self._lock:
            entries = self._prices.setdefault(price.identity, [])
            if price in entries:
                return price
            if any(self._overlaps(price, existing) for existing in entries):
                raise PriceOverlapError(
                    f"price period overlaps an existing price for {price.identity.canonical_id!r}"
                )
            entries.append(price)
            entries.sort(key=lambda item: item.effective_from)
        return price

    def get(self, identity: ModelIdentity, *, at: datetime) -> ModelPrice | None:
        """Return the price effective at *at* or ``None``."""

        when = _aware_utc(at, field_name="at")
        with self._lock:
            for price in reversed(self._prices.get(identity, [])):
                if price.applies_at(when):
                    return price
        return None

    def calculate(
        self,
        identity: ModelIdentity,
        *,
        usage: TokenUsage,
        at: datetime,
        required: bool = True,
    ) -> tuple[Decimal | None, ModelPrice | None]:
        """Return exact cost and its price record.

        Unknown prices fail closed when ``required`` is true.  When false, the pair
        ``(None, None)`` explicitly preserves unknown cost instead of converting it to zero.
        """

        price = self.get(identity, at=at)
        if price is None:
            if required:
                raise UnknownPriceError(
                    f"no price is effective for {identity.canonical_id!r} at {at.isoformat()}"
                )
            return None, None
        try:
            return price.calculate(usage), price
        except UnknownPriceError:
            if required:
                raise
            return None, price


__all__ = [
    "DuplicateModelError",
    "ModelCapabilities",
    "ModelIdentity",
    "ModelPrice",
    "ModelRegistry",
    "ModelTier",
    "PriceCatalog",
    "PriceOverlapError",
    "RegisteredModel",
    "RegistryError",
    "TokenUsage",
    "UnknownPriceError",
]
