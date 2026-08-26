"""Price tables and cost computation.

Token accounting convention (matches Anthropic/OpenAI usage reports):

* ``input_tokens``      – uncached prompt tokens billed at the input price.
* ``cached_tokens``     – prompt tokens served from a prompt cache, billed at the cached
  (discounted) price. They are **not** a subset of ``input_tokens``.
* ``cache_write_tokens`` – prompt tokens written to the cache, billed at the cache-write price.
* ``output_tokens``     – completion tokens billed at the output price.
* ``reasoning_tokens``  – thinking/reasoning tokens billed at the reasoning price (defaults to
  the output price). When a provider already includes reasoning in ``output_tokens`` pass 0.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.registry import ModelEntry

TOKENS_PER_UNIT = 1_000_000.0


class PriceOverride(BaseModel):
    """Per-model price override (USD per 1M tokens). Unset fields keep registry values."""

    model_config = ConfigDict(extra="forbid")

    price_in_per_1m: float | None = Field(default=None, ge=0)
    price_out_per_1m: float | None = Field(default=None, ge=0)
    price_cached_per_1m: float | None = Field(default=None, ge=0)
    price_cache_write_per_1m: float | None = Field(default=None, ge=0)
    price_reasoning_per_1m: float | None = Field(default=None, ge=0)


class EffectivePrices(BaseModel):
    """Fully resolved prices for one model (USD per 1M tokens)."""

    model_config = ConfigDict(extra="forbid")

    model: str
    input: float
    output: float
    cached: float
    cache_write: float
    reasoning: float


class PriceTable(BaseModel):
    """Overrides layered on top of registry prices (e.g. negotiated enterprise rates)."""

    model_config = ConfigDict(extra="forbid")

    overrides: dict[str, PriceOverride] = Field(default_factory=dict)
    default_cache_discount: float = Field(
        default=0.1,
        ge=0,
        le=1,
        description="Fallback cached-token price as a fraction of the input price when an "
        "override sets input but not cached price",
    )

    def resolve(self, entry: ModelEntry) -> EffectivePrices:
        """Resolve effective prices for ``entry`` applying any override."""
        o = self.overrides.get(entry.model)
        price_in = entry.price_in_per_1m
        price_out = entry.price_out_per_1m
        price_cached = entry.price_cached_per_1m
        price_cache_write = entry.cache_write_price
        price_reasoning = entry.reasoning_price
        if o is not None:
            if o.price_in_per_1m is not None:
                price_in = o.price_in_per_1m
                if o.price_cached_per_1m is None:
                    price_cached = price_in * self.default_cache_discount
                if o.price_cache_write_per_1m is None:
                    price_cache_write = price_in
            if o.price_out_per_1m is not None:
                price_out = o.price_out_per_1m
                if o.price_reasoning_per_1m is None:
                    price_reasoning = price_out
            if o.price_cached_per_1m is not None:
                price_cached = o.price_cached_per_1m
            if o.price_cache_write_per_1m is not None:
                price_cache_write = o.price_cache_write_per_1m
            if o.price_reasoning_per_1m is not None:
                price_reasoning = o.price_reasoning_per_1m
        return EffectivePrices(
            model=entry.model,
            input=price_in,
            output=price_out,
            cached=price_cached,
            cache_write=price_cache_write,
            reasoning=price_reasoning,
        )


def cost_usd(
    entry: ModelEntry,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
    reasoning_tokens: int = 0,
    *,
    cache_write_tokens: int = 0,
    price_table: PriceTable | None = None,
) -> float:
    """Compute the USD cost of one call against ``entry`` (see module docstring).

    Negative token counts are rejected. The result is rounded to 10 decimal places to keep
    ledger sums stable.
    """
    for name, value in (
        ("input_tokens", input_tokens),
        ("output_tokens", output_tokens),
        ("cached_tokens", cached_tokens),
        ("reasoning_tokens", reasoning_tokens),
        ("cache_write_tokens", cache_write_tokens),
    ):
        if value < 0:
            raise ValueError(f"{name} must be >= 0, got {value}")
    prices = (price_table or PriceTable()).resolve(entry)
    total = (
        input_tokens * prices.input
        + cached_tokens * prices.cached
        + cache_write_tokens * prices.cache_write
        + output_tokens * prices.output
        + reasoning_tokens * prices.reasoning
    ) / TOKENS_PER_UNIT
    return round(total, 10)


def blended_cost_per_1k(
    entry: ModelEntry,
    *,
    input_share: float = 0.8,
    cache_hit_ratio: float = 0.0,
    price_table: PriceTable | None = None,
) -> float:
    """Estimated USD cost per 1 000 tokens under an assumed input/output/cache mix.

    ``input_share`` is the fraction of tokens that are prompt tokens; of those,
    ``cache_hit_ratio`` are assumed to be served from cache.
    """
    if not 0.0 <= input_share <= 1.0:
        raise ValueError("input_share must be within [0, 1]")
    if not 0.0 <= cache_hit_ratio <= 1.0:
        raise ValueError("cache_hit_ratio must be within [0, 1]")
    prices = (price_table or PriceTable()).resolve(entry)
    prompt = input_share * ((1 - cache_hit_ratio) * prices.input + cache_hit_ratio * prices.cached)
    completion = (1 - input_share) * prices.output
    return round((prompt + completion) / 1000.0, 10)
