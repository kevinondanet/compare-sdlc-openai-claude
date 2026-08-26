"""Model registry: provider/model/version/capabilities/limits/prices/use cases.

The registry is loaded from ``templates/model-registry.yaml`` (or any YAML/dict with the
same shape) and optionally narrowed by an organisation allowlist. Routing, pricing and KPI
computation all consume :class:`ModelEntry` objects from here.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

ModelTier = Literal["low", "standard", "high"]
LatencyClass = Literal["fast", "medium", "slow"]

REGISTRY_ENV_VAR = "AISDLC_MODEL_REGISTRY"


class ModelNotFoundError(KeyError):
    """Raised when a model id is not present in the registry (or not allowlisted)."""


class RegistryLoadError(ValueError):
    """Raised when the registry file is missing or malformed."""


class ModelEntry(BaseModel):
    """One model in the registry.

    Prices are USD per one million tokens. ``price_cached_per_1m`` is the price for input
    tokens served from a prompt cache; ``price_cache_write_per_1m`` is the price for tokens
    written to the cache (defaults to the input price when unset). ``price_reasoning_per_1m``
    defaults to the output price when unset.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    version: str = ""
    family: str = Field(min_length=1, description="Model lineage used for independent review")
    capabilities: list[str] = Field(default_factory=list)
    context_limit: int = Field(gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    tool_support: bool = True
    price_in_per_1m: float = Field(ge=0)
    price_out_per_1m: float = Field(ge=0)
    price_cached_per_1m: float = Field(ge=0)
    price_cache_write_per_1m: float | None = Field(default=None, ge=0)
    price_reasoning_per_1m: float | None = Field(default=None, ge=0)
    price_configurable: bool = Field(
        default=False,
        description="True when the prices are placeholders that operators must configure",
    )
    approved_use_cases: list[str] = Field(default_factory=list)
    default_tier: ModelTier = "standard"
    latency_class: LatencyClass = "medium"
    typical_latency_ms: int = Field(default=2000, ge=0)
    open_weights: bool = False
    deprecated: bool = False
    notes: str = ""

    @field_validator("capabilities", "approved_use_cases")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        seen: dict[str, None] = {}
        for item in value:
            seen.setdefault(item, None)
        return list(seen)

    @property
    def cache_write_price(self) -> float:
        """Effective cache-write price per 1M tokens."""
        if self.price_cache_write_per_1m is None:
            return self.price_in_per_1m
        return self.price_cache_write_per_1m

    @property
    def reasoning_price(self) -> float:
        """Effective reasoning-token price per 1M tokens."""
        if self.price_reasoning_per_1m is None:
            return self.price_out_per_1m
        return self.price_reasoning_per_1m

    def has_capabilities(self, required: Iterable[str]) -> bool:
        """Return True if every required capability is present."""
        caps = set(self.capabilities)
        return all(c in caps for c in required)

    def supports_use_case(self, use_case: str) -> bool:
        """Return True if ``use_case`` is approved (``*`` approves everything)."""
        return "*" in self.approved_use_cases or use_case in self.approved_use_cases


class ModelRegistry:
    """In-memory registry of :class:`ModelEntry` objects with allowlist support."""

    def __init__(
        self,
        entries: Iterable[ModelEntry],
        *,
        allowlist: Iterable[str] | None = None,
        source: str = "",
        pricing_note: str = "",
    ) -> None:
        self._all: dict[str, ModelEntry] = {}
        for entry in entries:
            if entry.model in self._all:
                raise RegistryLoadError(f"duplicate model id in registry: {entry.model!r}")
            self._all[entry.model] = entry
        self.allowlist: frozenset[str] | None = (
            frozenset(allowlist) if allowlist is not None else None
        )
        self.source = source
        self.pricing_note = pricing_note

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(
        cls, data: dict[str, Any], *, allowlist: Iterable[str] | None = None, source: str = ""
    ) -> ModelRegistry:
        """Build a registry from a parsed YAML/JSON document ``{models: [...]}``."""
        models = data.get("models")
        if not isinstance(models, list):
            raise RegistryLoadError("registry document must contain a 'models' list")
        entries = [ModelEntry.model_validate(item) for item in models]
        note = str(data.get("pricing_note", "") or "")
        return cls(entries, allowlist=allowlist, source=source, pricing_note=note)

    @classmethod
    def load(cls, path: str | Path, *, allowlist: Iterable[str] | None = None) -> ModelRegistry:
        """Load a registry from a YAML file."""
        p = Path(path)
        if not p.is_file():
            raise RegistryLoadError(f"model registry file not found: {p}")
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise RegistryLoadError(f"model registry {p} must be a mapping at top level")
        return cls.from_dict(data, allowlist=allowlist, source=str(p))

    @staticmethod
    def default_path() -> Path:
        """Location of the bundled ``templates/model-registry.yaml``.

        ``AISDLC_MODEL_REGISTRY`` overrides the bundled path when set.
        """
        env = os.environ.get(REGISTRY_ENV_VAR)
        if env:
            return Path(env)
        return Path(__file__).resolve().parents[3] / "templates" / "model-registry.yaml"

    @classmethod
    def default(cls, *, allowlist: Iterable[str] | None = None) -> ModelRegistry:
        """Load the bundled default registry."""
        return cls.load(cls.default_path(), allowlist=allowlist)

    # ------------------------------------------------------------------ queries
    def _visible(self, model: str) -> bool:
        return self.allowlist is None or model in self.allowlist

    def with_allowlist(self, allowlist: Iterable[str] | None) -> ModelRegistry:
        """Return a copy of this registry narrowed by ``allowlist``."""
        combined: set[str] | None
        if allowlist is None:
            combined = set(self.allowlist) if self.allowlist is not None else None
        else:
            combined = set(allowlist)
            if self.allowlist is not None:
                combined &= set(self.allowlist)
        return ModelRegistry(
            self._all.values(),
            allowlist=combined,
            source=self.source,
            pricing_note=self.pricing_note,
        )

    def get(self, model: str) -> ModelEntry:
        """Return the entry for ``model`` or raise :class:`ModelNotFoundError`."""
        entry = self._all.get(model)
        if entry is None or not self._visible(model):
            raise ModelNotFoundError(model)
        return entry

    def __contains__(self, model: object) -> bool:
        return isinstance(model, str) and model in self._all and self._visible(model)

    def __iter__(self) -> Iterator[ModelEntry]:
        return iter(self.entries())

    def __len__(self) -> int:
        return len(self.entries())

    def entries(self) -> list[ModelEntry]:
        """All visible (allowlisted, non-deprecated) entries."""
        return [e for m, e in self._all.items() if self._visible(m) and not e.deprecated]

    def models(self) -> list[str]:
        """Visible model ids."""
        return [e.model for e in self.entries()]

    def families(self) -> list[str]:
        """Sorted distinct families among visible entries."""
        return sorted({e.family for e in self.entries()})

    def providers(self) -> list[str]:
        """Sorted distinct providers among visible entries."""
        return sorted({e.provider for e in self.entries()})

    def filter(
        self,
        *,
        capabilities: Iterable[str] | None = None,
        allowlist: Iterable[str] | None = None,
        exclude_families: Iterable[str] | None = None,
        family: str | None = None,
        provider: str | None = None,
        use_case: str | None = None,
        tier: ModelTier | None = None,
        min_context: int | None = None,
        tool_support: bool | None = None,
        max_latency_ms: int | None = None,
    ) -> list[ModelEntry]:
        """Return visible entries matching every provided criterion."""
        req_caps = list(capabilities or [])
        excluded = set(exclude_families or [])
        allowed = set(allowlist) if allowlist is not None else None
        out: list[ModelEntry] = []
        for e in self.entries():
            if allowed is not None and e.model not in allowed:
                continue
            if req_caps and not e.has_capabilities(req_caps):
                continue
            if e.family in excluded:
                continue
            if family is not None and e.family != family:
                continue
            if provider is not None and e.provider != provider:
                continue
            if use_case is not None and not e.supports_use_case(use_case):
                continue
            if tier is not None and e.default_tier != tier:
                continue
            if min_context is not None and e.context_limit < min_context:
                continue
            if tool_support is not None and e.tool_support != tool_support:
                continue
            if max_latency_ms is not None and e.typical_latency_ms > max_latency_ms:
                continue
            out.append(e)
        return out

    def to_dict(self) -> dict[str, Any]:
        """Serialise visible entries back to the YAML document shape."""
        return {
            "pricing_note": self.pricing_note,
            "models": [e.model_dump() for e in self.entries()],
        }
