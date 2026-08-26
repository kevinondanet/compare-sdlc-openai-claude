"""Tests for control_plane.registry and control_plane.pricing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aisdlc.control_plane.pricing import (
    PriceOverride,
    PriceTable,
    blended_cost_per_1k,
    cost_usd,
)
from aisdlc.control_plane.registry import (
    ModelEntry,
    ModelNotFoundError,
    ModelRegistry,
    RegistryLoadError,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _entry(**overrides: object) -> ModelEntry:
    base: dict[str, object] = {
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "family": "claude",
        "capabilities": ["code", "tools"],
        "context_limit": 1_000_000,
        "price_in_per_1m": 2.0,
        "price_out_per_1m": 10.0,
        "price_cached_per_1m": 0.2,
        "approved_use_cases": ["implementer", "reviewer"],
        "default_tier": "standard",
    }
    base.update(overrides)
    return ModelEntry.model_validate(base)


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry(
        [
            _entry(),
            _entry(
                model="claude-haiku-4-5-20251001",
                capabilities=["code", "fast"],
                default_tier="low",
                price_in_per_1m=1.0,
                price_out_per_1m=5.0,
                price_cached_per_1m=0.1,
                approved_use_cases=["verifier"],
                typical_latency_ms=800,
            ),
            _entry(
                provider="openai",
                model="gpt-5",
                family="gpt",
                capabilities=["code", "tools", "vision"],
                default_tier="high",
                price_in_per_1m=1.25,
                price_out_per_1m=10.0,
                price_cached_per_1m=0.125,
                approved_use_cases=["*"],
            ),
            _entry(
                provider="meta",
                model="llama-old",
                family="llama",
                deprecated=True,
            ),
        ]
    )


def test_default_template_loads_and_has_required_models() -> None:
    reg = ModelRegistry.default()
    assert reg.source.endswith("model-registry.yaml")
    for model in (
        "claude-fable-5",
        "claude-opus-5",
        "claude-sonnet-5",
        "claude-haiku-4-5-20251001",
    ):
        assert model in reg
        assert reg.get(model).provider == "anthropic"
        assert reg.get(model).family == "claude"
    assert "gpt" in reg.families()
    assert {"llama", "mistral", "qwen"} & set(reg.families())
    assert any(e.open_weights for e in reg)
    # Placeholder prices must be flagged; Anthropic list prices must not be.
    assert all(e.price_configurable for e in reg.filter(provider="openai"))
    assert not any(e.price_configurable for e in reg.filter(provider="anthropic"))
    assert reg.pricing_note


def test_template_yaml_is_valid_and_all_entries_have_prices() -> None:
    data = yaml.safe_load((REPO_ROOT / "templates" / "model-registry.yaml").read_text())
    assert isinstance(data["models"], list)
    for item in data["models"]:
        entry = ModelEntry.model_validate(item)
        assert entry.price_in_per_1m >= 0 and entry.price_out_per_1m >= 0
        assert entry.approved_use_cases
        assert entry.capabilities


def test_get_unknown_model_raises(registry: ModelRegistry) -> None:
    with pytest.raises(ModelNotFoundError):
        registry.get("nope")
    assert "nope" not in registry


def test_deprecated_entries_hidden(registry: ModelRegistry) -> None:
    assert "llama-old" not in registry.models()
    assert "llama" not in registry.families()
    assert len(registry) == 3


def test_filter_by_capabilities_family_and_use_case(registry: ModelRegistry) -> None:
    assert [e.model for e in registry.filter(capabilities=["vision"])] == ["gpt-5"]
    assert [e.model for e in registry.filter(exclude_families=["claude"])] == ["gpt-5"]
    assert [e.model for e in registry.filter(family="claude", tier="low")] == [
        "claude-haiku-4-5-20251001"
    ]
    # '*' approves every use case.
    assert {e.model for e in registry.filter(use_case="planner")} == {"gpt-5"}
    assert {e.model for e in registry.filter(use_case="reviewer")} == {"claude-sonnet-5", "gpt-5"}
    assert [e.model for e in registry.filter(max_latency_ms=1000)] == ["claude-haiku-4-5-20251001"]
    assert registry.filter(capabilities=["code", "does-not-exist"]) == []


def test_allowlist_narrows_registry(registry: ModelRegistry) -> None:
    narrowed = registry.with_allowlist(["gpt-5", "claude-sonnet-5"])
    assert set(narrowed.models()) == {"gpt-5", "claude-sonnet-5"}
    assert "claude-haiku-4-5-20251001" not in narrowed
    with pytest.raises(ModelNotFoundError):
        narrowed.get("claude-haiku-4-5-20251001")
    # filter-level allowlist intersects too
    assert [e.model for e in registry.filter(allowlist=["gpt-5"])] == ["gpt-5"]
    # nested allowlists intersect, never widen
    again = narrowed.with_allowlist(["gpt-5", "claude-haiku-4-5-20251001"])
    assert again.models() == ["gpt-5"]


def test_load_rejects_bad_documents(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not\n- a\n- mapping\n")
    with pytest.raises(RegistryLoadError):
        ModelRegistry.load(bad)
    (tmp_path / "nomodels.yaml").write_text("version: 1\n")
    with pytest.raises(RegistryLoadError):
        ModelRegistry.load(tmp_path / "nomodels.yaml")
    with pytest.raises(RegistryLoadError):
        ModelRegistry.load(tmp_path / "missing.yaml")


def test_duplicate_model_ids_rejected() -> None:
    with pytest.raises(RegistryLoadError):
        ModelRegistry([_entry(), _entry()])


def test_env_var_overrides_default_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "reg.yaml"
    path.write_text(yaml.safe_dump({"models": [_entry().model_dump()]}))
    monkeypatch.setenv("AISDLC_MODEL_REGISTRY", str(path))
    reg = ModelRegistry.default()
    assert reg.models() == ["claude-sonnet-5"]


def test_entry_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError):
        _entry(bogus=1)


def test_round_trip_to_dict(registry: ModelRegistry) -> None:
    again = ModelRegistry.from_dict(registry.to_dict())
    assert again.models() == registry.models()


# ---------------------------------------------------------------------------- pricing
def test_cost_usd_applies_cache_discount() -> None:
    e = _entry()
    # 1M uncached input = $2; 1M output = $10; 1M cached = $0.20
    assert cost_usd(e, 1_000_000, 0) == pytest.approx(2.0)
    assert cost_usd(e, 0, 1_000_000) == pytest.approx(10.0)
    assert cost_usd(e, 0, 0, cached_tokens=1_000_000) == pytest.approx(0.2)
    # Cached tokens are billed separately from uncached input, not double-counted.
    assert cost_usd(e, 500_000, 0, cached_tokens=500_000) == pytest.approx(1.0 + 0.1)


def test_cost_usd_reasoning_and_cache_write_defaults() -> None:
    e = _entry()
    assert cost_usd(e, 0, 0, reasoning_tokens=1_000_000) == pytest.approx(10.0)  # = output
    assert cost_usd(e, 0, 0, cache_write_tokens=1_000_000) == pytest.approx(2.0)  # = input
    e2 = _entry(price_reasoning_per_1m=4.0, price_cache_write_per_1m=2.5)
    assert cost_usd(e2, 0, 0, reasoning_tokens=1_000_000) == pytest.approx(4.0)
    assert cost_usd(e2, 0, 0, cache_write_tokens=1_000_000) == pytest.approx(2.5)


def test_cost_usd_small_call_and_zero() -> None:
    e = _entry()
    assert cost_usd(e, 0, 0) == 0.0
    assert cost_usd(e, 1000, 500) == pytest.approx(0.002 + 0.005)


def test_cost_usd_rejects_negative() -> None:
    with pytest.raises(ValueError):
        cost_usd(_entry(), -1, 0)


def test_price_table_override() -> None:
    e = _entry()
    table = PriceTable(overrides={"claude-sonnet-5": PriceOverride(price_in_per_1m=1.0)})
    prices = table.resolve(e)
    assert prices.input == 1.0
    assert prices.cached == pytest.approx(0.1)  # default 10% of the overridden input price
    assert prices.output == 10.0  # untouched
    assert cost_usd(e, 1_000_000, 0, price_table=table) == pytest.approx(1.0)
    full = PriceTable(
        overrides={
            "claude-sonnet-5": PriceOverride(
                price_in_per_1m=1.0,
                price_out_per_1m=2.0,
                price_cached_per_1m=0.05,
                price_reasoning_per_1m=1.5,
            )
        }
    )
    p = full.resolve(e)
    assert (p.input, p.output, p.cached, p.reasoning) == (1.0, 2.0, 0.05, 1.5)
    # Overrides for other models do not leak.
    assert PriceTable(overrides={"other": PriceOverride(price_in_per_1m=0)}).resolve(e).input == 2.0


def test_blended_cost_per_1k() -> None:
    e = _entry()
    # 80% input @ $2/1M, 20% output @ $10/1M -> (1.6 + 2.0) / 1000
    assert blended_cost_per_1k(e) == pytest.approx(0.0036)
    cheaper = blended_cost_per_1k(e, cache_hit_ratio=1.0)
    assert cheaper < blended_cost_per_1k(e)
    with pytest.raises(ValueError):
        blended_cost_per_1k(e, input_share=2.0)
