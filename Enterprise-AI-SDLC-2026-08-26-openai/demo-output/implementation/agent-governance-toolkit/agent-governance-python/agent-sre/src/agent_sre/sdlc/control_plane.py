# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Durable model, prompt, price, and benchmark catalog for the AI-SDLC control plane.

The in-memory registries remain the policy and routing primitives.  This module is
their durable boundary: immutable facts are stored as canonical JSON, every writer
uses ``BEGIN IMMEDIATE``, and fresh registry objects can be hydrated after a process
restart without weakening any registry invariant.
"""

from __future__ import annotations

import math
import os
import re
import sqlite3
import stat
import threading
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from agent_sre.sdlc.canonical import canonical_json_bytes, canonical_sha256, load_json_strict
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
)
from agent_sre.sdlc.routing import (
    BenchmarkConflictError,
    BenchmarkRecord,
    BenchmarkRegistry,
    ModelRouter,
    RoutingError,
)
from agent_sre.sdlc.usage_ledger import LedgerError, PromptIdentity

_SCHEMA_VERSION = 3
_MODEL_SCHEMA = "agt.control-plane/model/v1"
_MODEL_STATE_SCHEMA = "agt.control-plane/model-state/v1"
_PROMPT_SCHEMA = "agt.control-plane/prompt/v1"
_PROMPT_STATE_SCHEMA = "agt.control-plane/prompt-state/v1"
_PRICE_SCHEMA = "agt.control-plane/price/v1"
_PRICE_SUPERSESSION_SCHEMA = "agt.control-plane/price-supersession/v1"
_BENCHMARK_SCHEMA = "agt.control-plane/benchmark/v1"
_SQLITE_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")


class ControlPlaneError(RuntimeError):
    """Base error for the durable control-plane catalog."""


class ControlPlanePathError(ControlPlaneError):
    """Raised when the database path is not safely bounded by its allowed root."""


class ControlPlaneSchemaError(ControlPlaneError):
    """Raised when a database has an unsupported or incomplete schema."""


class ControlPlaneIntegrityError(ControlPlaneError):
    """Raised when persisted indexes, JSON, and canonical hashes disagree."""


class ControlPlaneClosedError(ControlPlaneError):
    """Raised when an operation is attempted after closing the catalog."""


class UnknownRegisteredModelError(ControlPlaneError):
    """Raised when a price or benchmark references an unregistered model."""


class DuplicatePromptError(ControlPlaneError):
    """Raised when one prompt identity is registered with different immutable facts."""


@dataclass(frozen=True, slots=True)
class RegisteredPrompt:
    """Immutable approved prompt facts with an initial enabled state."""

    identity: PromptIdentity
    provenance: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.identity, PromptIdentity):
            raise ControlPlaneError("prompt identity must be a PromptIdentity")
        if not isinstance(self.provenance, str) or not self.provenance.strip():
            raise ControlPlaneError("prompt provenance must be a non-empty string")
        if not isinstance(self.enabled, bool):
            raise ControlPlaneError("prompt enabled must be boolean")
        object.__setattr__(self, "provenance", self.provenance.strip())


class PromptRegistry:
    """Hydrated immutable prompt registry used by planners and release gates."""

    def __init__(self, prompts: Iterable[RegisteredPrompt] = ()) -> None:
        self._prompts: dict[PromptIdentity, RegisteredPrompt] = {}
        self._lock = threading.RLock()
        for prompt in prompts:
            self.register(prompt)

    def register(self, prompt: RegisteredPrompt) -> RegisteredPrompt:
        """Register a prompt idempotently, rejecting conflicting facts."""

        if not isinstance(prompt, RegisteredPrompt):
            raise ControlPlaneError("prompt must be a RegisteredPrompt")
        with self._lock:
            existing = self._prompts.get(prompt.identity)
            if existing is None:
                self._prompts[prompt.identity] = prompt
                return prompt
            if existing != prompt:
                raise DuplicatePromptError(
                    "prompt identity is already registered with different facts"
                )
            return existing

    def get(self, identity: PromptIdentity) -> RegisteredPrompt | None:
        """Return the exact registered prompt identity, if present."""

        with self._lock:
            return self._prompts.get(identity)

    def list_prompts(self, *, enabled_only: bool = True) -> tuple[RegisteredPrompt, ...]:
        """Return prompts in deterministic identity order."""

        with self._lock:
            prompts = [
                prompt for prompt in self._prompts.values() if prompt.enabled or not enabled_only
            ]
        return tuple(
            sorted(
                prompts,
                key=lambda item: (
                    item.identity.prompt_id,
                    item.identity.version,
                    item.identity.digest,
                ),
            )
        )


def _time_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ControlPlaneError("catalog datetimes must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_time(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise ControlPlaneIntegrityError(f"stored {field_name} must be a UTC timestamp string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ControlPlaneIntegrityError(f"stored {field_name} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ControlPlaneIntegrityError(f"stored {field_name} must be timezone-aware")
    normalized = parsed.astimezone(UTC)
    if value != _time_text(normalized):
        raise ControlPlaneIntegrityError(f"stored {field_name} is not canonical UTC")
    return normalized


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise ControlPlaneError("catalog decimals must be finite")
    return format(value, "f")


def _identity_payload(identity: ModelIdentity) -> dict[str, str]:
    return {
        "deployment": identity.deployment,
        "model": identity.model,
        "provider": identity.provider,
        "provider_family": identity.provider_family,
        "version": identity.version,
    }


def _model_key(identity: ModelIdentity) -> str:
    return canonical_sha256(_identity_payload(identity))


def _prompt_identity_payload(identity: PromptIdentity) -> dict[str, str]:
    return {
        "digest": identity.digest,
        "prompt_id": identity.prompt_id,
        "version": identity.version,
    }


def _prompt_key(identity: PromptIdentity) -> str:
    return canonical_sha256(_prompt_identity_payload(identity))


def _model_payload(model: RegisteredModel) -> dict[str, Any]:
    capabilities = model.capabilities
    return {
        "capabilities": {
            "allowed_risk_levels": sorted(capabilities.allowed_risk_levels),
            "allowed_tools": sorted(capabilities.allowed_tools),
            "allowed_use_cases": sorted(capabilities.allowed_use_cases),
            "capabilities": sorted(capabilities.capabilities),
            "max_context_tokens": capabilities.max_context_tokens,
            "tier": int(capabilities.tier),
        },
        "enabled": model.enabled,
        "identity": _identity_payload(model.identity),
        "schema": _MODEL_SCHEMA,
    }


def _model_state_payload(
    identity: ModelIdentity,
    *,
    sequence: int,
    enabled: bool,
    prior_payload_hash: str,
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "identity": _identity_payload(identity),
        "prior_payload_hash": prior_payload_hash,
        "schema": _MODEL_STATE_SCHEMA,
        "sequence": sequence,
    }


def _prompt_payload(prompt: RegisteredPrompt) -> dict[str, Any]:
    return {
        "enabled": prompt.enabled,
        "identity": _prompt_identity_payload(prompt.identity),
        "provenance": prompt.provenance,
        "schema": _PROMPT_SCHEMA,
    }


def _prompt_state_payload(
    identity: PromptIdentity,
    *,
    sequence: int,
    enabled: bool,
    prior_payload_hash: str,
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "identity": _prompt_identity_payload(identity),
        "prior_payload_hash": prior_payload_hash,
        "schema": _PROMPT_STATE_SCHEMA,
        "sequence": sequence,
    }


def _price_payload(price: ModelPrice) -> dict[str, Any]:
    return {
        "cached_input_per_million": (
            _decimal_text(price.cached_input_per_million)
            if price.cached_input_per_million is not None
            else None
        ),
        "effective_from": _time_text(price.effective_from),
        "effective_to": _time_text(price.effective_to) if price.effective_to is not None else None,
        "identity": _identity_payload(price.identity),
        "input_per_million": _decimal_text(price.input_per_million),
        "output_per_million": _decimal_text(price.output_per_million),
        "provenance": price.provenance,
        "reasoning_per_million": (
            _decimal_text(price.reasoning_per_million)
            if price.reasoning_per_million is not None
            else None
        ),
        "schema": _PRICE_SCHEMA,
    }


def _price_supersession_payload(
    identity: ModelIdentity,
    *,
    superseded_effective_from: datetime,
    superseded_payload_hash: str,
    successor_effective_from: datetime,
    successor_payload_hash: str,
) -> dict[str, Any]:
    return {
        "identity": _identity_payload(identity),
        "schema": _PRICE_SUPERSESSION_SCHEMA,
        "successor_effective_from": _time_text(successor_effective_from),
        "successor_payload_hash": successor_payload_hash,
        "superseded_effective_from": _time_text(superseded_effective_from),
        "superseded_payload_hash": superseded_payload_hash,
    }


def _benchmark_payload(record: BenchmarkRecord) -> dict[str, Any]:
    return {
        "benchmark_id": record.benchmark_id,
        "identity": _identity_payload(record.identity),
        "latency_ms": _decimal_text(record.latency_ms),
        "measured_at": _time_text(record.measured_at),
        "provenance": record.provenance,
        "quality_score": _decimal_text(record.quality_score),
        "sample_size": record.sample_size,
        "schema": _BENCHMARK_SCHEMA,
        "task_type": record.task_type,
        "valid_until": _time_text(record.valid_until) if record.valid_until is not None else None,
    }


def _expect_object(
    value: object,
    *,
    fields: frozenset[str],
    record_name: str,
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise ControlPlaneIntegrityError(f"stored {record_name} has an invalid object shape")
    return value


def _identity_from_payload(value: object, *, record_name: str) -> ModelIdentity:
    payload = _expect_object(
        value,
        fields=frozenset({"provider", "provider_family", "model", "version", "deployment"}),
        record_name=f"{record_name} identity",
    )
    if any(not isinstance(payload[name], str) for name in payload):
        raise ControlPlaneIntegrityError(f"stored {record_name} identity fields must be strings")
    try:
        return ModelIdentity(
            provider=payload["provider"],
            provider_family=payload["provider_family"],
            model=payload["model"],
            version=payload["version"],
            deployment=payload["deployment"],
        )
    except RegistryError as exc:
        raise ControlPlaneIntegrityError(f"stored {record_name} identity is invalid") from exc


def _prompt_identity_from_payload(value: object, *, record_name: str) -> PromptIdentity:
    payload = _expect_object(
        value,
        fields=frozenset({"prompt_id", "version", "digest"}),
        record_name=f"{record_name} identity",
    )
    if any(not isinstance(payload[name], str) for name in payload):
        raise ControlPlaneIntegrityError(f"stored {record_name} identity fields must be strings")
    try:
        identity = PromptIdentity(
            prompt_id=payload["prompt_id"],
            version=payload["version"],
            digest=payload["digest"],
        )
    except LedgerError as exc:
        raise ControlPlaneIntegrityError(f"stored {record_name} identity is invalid") from exc
    if _prompt_identity_payload(identity) != payload:
        raise ControlPlaneIntegrityError(f"stored {record_name} identity is not canonical")
    return identity


def _string_set(value: object, *, field_name: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ControlPlaneIntegrityError(f"stored {field_name} must be a string array")
    if value != sorted(set(value)):
        raise ControlPlaneIntegrityError(f"stored {field_name} must be sorted and unique")
    return frozenset(value)


def _decimal_from_payload(value: object, *, field_name: str) -> Decimal:
    if not isinstance(value, str):
        raise ControlPlaneIntegrityError(f"stored {field_name} must be an exact decimal string")
    try:
        result = Decimal(value)
    except ArithmeticError as exc:
        raise ControlPlaneIntegrityError(f"stored {field_name} is not a decimal") from exc
    if not result.is_finite() or value != _decimal_text(result):
        raise ControlPlaneIntegrityError(f"stored {field_name} is not a canonical finite decimal")
    return result


def _model_from_payload(value: object) -> RegisteredModel:
    payload = _expect_object(
        value,
        fields=frozenset({"schema", "identity", "capabilities", "enabled"}),
        record_name="model",
    )
    if payload["schema"] != _MODEL_SCHEMA or not isinstance(payload["enabled"], bool):
        raise ControlPlaneIntegrityError("stored model schema or enabled flag is invalid")
    capabilities = _expect_object(
        payload["capabilities"],
        fields=frozenset(
            {
                "tier",
                "max_context_tokens",
                "capabilities",
                "allowed_tools",
                "allowed_risk_levels",
                "allowed_use_cases",
            }
        ),
        record_name="model capabilities",
    )
    tier = capabilities["tier"]
    context = capabilities["max_context_tokens"]
    if isinstance(tier, bool) or not isinstance(tier, int):
        raise ControlPlaneIntegrityError("stored model tier must be an integer")
    if isinstance(context, bool) or not isinstance(context, int):
        raise ControlPlaneIntegrityError("stored max_context_tokens must be an integer")
    try:
        model = RegisteredModel(
            identity=_identity_from_payload(payload["identity"], record_name="model"),
            capabilities=ModelCapabilities(
                tier=ModelTier(tier),
                max_context_tokens=context,
                capabilities=_string_set(
                    capabilities["capabilities"], field_name="model capabilities"
                ),
                allowed_tools=_string_set(
                    capabilities["allowed_tools"], field_name="model allowed_tools"
                ),
                allowed_risk_levels=_string_set(
                    capabilities["allowed_risk_levels"],
                    field_name="model allowed_risk_levels",
                ),
                allowed_use_cases=_string_set(
                    capabilities["allowed_use_cases"],
                    field_name="model allowed_use_cases",
                ),
            ),
            enabled=payload["enabled"],
        )
    except (RegistryError, ValueError) as exc:
        raise ControlPlaneIntegrityError("stored model facts are invalid") from exc
    if _model_payload(model) != payload:
        raise ControlPlaneIntegrityError("stored model facts are not canonical")
    return model


def _sha256_from_payload(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ControlPlaneIntegrityError(f"stored {field_name} must be a lowercase SHA-256 value")
    return value


def _model_state_from_payload(
    value: object,
) -> tuple[ModelIdentity, int, bool, str]:
    payload = _expect_object(
        value,
        fields=frozenset({"schema", "identity", "sequence", "enabled", "prior_payload_hash"}),
        record_name="model state transition",
    )
    sequence = payload["sequence"]
    enabled = payload["enabled"]
    if payload["schema"] != _MODEL_STATE_SCHEMA:
        raise ControlPlaneIntegrityError("stored model state transition schema is invalid")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise ControlPlaneIntegrityError("stored model state sequence must be a positive integer")
    if not isinstance(enabled, bool):
        raise ControlPlaneIntegrityError("stored model state enabled flag must be boolean")
    identity = _identity_from_payload(payload["identity"], record_name="model state transition")
    prior_hash = _sha256_from_payload(
        payload["prior_payload_hash"], field_name="model state prior_payload_hash"
    )
    if (
        _model_state_payload(
            identity,
            sequence=sequence,
            enabled=enabled,
            prior_payload_hash=prior_hash,
        )
        != payload
    ):
        raise ControlPlaneIntegrityError("stored model state transition is not canonical")
    return identity, sequence, enabled, prior_hash


def _prompt_from_payload(value: object) -> RegisteredPrompt:
    payload = _expect_object(
        value,
        fields=frozenset({"schema", "identity", "provenance", "enabled"}),
        record_name="prompt",
    )
    if (
        payload["schema"] != _PROMPT_SCHEMA
        or not isinstance(payload["provenance"], str)
        or not isinstance(payload["enabled"], bool)
    ):
        raise ControlPlaneIntegrityError("stored prompt schema or facts are invalid")
    try:
        prompt = RegisteredPrompt(
            identity=_prompt_identity_from_payload(payload["identity"], record_name="prompt"),
            provenance=payload["provenance"],
            enabled=payload["enabled"],
        )
    except ControlPlaneError as exc:
        raise ControlPlaneIntegrityError("stored prompt facts are invalid") from exc
    if _prompt_payload(prompt) != payload:
        raise ControlPlaneIntegrityError("stored prompt facts are not canonical")
    return prompt


def _prompt_state_from_payload(
    value: object,
) -> tuple[PromptIdentity, int, bool, str]:
    payload = _expect_object(
        value,
        fields=frozenset({"schema", "identity", "sequence", "enabled", "prior_payload_hash"}),
        record_name="prompt state transition",
    )
    sequence = payload["sequence"]
    enabled = payload["enabled"]
    if payload["schema"] != _PROMPT_STATE_SCHEMA:
        raise ControlPlaneIntegrityError("stored prompt state transition schema is invalid")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise ControlPlaneIntegrityError("stored prompt state sequence must be a positive integer")
    if not isinstance(enabled, bool):
        raise ControlPlaneIntegrityError("stored prompt state enabled flag must be boolean")
    identity = _prompt_identity_from_payload(
        payload["identity"], record_name="prompt state transition"
    )
    prior_hash = _sha256_from_payload(
        payload["prior_payload_hash"], field_name="prompt state prior_payload_hash"
    )
    if (
        _prompt_state_payload(
            identity,
            sequence=sequence,
            enabled=enabled,
            prior_payload_hash=prior_hash,
        )
        != payload
    ):
        raise ControlPlaneIntegrityError("stored prompt state transition is not canonical")
    return identity, sequence, enabled, prior_hash


def _price_from_payload(value: object) -> ModelPrice:
    payload = _expect_object(
        value,
        fields=frozenset(
            {
                "schema",
                "identity",
                "effective_from",
                "effective_to",
                "input_per_million",
                "output_per_million",
                "cached_input_per_million",
                "reasoning_per_million",
                "provenance",
            }
        ),
        record_name="price",
    )
    if payload["schema"] != _PRICE_SCHEMA or not isinstance(payload["provenance"], str):
        raise ControlPlaneIntegrityError("stored price schema or provenance is invalid")
    end_value = payload["effective_to"]
    cached_value = payload["cached_input_per_million"]
    reasoning_value = payload["reasoning_per_million"]
    if end_value is not None and not isinstance(end_value, str):
        raise ControlPlaneIntegrityError("stored effective_to must be null or a timestamp")
    if cached_value is not None and not isinstance(cached_value, str):
        raise ControlPlaneIntegrityError("stored cached input price must be null or a decimal")
    if reasoning_value is not None and not isinstance(reasoning_value, str):
        raise ControlPlaneIntegrityError("stored reasoning price must be null or a decimal")
    try:
        price = ModelPrice(
            identity=_identity_from_payload(payload["identity"], record_name="price"),
            effective_from=_parse_time(payload["effective_from"], field_name="effective_from"),
            effective_to=(
                _parse_time(end_value, field_name="effective_to") if end_value is not None else None
            ),
            input_per_million=_decimal_from_payload(
                payload["input_per_million"], field_name="input_per_million"
            ),
            output_per_million=_decimal_from_payload(
                payload["output_per_million"], field_name="output_per_million"
            ),
            cached_input_per_million=(
                _decimal_from_payload(cached_value, field_name="cached_input_per_million")
                if cached_value is not None
                else None
            ),
            reasoning_per_million=(
                _decimal_from_payload(reasoning_value, field_name="reasoning_per_million")
                if reasoning_value is not None
                else None
            ),
            provenance=payload["provenance"],
        )
    except RegistryError as exc:
        raise ControlPlaneIntegrityError("stored price facts are invalid") from exc
    if _price_payload(price) != payload:
        raise ControlPlaneIntegrityError("stored price facts are not canonical")
    return price


def _price_supersession_from_payload(
    value: object,
) -> tuple[ModelIdentity, datetime, str, datetime, str]:
    payload = _expect_object(
        value,
        fields=frozenset(
            {
                "schema",
                "identity",
                "superseded_effective_from",
                "superseded_payload_hash",
                "successor_effective_from",
                "successor_payload_hash",
            }
        ),
        record_name="price supersession",
    )
    if payload["schema"] != _PRICE_SUPERSESSION_SCHEMA:
        raise ControlPlaneIntegrityError("stored price supersession schema is invalid")
    identity = _identity_from_payload(payload["identity"], record_name="price supersession")
    superseded_at = _parse_time(
        payload["superseded_effective_from"], field_name="superseded_effective_from"
    )
    successor_at = _parse_time(
        payload["successor_effective_from"], field_name="successor_effective_from"
    )
    superseded_hash = _sha256_from_payload(
        payload["superseded_payload_hash"], field_name="superseded_payload_hash"
    )
    successor_hash = _sha256_from_payload(
        payload["successor_payload_hash"], field_name="successor_payload_hash"
    )
    if (
        _price_supersession_payload(
            identity,
            superseded_effective_from=superseded_at,
            superseded_payload_hash=superseded_hash,
            successor_effective_from=successor_at,
            successor_payload_hash=successor_hash,
        )
        != payload
    ):
        raise ControlPlaneIntegrityError("stored price supersession is not canonical")
    return identity, superseded_at, superseded_hash, successor_at, successor_hash


def _benchmark_from_payload(value: object) -> BenchmarkRecord:
    payload = _expect_object(
        value,
        fields=frozenset(
            {
                "schema",
                "benchmark_id",
                "identity",
                "task_type",
                "quality_score",
                "latency_ms",
                "measured_at",
                "valid_until",
                "provenance",
                "sample_size",
            }
        ),
        record_name="benchmark",
    )
    string_fields = ("benchmark_id", "task_type", "provenance")
    if payload["schema"] != _BENCHMARK_SCHEMA or any(
        not isinstance(payload[field], str) for field in string_fields
    ):
        raise ControlPlaneIntegrityError("stored benchmark schema or string facts are invalid")
    sample_size = payload["sample_size"]
    if isinstance(sample_size, bool) or not isinstance(sample_size, int):
        raise ControlPlaneIntegrityError("stored benchmark sample_size must be an integer")
    valid_until = payload["valid_until"]
    if valid_until is not None and not isinstance(valid_until, str):
        raise ControlPlaneIntegrityError("stored benchmark valid_until must be null or a timestamp")
    try:
        record = BenchmarkRecord(
            benchmark_id=payload["benchmark_id"],
            identity=_identity_from_payload(payload["identity"], record_name="benchmark"),
            task_type=payload["task_type"],
            quality_score=_decimal_from_payload(
                payload["quality_score"], field_name="quality_score"
            ),
            latency_ms=_decimal_from_payload(payload["latency_ms"], field_name="latency_ms"),
            measured_at=_parse_time(payload["measured_at"], field_name="measured_at"),
            valid_until=(
                _parse_time(valid_until, field_name="valid_until")
                if valid_until is not None
                else None
            ),
            provenance=payload["provenance"],
            sample_size=sample_size,
        )
    except RoutingError as exc:
        raise ControlPlaneIntegrityError("stored benchmark facts are invalid") from exc
    if _benchmark_payload(record) != payload:
        raise ControlPlaneIntegrityError("stored benchmark facts are not canonical")
    return record


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE schema_versions (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE registered_models (
        model_key TEXT PRIMARY KEY,
        payload_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE model_prices (
        model_key TEXT NOT NULL,
        effective_from TEXT NOT NULL,
        effective_to TEXT,
        payload_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (model_key, effective_from),
        FOREIGN KEY (model_key) REFERENCES registered_models(model_key)
    )
    """,
    """
    CREATE TABLE benchmark_records (
        benchmark_id TEXT PRIMARY KEY,
        model_key TEXT NOT NULL,
        measured_at TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (model_key) REFERENCES registered_models(model_key)
    )
    """,
    "CREATE INDEX idx_model_prices_identity ON model_prices(model_key, effective_from)",
    "CREATE INDEX idx_benchmarks_identity ON benchmark_records(model_key, measured_at)",
    """
    CREATE TRIGGER schema_versions_no_update
    BEFORE UPDATE ON schema_versions BEGIN
        SELECT RAISE(ABORT, 'schema_versions is append-only');
    END
    """,
    """
    CREATE TRIGGER schema_versions_no_delete
    BEFORE DELETE ON schema_versions BEGIN
        SELECT RAISE(ABORT, 'schema_versions is append-only');
    END
    """,
    """
    CREATE TRIGGER registered_models_no_update
    BEFORE UPDATE ON registered_models BEGIN
        SELECT RAISE(ABORT, 'registered_models is append-only');
    END
    """,
    """
    CREATE TRIGGER registered_models_no_delete
    BEFORE DELETE ON registered_models BEGIN
        SELECT RAISE(ABORT, 'registered_models is append-only');
    END
    """,
    """
    CREATE TRIGGER model_prices_no_update
    BEFORE UPDATE ON model_prices BEGIN
        SELECT RAISE(ABORT, 'model_prices is append-only');
    END
    """,
    """
    CREATE TRIGGER model_prices_no_delete
    BEFORE DELETE ON model_prices BEGIN
        SELECT RAISE(ABORT, 'model_prices is append-only');
    END
    """,
    """
    CREATE TRIGGER benchmark_records_no_update
    BEFORE UPDATE ON benchmark_records BEGIN
        SELECT RAISE(ABORT, 'benchmark_records is append-only');
    END
    """,
    """
    CREATE TRIGGER benchmark_records_no_delete
    BEFORE DELETE ON benchmark_records BEGIN
        SELECT RAISE(ABORT, 'benchmark_records is append-only');
    END
    """,
)

_SCHEMA_V2_STATEMENTS = (
    """
    CREATE TABLE model_state_transitions (
        model_key TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
        prior_payload_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (model_key, sequence),
        FOREIGN KEY (model_key) REFERENCES registered_models(model_key)
    )
    """,
    """
    CREATE TABLE price_supersessions (
        model_key TEXT NOT NULL,
        superseded_effective_from TEXT NOT NULL,
        successor_effective_from TEXT NOT NULL,
        superseded_payload_hash TEXT NOT NULL,
        successor_payload_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (model_key, superseded_effective_from),
        UNIQUE (model_key, successor_effective_from),
        FOREIGN KEY (model_key, superseded_effective_from)
            REFERENCES model_prices(model_key, effective_from),
        FOREIGN KEY (model_key, successor_effective_from)
            REFERENCES model_prices(model_key, effective_from)
    )
    """,
    """
    CREATE TRIGGER model_state_transitions_no_update
    BEFORE UPDATE ON model_state_transitions BEGIN
        SELECT RAISE(ABORT, 'model_state_transitions is append-only');
    END
    """,
    """
    CREATE TRIGGER model_state_transitions_no_delete
    BEFORE DELETE ON model_state_transitions BEGIN
        SELECT RAISE(ABORT, 'model_state_transitions is append-only');
    END
    """,
    """
    CREATE TRIGGER price_supersessions_no_update
    BEFORE UPDATE ON price_supersessions BEGIN
        SELECT RAISE(ABORT, 'price_supersessions is append-only');
    END
    """,
    """
    CREATE TRIGGER price_supersessions_no_delete
    BEFORE DELETE ON price_supersessions BEGIN
        SELECT RAISE(ABORT, 'price_supersessions is append-only');
    END
    """,
)

_SCHEMA_V3_STATEMENTS = (
    """
    CREATE TABLE registered_prompts (
        prompt_key TEXT PRIMARY KEY,
        payload_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE prompt_state_transitions (
        prompt_key TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
        prior_payload_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (prompt_key, sequence),
        FOREIGN KEY (prompt_key) REFERENCES registered_prompts(prompt_key)
    )
    """,
    """
    CREATE TRIGGER registered_prompts_no_update
    BEFORE UPDATE ON registered_prompts BEGIN
        SELECT RAISE(ABORT, 'registered_prompts is append-only');
    END
    """,
    """
    CREATE TRIGGER registered_prompts_no_delete
    BEFORE DELETE ON registered_prompts BEGIN
        SELECT RAISE(ABORT, 'registered_prompts is append-only');
    END
    """,
    """
    CREATE TRIGGER prompt_state_transitions_no_update
    BEFORE UPDATE ON prompt_state_transitions BEGIN
        SELECT RAISE(ABORT, 'prompt_state_transitions is append-only');
    END
    """,
    """
    CREATE TRIGGER prompt_state_transitions_no_delete
    BEFORE DELETE ON prompt_state_transitions BEGIN
        SELECT RAISE(ABORT, 'prompt_state_transitions is append-only');
    END
    """,
)

_ALL_SCHEMA_STATEMENTS = (
    *_SCHEMA_STATEMENTS,
    *_SCHEMA_V2_STATEMENTS,
    *_SCHEMA_V3_STATEMENTS,
)


class ControlPlaneCatalog:
    """Safe-root-bounded SQLite catalog for immutable model control-plane facts."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        allowed_root: str | os.PathLike[str],
        timeout_seconds: float = 30.0,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ControlPlaneError("timeout_seconds must be finite and positive")
        self._state_lock = threading.RLock()
        self._closed = False
        self._root, self._path = self._safe_database_path(
            database_path,
            allowed_root=allowed_root,
        )
        root_stat = self._root.stat(follow_symlinks=False)
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._parent_identities = self._capture_parent_identities(self._root, self._path)
        database_identity = self._assert_database_file_types(
            self._path,
            require_database=True,
        )
        assert database_identity is not None
        self._database_identity = database_identity
        self._timeout_seconds = float(timeout_seconds)
        self._initialize()
        self._assert_current_path_safety()

    @staticmethod
    def _relative_to_canonical_root(candidate: Path, root: Path) -> Path:
        for ancestor in (candidate, *candidate.parents):
            try:
                if ancestor.resolve(strict=False) == root:
                    return candidate.relative_to(ancestor)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ControlPlanePathError("database_path cannot be safely resolved") from exc
        raise ControlPlanePathError("database_path escapes allowed_root")

    @staticmethod
    def _assert_path_component_types(root: Path, relative: Path) -> None:
        cursor = root
        for index, part in enumerate(relative.parts):
            cursor /= part
            try:
                mode = cursor.lstat().st_mode
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ControlPlanePathError("database_path cannot be safely inspected") from exc
            if stat.S_ISLNK(mode):
                raise ControlPlanePathError("database_path must not traverse a symbolic link")
            is_database = index == len(relative.parts) - 1
            if is_database and not stat.S_ISREG(mode):
                raise ControlPlanePathError("database_path must identify a regular file")
            if not is_database and not stat.S_ISDIR(mode):
                raise ControlPlanePathError("database_path parent must be a directory")

    @staticmethod
    def _database_paths(database: Path) -> tuple[Path, ...]:
        return (database, *(Path(f"{database}{suffix}") for suffix in _SQLITE_COMPANION_SUFFIXES))

    @staticmethod
    def _assert_database_file_types(
        database: Path, *, require_database: bool
    ) -> tuple[int, int] | None:
        database_identity: tuple[int, int] | None = None
        for path in ControlPlaneCatalog._database_paths(database):
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                if path == database and require_database:
                    raise ControlPlanePathError(
                        "database file changed after catalog construction"
                    ) from None
                continue
            except OSError as exc:
                raise ControlPlanePathError("database files cannot be safely inspected") from exc
            if not stat.S_ISREG(path_stat.st_mode):
                raise ControlPlanePathError("database files must be regular files, not links")
            if path == database:
                database_identity = (path_stat.st_dev, path_stat.st_ino)
        return database_identity

    @staticmethod
    def _create_database_file(database: Path) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(database, flags, 0o600)
        except FileExistsError:
            return
        except OSError as exc:
            raise ControlPlanePathError("database file cannot be safely created") from exc
        os.close(descriptor)

    @staticmethod
    def _capture_parent_identities(
        root: Path,
        database: Path,
    ) -> tuple[tuple[Path, tuple[int, int]], ...]:
        try:
            relative_parent = database.parent.relative_to(root)
        except ValueError as exc:  # pragma: no cover - safe path construction establishes this
            raise ControlPlanePathError("database_path escapes allowed_root") from exc
        identities: list[tuple[Path, tuple[int, int]]] = []
        cursor = root
        for part in relative_parent.parts:
            cursor /= part
            try:
                directory_stat = cursor.lstat()
            except OSError as exc:
                raise ControlPlanePathError("database parent cannot be safely inspected") from exc
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise ControlPlanePathError("database_path parent must be a directory")
            identities.append((cursor, (directory_stat.st_dev, directory_stat.st_ino)))
        return tuple(identities)

    @staticmethod
    def _safe_database_path(
        database_path: str | os.PathLike[str],
        *,
        allowed_root: str | os.PathLike[str],
    ) -> tuple[Path, Path]:
        raw_root = os.fspath(allowed_root)
        if not raw_root or "\x00" in raw_root:
            raise ControlPlanePathError("allowed_root must be a filesystem directory")
        root_candidate = Path(os.path.abspath(Path(raw_root).expanduser()))
        if root_candidate.is_symlink():
            raise ControlPlanePathError("allowed_root must not be a symbolic link")
        try:
            root = root_candidate.resolve(strict=True)
        except OSError as exc:
            raise ControlPlanePathError("allowed_root must already exist") from exc
        if not root.is_dir():
            raise ControlPlanePathError("allowed_root must be a directory")

        raw_path = os.fspath(database_path)
        if (
            not raw_path
            or "\x00" in raw_path
            or raw_path == ":memory:"
            or raw_path.startswith("file:")
        ):
            raise ControlPlanePathError("database_path must be a filesystem path, not a SQLite URI")
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = Path(os.path.abspath(candidate))
        relative = ControlPlaneCatalog._relative_to_canonical_root(candidate, root)
        if not relative.parts:
            raise ControlPlanePathError("database_path must identify a regular file")
        database = root.joinpath(*relative.parts)
        ControlPlaneCatalog._assert_path_component_types(root, relative)
        try:
            database.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ControlPlanePathError("database parent cannot be safely created") from exc
        ControlPlaneCatalog._assert_path_component_types(root, relative)
        ControlPlaneCatalog._assert_database_file_types(database, require_database=False)
        ControlPlaneCatalog._create_database_file(database)
        ControlPlaneCatalog._assert_database_file_types(database, require_database=True)
        return root, database

    def _ensure_open(self) -> None:
        with self._state_lock:
            if self._closed:
                raise ControlPlaneClosedError("control-plane catalog is closed")

    def _assert_current_path_safety(self) -> tuple[int, int]:
        if self._root.is_symlink() or not self._root.is_dir():
            raise ControlPlanePathError("allowed_root changed after catalog construction")
        try:
            root_stat = self._root.stat(follow_symlinks=False)
        except OSError as exc:
            raise ControlPlanePathError("allowed_root changed after catalog construction") from exc
        if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
            raise ControlPlanePathError("allowed_root changed after catalog construction")
        try:
            relative = self._path.relative_to(self._root)
        except ValueError as exc:  # pragma: no cover - constructor establishes this invariant
            raise ControlPlanePathError("database_path escapes allowed_root") from exc
        self._assert_path_component_types(self._root, relative)
        for directory, expected_identity in self._parent_identities:
            try:
                directory_stat = directory.lstat()
            except OSError as exc:
                raise ControlPlanePathError(
                    "database parent changed after catalog construction"
                ) from exc
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or (directory_stat.st_dev, directory_stat.st_ino) != expected_identity
            ):
                raise ControlPlanePathError("database parent changed after catalog construction")
        identity = self._assert_database_file_types(self._path, require_database=True)
        assert identity is not None
        if identity != self._database_identity:
            raise ControlPlanePathError("database file changed after catalog construction")
        return identity

    def _connect(self) -> sqlite3.Connection:
        self._ensure_open()
        identity_before = self._assert_current_path_safety()
        connection = sqlite3.connect(
            str(self._path),
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        try:
            identity_after = self._assert_current_path_safety()
            if identity_after != identity_before:
                raise ControlPlanePathError("database file changed while opening the catalog")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
        except BaseException:
            connection.close()
            raise
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            version_row = connection.execute("PRAGMA user_version").fetchone()
            assert version_row is not None
            version = int(version_row[0])
            if version == 0:
                existing = connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                if existing:
                    raise ControlPlaneSchemaError(
                        "unversioned database already contains application tables"
                    )
                for statement in _ALL_SCHEMA_STATEMENTS:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_versions (version, applied_at) VALUES (?, ?)",
                    (_SCHEMA_VERSION, _time_text(datetime.now(UTC))),
                )
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            elif version in {1, 2}:
                if version == 1:
                    for statement in _SCHEMA_V2_STATEMENTS:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO schema_versions (version, applied_at) VALUES (?, ?)",
                        (2, _time_text(datetime.now(UTC))),
                    )
                for statement in _SCHEMA_V3_STATEMENTS:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_versions (version, applied_at) VALUES (?, ?)",
                    (3, _time_text(datetime.now(UTC))),
                )
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            elif version != _SCHEMA_VERSION:
                raise ControlPlaneSchemaError(
                    f"unsupported control-plane schema version {version}; expected {_SCHEMA_VERSION}"
                )
            self._verify_schema(connection)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        with suppress(OSError):
            self._path.chmod(0o600)

    @staticmethod
    def _verify_schema(connection: sqlite3.Connection) -> None:
        required = {
            "schema_versions",
            "registered_models",
            "model_prices",
            "benchmark_records",
            "model_state_transitions",
            "price_supersessions",
            "registered_prompts",
            "prompt_state_transitions",
        }
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if not required <= {str(row["name"]) for row in rows}:
            raise ControlPlaneSchemaError("control-plane database schema is incomplete")
        version = connection.execute(
            "SELECT MAX(version) AS version FROM schema_versions"
        ).fetchone()
        if version is None or version["version"] != _SCHEMA_VERSION:
            raise ControlPlaneSchemaError("control-plane schema history is inconsistent")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            version_row = connection.execute("PRAGMA user_version").fetchone()
            if version_row is None or int(version_row[0]) != _SCHEMA_VERSION:
                raise ControlPlaneSchemaError("control-plane schema version changed after opening")
            self._verify_schema(connection)
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _decode_row(row: sqlite3.Row, *, record_name: str) -> Mapping[str, Any]:
        encoded = row["payload_json"]
        stored_hash = row["payload_hash"]
        if not isinstance(encoded, str) or not isinstance(stored_hash, str):
            raise ControlPlaneIntegrityError(f"stored {record_name} payload columns are invalid")
        try:
            payload = load_json_strict(encoded)
        except (TypeError, ValueError) as exc:
            raise ControlPlaneIntegrityError(f"stored {record_name} JSON is invalid") from exc
        if not isinstance(payload, dict):
            raise ControlPlaneIntegrityError(f"stored {record_name} payload must be an object")
        if canonical_json_bytes(payload).decode("utf-8") != encoded:
            raise ControlPlaneIntegrityError(f"stored {record_name} JSON is not canonical")
        if canonical_sha256(payload) != stored_hash:
            raise ControlPlaneIntegrityError(f"stored {record_name} payload hash is invalid")
        return payload

    @classmethod
    def _model_from_row(cls, row: sqlite3.Row) -> RegisteredModel:
        model = _model_from_payload(cls._decode_row(row, record_name="model"))
        if row["model_key"] != _model_key(model.identity):
            raise ControlPlaneIntegrityError("stored model index disagrees with its identity")
        return model

    @classmethod
    def _price_from_row(cls, row: sqlite3.Row) -> ModelPrice:
        price = _price_from_payload(cls._decode_row(row, record_name="price"))
        if row["model_key"] != _model_key(price.identity):
            raise ControlPlaneIntegrityError("stored price index disagrees with its identity")
        if row["effective_from"] != _time_text(price.effective_from):
            raise ControlPlaneIntegrityError("stored price index disagrees with its effective date")
        if row["effective_to"] != (
            _time_text(price.effective_to) if price.effective_to is not None else None
        ):
            raise ControlPlaneIntegrityError("stored price end index disagrees with its payload")
        return price

    @classmethod
    def _benchmark_from_row(cls, row: sqlite3.Row) -> BenchmarkRecord:
        record = _benchmark_from_payload(cls._decode_row(row, record_name="benchmark"))
        if row["benchmark_id"] != record.benchmark_id:
            raise ControlPlaneIntegrityError("stored benchmark id disagrees with its payload")
        if row["model_key"] != _model_key(record.identity):
            raise ControlPlaneIntegrityError("stored benchmark index disagrees with its identity")
        if row["measured_at"] != _time_text(record.measured_at):
            raise ControlPlaneIntegrityError("stored benchmark time disagrees with its payload")
        return record

    @classmethod
    def _model_state_from_row(
        cls,
        row: sqlite3.Row,
    ) -> tuple[ModelIdentity, int, bool, str, str]:
        identity, sequence, enabled, prior_hash = _model_state_from_payload(
            cls._decode_row(row, record_name="model state transition")
        )
        if row["model_key"] != _model_key(identity):
            raise ControlPlaneIntegrityError("stored model state index disagrees with its identity")
        if row["sequence"] != sequence or row["enabled"] != int(enabled):
            raise ControlPlaneIntegrityError("stored model state index disagrees with its payload")
        if row["prior_payload_hash"] != prior_hash:
            raise ControlPlaneIntegrityError("stored model state chain index is invalid")
        return identity, sequence, enabled, prior_hash, str(row["payload_hash"])

    @classmethod
    def _prompt_from_row(cls, row: sqlite3.Row) -> RegisteredPrompt:
        prompt = _prompt_from_payload(cls._decode_row(row, record_name="prompt"))
        if row["prompt_key"] != _prompt_key(prompt.identity):
            raise ControlPlaneIntegrityError("stored prompt index disagrees with its identity")
        return prompt

    @classmethod
    def _prompt_state_from_row(
        cls,
        row: sqlite3.Row,
    ) -> tuple[PromptIdentity, int, bool, str, str]:
        identity, sequence, enabled, prior_hash = _prompt_state_from_payload(
            cls._decode_row(row, record_name="prompt state transition")
        )
        if row["prompt_key"] != _prompt_key(identity):
            raise ControlPlaneIntegrityError(
                "stored prompt state index disagrees with its identity"
            )
        if row["sequence"] != sequence or row["enabled"] != int(enabled):
            raise ControlPlaneIntegrityError("stored prompt state index disagrees with its payload")
        if row["prior_payload_hash"] != prior_hash:
            raise ControlPlaneIntegrityError("stored prompt state chain index is invalid")
        return identity, sequence, enabled, prior_hash, str(row["payload_hash"])

    @classmethod
    def _price_supersession_from_row(
        cls,
        row: sqlite3.Row,
    ) -> tuple[ModelIdentity, datetime, str, datetime, str]:
        identity, superseded_at, superseded_hash, successor_at, successor_hash = (
            _price_supersession_from_payload(cls._decode_row(row, record_name="price supersession"))
        )
        if row["model_key"] != _model_key(identity):
            raise ControlPlaneIntegrityError(
                "stored price supersession index disagrees with its identity"
            )
        if (
            row["superseded_effective_from"] != _time_text(superseded_at)
            or row["successor_effective_from"] != _time_text(successor_at)
            or row["superseded_payload_hash"] != superseded_hash
            or row["successor_payload_hash"] != successor_hash
        ):
            raise ControlPlaneIntegrityError(
                "stored price supersession index disagrees with its payload"
            )
        return identity, superseded_at, superseded_hash, successor_at, successor_hash

    @classmethod
    def _effective_models(
        cls,
        model_rows: list[sqlite3.Row],
        transition_rows: list[sqlite3.Row],
    ) -> list[RegisteredModel]:
        models: dict[str, tuple[RegisteredModel, str]] = {}
        for row in model_rows:
            model = cls._model_from_row(row)
            models[str(row["model_key"])] = (model, str(row["payload_hash"]))

        grouped: dict[str, list[sqlite3.Row]] = {}
        for row in transition_rows:
            grouped.setdefault(str(row["model_key"]), []).append(row)
        effective: list[RegisteredModel] = []
        for key, (model, model_hash) in models.items():
            expected_sequence = 1
            prior_hash = model_hash
            enabled = model.enabled
            for row in grouped.pop(key, []):
                identity, sequence, next_enabled, stored_prior, transition_hash = (
                    cls._model_state_from_row(row)
                )
                if identity != model.identity:
                    raise ControlPlaneIntegrityError("model state identity key collision detected")
                if sequence != expected_sequence or stored_prior != prior_hash:
                    raise ControlPlaneIntegrityError(
                        "stored model state transition chain is invalid"
                    )
                if next_enabled == enabled:
                    raise ControlPlaneIntegrityError("stored model state transition is redundant")
                enabled = next_enabled
                prior_hash = transition_hash
                expected_sequence += 1
            effective.append(replace(model, enabled=enabled))
        if grouped:
            raise ControlPlaneIntegrityError("stored model state references an unknown model")
        return effective

    @classmethod
    def _effective_prompts(
        cls,
        prompt_rows: list[sqlite3.Row],
        transition_rows: list[sqlite3.Row],
    ) -> list[RegisteredPrompt]:
        prompts: dict[str, tuple[RegisteredPrompt, str]] = {}
        for row in prompt_rows:
            prompt = cls._prompt_from_row(row)
            prompts[str(row["prompt_key"])] = (prompt, str(row["payload_hash"]))

        grouped: dict[str, list[sqlite3.Row]] = {}
        for row in transition_rows:
            grouped.setdefault(str(row["prompt_key"]), []).append(row)
        effective: list[RegisteredPrompt] = []
        for key, (prompt, prompt_hash) in prompts.items():
            expected_sequence = 1
            prior_hash = prompt_hash
            enabled = prompt.enabled
            for row in grouped.pop(key, []):
                identity, sequence, next_enabled, stored_prior, transition_hash = (
                    cls._prompt_state_from_row(row)
                )
                if identity != prompt.identity:
                    raise ControlPlaneIntegrityError("prompt state identity key collision detected")
                if sequence != expected_sequence or stored_prior != prior_hash:
                    raise ControlPlaneIntegrityError(
                        "stored prompt state transition chain is invalid"
                    )
                if next_enabled == enabled:
                    raise ControlPlaneIntegrityError("stored prompt state transition is redundant")
                enabled = next_enabled
                prior_hash = transition_hash
                expected_sequence += 1
            effective.append(replace(prompt, enabled=enabled))
        if grouped:
            raise ControlPlaneIntegrityError("stored prompt state references an unknown prompt")
        return effective

    @classmethod
    def _effective_prices(
        cls,
        price_rows: list[sqlite3.Row],
        supersession_rows: list[sqlite3.Row],
    ) -> list[ModelPrice]:
        raw: dict[tuple[str, str], tuple[ModelPrice, str]] = {}
        for row in price_rows:
            price = cls._price_from_row(row)
            key = (str(row["model_key"]), str(row["effective_from"]))
            raw[key] = (price, str(row["payload_hash"]))

        cutovers: dict[tuple[str, str], datetime] = {}
        for row in supersession_rows:
            identity, superseded_at, superseded_hash, successor_at, successor_hash = (
                cls._price_supersession_from_row(row)
            )
            model_key = _model_key(identity)
            superseded_key = (model_key, _time_text(superseded_at))
            successor_key = (model_key, _time_text(successor_at))
            superseded = raw.get(superseded_key)
            successor = raw.get(successor_key)
            if superseded is None or successor is None:
                raise ControlPlaneIntegrityError("price supersession references an unknown price")
            if (
                superseded[0].identity != identity
                or successor[0].identity != identity
                or superseded[1] != superseded_hash
                or successor[1] != successor_hash
                or superseded[0].effective_to is not None
                or successor_at <= superseded_at
            ):
                raise ControlPlaneIntegrityError("stored price supersession facts are inconsistent")
            if superseded_key in cutovers:
                raise ControlPlaneIntegrityError("stored price has multiple supersessions")
            cutovers[superseded_key] = successor_at

        effective = [
            replace(price, effective_to=cutovers[key]) if key in cutovers else price
            for key, (price, _payload_hash) in raw.items()
        ]
        try:
            PriceCatalog(effective)
        except PriceOverlapError as exc:
            raise ControlPlaneIntegrityError("stored effective price periods overlap") from exc
        return effective

    @classmethod
    def _require_model(
        cls,
        connection: sqlite3.Connection,
        identity: ModelIdentity,
    ) -> RegisteredModel:
        key = _model_key(identity)
        row = connection.execute(
            "SELECT model_key, payload_hash, payload_json FROM registered_models WHERE model_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            raise UnknownRegisteredModelError(
                f"model {identity.canonical_id!r} must be registered before dependent facts"
            )
        model = cls._model_from_row(row)
        if model.identity != identity:
            raise ControlPlaneIntegrityError("model identity key collision detected")
        return model

    def register_model(self, model: RegisteredModel) -> RegisteredModel:
        """Persist immutable model facts idempotently."""

        if not isinstance(model, RegisteredModel):
            raise RegistryError("model must be a RegisteredModel")
        if (
            not isinstance(model.identity, ModelIdentity)
            or not isinstance(model.capabilities, ModelCapabilities)
            or not isinstance(model.enabled, bool)
        ):
            raise RegistryError("model contains invalid identity, capability, or enabled facts")
        payload = _model_payload(model)
        encoded = canonical_json_bytes(payload).decode("utf-8")
        payload_hash = canonical_sha256(payload)
        key = _model_key(model.identity)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT model_key, payload_hash, payload_json FROM registered_models "
                "WHERE model_key = ?",
                (key,),
            ).fetchone()
            if row is not None:
                existing = self._model_from_row(row)
                if existing.identity != model.identity:
                    raise ControlPlaneIntegrityError("model identity key collision detected")
                if row["payload_hash"] != payload_hash:
                    raise DuplicateModelError(
                        f"model identity {model.identity.canonical_id!r} is already registered "
                        "with different facts"
                    )
                return existing
            connection.execute(
                "INSERT INTO registered_models "
                "(model_key, payload_hash, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (key, payload_hash, encoded, _time_text(datetime.now(UTC))),
            )
        return model

    def set_model_enabled(
        self,
        identity: ModelIdentity,
        *,
        enabled: bool,
    ) -> RegisteredModel:
        """Append an idempotent enabled/disabled transition and return the effective model."""

        if not isinstance(identity, ModelIdentity):
            raise RegistryError("identity must be a ModelIdentity")
        if not isinstance(enabled, bool):
            raise RegistryError("enabled must be boolean")
        key = _model_key(identity)
        with self._transaction() as connection:
            model_row = connection.execute(
                "SELECT model_key, payload_hash, payload_json FROM registered_models "
                "WHERE model_key = ?",
                (key,),
            ).fetchone()
            if model_row is None:
                raise UnknownRegisteredModelError(
                    f"model {identity.canonical_id!r} must be registered before state transitions"
                )
            transition_rows = connection.execute(
                "SELECT model_key, sequence, enabled, prior_payload_hash, payload_hash, "
                "payload_json FROM model_state_transitions WHERE model_key = ? ORDER BY sequence",
                (key,),
            ).fetchall()
            effective = self._effective_models([model_row], transition_rows)[0]
            if effective.identity != identity:
                raise ControlPlaneIntegrityError("model identity key collision detected")
            if effective.enabled == enabled:
                return effective

            sequence = len(transition_rows) + 1
            prior_hash = str(
                transition_rows[-1]["payload_hash"]
                if transition_rows
                else model_row["payload_hash"]
            )
            payload = _model_state_payload(
                identity,
                sequence=sequence,
                enabled=enabled,
                prior_payload_hash=prior_hash,
            )
            payload_hash = canonical_sha256(payload)
            connection.execute(
                "INSERT INTO model_state_transitions "
                "(model_key, sequence, enabled, prior_payload_hash, payload_hash, payload_json, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    key,
                    sequence,
                    int(enabled),
                    prior_hash,
                    payload_hash,
                    canonical_json_bytes(payload).decode("utf-8"),
                    _time_text(datetime.now(UTC)),
                ),
            )
        return replace(effective, enabled=enabled)

    def disable_model(self, identity: ModelIdentity) -> RegisteredModel:
        """Append a disabled transition when needed."""

        return self.set_model_enabled(identity, enabled=False)

    def enable_model(self, identity: ModelIdentity) -> RegisteredModel:
        """Append an enabled transition when needed."""

        return self.set_model_enabled(identity, enabled=True)

    def register_prompt(self, prompt: RegisteredPrompt) -> RegisteredPrompt:
        """Persist immutable approved prompt facts idempotently."""

        if not isinstance(prompt, RegisteredPrompt):
            raise ControlPlaneError("prompt must be a RegisteredPrompt")
        payload = _prompt_payload(prompt)
        payload_hash = canonical_sha256(payload)
        key = _prompt_key(prompt.identity)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT prompt_key, payload_hash, payload_json FROM registered_prompts "
                "WHERE prompt_key = ?",
                (key,),
            ).fetchone()
            if row is not None:
                existing = self._prompt_from_row(row)
                if existing.identity != prompt.identity:
                    raise ControlPlaneIntegrityError("prompt identity key collision detected")
                if row["payload_hash"] != payload_hash:
                    raise DuplicatePromptError(
                        "prompt identity is already registered with different facts"
                    )
                return existing
            connection.execute(
                "INSERT INTO registered_prompts "
                "(prompt_key, payload_hash, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (
                    key,
                    payload_hash,
                    canonical_json_bytes(payload).decode("utf-8"),
                    _time_text(datetime.now(UTC)),
                ),
            )
        return prompt

    def set_prompt_enabled(
        self,
        identity: PromptIdentity,
        *,
        enabled: bool,
    ) -> RegisteredPrompt:
        """Append an idempotent enabled/disabled prompt transition."""

        if not isinstance(identity, PromptIdentity):
            raise ControlPlaneError("identity must be a PromptIdentity")
        if not isinstance(enabled, bool):
            raise ControlPlaneError("enabled must be boolean")
        key = _prompt_key(identity)
        with self._transaction() as connection:
            prompt_row = connection.execute(
                "SELECT prompt_key, payload_hash, payload_json FROM registered_prompts "
                "WHERE prompt_key = ?",
                (key,),
            ).fetchone()
            if prompt_row is None:
                raise ControlPlaneError("prompt must be registered before state transitions")
            transition_rows = connection.execute(
                "SELECT prompt_key, sequence, enabled, prior_payload_hash, payload_hash, "
                "payload_json FROM prompt_state_transitions WHERE prompt_key = ? "
                "ORDER BY sequence",
                (key,),
            ).fetchall()
            effective = self._effective_prompts([prompt_row], transition_rows)[0]
            if effective.identity != identity:
                raise ControlPlaneIntegrityError("prompt identity key collision detected")
            if effective.enabled == enabled:
                return effective

            sequence = len(transition_rows) + 1
            prior_hash = str(
                transition_rows[-1]["payload_hash"]
                if transition_rows
                else prompt_row["payload_hash"]
            )
            payload = _prompt_state_payload(
                identity,
                sequence=sequence,
                enabled=enabled,
                prior_payload_hash=prior_hash,
            )
            payload_hash = canonical_sha256(payload)
            connection.execute(
                "INSERT INTO prompt_state_transitions "
                "(prompt_key, sequence, enabled, prior_payload_hash, payload_hash, payload_json, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    key,
                    sequence,
                    int(enabled),
                    prior_hash,
                    payload_hash,
                    canonical_json_bytes(payload).decode("utf-8"),
                    _time_text(datetime.now(UTC)),
                ),
            )
        return replace(effective, enabled=enabled)

    def disable_prompt(self, identity: PromptIdentity) -> RegisteredPrompt:
        """Append a disabled prompt transition when needed."""

        return self.set_prompt_enabled(identity, enabled=False)

    def enable_prompt(self, identity: PromptIdentity) -> RegisteredPrompt:
        """Append an enabled prompt transition when needed."""

        return self.set_prompt_enabled(identity, enabled=True)

    def prompt_registry(self) -> PromptRegistry:
        """Hydrate all approved prompts with their effective enabled state."""

        with self._transaction() as connection:
            prompt_rows = connection.execute(
                "SELECT prompt_key, payload_hash, payload_json FROM registered_prompts "
                "ORDER BY prompt_key"
            ).fetchall()
            transition_rows = connection.execute(
                "SELECT prompt_key, sequence, enabled, prior_payload_hash, payload_hash, "
                "payload_json FROM prompt_state_transitions ORDER BY prompt_key, sequence"
            ).fetchall()
            return PromptRegistry(self._effective_prompts(prompt_rows, transition_rows))

    def get_prompt(
        self,
        identity: PromptIdentity,
        *,
        enabled_only: bool = True,
    ) -> RegisteredPrompt | None:
        """Return an approved prompt for planner lookup, excluding disabled prompts by default."""

        if not isinstance(identity, PromptIdentity):
            raise ControlPlaneError("identity must be a PromptIdentity")
        prompt = self.prompt_registry().get(identity)
        if prompt is None or (enabled_only and not prompt.enabled):
            return None
        return prompt

    def add_price(self, price: ModelPrice) -> ModelPrice:
        """Persist a price, superseding the current open-ended price when applicable."""

        if not isinstance(price, ModelPrice):
            raise RegistryError("price must be a ModelPrice")
        if not isinstance(price.identity, ModelIdentity):
            raise RegistryError("price identity must be a ModelIdentity")
        payload = _price_payload(price)
        encoded = canonical_json_bytes(payload).decode("utf-8")
        payload_hash = canonical_sha256(payload)
        key = _model_key(price.identity)
        effective_from = _time_text(price.effective_from)
        with self._transaction() as connection:
            self._require_model(connection, price.identity)
            rows = connection.execute(
                "SELECT model_key, effective_from, effective_to, payload_hash, payload_json "
                "FROM model_prices WHERE model_key = ? ORDER BY effective_from",
                (key,),
            ).fetchall()
            supersession_rows = connection.execute(
                "SELECT model_key, superseded_effective_from, successor_effective_from, "
                "superseded_payload_hash, successor_payload_hash, payload_hash, payload_json "
                "FROM price_supersessions WHERE model_key = ? "
                "ORDER BY superseded_effective_from",
                (key,),
            ).fetchall()
            existing_prices = self._effective_prices(rows, supersession_rows)
            same_start = next(
                (row for row in rows if row["effective_from"] == effective_from),
                None,
            )
            if same_start is not None:
                if same_start["payload_hash"] != payload_hash:
                    raise PriceOverlapError(
                        f"price identity {price.identity.canonical_id!r} and effective date "
                        "already identify different facts"
                    )
                return self._price_from_row(same_start)

            overlaps = [
                existing for existing in existing_prices if PriceCatalog._overlaps(existing, price)
            ]
            predecessor = (
                overlaps[0]
                if len(overlaps) == 1
                and overlaps[0].effective_to is None
                and overlaps[0].effective_from < price.effective_from
                else None
            )
            if overlaps and predecessor is None:
                PriceCatalog(existing_prices).add(price)
            connection.execute(
                "INSERT INTO model_prices "
                "(model_key, effective_from, effective_to, payload_hash, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    key,
                    effective_from,
                    _time_text(price.effective_to) if price.effective_to is not None else None,
                    payload_hash,
                    encoded,
                    _time_text(datetime.now(UTC)),
                ),
            )
            if predecessor is not None:
                predecessor_start = _time_text(predecessor.effective_from)
                predecessor_row = next(
                    row for row in rows if row["effective_from"] == predecessor_start
                )
                supersession = _price_supersession_payload(
                    price.identity,
                    superseded_effective_from=predecessor.effective_from,
                    superseded_payload_hash=str(predecessor_row["payload_hash"]),
                    successor_effective_from=price.effective_from,
                    successor_payload_hash=payload_hash,
                )
                connection.execute(
                    "INSERT INTO price_supersessions "
                    "(model_key, superseded_effective_from, successor_effective_from, "
                    "superseded_payload_hash, successor_payload_hash, payload_hash, payload_json, "
                    "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        key,
                        predecessor_start,
                        effective_from,
                        predecessor_row["payload_hash"],
                        payload_hash,
                        canonical_sha256(supersession),
                        canonical_json_bytes(supersession).decode("utf-8"),
                        _time_text(datetime.now(UTC)),
                    ),
                )
        return price

    def add_benchmark(self, record: BenchmarkRecord) -> BenchmarkRecord:
        """Persist an immutable benchmark record idempotently."""

        if not isinstance(record, BenchmarkRecord):
            raise RoutingError("record must be a BenchmarkRecord")
        if not isinstance(record.identity, ModelIdentity):
            raise RoutingError("benchmark identity must be a ModelIdentity")
        payload = _benchmark_payload(record)
        encoded = canonical_json_bytes(payload).decode("utf-8")
        payload_hash = canonical_sha256(payload)
        key = _model_key(record.identity)
        with self._transaction() as connection:
            self._require_model(connection, record.identity)
            row = connection.execute(
                "SELECT benchmark_id, model_key, measured_at, payload_hash, payload_json "
                "FROM benchmark_records WHERE benchmark_id = ?",
                (record.benchmark_id,),
            ).fetchone()
            if row is not None:
                existing = self._benchmark_from_row(row)
                if row["payload_hash"] != payload_hash:
                    raise BenchmarkConflictError(
                        f"benchmark id {record.benchmark_id!r} already identifies different facts"
                    )
                return existing
            connection.execute(
                "INSERT INTO benchmark_records "
                "(benchmark_id, model_key, measured_at, payload_hash, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.benchmark_id,
                    key,
                    _time_text(record.measured_at),
                    payload_hash,
                    encoded,
                    _time_text(datetime.now(UTC)),
                ),
            )
        return record

    @classmethod
    def _hydrate(
        cls,
        connection: sqlite3.Connection,
    ) -> tuple[ModelRegistry, PriceCatalog, BenchmarkRegistry]:
        model_rows = connection.execute(
            "SELECT model_key, payload_hash, payload_json FROM registered_models ORDER BY model_key"
        ).fetchall()
        price_rows = connection.execute(
            "SELECT model_key, effective_from, effective_to, payload_hash, payload_json "
            "FROM model_prices ORDER BY model_key, effective_from"
        ).fetchall()
        benchmark_rows = connection.execute(
            "SELECT benchmark_id, model_key, measured_at, payload_hash, payload_json "
            "FROM benchmark_records ORDER BY benchmark_id"
        ).fetchall()
        transition_rows = connection.execute(
            "SELECT model_key, sequence, enabled, prior_payload_hash, payload_hash, payload_json "
            "FROM model_state_transitions ORDER BY model_key, sequence"
        ).fetchall()
        supersession_rows = connection.execute(
            "SELECT model_key, superseded_effective_from, successor_effective_from, "
            "superseded_payload_hash, successor_payload_hash, payload_hash, payload_json "
            "FROM price_supersessions ORDER BY model_key, superseded_effective_from"
        ).fetchall()
        models = ModelRegistry(cls._effective_models(model_rows, transition_rows))
        prices = PriceCatalog(cls._effective_prices(price_rows, supersession_rows))
        benchmarks = BenchmarkRegistry(cls._benchmark_from_row(row) for row in benchmark_rows)
        return models, prices, benchmarks

    def model_registry(self) -> ModelRegistry:
        """Hydrate and return all registered models."""

        with self._transaction() as connection:
            models, _, _ = self._hydrate(connection)
        return models

    def price_catalog(self) -> PriceCatalog:
        """Hydrate and return all effective-dated prices."""

        with self._transaction() as connection:
            _, prices, _ = self._hydrate(connection)
        return prices

    def benchmark_registry(self) -> BenchmarkRegistry:
        """Hydrate and return all immutable benchmark facts."""

        with self._transaction() as connection:
            _, _, benchmarks = self._hydrate(connection)
        return benchmarks

    def model_router(self) -> ModelRouter:
        """Hydrate one consistent snapshot and return a ready-to-use router."""

        with self._transaction() as connection:
            models, prices, benchmarks = self._hydrate(connection)
        return ModelRouter(models=models, prices=prices, benchmarks=benchmarks)

    def close(self) -> None:
        """Close this catalog handle; calling it repeatedly is safe."""

        with self._state_lock:
            self._closed = True

    def __enter__(self) -> ControlPlaneCatalog:
        self._ensure_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


__all__ = [
    "ControlPlaneCatalog",
    "ControlPlaneClosedError",
    "ControlPlaneError",
    "ControlPlaneIntegrityError",
    "ControlPlanePathError",
    "ControlPlaneSchemaError",
    "DuplicatePromptError",
    "PromptRegistry",
    "RegisteredPrompt",
    "UnknownRegisteredModelError",
]
