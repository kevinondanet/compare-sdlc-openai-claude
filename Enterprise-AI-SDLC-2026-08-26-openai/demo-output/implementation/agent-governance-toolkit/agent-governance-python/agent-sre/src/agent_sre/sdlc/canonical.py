# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical JSON helpers for release governance artifacts."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel

_MAX_JSON_BYTES = 8 * 1024 * 1024


class DuplicateJSONKeyError(ValueError):
    """Raised when an input JSON object contains a duplicate key."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def load_json_strict(data: str | bytes, *, max_bytes: int = _MAX_JSON_BYTES) -> Any:
    """Load JSON while rejecting duplicate keys and non-finite numbers."""

    encoded = data.encode("utf-8") if isinstance(data, str) else data
    if len(encoded) > max_bytes:
        raise ValueError(f"JSON input exceeds the {max_bytes}-byte limit")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("JSON input must be UTF-8") from exc
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def load_json_file_strict(path: str | Path, *, max_bytes: int = _MAX_JSON_BYTES) -> Any:
    """Read and strictly parse a bounded JSON file."""

    candidate = Path(path)
    size = candidate.stat().st_size
    if size > max_bytes:
        raise ValueError(f"JSON input exceeds the {max_bytes}-byte limit")
    return load_json_strict(candidate.read_bytes(), max_bytes=max_bytes)


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return _json_value(value.value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite Decimal is not permitted")
        return format(value, "f")
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_json_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite float is not permitted")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes.

    The format deliberately matches the PyRIT evidence producer contract:
    sorted object keys, compact separators, UTF-8 characters, and no NaN or
    Infinity values.
    """

    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return the lowercase SHA-256 digest of canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def digest_without(value: BaseModel | Mapping[str, Any], *fields: str) -> str:
    """Digest a model or mapping after excluding top-level fields."""

    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    for field in fields:
        payload.pop(field, None)
    return canonical_sha256(payload)


def with_digest(payload: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    """Copy a payload and attach its canonical digest under *field*."""

    result = dict(payload)
    result.pop(field, None)
    result[field] = canonical_sha256(result)
    return result
