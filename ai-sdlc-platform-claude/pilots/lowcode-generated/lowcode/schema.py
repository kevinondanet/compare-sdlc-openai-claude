"""Form specifications: fields, validation and the submission cut-off.

A business user describes a form as JSON (``forms/<name>.json``); the engine validates
submissions against it and the generator turns it into an application module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path
from typing import Any

FIELD_TYPES: tuple[str, ...] = ("text", "number", "choice")
WEEKDAYS: tuple[str, ...] = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)


class ValidationError(ValueError):
    """A submission violates the form specification (``errors`` maps field -> message)."""

    def __init__(self, errors: dict[str, str]) -> None:
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in sorted(self.errors.items())))


@dataclass(frozen=True)
class Field:
    """One form field."""

    name: str
    type: str = "text"
    required: bool = True
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    max_length: int | None = None

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise ValueError(f"field name {self.name!r} must be an identifier")
        if self.type not in FIELD_TYPES:
            raise ValueError(f"field {self.name!r}: type must be one of {FIELD_TYPES}")
        if self.type == "choice" and not self.choices:
            raise ValueError(f"field {self.name!r}: a choice field needs choices")

    def clean(self, raw: Any) -> Any:
        """Validate one value and return its normalised form (raises ``ValueError``)."""
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            if self.required:
                raise ValueError("is required")
            return None
        if self.type == "number":
            try:
                number = float(raw)
            except (TypeError, ValueError):
                raise ValueError("must be a number") from None
            if self.minimum is not None and number < self.minimum:
                raise ValueError(f"must be at least {self.minimum:g}")
            if self.maximum is not None and number > self.maximum:
                raise ValueError(f"must be at most {self.maximum:g}")
            return int(number) if number.is_integer() else number
        text = str(raw).strip()
        if self.type == "choice":
            if text not in self.choices:
                raise ValueError(f"must be one of {', '.join(self.choices)}")
            return text
        if self.max_length is not None and len(text) > self.max_length:
            raise ValueError(f"must be at most {self.max_length} characters")
        return text


@dataclass(frozen=True)
class Cutoff:
    """Submissions close at ``time`` on ``weekday`` and reopen the next day."""

    weekday: str
    time: time

    def __post_init__(self) -> None:
        if self.weekday not in WEEKDAYS:
            raise ValueError(f"weekday must be one of {WEEKDAYS}")

    def is_open(self, now: datetime) -> bool:
        """Whether a submission at *now* is still accepted."""
        return not (WEEKDAYS[now.weekday()] == self.weekday and now.time() >= self.time)

    def describe(self) -> str:
        """Human-readable cut-off."""
        return f"{self.weekday.capitalize()} {self.time.strftime('%H:%M')}"


@dataclass(frozen=True)
class FormSpec:
    """A whole form: identity, fields and cut-off."""

    slug: str
    title: str
    fields: tuple[Field, ...]
    cutoff: Cutoff | None = None
    source: dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if not self.slug.isidentifier():
            raise ValueError(f"slug {self.slug!r} must be an identifier")
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("field names must be unique")
        if not names:
            raise ValueError("a form needs at least one field")

    @property
    def columns(self) -> tuple[str, ...]:
        """Column names of the resulting table."""
        return tuple(f.name for f in self.fields)

    def field(self, name: str) -> Field:
        """Look up a field by name."""
        for item in self.fields:
            if item.name == name:
                return item
        raise KeyError(name)

    def validate(self, values: dict[str, Any]) -> dict[str, Any]:
        """Validate *values*; returns the cleaned row or raises :class:`ValidationError`."""
        errors: dict[str, str] = {}
        cleaned: dict[str, Any] = {}
        for item in self.fields:
            try:
                cleaned[item.name] = item.clean(values.get(item.name))
            except ValueError as exc:
                errors[item.name] = str(exc)
        unknown = sorted(set(values) - set(self.columns))
        for name in unknown:
            errors[name] = "is not a field of this form"
        if errors:
            raise ValidationError(errors)
        return cleaned

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FormSpec:
        """Build a spec from its JSON form."""
        fields = tuple(
            Field(
                name=str(f["name"]),
                type=str(f.get("type", "text")),
                required=bool(f.get("required", True)),
                choices=tuple(str(c) for c in f.get("choices", ())),
                minimum=f.get("minimum"),
                maximum=f.get("maximum"),
                max_length=f.get("max_length"),
            )
            for f in data.get("fields", [])
        )
        cutoff = None
        if data.get("cutoff"):
            hour, minute = str(data["cutoff"]["time"]).split(":")
            cutoff = Cutoff(str(data["cutoff"]["weekday"]).lower(), time(int(hour), int(minute)))
        return cls(
            slug=str(data["slug"]),
            title=str(data.get("title", data["slug"])),
            fields=fields,
            cutoff=cutoff,
            source=dict(data),
        )

    @classmethod
    def load(cls, path: str | Path) -> FormSpec:
        """Load a ``forms/<name>.json`` file."""
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
