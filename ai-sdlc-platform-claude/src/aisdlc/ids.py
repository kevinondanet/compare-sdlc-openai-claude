"""Stable identifier scheme for canonical artifacts (ARCHITECTURE.md §2.1).

Every cross-reference between artifacts uses one of the identifier kinds defined here.
The module exposes:

* ``PATTERNS`` — compiled regular expressions per kind,
* ``is_valid`` / ``validate_id`` / ``kind_of`` — validators,
* ``next_id`` — deterministic generator for numeric kinds,
* ``slugify`` / ``change_id`` — helpers for slug-based kinds,
* ``Annotated`` string aliases (``RequirementId`` …) for use in pydantic models.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from functools import partial
from typing import Annotated, Final

from pydantic import AfterValidator

__all__ = [
    "KINDS",
    "PATTERNS",
    "WIDTHS",
    "InvalidIdError",
    "is_valid",
    "validate_id",
    "kind_of",
    "numeric_suffix",
    "next_id",
    "slugify",
    "change_id",
    "scenario_parent",
    "evidence_kind_of",
    "ChangeId",
    "RequirementId",
    "ScenarioId",
    "AssumptionId",
    "OpenQuestionId",
    "AdrId",
    "InterfaceId",
    "ThreatId",
    "TaskId",
    "TestId",
    "FindingId",
    "EvidenceId",
    "BenchmarkId",
]

KINDS: Final[tuple[str, ...]] = (
    "CHG",
    "REQ",
    "SCN",
    "ASM",
    "OQ",
    "ADR",
    "IFC",
    "THR",
    "TASK",
    "TEST",
    "FND",
    "EVD",
    "BM",
)
"""All identifier kinds, in the order of ARCHITECTURE.md §2.1."""

_SLUG: Final[str] = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_VERSION: Final[str] = r"v?\d+(?:\.\d+)*"

PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "CHG": re.compile(rf"^CHG-(?P<slug>{_SLUG})$"),
    "REQ": re.compile(r"^REQ-(?P<num>\d{3,})$"),
    "SCN": re.compile(r"^SCN-(?P<req>\d{3,})-(?P<num>\d{2,})$"),
    "ASM": re.compile(r"^ASM-(?P<num>\d{3,})$"),
    "OQ": re.compile(r"^OQ-(?P<num>\d{3,})$"),
    "ADR": re.compile(r"^ADR-(?P<num>\d{4,})$"),
    "IFC": re.compile(r"^IFC-(?P<num>\d{3,})$"),
    "THR": re.compile(r"^THR-(?P<num>\d{3,})$"),
    "TASK": re.compile(r"^TASK-(?P<num>\d{3,})$"),
    "TEST": re.compile(r"^TEST-(?P<num>\d{3,})$"),
    "FND": re.compile(r"^FND-(?P<num>\d{3,})$"),
    "EVD": re.compile(r"^EVD-(?P<ekind>[a-z][a-z0-9_]*)-(?P<num>\d{3,})$"),
    "BM": re.compile(rf"^BM-(?P<slug>{_SLUG})-(?P<version>{_VERSION})$"),
}
"""Compiled regular expression per kind. Named groups expose the components."""

WIDTHS: Final[dict[str, int]] = {
    "REQ": 3,
    "SCN": 2,
    "ASM": 3,
    "OQ": 3,
    "ADR": 4,
    "IFC": 3,
    "THR": 3,
    "TASK": 3,
    "TEST": 3,
    "FND": 3,
    "EVD": 3,
}
"""Zero-padding width of the numeric suffix for numeric kinds."""


class InvalidIdError(ValueError):
    """Raised when a string is not a valid identifier of the requested kind."""

    def __init__(self, kind: str, value: object) -> None:
        self.kind = kind
        self.value = value
        pattern = PATTERNS.get(kind)
        expected = pattern.pattern if pattern is not None else "<unknown kind>"
        super().__init__(f"{value!r} is not a valid {kind} identifier (expected {expected})")


def _pattern(kind: str) -> re.Pattern[str]:
    try:
        return PATTERNS[kind]
    except KeyError as exc:
        raise ValueError(f"unknown identifier kind {kind!r}; known kinds: {KINDS}") from exc


def is_valid(kind: str, value: object) -> bool:
    """Return ``True`` when *value* is a well-formed identifier of *kind*."""
    return isinstance(value, str) and _pattern(kind).match(value) is not None


def validate_id(kind: str, value: object) -> str:
    """Return *value* unchanged when it is a valid *kind* identifier, else raise.

    Suitable as a pydantic ``AfterValidator`` (see the ``Annotated`` aliases below).
    """
    if not is_valid(kind, value):
        raise InvalidIdError(kind, value)
    assert isinstance(value, str)
    return value


def kind_of(value: str) -> str | None:
    """Return the kind of *value* (``"REQ"`` …) or ``None`` if it matches no kind."""
    for kind in KINDS:
        if PATTERNS[kind].match(value):
            return kind
    return None


def numeric_suffix(value: str) -> int:
    """Return the trailing numeric component of a numeric identifier.

    Raises :class:`InvalidIdError` for slug-based kinds (``CHG``, ``BM``) or malformed ids.
    """
    kind = kind_of(value)
    if kind is None or kind not in WIDTHS:
        raise InvalidIdError(kind or "?", value)
    match = PATTERNS[kind].match(value)
    assert match is not None
    return int(match.group("num"))


def scenario_parent(scenario_id: str) -> str:
    """Return the requirement id (``REQ-003``) that scenario ``SCN-003-01`` belongs to."""
    match = PATTERNS["SCN"].match(scenario_id)
    if match is None:
        raise InvalidIdError("SCN", scenario_id)
    return f"REQ-{match.group('req')}"


def evidence_kind_of(evidence_id: str) -> str:
    """Return the evidence kind (``tests``) encoded in ``EVD-tests-001``."""
    match = PATTERNS["EVD"].match(evidence_id)
    if match is None:
        raise InvalidIdError("EVD", evidence_id)
    return match.group("ekind")


def next_id(
    kind: str,
    existing: Iterable[str],
    *,
    parent: str | None = None,
    evidence_kind: str | None = None,
) -> str:
    """Return the next free identifier of *kind* given the *existing* ids.

    * Numeric kinds (``REQ``, ``ASM`` …) return ``max + 1`` zero-padded to the kind's width;
      the first id is ``001`` (``0001`` for ``ADR``).
    * ``SCN`` requires ``parent`` (a ``REQ`` id); only scenarios of that requirement count.
    * ``EVD`` requires ``evidence_kind`` (``tests``, ``reviews`` …); only evidence of that
      kind counts.
    * ``CHG`` and ``BM`` are slug-based and cannot be generated — use :func:`change_id`.

    Ids in *existing* that are not of *kind* are ignored, so a mixed bag of ids may be
    passed. Malformed ids of the requested prefix are ignored as well.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown identifier kind {kind!r}; known kinds: {KINDS}")
    if kind not in WIDTHS:
        raise ValueError(f"{kind} identifiers are slug-based and cannot be generated")
    pattern = PATTERNS[kind]
    width = WIDTHS[kind]

    if kind == "SCN":
        if parent is None:
            raise ValueError("next_id('SCN', ...) requires parent=<REQ id>")
        req_num = PATTERNS["REQ"].match(validate_id("REQ", parent))
        assert req_num is not None
        prefix_group = req_num.group("num")
        highest = 0
        for value in existing:
            match = pattern.match(value)
            if match and match.group("req") == prefix_group:
                highest = max(highest, int(match.group("num")))
        return f"SCN-{prefix_group}-{highest + 1:0{width}d}"

    if kind == "EVD":
        if evidence_kind is None:
            raise ValueError("next_id('EVD', ...) requires evidence_kind=<kind>")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", evidence_kind):
            raise ValueError(f"invalid evidence kind {evidence_kind!r}")
        highest = 0
        for value in existing:
            match = pattern.match(value)
            if match and match.group("ekind") == evidence_kind:
                highest = max(highest, int(match.group("num")))
        return f"EVD-{evidence_kind}-{highest + 1:0{width}d}"

    highest = 0
    for value in existing:
        match = pattern.match(value)
        if match:
            highest = max(highest, int(match.group("num")))
    return f"{kind}-{highest + 1:0{width}d}"


def slugify(text: str, *, max_length: int = 60) -> str:
    """Convert free text into a lowercase ASCII slug usable in ``CHG``/``BM`` ids."""
    normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-")
    slug = slug[:max_length].rstrip("-")
    if not slug:
        raise ValueError(f"cannot derive a slug from {text!r}")
    return slug


def change_id(title: str) -> str:
    """Build a ``CHG-<slug>`` identifier from a human title."""
    return f"CHG-{slugify(title)}"


ChangeId = Annotated[str, AfterValidator(partial(validate_id, "CHG"))]
RequirementId = Annotated[str, AfterValidator(partial(validate_id, "REQ"))]
ScenarioId = Annotated[str, AfterValidator(partial(validate_id, "SCN"))]
AssumptionId = Annotated[str, AfterValidator(partial(validate_id, "ASM"))]
OpenQuestionId = Annotated[str, AfterValidator(partial(validate_id, "OQ"))]
AdrId = Annotated[str, AfterValidator(partial(validate_id, "ADR"))]
InterfaceId = Annotated[str, AfterValidator(partial(validate_id, "IFC"))]
ThreatId = Annotated[str, AfterValidator(partial(validate_id, "THR"))]
TaskId = Annotated[str, AfterValidator(partial(validate_id, "TASK"))]
TestId = Annotated[str, AfterValidator(partial(validate_id, "TEST"))]
FindingId = Annotated[str, AfterValidator(partial(validate_id, "FND"))]
EvidenceId = Annotated[str, AfterValidator(partial(validate_id, "EVD"))]
BenchmarkId = Annotated[str, AfterValidator(partial(validate_id, "BM"))]
