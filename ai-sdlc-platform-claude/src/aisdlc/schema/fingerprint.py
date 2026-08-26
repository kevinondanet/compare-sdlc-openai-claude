"""Content fingerprints, optimistic concurrency and semantic requirement merge.

Concurrent edits to one change package (two agents, or an agent and a human) are the
classic OpenSpec data-loss risk. This module gives callers:

* :func:`compute_fingerprint` — a sha256 over the *authored* canonical artifacts;
* :func:`check_and_update` — fail with :class:`OptimisticConcurrencyError` when the
  on-disk content no longer matches the fingerprint the caller started from;
* :func:`merge_requirements` — three-way merge by requirement id that never drops a
  scenario and reports conflicts instead of guessing;
* :func:`merge_packages` — three-way merge of whole packages (requirements through
  :func:`merge_requirements`, every other artifact as a unit) for callers that hit
  :class:`OptimisticConcurrencyError` and want to reapply their edits on the new base.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.schema.models import ChangePackage, Requirement, Scenario

__all__ = [
    "FINGERPRINT_FILE",
    "CANONICAL_FILES",
    "CANONICAL_DIRS",
    "OptimisticConcurrencyError",
    "canonical_files",
    "compute_fingerprint",
    "read_fingerprint",
    "write_fingerprint",
    "check_fingerprint",
    "check_and_update",
    "MergeConflict",
    "MergeResult",
    "merge_requirements",
    "PackageMergeResult",
    "merge_packages",
]

FINGERPRINT_FILE = ".fingerprint"
CANONICAL_FILES: tuple[str, ...] = (
    "intent.md",
    "requirements.md",
    "assumptions.md",
    "plan.md",
    "tasks.md",
)
"""Top-level authored artifacts covered by the fingerprint."""
CANONICAL_DIRS: tuple[str, ...] = ("scenarios", "architecture")
"""Directories whose files (recursively) are covered by the fingerprint."""


class OptimisticConcurrencyError(RuntimeError):
    """The package changed on disk since the caller's base fingerprint was taken."""

    def __init__(self, expected: str, actual: str, directory: Path) -> None:
        self.expected = expected
        self.actual = actual
        self.directory = directory
        super().__init__(
            f"{directory} changed concurrently: base fingerprint {expected[:12]}… "
            f"but current is {actual[:12]}…; reload and merge before saving"
        )


def canonical_files(directory: str | Path) -> list[Path]:
    """Sorted list of authored artifact files present under *directory*."""
    root = Path(directory)
    files: list[Path] = [root / name for name in CANONICAL_FILES if (root / name).is_file()]
    for sub in CANONICAL_DIRS:
        base = root / sub
        if base.is_dir():
            files.extend(p for p in base.rglob("*") if p.is_file())
    return sorted(files)


def compute_fingerprint(directory: str | Path) -> str:
    """sha256 hex digest over ``<relative path>\\0<sha256(content)>\\n`` of canonical files.

    Evidence, handoffs, the final verdict and ``.fingerprint`` itself are excluded: they
    are produced, not authored, and must not invalidate an author's base.
    """
    root = Path(directory)
    digest = hashlib.sha256()
    for path in canonical_files(root):
        rel = path.relative_to(root).as_posix()
        content_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(f"{rel}\0{content_hash}\n".encode())
    return digest.hexdigest()


def read_fingerprint(directory: str | Path) -> str | None:
    """Return the stored ``.fingerprint`` value, or ``None`` when absent."""
    path = Path(directory) / FINGERPRINT_FILE
    if not path.is_file():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return value or None


def write_fingerprint(directory: str | Path, value: str | None = None) -> str:
    """Write ``.fingerprint`` (computing it when *value* is omitted); returns the value."""
    fingerprint = value if value is not None else compute_fingerprint(directory)
    (Path(directory) / FINGERPRINT_FILE).write_text(fingerprint + "\n", encoding="utf-8")
    return fingerprint


def check_fingerprint(directory: str | Path, base: str) -> str:
    """Raise :class:`OptimisticConcurrencyError` unless the current content matches *base*."""
    current = compute_fingerprint(directory)
    if current != base:
        raise OptimisticConcurrencyError(base, current, Path(directory))
    return current


def check_and_update(
    directory: str | Path,
    base: str,
    apply: Callable[[], None] | None = None,
) -> str:
    """Verify *base* is current, optionally run *apply* (the writes), then refresh the file.

    Returns the new fingerprint. If the on-disk content differs from *base* nothing is
    written and :class:`OptimisticConcurrencyError` is raised, so the caller can reload,
    :func:`merge_requirements`, and retry.
    """
    check_fingerprint(directory, base)
    if apply is not None:
        apply()
    return write_fingerprint(directory)


# --------------------------------------------------------------------------------------
# Semantic merge of requirements
# --------------------------------------------------------------------------------------

_SCALAR_FIELDS: tuple[str, ...] = ("text", "kind", "priority", "rationale", "tags")


class MergeConflict(BaseModel):
    """A conflicting three-way edit; ``ours`` is kept in the merged output."""

    model_config = ConfigDict(extra="forbid")

    requirement_id: str
    field: str
    scenario_id: str | None = None
    base: Any = None
    ours: Any = None
    theirs: Any = None
    message: str = ""


class MergeResult(BaseModel):
    """Outcome of :func:`merge_requirements`."""

    model_config = ConfigDict(extra="forbid")

    merged: list[Requirement] = Field(default_factory=list)
    conflicts: list[MergeConflict] = Field(default_factory=list)
    added: list[str] = Field(default_factory=list, description="Requirement ids added.")
    removed: list[str] = Field(default_factory=list, description="Requirement ids removed.")
    notes: list[str] = Field(default_factory=list, description="Non-conflicting decisions.")

    @property
    def clean(self) -> bool:
        """``True`` when the merge produced no conflicts."""
        return not self.conflicts


def _by_id(items: Sequence[Requirement]) -> dict[str, Requirement]:
    return {item.id: item for item in items}


def _scenarios_by_id(requirement: Requirement | None) -> dict[str, Scenario]:
    if requirement is None:
        return {}
    return {s.id: s for s in requirement.scenarios}


def _merge_scenarios(
    req_id: str,
    base: Requirement | None,
    ours: Requirement,
    theirs: Requirement,
    conflicts: list[MergeConflict],
    notes: list[str],
) -> list[Scenario]:
    """Union of scenarios by id; never drops one; conflicting edits keep ours."""
    base_s, ours_s, theirs_s = (
        _scenarios_by_id(base),
        _scenarios_by_id(ours),
        _scenarios_by_id(theirs),
    )
    order: list[str] = []
    for source in (base_s, ours_s, theirs_s):
        for sid in source:
            if sid not in order:
                order.append(sid)
    merged: list[Scenario] = []
    for sid in order:
        b, o, t = base_s.get(sid), ours_s.get(sid), theirs_s.get(sid)
        if o is not None and t is not None:
            if o == t or b == t:
                merged.append(o)
            elif b == o:
                merged.append(t)
            else:
                conflicts.append(
                    MergeConflict(
                        requirement_id=req_id,
                        field="scenarios",
                        scenario_id=sid,
                        base=b.model_dump(mode="json") if b else None,
                        ours=o.model_dump(mode="json"),
                        theirs=t.model_dump(mode="json"),
                        message=f"scenario {sid} edited differently on both sides",
                    )
                )
                merged.append(o)
        elif o is not None:
            merged.append(o)
            if b is not None and t is None:
                notes.append(f"{sid}: removed on theirs but kept (scenarios are never dropped)")
        elif t is not None:
            merged.append(t)
            if b is not None and o is None:
                notes.append(f"{sid}: removed on ours but kept (scenarios are never dropped)")
        elif b is not None:
            merged.append(b)
            notes.append(f"{sid}: removed on both sides but kept (scenarios are never dropped)")
    return merged


def _merge_one(
    req_id: str,
    base: Requirement | None,
    ours: Requirement,
    theirs: Requirement,
    conflicts: list[MergeConflict],
    notes: list[str],
) -> Requirement:
    values: dict[str, Any] = {"id": req_id}
    for field in _SCALAR_FIELDS:
        b = getattr(base, field) if base is not None else None
        o, t = getattr(ours, field), getattr(theirs, field)
        if o == t or t == b:
            values[field] = o
        elif o == b:
            values[field] = t
        else:
            conflicts.append(
                MergeConflict(
                    requirement_id=req_id,
                    field=field,
                    base=b,
                    ours=o,
                    theirs=t,
                    message=f"{field} edited differently on both sides",
                )
            )
            values[field] = o
    values["scenarios"] = _merge_scenarios(req_id, base, ours, theirs, conflicts, notes)
    return Requirement.model_validate(values)


def merge_requirements(
    base: Sequence[Requirement],
    ours: Sequence[Requirement],
    theirs: Sequence[Requirement],
) -> MergeResult:
    """Three-way merge of requirement lists keyed by requirement id.

    Rules:

    * A requirement changed on one side only takes that side's version.
    * Changed on both sides: each scalar field is merged independently; a field changed
      differently on both sides is a :class:`MergeConflict` (ours is kept, conflict
      reported — never silently resolved).
    * Scenarios are merged as a union by scenario id. A scenario is **never dropped**, even
      if one (or both) sides deleted it; the decision is recorded in ``notes``.
    * A requirement deleted on one side while unchanged on the other is removed; deleted
      on one side but edited on the other is kept and reported as a conflict.
    * Added on both sides with different content: merged field-wise with an empty base,
      conflicts reported.

    Output order: base order, then additions from ours, then additions from theirs.
    """
    base_m, ours_m, theirs_m = _by_id(base), _by_id(ours), _by_id(theirs)
    conflicts: list[MergeConflict] = []
    notes: list[str] = []
    merged: list[Requirement] = []
    added: list[str] = []
    removed: list[str] = []

    order: list[str] = list(base_m)
    for source in (ours_m, theirs_m):
        for rid in source:
            if rid not in order:
                order.append(rid)

    for rid in order:
        b, o, t = base_m.get(rid), ours_m.get(rid), theirs_m.get(rid)
        if o is not None and t is not None:
            if b is None:
                added.append(rid)
            merged.append(_merge_one(rid, b, o, t, conflicts, notes))
        elif o is None and t is None:
            removed.append(rid)
        elif o is not None:  # theirs missing
            if b is None:
                added.append(rid)
                merged.append(o)
            elif o == b:
                removed.append(rid)
            else:
                conflicts.append(
                    MergeConflict(
                        requirement_id=rid,
                        field="*",
                        base=b.model_dump(mode="json"),
                        ours=o.model_dump(mode="json"),
                        theirs=None,
                        message="deleted on theirs but edited on ours; kept ours",
                    )
                )
                merged.append(o)
        else:  # ours missing, theirs present
            assert t is not None
            if b is None:
                added.append(rid)
                merged.append(t)
            elif t == b:
                removed.append(rid)
            else:
                conflicts.append(
                    MergeConflict(
                        requirement_id=rid,
                        field="*",
                        base=b.model_dump(mode="json"),
                        ours=None,
                        theirs=t.model_dump(mode="json"),
                        message="deleted on ours but edited on theirs; kept theirs",
                    )
                )
                merged.append(t)

    return MergeResult(
        merged=merged, conflicts=conflicts, added=added, removed=removed, notes=notes
    )


# --------------------------------------------------------------------------------------
# Three-way merge of whole packages
# --------------------------------------------------------------------------------------

#: Package fields merged as a unit (changed on one side only -> that side wins).
_PACKAGE_UNIT_FIELDS: tuple[str, ...] = (
    "intent",
    "assumptions",
    "open_questions",
    "decisions",
    "interfaces",
    "threat_model",
    "plan",
    "tasks",
    "evidence",
    "final_verdict",
    "scenario_files",
)


class PackageMergeResult(BaseModel):
    """Outcome of :func:`merge_packages`."""

    model_config = ConfigDict(extra="forbid")

    package: ChangePackage
    requirements: MergeResult
    field_conflicts: list[str] = Field(
        default_factory=list,
        description="Artifacts edited differently on both sides (ours kept), e.g. 'tasks', "
        "'bodies[plan.md]'.",
    )

    @property
    def clean(self) -> bool:
        """``True`` when nothing conflicted."""
        return self.requirements.clean and not self.field_conflicts


def _pick(name: str, base: Any, ours: Any, theirs: Any, conflicts: list[str]) -> Any:
    if ours == theirs or theirs == base:
        return ours
    if ours == base:
        return theirs
    conflicts.append(name)
    return ours


def merge_packages(
    base: ChangePackage, ours: ChangePackage, theirs: ChangePackage
) -> PackageMergeResult:
    """Three-way merge of *ours* (in-memory edits) onto *theirs* (current on-disk content).

    *base* is the package both sides started from (the caller's snapshot right after
    loading). Requirements merge through :func:`merge_requirements`; every other
    artifact and each prose body merges as a unit: unchanged on our side -> theirs,
    unchanged on their side -> ours, changed differently on both -> ours is kept and the
    field name is reported in ``field_conflicts``. The result carries *theirs*' root and
    base fingerprint so it can be saved with ``save(base_fingerprint=...)`` immediately.
    """
    conflicts: list[str] = []
    values: dict[str, Any] = {}
    for name in _PACKAGE_UNIT_FIELDS:
        values[name] = _pick(
            name, getattr(base, name), getattr(ours, name), getattr(theirs, name), conflicts
        )
    requirements = merge_requirements(base.requirements, ours.requirements, theirs.requirements)
    values["requirements"] = requirements.merged
    bodies: dict[str, str] = {}
    for key in sorted({*base.bodies, *ours.bodies, *theirs.bodies}):
        picked = _pick(
            f"bodies[{key}]",
            base.bodies.get(key),
            ours.bodies.get(key),
            theirs.bodies.get(key),
            conflicts,
        )
        if picked is not None:
            bodies[key] = picked
    values["bodies"] = bodies
    package = ChangePackage(
        **values, root=theirs.root or ours.root, base_fingerprint=theirs.base_fingerprint
    )
    return PackageMergeResult(package=package, requirements=requirements, field_conflicts=conflicts)
