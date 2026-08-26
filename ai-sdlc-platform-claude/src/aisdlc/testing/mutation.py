"""Mutation-score evidence with explicit scope disclosure.

Two sources feed a :class:`MutationReport`:

* :func:`parse_mutation_json` / :func:`load_mutation_report` — results exported by mutmut or
  cosmic-ray (count dictionaries, ``mutants``/work-item lists);
* :func:`run_builtin_mutation` — a small, bounded mutation runner for Python that swaps
  operators/constants in a fixed set of files, runs the verification command for each
  mutant and computes the score.

Score = ``(killed + timeout) / (killed + timeout + survived)`` — timeouts count as killed
(mutmut convention), ``suspicious``/``skipped``/``incompetent`` mutants are excluded from the
denominator.  A report whose mutants were not all tested is ``complete=False`` and never
ratchets.  :meth:`MutationReport.to_model` yields the canonical
:class:`~aisdlc.schema.models.Mutation` with ``scope``/``excluded`` disclosed.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import random
import shlex
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.schema.models import Mutation, TestEvidence

__all__ = [
    "DEFAULT_OPERATORS",
    "MutantResult",
    "MutantStatus",
    "MutationReport",
    "MutationSite",
    "attach_mutation",
    "find_mutation_sites",
    "load_mutation_report",
    "parse_mutation_json",
    "ratchet_mutation_floor",
    "run_builtin_mutation",
]


class MutantStatus(StrEnum):
    """Outcome of one mutant."""

    KILLED = "killed"
    SURVIVED = "survived"
    TIMEOUT = "timeout"
    SUSPICIOUS = "suspicious"
    SKIPPED = "skipped"
    INCOMPETENT = "incompetent"
    UNTESTED = "untested"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MutantResult(_Model):
    """One mutant and what happened to it."""

    id: str
    file: str = ""
    line: int | None = Field(default=None, ge=0)
    operator: str = ""
    description: str = ""
    status: MutantStatus


class MutationReport(_Model):
    """Mutation run summary with the scope that was actually mutated."""

    tool: str = "unknown"
    killed: int = Field(default=0, ge=0)
    survived: int = Field(default=0, ge=0)
    timeout: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    incompetent: int = Field(default=0, ge=0)
    untested: int = Field(default=0, ge=0)
    scope: list[str] = Field(default_factory=list, description="Files/dirs that were mutated.")
    excluded: list[str] = Field(default_factory=list, description="Files/dirs left out.")
    complete: bool = True
    sampled: bool = Field(default=False, description="Only a sample of sites was tested.")
    mutants: list[MutantResult] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def total(self) -> int:
        """All mutants generated."""
        return (
            self.killed
            + self.survived
            + self.timeout
            + self.suspicious
            + self.skipped
            + self.incompetent
            + self.untested
        )

    @property
    def tested(self) -> int:
        """Mutants that count towards the score."""
        return self.killed + self.survived + self.timeout

    @property
    def score(self) -> float | None:
        """``(killed + timeout) / tested`` or ``None`` when nothing was tested."""
        if self.tested == 0:
            return None
        return round((self.killed + self.timeout) / self.tested, 4)

    def to_model(self) -> Mutation:
        """The canonical :class:`Mutation` record (score omitted when incomplete)."""
        return Mutation(
            score=self.score if self.complete else None,
            scope=list(self.scope),
            excluded=list(self.excluded),
        )


# --------------------------------------------------------------------------------------
# External tool output
# --------------------------------------------------------------------------------------

_STATUS_ALIASES: dict[str, MutantStatus] = {
    "killed": MutantStatus.KILLED,
    "ok_killed": MutantStatus.KILLED,
    "bad_survived": MutantStatus.SURVIVED,
    "survived": MutantStatus.SURVIVED,
    "timeout": MutantStatus.TIMEOUT,
    "bad_timeout": MutantStatus.TIMEOUT,
    "timed_out": MutantStatus.TIMEOUT,
    "suspicious": MutantStatus.SUSPICIOUS,
    "ok_suspicious": MutantStatus.SUSPICIOUS,
    "skipped": MutantStatus.SKIPPED,
    "incompetent": MutantStatus.INCOMPETENT,
    "untested": MutantStatus.UNTESTED,
    "not_checked": MutantStatus.UNTESTED,
    "pending": MutantStatus.UNTESTED,
    "": MutantStatus.UNTESTED,
}

_COUNT_KEYS: dict[str, MutantStatus] = {
    "killed": MutantStatus.KILLED,
    "survived": MutantStatus.SURVIVED,
    "timeout": MutantStatus.TIMEOUT,
    "timeouts": MutantStatus.TIMEOUT,
    "suspicious": MutantStatus.SUSPICIOUS,
    "skipped": MutantStatus.SKIPPED,
    "incompetent": MutantStatus.INCOMPETENT,
    "untested": MutantStatus.UNTESTED,
}


def _status_of(item: Mapping[str, Any]) -> MutantStatus:
    raw = item.get("status", item.get("test_outcome", item.get("result")))
    worker = str(item.get("worker_outcome", "")).lower()
    if worker == "timeout":
        return MutantStatus.TIMEOUT
    if worker in ("exception", "abnormal"):
        return MutantStatus.INCOMPETENT
    key = str(raw or "").strip().lower()
    if key in _STATUS_ALIASES:
        return _STATUS_ALIASES[key]
    raise ValueError(f"unknown mutant status {raw!r}")


def _mutant(item: Mapping[str, Any], index: int) -> MutantResult:
    ident = item.get("id", item.get("job_id", item.get("mutant_id", index)))
    line = item.get("line", item.get("line_number", item.get("start_pos", [None])[0]))
    return MutantResult(
        id=str(ident),
        file=str(item.get("file", item.get("filename", item.get("module_path", "")))),
        line=int(line) if isinstance(line, int) else None,
        operator=str(item.get("operator", item.get("operator_name", ""))),
        description=str(item.get("description", item.get("diff", ""))),
        status=_status_of(item),
    )


def parse_mutation_json(
    data: Mapping[str, Any] | Sequence[Any],
    *,
    scope: Iterable[str] = (),
    excluded: Iterable[str] = (),
    tool: str | None = None,
) -> MutationReport:
    """Normalise mutmut/cosmic-ray style JSON into a :class:`MutationReport`.

    Accepted shapes:

    * ``{"killed": 10, "survived": 2, "timeout": 1, ...}`` (optionally under ``summary``);
    * ``{"mutants": [{"id":..., "status": "killed", "file":..., "line":...}, ...]}``;
    * a bare list of mutant/work-item objects (cosmic-ray: ``test_outcome`` and
      ``worker_outcome``).

    ``scope``/``excluded`` are taken from the data (``scope``, ``paths_to_mutate``,
    ``excluded``/``paths_to_exclude``) unless given explicitly.  Mutants still ``untested``
    mark the report incomplete.
    """
    if isinstance(data, Mapping):
        payload: dict[str, Any] = dict(data)
        if isinstance(payload.get("summary"), Mapping):
            payload = {**payload, **dict(payload["summary"])}
        items: Sequence[Any] | None = None
        for key in ("mutants", "work_items", "results", "items"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
    else:
        payload = {}
        items = list(data)
    name = tool or str(payload.get("tool", payload.get("generator", "unknown")))
    report_scope = list(scope) or _as_list(payload.get("scope", payload.get("paths_to_mutate")))
    report_excluded = list(excluded) or _as_list(
        payload.get("excluded", payload.get("paths_to_exclude"))
    )
    counts: dict[MutantStatus, int] = dict.fromkeys(MutantStatus, 0)
    mutants: list[MutantResult] = []
    if items is not None:
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                raise ValueError(f"mutant entry {index} is not an object")
            mutant = _mutant(item, index)
            mutants.append(mutant)
            counts[mutant.status] += 1
    else:
        found = False
        for key, status in _COUNT_KEYS.items():
            if key in payload:
                found = True
                value = payload[key]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"count {key}={value!r} is not a non-negative integer")
                counts[status] += value
        if not found:
            raise ValueError("no mutant counts or mutant list found in mutation JSON")
    complete = counts[MutantStatus.UNTESTED] == 0 and bool(payload.get("complete", True))
    notes: list[str] = []
    if not complete:
        notes.append(f"{counts[MutantStatus.UNTESTED]} mutant(s) untested; report incomplete")
    return MutationReport(
        tool=name,
        killed=counts[MutantStatus.KILLED],
        survived=counts[MutantStatus.SURVIVED],
        timeout=counts[MutantStatus.TIMEOUT],
        suspicious=counts[MutantStatus.SUSPICIOUS],
        skipped=counts[MutantStatus.SKIPPED],
        incompetent=counts[MutantStatus.INCOMPETENT],
        untested=counts[MutantStatus.UNTESTED],
        scope=report_scope,
        excluded=report_excluded,
        complete=complete,
        mutants=mutants,
        notes=notes,
    )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def load_mutation_report(
    path: str | Path,
    *,
    scope: Iterable[str] = (),
    excluded: Iterable[str] = (),
    tool: str | None = None,
) -> MutationReport:
    """Read a JSON file and :func:`parse_mutation_json` it."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict | list):
        raise ValueError(f"{path}: expected an object or a list")
    return parse_mutation_json(data, scope=scope, excluded=excluded, tool=tool)


# --------------------------------------------------------------------------------------
# Built-in Python mutation runner
# --------------------------------------------------------------------------------------

_COMPARE_SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_BINOP_SWAPS: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.Div,
    ast.Div: ast.Mult,
    ast.FloorDiv: ast.Mult,
    ast.Mod: ast.Mult,
}

DEFAULT_OPERATORS: tuple[str, ...] = ("compare", "binop", "boolop", "constant", "not")
"""Operator families the built-in runner applies."""


class MutationSite(_Model):
    """A location in a file where one mutation applies."""

    file: str
    line: int
    column: int
    operator: str
    description: str
    index: int = Field(description="Position in the file's AST walk (stable identifier).")


class _SiteFinder(ast.NodeVisitor):
    def __init__(self, operators: Sequence[str]) -> None:
        self.operators = set(operators)
        self.sites: list[tuple[int, str, str]] = []  # (node index, operator, description)
        self._index = -1

    def generic_visit(self, node: ast.AST) -> None:
        self._index += 1
        idx = self._index
        if isinstance(node, ast.Compare) and "compare" in self.operators:
            for op in node.ops:
                if type(op) in _COMPARE_SWAPS:
                    self.sites.append(
                        (idx, "compare", f"{_name(op)} -> {_name(_COMPARE_SWAPS[type(op)]())}")
                    )
                    break
        elif isinstance(node, ast.BinOp) and "binop" in self.operators:
            if type(node.op) in _BINOP_SWAPS:
                swapped = _BINOP_SWAPS[type(node.op)]()
                self.sites.append((idx, "binop", f"{_name(node.op)} -> {_name(swapped)}"))
        elif isinstance(node, ast.BoolOp) and "boolop" in self.operators:
            self.sites.append((idx, "boolop", "and <-> or"))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            if "not" in self.operators:
                self.sites.append((idx, "not", "drop 'not'"))
        elif isinstance(node, ast.Constant) and "constant" in self.operators:
            value = node.value
            if isinstance(value, bool):
                self.sites.append((idx, "constant", f"{value} -> {not value}"))
            elif isinstance(value, int) and not isinstance(value, bool):
                self.sites.append((idx, "constant", f"{value} -> {value + 1}"))
        super().generic_visit(node)


def _name(op: ast.AST) -> str:
    return type(op).__name__


def _mutate_at(tree: ast.Module, index: int) -> ast.Module:
    clone = copy.deepcopy(tree)
    counter = -1

    class _Mutator(ast.NodeTransformer):
        def generic_visit(self, node: ast.AST) -> ast.AST:
            nonlocal counter
            counter += 1
            if counter == index:
                return _apply(node)
            return super().generic_visit(node)

    mutated = _Mutator().visit(clone)
    if not isinstance(mutated, ast.Module):
        raise TypeError("mutation did not yield a module")
    return mutated


def _apply(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Compare):
        ops = list(node.ops)
        for i, op in enumerate(ops):
            if type(op) in _COMPARE_SWAPS:
                ops[i] = _COMPARE_SWAPS[type(op)]()
                break
        node.ops = ops
        return node
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAPS:
        node.op = _BINOP_SWAPS[type(node.op)]()
        return node
    if isinstance(node, ast.BoolOp):
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        return node
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ast.copy_location(node.operand, node)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            node.value = not node.value
        elif isinstance(node.value, int):
            node.value = node.value + 1
        return node
    return node


def find_mutation_sites(
    path: str | Path, *, operators: Sequence[str] = DEFAULT_OPERATORS
) -> list[MutationSite]:
    """All mutation sites the built-in runner can apply to the Python file at *path*."""
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    finder = _SiteFinder(operators)
    finder.visit(tree)
    nodes = _indexed_nodes(tree)
    sites: list[MutationSite] = []
    for index, operator, description in finder.sites:
        node = nodes[index]
        sites.append(
            MutationSite(
                file=str(path),
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                operator=operator,
                description=description,
                index=index,
            )
        )
    return sites


def _indexed_nodes(tree: ast.AST) -> list[ast.AST]:
    ordered: list[ast.AST] = []

    class _Collector(ast.NodeVisitor):
        def generic_visit(self, node: ast.AST) -> None:
            ordered.append(node)
            super().generic_visit(node)

    _Collector().visit(tree)
    return ordered


def _run(argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: float) -> int | None:
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, never a shell
            list(argv),
            cwd=str(cwd),
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    return proc.returncode


def run_builtin_mutation(
    files: Sequence[str | Path],
    command: str | Sequence[str],
    *,
    cwd: str | Path,
    max_mutants: int = 25,
    timeout: float = 120.0,
    seed: int = 0,
    operators: Sequence[str] = DEFAULT_OPERATORS,
    excluded: Iterable[str] = (),
    env: Mapping[str, str] | None = None,
) -> MutationReport:
    """Mutate *files* one site at a time, run *command* for each and score the result.

    * Each mutant is written in place (original bytes are restored afterwards, even on
      error); the verification command runs without a shell; ``PYTHONDONTWRITEBYTECODE``
      is set and mutant mtimes are made unique so stale bytecode can never mask a mutant.
    * The command is first run unmodified: a failing baseline aborts with an incomplete
      report (``notes`` explains why) — mutants cannot be judged against a red suite.
    * At most *max_mutants* sites are tested; when more exist a deterministic sample
      (``random.Random(seed)``) is taken and ``sampled`` is set.

    Exit code 0 → ``survived``; non-zero → ``killed``; timeout → ``timeout``.
    """
    root = Path(cwd)
    argv = shlex.split(command) if isinstance(command, str) else [str(p) for p in command]
    if not argv:
        raise ValueError("empty verification command")
    run_env: dict[str, str] = {**os.environ, **(env or {})}
    run_env["PYTHONDONTWRITEBYTECODE"] = "1"
    scope = [str(Path(f)) for f in files]
    report_excluded = list(excluded)
    notes: list[str] = []

    sites: list[MutationSite] = []
    for file in files:
        path = Path(file)
        if not path.is_absolute():
            path = root / path
        if not path.is_file():
            notes.append(f"{file}: not a file; skipped")
            continue
        try:
            sites.extend(find_mutation_sites(path, operators=operators))
        except SyntaxError as exc:
            notes.append(f"{file}: cannot parse ({exc}); skipped")
    if not sites:
        notes.append("no mutation sites found")
        return MutationReport(
            tool="aisdlc-builtin",
            scope=scope,
            excluded=report_excluded,
            complete=False,
            notes=notes,
        )
    sampled = False
    available = len(sites)
    if available > max_mutants:
        chosen = random.Random(seed).sample(sites, max_mutants)
        sites = sorted(chosen, key=lambda s: (s.file, s.index))
        sampled = True
        notes.append(f"sampled {max_mutants} of {available} sites (seed={seed})")

    baseline = _run(argv, root, run_env, timeout)
    if baseline is None:
        notes.append("baseline run timed out; no mutants tested")
        return MutationReport(
            tool="aisdlc-builtin",
            untested=len(sites),
            scope=scope,
            excluded=report_excluded,
            complete=False,
            sampled=sampled,
            notes=notes,
        )
    if baseline != 0:
        notes.append(f"baseline run failed with exit code {baseline}; no mutants tested")
        return MutationReport(
            tool="aisdlc-builtin",
            untested=len(sites),
            scope=scope,
            excluded=report_excluded,
            complete=False,
            sampled=sampled,
            notes=notes,
        )

    mutants: list[MutantResult] = []
    counts: dict[MutantStatus, int] = dict.fromkeys(MutantStatus, 0)
    trees: dict[str, tuple[ast.Module, bytes, float]] = {}
    for n, site in enumerate(sites):
        path = Path(site.file)
        if site.file not in trees:
            original = path.read_bytes()
            trees[site.file] = (
                ast.parse(original.decode("utf-8"), filename=site.file),
                original,
                path.stat().st_mtime,
            )
        tree, original, mtime = trees[site.file]
        mutated = ast.unparse(_mutate_at(tree, site.index)) + "\n"
        try:
            path.write_text(mutated, encoding="utf-8")
            unique = mtime - 100_000 - n
            os.utime(path, (unique, unique))
            code = _run(argv, root, run_env, timeout)
        finally:
            path.write_bytes(original)
            os.utime(path, (mtime, mtime))
        if code is None:
            status = MutantStatus.TIMEOUT
        elif code == 0:
            status = MutantStatus.SURVIVED
        else:
            status = MutantStatus.KILLED
        counts[status] += 1
        mutants.append(
            MutantResult(
                id=f"{Path(site.file).name}:{site.line}:{site.index}",
                file=site.file,
                line=site.line,
                operator=site.operator,
                description=site.description,
                status=status,
            )
        )
    return MutationReport(
        tool="aisdlc-builtin",
        killed=counts[MutantStatus.KILLED],
        survived=counts[MutantStatus.SURVIVED],
        timeout=counts[MutantStatus.TIMEOUT],
        scope=scope,
        excluded=report_excluded,
        complete=True,
        sampled=sampled,
        mutants=mutants,
        notes=notes,
    )


# --------------------------------------------------------------------------------------
# Ratchet + evidence integration
# --------------------------------------------------------------------------------------


def ratchet_mutation_floor(previous: float, report: MutationReport, *, step: float = 0.01) -> float:
    """Raise the mutation floor to the observed score (rounded down to *step*), never lower.

    Incomplete or sampled-only reports do not ratchet.
    """
    score = report.score
    if not report.complete or report.sampled or score is None:
        return previous
    observed = int(score / step) * step
    return round(max(previous, min(1.0, observed)), 4)


def attach_mutation(evidence: TestEvidence, report: MutationReport) -> TestEvidence:
    """Return a copy of *evidence* carrying ``report.to_model()`` as its mutation record."""
    return evidence.model_copy(update={"mutation": report.to_model()})
