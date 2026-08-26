"""Import/export OpenSpec change directories.

OpenSpec layout (``openspec/changes/<id>/``)::

    proposal.md              ## Why / ## What Changes / ## Impact (+ any other sections)
    tasks.md                 ## 1. Group  /  - [ ] 1.1 Task
    design.md                optional free-form design notes
    specs/<capability>/spec.md
        ## ADDED|MODIFIED|REMOVED|RENAMED Requirements   (or plain "## Requirements")
        ### Requirement: <name>
        <normative text>
        #### Scenario: <name>
        - **WHEN** ... / - **THEN** ... / - **AND** ...   (or plain WHEN/THEN lines)

The parser is tolerant: headings are matched case-insensitively, clause markers may be
bold bullets or bare words, and unknown sections are preserved as prose bodies and
reported as :class:`Unmapped` rather than dropped.

Identifiers survive a round trip through HTML comments the exporter writes right after
each heading (``<!-- aisdlc-id: REQ-001 kind=functional priority=must -->``); an ``REQ-nnn``
/ ``SCN-nnn-nn`` / ``TASK-nnn`` token in a heading is honoured too. Everything else gets
sequential ids in document order.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.schema import markdown as md
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    Assumption,
    ChangePackage,
    Intent,
    Kernel,
    ModelTier,
    OpenQuestion,
    Plan,
    Priority,
    QuestionStatus,
    Requirement,
    RequirementKind,
    RiskClass,
    Scenario,
    Task,
    TaskStatus,
    Verification,
    Wave,
)

__all__ = [
    "DESIGN_FILE",
    "PROPOSAL_FILE",
    "SPECS_DIR",
    "SPEC_FILE",
    "TASKS_FILE",
    "ExportResult",
    "ImportResult",
    "OpenSpecError",
    "OpenSpecRequirement",
    "OpenSpecScenario",
    "OpenSpecTask",
    "Unmapped",
    "export_change",
    "import_change",
    "parse_proposal",
    "parse_spec",
    "parse_tasks",
    "render_proposal",
    "render_spec",
    "render_tasks",
    "to_requirements",
    "to_tasks",
]

PROPOSAL_FILE = "proposal.md"
TASKS_FILE = "tasks.md"
DESIGN_FILE = "design.md"
SPECS_DIR = "specs"
SPEC_FILE = "spec.md"

_SECTIONS = ("ADDED", "MODIFIED", "REMOVED", "RENAMED")

_ID_COMMENT_RE = re.compile(r"<!--\s*aisdlc-id:\s*(?P<id>[A-Z]+-[A-Za-z0-9-]+)(?P<attrs>[^>]*)-->")
_ATTR_RE = re.compile(r"(\w+)=([^\s]+)")
_REQ_SECTION_RE = re.compile(
    r"^##\s+(?:(?P<kind>ADDED|MODIFIED|REMOVED|RENAMED)\s+)?Requirements\s*$", re.IGNORECASE
)
_H1_RE = re.compile(r"^#\s+(?P<title>.+?)\s*$")
_H2_RE = re.compile(r"^##\s+(?P<title>.+?)\s*$")
_REQ_HEADING_RE = re.compile(r"^###\s+Requirement\s*:\s*(?P<name>.*?)\s*$", re.IGNORECASE)
_SCN_HEADING_RE = re.compile(r"^####\s+Scenario\s*:\s*(?P<name>.*?)\s*$", re.IGNORECASE)
_CLAUSE_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*|__)?\s*(?P<kw>GIVEN|WHEN|THEN|AND)\b"
    r"\s*(?:\*\*|__)?\s*:?\s*(?P<text>.*?)\s*$",
    re.IGNORECASE,
)
_TASK_RE = re.compile(
    r"^(?P<indent>\s*)[-*]\s*\[(?P<done>[ xX])\]\s*"
    r"(?:(?P<number>\d+(?:\.\d+)*)\.?\s+)?(?P<title>.*?)\s*$"
)
_TASK_ATTR_RE = re.compile(r"^\s+[-*]\s*(?P<key>[a-z_]+)\s*:\s*(?P<value>.*?)\s*$", re.IGNORECASE)
_VERIFY_RE = re.compile(
    r"^`(?P<cmd>[^`]+)`(?:\s*\(exit\s+(?P<code>-?\d+)\))?(?:\s*/(?P<regex>.+)/)?\s*$"
)
_GROUP_RE = re.compile(r"^##\s+(?:(?P<number>\d+)\.\s*)?(?P<name>.+?)\s*$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(?:\[(?P<done>[ xX])\]\s*)?(?P<text>.+?)\s*$")
_REQ_ID_RE = re.compile(r"\bREQ-\d{3,}\b")
_SCN_ID_RE = re.compile(r"\bSCN-\d{3,}-\d{2,}\b")
_TASK_ID_RE = re.compile(r"\bTASK-\d{3,}\b")
_CHG_ID_RE = re.compile(r"\bCHG-[a-z0-9]+(?:-[a-z0-9]+)*\b")


class OpenSpecError(RuntimeError):
    """An OpenSpec directory could not be imported or exported."""


class OpenSpecModel(BaseModel):
    """Base for OpenSpec intermediate models."""

    model_config = ConfigDict(extra="forbid")


class OpenSpecScenario(OpenSpecModel):
    """A ``#### Scenario:`` block as written."""

    name: str = ""
    id: str | None = None
    given: str | None = None
    when: str | None = None
    then: str | None = None
    raw: str = ""


class OpenSpecRequirement(OpenSpecModel):
    """A ``### Requirement:`` block with its scenarios."""

    name: str = ""
    id: str | None = None
    text: str = ""
    section: str | None = Field(default=None, description="ADDED | MODIFIED | REMOVED | None")
    capability: str = ""
    scenarios: list[OpenSpecScenario] = Field(default_factory=list)
    attrs: dict[str, str] = Field(default_factory=dict)


class OpenSpecTask(OpenSpecModel):
    """A ``- [ ] 1.1 Title`` line with optional attribute sub-bullets."""

    number: str = ""
    title: str
    done: bool = False
    group: str = ""
    group_index: int = 0
    id: str | None = None
    attrs: dict[str, str] = Field(default_factory=dict)


class Unmapped(OpenSpecModel):
    """Content that has no structured home; never dropped silently."""

    source: str
    location: str
    kind: str
    text: str
    disposition: str = Field(
        description="kept_in_body | not_imported | not_exported | reassigned | skipped"
    )

    def __str__(self) -> str:
        return f"{self.source}:{self.location} [{self.kind}] {self.disposition}"


class ImportResult(OpenSpecModel):
    """Outcome of :func:`import_change`."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    package: ChangePackage
    unmapped: list[Unmapped] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    id_map: dict[str, str] = Field(
        default_factory=dict, description="OpenSpec name/number -> canonical id."
    )


class ExportResult(OpenSpecModel):
    """Outcome of :func:`export_change`."""

    out_dir: Path
    files: list[Path] = Field(default_factory=list)
    unmapped: list[Unmapped] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------------------


def _strip_id_comment(line: str) -> tuple[str, str | None, dict[str, str]]:
    """Remove an ``aisdlc-id`` comment from *line*, returning (line, id, attrs)."""
    match = _ID_COMMENT_RE.search(line)
    if not match:
        return line, None, {}
    attrs = {k: v for k, v in _ATTR_RE.findall(match.group("attrs"))}
    cleaned = (line[: match.start()] + line[match.end() :]).rstrip()
    return cleaned, match.group("id"), attrs


def _extract_id(name: str, pattern: re.Pattern[str]) -> tuple[str, str | None]:
    match = pattern.search(name)
    if not match:
        return name.strip(), None
    cleaned = (name[: match.start()] + name[match.end() :]).strip(" -—:–\t")
    return cleaned, match.group(0)


def _paragraphs(lines: Sequence[str]) -> str:
    text = "\n".join(lines).strip("\n")
    parts = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    return "\n\n".join(" ".join(p.splitlines()).strip() for p in parts)


def _trim(lines: Sequence[str]) -> list[str]:
    out = list(lines)
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return out


@dataclass
class _ScnBuilder:
    name: str
    id: str | None = None
    lines: list[str] = field(default_factory=list)

    def build(self) -> OpenSpecScenario:
        given: list[str] = []
        when: list[str] = []
        then: list[str] = []
        last: list[str] | None = None
        for line in self.lines:
            match = _CLAUSE_RE.match(line)
            if not match:
                continue
            keyword = match.group("kw").upper()
            text = match.group("text").strip()
            if keyword == "GIVEN":
                last = given
            elif keyword == "WHEN":
                last = when
            elif keyword == "THEN":
                last = then
            elif last is None:
                continue
            last.append(text)
        raw = "\n".join(_trim(self.lines))
        return OpenSpecScenario(
            name=self.name,
            id=self.id,
            given=" AND ".join(given) or None,
            when=" AND ".join(when) or None,
            then=" AND ".join(then) or None,
            raw=raw,
        )


@dataclass
class _ReqBuilder:
    name: str
    section: str | None
    capability: str
    id: str | None = None
    attrs: dict[str, str] = field(default_factory=dict)
    lines: list[str] = field(default_factory=list)
    scenarios: list[_ScnBuilder] = field(default_factory=list)

    def build(self) -> OpenSpecRequirement:
        return OpenSpecRequirement(
            name=self.name,
            id=self.id,
            text=_paragraphs(self.lines),
            section=self.section,
            capability=self.capability,
            scenarios=[s.build() for s in self.scenarios],
            attrs=self.attrs,
        )


def parse_spec(
    text: str, *, capability: str = "", source: str = SPEC_FILE
) -> tuple[list[OpenSpecRequirement], list[Unmapped]]:
    """Parse one ``spec.md`` into requirements plus unmapped content."""
    requirements: list[OpenSpecRequirement] = []
    unmapped: list[Unmapped] = []
    section: str | None = None
    in_requirements = False
    other_title: str | None = None
    other_lines: list[str] = []
    current: _ReqBuilder | None = None

    def flush_other() -> None:
        nonlocal other_title, other_lines
        body = _trim(other_lines)
        if other_title is not None or body:
            heading = other_title if other_title is not None else "(preamble)"
            content = "\n".join(([f"## {other_title}"] if other_title else []) + body)
            if content.strip():
                unmapped.append(
                    Unmapped(
                        source=source,
                        location=heading,
                        kind="section",
                        text=content,
                        disposition="kept_in_body",
                    )
                )
        other_title, other_lines = None, []

    def flush_req() -> None:
        nonlocal current
        if current is not None:
            requirements.append(current.build())
        current = None

    for lineno, line in enumerate(text.splitlines(), start=1):
        sec = _REQ_SECTION_RE.match(line)
        if sec:
            flush_req()
            flush_other()
            kind = (sec.group("kind") or "").upper() or None
            if kind == "RENAMED":
                in_requirements = False
                other_title = line.lstrip("# ").strip()
                continue
            section = kind
            in_requirements = True
            continue
        h2 = _H2_RE.match(line)
        if h2:
            flush_req()
            flush_other()
            in_requirements = False
            other_title = h2.group("title")
            continue
        if not in_requirements:
            if _H1_RE.match(line) and not other_lines and other_title is None:
                continue  # document title
            other_lines.append(line)
            continue
        req = _REQ_HEADING_RE.match(line)
        if req:
            flush_req()
            name, explicit = _extract_id(req.group("name"), _REQ_ID_RE)
            current = _ReqBuilder(name=name, section=section, capability=capability, id=explicit)
            continue
        scn = _SCN_HEADING_RE.match(line)
        if scn:
            if current is None:
                unmapped.append(
                    Unmapped(
                        source=source,
                        location=f"line {lineno}",
                        kind="scenario",
                        text=line,
                        disposition="skipped",
                    )
                )
                continue
            name, explicit = _extract_id(scn.group("name"), _SCN_ID_RE)
            current.scenarios.append(_ScnBuilder(name=name, id=explicit))
            continue
        cleaned, found_id, attrs = _strip_id_comment(line)
        if found_id is not None and current is not None:
            if current.scenarios and ids.kind_of(found_id) == "SCN":
                current.scenarios[-1].id = found_id
            elif ids.kind_of(found_id) == "REQ":
                current.id = found_id
                current.attrs.update(attrs)
            if not cleaned.strip():
                continue
            line = cleaned
        if current is None:
            if line.strip():
                unmapped.append(
                    Unmapped(
                        source=source,
                        location=f"line {lineno}",
                        kind="text",
                        text=line,
                        disposition="kept_in_body",
                    )
                )
            continue
        if current.scenarios:
            current.scenarios[-1].lines.append(line)
        else:
            current.lines.append(line)
    flush_req()
    flush_other()
    return requirements, unmapped


def parse_tasks(
    text: str, *, source: str = TASKS_FILE
) -> tuple[list[OpenSpecTask], list[Unmapped]]:
    """Parse ``tasks.md`` into tasks (grouped by ``##`` headings) plus unmapped content."""
    tasks: list[OpenSpecTask] = []
    unmapped: list[Unmapped] = []
    group_name = ""
    group_index = -1
    current: OpenSpecTask | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if _H1_RE.match(line):
            continue
        group = _GROUP_RE.match(line)
        if group:
            group_index += 1
            group_name = group.group("name")
            current = None
            continue
        task = _TASK_RE.match(line)
        if task and not task.group("indent"):
            title, found_id, attrs = _strip_id_comment(task.group("title"))
            title, heading_id = _extract_id(title, _TASK_ID_RE)
            current = OpenSpecTask(
                number=task.group("number") or "",
                title=title.strip(),
                done=task.group("done").lower() == "x",
                group=group_name,
                group_index=max(group_index, 0),
                id=found_id or heading_id,
                attrs=attrs,
            )
            tasks.append(current)
            continue
        attr = _TASK_ATTR_RE.match(line)
        if attr and current is not None:
            current.attrs[attr.group("key").lower()] = attr.group("value")
            continue
        unmapped.append(
            Unmapped(
                source=source,
                location=f"line {lineno}",
                kind="text",
                text=line,
                disposition="kept_in_body",
            )
        )
    return tasks, unmapped


def parse_proposal(text: str) -> tuple[dict[str, Any], str | None, dict[str, str]]:
    """Split ``proposal.md`` into (front-matter, title, {section title: body})."""
    try:
        data, body = md.split_front_matter(text)
    except md.FrontMatterError:
        data, body = None, text
    title: str | None = None
    sections: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []

    def flush() -> None:
        if current is not None:
            sections[current] = "\n".join(_trim(buf))

    for line in body.splitlines():
        h1 = _H1_RE.match(line)
        if h1 and title is None and current is None:
            title = h1.group("title")
            continue
        h2 = _H2_RE.match(line)
        if h2:
            flush()
            current = h2.group("title")
            buf = []
            continue
        if current is None:
            if line.strip():
                current = ""
                buf = [line]
            continue
        buf.append(line)
    flush()
    return data or {}, title, sections


def _bullets(body: str) -> list[tuple[str, bool | None]]:
    items: list[tuple[str, bool | None]] = []
    for line in body.splitlines():
        match = _BULLET_RE.match(line)
        if match:
            done = match.group("done")
            items.append((match.group("text"), None if done is None else done.lower() == "x"))
    if not items:
        items = [(line.strip(), None) for line in body.splitlines() if line.strip()]
    return items


# --------------------------------------------------------------------------------------
# Conversion to canonical models
# --------------------------------------------------------------------------------------


def _existing_ids(items: Iterable[str | None], kind: str) -> list[str]:
    return [i for i in items if i and ids.is_valid(kind, i)]


def to_requirements(
    specs: Sequence[OpenSpecRequirement],
) -> tuple[list[Requirement], list[str], dict[str, str]]:
    """Convert parsed OpenSpec requirements to canonical :class:`Requirement` objects.

    Returns ``(requirements, warnings, id_map)``. Explicit ids win; duplicates and invalid
    ids are reassigned with a warning.
    """
    warnings: list[str] = []
    id_map: dict[str, str] = {}
    taken: list[str] = []
    result: list[Requirement] = []
    for spec in specs:
        req_id = spec.id
        if req_id is not None and (req_id in taken or not ids.is_valid("REQ", req_id)):
            warnings.append(f"requirement id {req_id!r} ({spec.name}) reassigned")
            req_id = None
        if req_id is None:
            req_id = ids.next_id("REQ", taken)
        taken.append(req_id)
        id_map[spec.name or req_id] = req_id
        scn_taken: list[str] = []
        scenarios: list[Scenario] = []
        for scn in spec.scenarios:
            scn_id = scn.id
            if scn_id is not None and (
                scn_id in scn_taken
                or not ids.is_valid("SCN", scn_id)
                or ids.scenario_parent(scn_id) != req_id
            ):
                warnings.append(f"scenario id {scn_id!r} ({scn.name}) reassigned under {req_id}")
                scn_id = None
            if scn_id is None:
                scn_id = ids.next_id("SCN", scn_taken, parent=req_id)
            scn_taken.append(scn_id)
            raw = scn.raw
            if not (scn.when and scn.then) and not raw.strip():
                raw = scn.name or scn_id
            scenarios.append(
                Scenario(
                    id=scn_id, name=scn.name, given=scn.given, when=scn.when, then=scn.then, raw=raw
                )
            )
            id_map[f"{spec.name}/{scn.name}" if scn.name else scn_id] = scn_id
        tags: list[str] = []
        if spec.capability:
            tags.append(f"capability:{spec.capability}")
        if spec.section:
            tags.append(f"openspec:{spec.section.lower()}")
        if spec.name and spec.name != req_id:
            tags.append(f"name:{spec.name}")
        kind = _enum_attr(spec.attrs.get("kind"), RequirementKind, RequirementKind.FUNCTIONAL)
        default_priority = Priority.WONT if spec.section == "REMOVED" else Priority.MUST
        priority = _enum_attr(spec.attrs.get("priority"), Priority, default_priority)
        result.append(
            Requirement(
                id=req_id,
                text=spec.text or spec.name or req_id,
                kind=kind,
                priority=priority,
                scenarios=scenarios,
                tags=tags,
            )
        )
    return result, warnings, id_map


def _enum_attr(value: str | None, enum: Any, default: Any) -> Any:
    if value is None:
        return default
    try:
        return enum(value)
    except ValueError:
        return default


def _split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip().strip("`") for v in value.split(",") if v.strip().strip("`")]


def to_tasks(
    parsed: Sequence[OpenSpecTask], known_requirements: Iterable[str] = ()
) -> tuple[list[Task], Plan | None, list[str], dict[str, str]]:
    """Convert parsed tasks to canonical :class:`Task` objects and a :class:`Plan` of waves."""
    warnings: list[str] = []
    id_map: dict[str, str] = {}
    known = set(known_requirements)
    taken: list[str] = []
    assigned: list[tuple[OpenSpecTask, str]] = []
    for item in parsed:
        task_id = item.id
        if task_id is not None and (task_id in taken or not ids.is_valid("TASK", task_id)):
            warnings.append(f"task id {task_id!r} ({item.title}) reassigned")
            task_id = None
        if task_id is None:
            task_id = ids.next_id("TASK", taken)
        taken.append(task_id)
        assigned.append((item, task_id))
        id_map[item.number or item.title] = task_id
    number_to_id = {item.number: tid for item, tid in assigned if item.number}
    tasks: list[Task] = []
    for item, task_id in assigned:
        verification: Verification | None = None
        verify = item.attrs.get("verify")
        if verify:
            match = _VERIFY_RE.match(verify.strip())
            if match:
                verification = Verification(
                    command=match.group("cmd"),
                    expect_exit_code=int(match.group("code") or 0),
                    expect_output_regex=match.group("regex"),
                )
            else:
                verification = Verification(command=verify.strip().strip("`"))
        requirement_ids = [
            r for r in _split_list(item.attrs.get("requirements")) if ids.is_valid("REQ", r)
        ]
        unknown = [r for r in requirement_ids if known and r not in known]
        if unknown:
            warnings.append(f"{task_id} references unknown requirements {unknown}")
        depends: list[str] = []
        for dep in _split_list(item.attrs.get("depends")):
            resolved = dep if ids.is_valid("TASK", dep) else number_to_id.get(dep)
            if resolved and resolved != task_id and resolved in taken:
                depends.append(resolved)
            else:
                warnings.append(f"{task_id} dependency {dep!r} could not be resolved")
        status = TaskStatus.DONE if item.done else TaskStatus.PENDING
        status = _enum_attr(item.attrs.get("status"), TaskStatus, status)
        tier = _enum_attr(item.attrs.get("tier"), ModelTier, None)
        tasks.append(
            Task(
                id=task_id,
                title=item.title or task_id,
                description=item.attrs.get("description", item.group),
                requirement_ids=requirement_ids,
                depends_on=depends,
                verification=verification,
                status=status,
                wave=item.group_index,
                model_tier=tier,
                files=_split_list(item.attrs.get("files")),
            )
        )
    if not tasks:
        return tasks, None, warnings, id_map
    waves: dict[int, Wave] = {}
    for item, task_id in assigned:
        wave = waves.setdefault(
            item.group_index, Wave(index=item.group_index, description=item.group)
        )
        wave.task_ids.append(task_id)
    plan = Plan(summary="Imported from OpenSpec tasks.md", waves=[waves[i] for i in sorted(waves)])
    return tasks, plan, warnings, id_map


# --------------------------------------------------------------------------------------
# Import
# --------------------------------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _humanize(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ").strip().capitalize()


def _capability_of(spec_path: Path, specs_dir: Path) -> str:
    rel = spec_path.parent.relative_to(specs_dir)
    return rel.as_posix() if rel.parts else ""


def import_change(
    change_dir: str | Path,
    *,
    change_id: str | None = None,
    owner: str | None = None,
    risk_class: RiskClass | None = None,
) -> ImportResult:
    """Import ``openspec/changes/<id>/`` into an in-memory :class:`ChangePackage`.

    Nothing is written; call ``result.package.save(dir)`` (or ``package.create`` then save)
    to persist. Unmapped content is preserved as prose bodies and listed in
    ``result.unmapped``.
    """
    directory = Path(change_dir)
    if not directory.is_dir():
        raise OpenSpecError(f"not a directory: {directory}")
    proposal_path = directory / PROPOSAL_FILE
    specs_dir = directory / SPECS_DIR
    if not proposal_path.is_file() and not specs_dir.is_dir():
        raise OpenSpecError(f"{directory} has neither {PROPOSAL_FILE} nor {SPECS_DIR}/")

    unmapped: list[Unmapped] = []
    warnings: list[str] = []
    id_map: dict[str, str] = {}
    bodies: dict[str, str] = {}

    front: dict[str, Any] = {}
    title: str | None = None
    sections: dict[str, str] = {}
    if proposal_path.is_file():
        front, title, sections = parse_proposal(_read(proposal_path))

    slug_source = change_id or str(front.get("change_id") or "")
    if not slug_source:
        raw_title = title or ""
        found = _CHG_ID_RE.search(directory.name) or _CHG_ID_RE.search(raw_title)
        slug_source = found.group(0) if found else directory.name
    cid = slug_source if ids.is_valid("CHG", slug_source) else ids.change_id(slug_source)
    if title:
        title = re.sub(r"^(change|proposal)\s*:\s*", "", title, flags=re.IGNORECASE).strip()
        title, _ = _extract_id(title, _CHG_ID_RE)
    intent_title = title or _humanize(cid.removeprefix("CHG-"))

    kernel = Kernel()
    assumptions: list[Assumption] = []
    questions: list[OpenQuestion] = []
    intent_body: list[str] = []
    for heading, body in sections.items():
        key = heading.strip().lower()
        if key == "why":
            kernel.why = body.strip()
        elif key in ("what changes", "what", "changes", "capabilities"):
            kernel.capabilities = [t for t, _ in _bullets(body)]
        elif key in ("constraints",):
            kernel.constraints = [t for t, _ in _bullets(body)]
        elif key in ("non-goals", "non goals", "out of scope", "not in scope"):
            kernel.non_goals = [t for t, _ in _bullets(body)]
        elif key in ("success signal", "success", "success criteria"):
            kernel.success_signal = body.strip()
        elif key == "assumptions":
            for text, _done in _bullets(body):
                text, asm_id, _ = _strip_id_comment(text)
                asm_id = asm_id if asm_id and ids.is_valid("ASM", asm_id) else None
                assumptions.append(
                    Assumption(
                        id=asm_id or ids.next_id("ASM", [a.id for a in assumptions]),
                        text=text.strip(),
                    )
                )
        elif key == "open questions":
            for text, done in _bullets(body):
                text, oq_id, _ = _strip_id_comment(text)
                oq_id = oq_id if oq_id and ids.is_valid("OQ", oq_id) else None
                question, _, decision = text.partition(" — ")
                blocking = "(blocking)" in question.lower()
                question = re.sub(r"\s*\(blocking\)", "", question, flags=re.IGNORECASE).strip()
                questions.append(
                    OpenQuestion(
                        id=oq_id or ids.next_id("OQ", [q.id for q in questions]),
                        question=question,
                        status=QuestionStatus.RESOLVED if done else QuestionStatus.OPEN,
                        blocking=blocking,
                        decision=decision.strip() or None,
                    )
                )
        else:
            header = f"## {heading}" if heading else ""
            block = "\n".join(x for x in (header, body) if x)
            intent_body.append(block)
            unmapped.append(
                Unmapped(
                    source=PROPOSAL_FILE,
                    location=heading or "(preamble)",
                    kind="section",
                    text=block,
                    disposition="kept_in_body",
                )
            )
    if intent_body:
        bodies[pkgio.INTENT_FILE] = "\n\n".join(intent_body) + "\n"

    intent = Intent(
        id=cid,
        title=intent_title,
        kernel=kernel,
        owner=owner or (str(front["owner"]) if front.get("owner") else None),
        risk_class=risk_class or _enum_attr(front.get("risk_class"), RiskClass, RiskClass.STANDARD),
        stakeholders=[str(s) for s in front.get("stakeholders", [])],
        labels=[str(s) for s in front.get("labels", [])],
    )

    parsed_reqs: list[OpenSpecRequirement] = []
    req_body: list[str] = []
    if specs_dir.is_dir():
        for spec_path in sorted(specs_dir.rglob(SPEC_FILE)):
            capability = _capability_of(spec_path, specs_dir)
            source = spec_path.relative_to(directory).as_posix()
            reqs, extra = parse_spec(_read(spec_path), capability=capability, source=source)
            parsed_reqs.extend(reqs)
            for item in extra:
                unmapped.append(item)
                if item.disposition == "kept_in_body":
                    req_body.append(f"<!-- openspec: {source} -->\n{item.text}")
    requirements, req_warnings, req_map = to_requirements(parsed_reqs)
    warnings.extend(req_warnings)
    id_map.update(req_map)
    if req_body:
        bodies[pkgio.REQUIREMENTS_FILE] = "\n\n".join(req_body) + "\n"

    tasks: list[Task] = []
    plan: Plan | None = None
    tasks_path = directory / TASKS_FILE
    if tasks_path.is_file():
        parsed_tasks, extra = parse_tasks(_read(tasks_path))
        unmapped.extend(extra)
        tasks, plan, task_warnings, task_map = to_tasks(parsed_tasks, [r.id for r in requirements])
        warnings.extend(task_warnings)
        id_map.update(task_map)
        kept = [u.text for u in extra if u.disposition == "kept_in_body"]
        if kept:
            bodies[pkgio.TASKS_FILE] = "\n".join(kept) + "\n"

    design_path = directory / DESIGN_FILE
    if design_path.is_file():
        design = _read(design_path)
        bodies[pkgio.CONTEXT_FILE] = design if design.endswith("\n") else design + "\n"
        unmapped.append(
            Unmapped(
                source=DESIGN_FILE,
                location="(file)",
                kind="design",
                text=design,
                disposition="kept_in_body",
            )
        )

    known = {PROPOSAL_FILE, TASKS_FILE, DESIGN_FILE}
    for other in sorted(directory.iterdir()):
        if other.name in known or other.name == SPECS_DIR or other.name.startswith("."):
            continue
        unmapped.append(
            Unmapped(
                source=other.name,
                location="(file)",
                kind="file",
                text=str(other),
                disposition="not_imported",
            )
        )

    package = ChangePackage(
        intent=intent,
        requirements=requirements,
        assumptions=assumptions,
        open_questions=questions,
        plan=plan,
        tasks=tasks,
        bodies=bodies,
    )
    return ImportResult(package=package, unmapped=unmapped, warnings=warnings, id_map=id_map)


# --------------------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------------------


def _tag_value(req: Requirement, prefix: str) -> str | None:
    for tag in req.tags:
        if tag.startswith(prefix + ":"):
            return tag[len(prefix) + 1 :]
    return None


def _render_scenario(scn: Scenario) -> str:
    lines = [f"#### Scenario: {scn.name or scn.id}", f"<!-- aisdlc-id: {scn.id} -->"]
    if scn.when and scn.then:
        if scn.given:
            lines.append(f"- **GIVEN** {scn.given}")
        lines.append(f"- **WHEN** {scn.when}")
        lines.append(f"- **THEN** {scn.then}")
    else:
        lines.append(scn.raw.rstrip())
    return "\n".join(lines)


def _render_requirement(req: Requirement) -> str:
    name = _tag_value(req, "name") or req.id
    lines = [
        f"### Requirement: {name}",
        f"<!-- aisdlc-id: {req.id} kind={req.kind.value} priority={req.priority.value} -->",
        req.text.rstrip(),
    ]
    for scn in req.scenarios:
        lines.append("")
        lines.append(_render_scenario(scn))
    return "\n".join(lines)


def render_spec(requirements: Sequence[Requirement], *, preamble: str = "") -> str:
    """Render requirements as an OpenSpec delta ``spec.md`` (sections from ``openspec:`` tags)."""
    by_section: dict[str, list[Requirement]] = {}
    for req in requirements:
        section = (_tag_value(req, "openspec") or "added").upper()
        by_section.setdefault(section, []).append(req)
    parts: list[str] = []
    if preamble.strip():
        parts.append(preamble.rstrip())
    for section in [
        *(s for s in _SECTIONS if s in by_section),
        *sorted(set(by_section) - set(_SECTIONS)),
    ]:
        parts.append(f"## {section} Requirements")
        parts.extend(_render_requirement(r) for r in by_section[section])
    return "\n\n".join(parts) + "\n"


def _render_task(task: Task, number: str) -> str:
    box = "x" if task.status == TaskStatus.DONE else " "
    lines = [f"- [{box}] {number} {task.title} <!-- aisdlc-id: {task.id} -->"]
    if task.status not in (TaskStatus.DONE, TaskStatus.PENDING):
        lines.append(f"  - status: {task.status.value}")
    if task.description:
        lines.append(f"  - description: {task.description}")
    if task.requirement_ids:
        lines.append(f"  - requirements: {', '.join(task.requirement_ids)}")
    if task.depends_on:
        lines.append(f"  - depends: {', '.join(task.depends_on)}")
    if task.files:
        lines.append("  - files: " + ", ".join(f"`{f}`" for f in task.files))
    if task.model_tier is not None:
        lines.append(f"  - tier: {task.model_tier.value}")
    if task.verification is not None:
        ver = task.verification
        text = f"`{ver.command}` (exit {ver.expect_exit_code})"
        if ver.expect_output_regex:
            text += f" /{ver.expect_output_regex}/"
        lines.append(f"  - verify: {text}")
    return "\n".join(lines)


def render_tasks(pkg: ChangePackage) -> str:
    """Render tasks grouped by plan wave as OpenSpec ``tasks.md``."""
    by_id = {t.id: t for t in pkg.tasks}
    groups: list[tuple[str, list[Task]]] = []
    placed: set[str] = set()
    if pkg.plan is not None:
        for wave in pkg.plan.waves:
            members = [by_id[t] for t in wave.task_ids if t in by_id]
            placed.update(t.id for t in members)
            label = wave.description or f"Wave {wave.index}"
            if wave.checkpoint:
                label += " (checkpoint)"
            groups.append((label, members))
    rest = [t for t in pkg.tasks if t.id not in placed]
    if rest:
        groups.append(("Tasks", rest))
    parts = ["# Tasks"]
    for gi, (label, members) in enumerate(groups, start=1):
        block = [f"## {gi}. {label}"]
        block.extend(_render_task(t, f"{gi}.{ti}") for ti, t in enumerate(members, start=1))
        parts.append("\n".join(block))
    body = pkg.bodies.get(pkgio.TASKS_FILE, "").strip()
    if body:
        parts.append(body)
    return "\n\n".join(parts) + "\n"


def render_proposal(pkg: ChangePackage) -> str:
    """Render ``proposal.md`` (front-matter carries owner/risk; sections carry the kernel)."""
    intent = pkg.intent
    front: dict[str, Any] = {"change_id": intent.id, "risk_class": intent.risk_class.value}
    if intent.owner:
        front["owner"] = intent.owner
    if intent.stakeholders:
        front["stakeholders"] = list(intent.stakeholders)
    if intent.labels:
        front["labels"] = list(intent.labels)
    k = intent.kernel
    parts = [f"# Change: {intent.title}", "## Why", k.why.strip() or "(not stated)"]
    parts.append(
        "## What Changes\n"
        + ("".join(f"- {c}\n" for c in k.capabilities) or "- (not stated)\n").rstrip()
    )
    if k.constraints:
        parts.append("## Constraints\n" + "".join(f"- {c}\n" for c in k.constraints).rstrip())
    if k.non_goals:
        parts.append("## Non-Goals\n" + "".join(f"- {c}\n" for c in k.non_goals).rstrip())
    if k.success_signal.strip():
        parts.append("## Success Signal\n" + k.success_signal.strip())
    if pkg.assumptions:
        parts.append(
            "## Assumptions\n"
            + "".join(f"- {a.text} <!-- aisdlc-id: {a.id} -->\n" for a in pkg.assumptions).rstrip()
        )
    if pkg.open_questions:
        lines = []
        for q in pkg.open_questions:
            box = "x" if q.status == QuestionStatus.RESOLVED else " "
            text = q.question + (" (blocking)" if q.blocking else "")
            if q.decision:
                text += f" — {q.decision}"
            lines.append(f"- [{box}] {text} <!-- aisdlc-id: {q.id} -->")
        parts.append("## Open Questions\n" + "\n".join(lines))
    body = pkg.bodies.get(pkgio.INTENT_FILE, "").strip()
    if body:
        parts.append(body)
    return md.join_front_matter(front, "\n\n".join(parts) + "\n")


def render_design(pkg: ChangePackage) -> str | None:
    """Render ``design.md`` from the architecture context, ADRs, interfaces and threats."""
    parts: list[str] = []
    context = pkg.bodies.get(pkgio.CONTEXT_FILE, "").strip()
    if context:
        parts.append(context)
    if pkg.decisions:
        block = ["## Decisions"]
        for adr in pkg.decisions:
            block.append(f"### {adr.id}: {adr.title} ({adr.status.value})")
            if adr.context:
                block.append(f"Context: {adr.context}")
            if adr.decision:
                block.append(f"Decision: {adr.decision}")
        parts.append("\n\n".join(block))
    if pkg.interfaces:
        block = ["## Interfaces"]
        block.extend(f"- {i.id} {i.name} ({i.kind.value}): {i.description}" for i in pkg.interfaces)
        parts.append("\n".join(block))
    if pkg.threat_model is not None and pkg.threat_model.threats:
        block = ["## Threat Model"]
        block.extend(
            f"- {t.id} [{t.severity.value}/{t.status.value}] {t.title}: {t.description}"
            for t in pkg.threat_model.threats
        )
        parts.append("\n".join(block))
    if not parts:
        return None
    return "\n\n".join(parts) + "\n"


def export_change(
    pkg: ChangePackage, out_dir: str | Path, *, capability: str | None = None
) -> ExportResult:
    """Write *pkg* as an OpenSpec change directory at *out_dir* (created if needed).

    Requirements are grouped into ``specs/<capability>/spec.md`` by their ``capability:``
    tag (default: *capability* or the change slug). Evidence, verdicts and other content
    OpenSpec has no home for are reported in ``result.unmapped``.
    """
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    unmapped: list[Unmapped] = []

    proposal = directory / PROPOSAL_FILE
    proposal.write_text(render_proposal(pkg), encoding="utf-8")
    files.append(proposal)

    default_cap = capability or pkg.change_id.removeprefix("CHG-")
    by_cap: dict[str, list[Requirement]] = {}
    for req in pkg.requirements:
        by_cap.setdefault(_tag_value(req, "capability") or default_cap, []).append(req)
    if not by_cap:
        by_cap[default_cap] = []
    req_body = pkg.bodies.get(pkgio.REQUIREMENTS_FILE, "")
    first = True
    for cap, reqs in by_cap.items():
        spec_path = directory / SPECS_DIR / cap / SPEC_FILE
        spec_path.parent.mkdir(parents=True, exist_ok=True)
        spec_path.write_text(
            render_spec(reqs, preamble=req_body if first else ""), encoding="utf-8"
        )
        files.append(spec_path)
        first = False

    if pkg.tasks:
        tasks_path = directory / TASKS_FILE
        tasks_path.write_text(render_tasks(pkg), encoding="utf-8")
        files.append(tasks_path)

    design = render_design(pkg)
    if design is not None:
        design_path = directory / DESIGN_FILE
        design_path.write_text(design, encoding="utf-8")
        files.append(design_path)

    evidence_ids = pkg.evidence.ids()
    if evidence_ids:
        unmapped.append(
            Unmapped(
                source="evidence/",
                location=", ".join(evidence_ids),
                kind="evidence",
                text=f"{len(evidence_ids)} evidence record(s) have no OpenSpec equivalent",
                disposition="not_exported",
            )
        )
    if pkg.final_verdict is not None:
        unmapped.append(
            Unmapped(
                source=pkgio.FINAL_VERDICT_FILE,
                location="(file)",
                kind="verdict",
                text=f"final verdict overall={pkg.final_verdict.overall}",
                disposition="not_exported",
            )
        )
    if pkg.threat_model is not None and (pkg.threat_model.mitigations or pkg.threat_model.assets):
        unmapped.append(
            Unmapped(
                source=pkgio.THREAT_MODEL_FILE,
                location="assets/mitigations/manifest",
                kind="threat_model",
                text="only threats are rendered into design.md; assets, mitigations and the "
                "tool/data manifest are not exported",
                disposition="not_exported",
            )
        )
    for rel in pkg.bodies:
        if rel not in (
            pkgio.INTENT_FILE,
            pkgio.REQUIREMENTS_FILE,
            pkgio.TASKS_FILE,
            pkgio.CONTEXT_FILE,
        ):
            if pkg.bodies[rel].strip():
                unmapped.append(
                    Unmapped(
                        source=rel,
                        location="(body)",
                        kind="prose",
                        text=pkg.bodies[rel],
                        disposition="not_exported",
                    )
                )
    return ExportResult(out_dir=directory, files=files, unmapped=unmapped)
