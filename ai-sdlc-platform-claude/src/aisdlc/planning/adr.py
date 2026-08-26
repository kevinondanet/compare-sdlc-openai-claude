"""Architecture decision records (MADR-style) — creation, rendering, parsing, validation.

An ADR lives at ``architecture/decisions/ADR-nnnn.md``: front-matter is the
:class:`~aisdlc.schema.models.ArchitectureDecision`, the body is MADR prose. Because the
canonical model has no ``requirement_ids`` field (``extra="forbid"``), the related
requirements are kept in a ``## Related requirements`` body section and round-tripped
through :class:`AdrDocument`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path

from pydantic import Field, ValidationError

from aisdlc import ids
from aisdlc.ids import RequirementId
from aisdlc.schema import markdown as md
from aisdlc.schema.grammar import IssueSeverity, ValidationIssue
from aisdlc.schema.models import AdrStatus, ArchitectureDecision, ArtifactModel, utcnow
from aisdlc.schema.package import DECISIONS_DIR

__all__ = [
    "RELATED_SECTION",
    "AdrError",
    "AdrDocument",
    "new_adr",
    "madr_body",
    "related_requirement_ids",
    "with_related_section",
    "render_adr",
    "parse_adr",
    "adr_path",
    "write_adr",
    "read_adr",
    "list_adrs",
    "validate_adr",
    "validate_adrs",
]

RELATED_SECTION = "## Related requirements"
"""Body heading under which related requirement ids are listed."""

_REQ_RE = re.compile(r"\bREQ-\d{3,}\b")
_HEADING_RE = re.compile(r"^##\s+", re.MULTILINE)


class AdrError(ValueError):
    """An ADR file could not be read or parsed."""


class AdrDocument(ArtifactModel):
    """An ADR with its body and the requirement ids it relates to."""

    decision: ArchitectureDecision
    requirement_ids: list[RequirementId] = Field(default_factory=list)
    body: str = ""

    @property
    def id(self) -> str:
        """The ``ADR-nnnn`` id."""
        return self.decision.id


# --------------------------------------------------------------------------------------
# Creation and rendering
# --------------------------------------------------------------------------------------


def new_adr(
    title: str,
    *,
    existing_ids: Iterable[str] = (),
    status: AdrStatus = AdrStatus.PROPOSED,
    context: str = "",
    decision: str = "",
    consequences: Iterable[str] = (),
    alternatives: Iterable[str] = (),
    requirement_ids: Iterable[str] = (),
    supersedes: str | None = None,
    deciders: Iterable[str] = (),
    date: datetime | None = None,
) -> AdrDocument:
    """Create a new ADR with the next free id after *existing_ids*.

    The body is generated with :func:`madr_body`. *date* defaults to now.
    """
    if not title.strip():
        raise AdrError("ADR title must not be empty")
    adr_id = ids.next_id("ADR", existing_ids)
    try:
        record = ArchitectureDecision(
            id=adr_id,
            title=title.strip(),
            status=status,
            context=context,
            decision=decision,
            consequences=[c for c in consequences if c.strip()],
            alternatives=[a for a in alternatives if a.strip()],
            supersedes=supersedes,
            date=date if date is not None else utcnow(),
            deciders=[d for d in deciders if d.strip()],
        )
    except ValidationError as exc:
        raise AdrError(str(exc)) from exc
    req_ids = [ids.validate_id("REQ", r) for r in requirement_ids]
    return AdrDocument(decision=record, requirement_ids=req_ids, body=madr_body(record, req_ids))


def madr_body(decision: ArchitectureDecision, requirement_ids: Sequence[str] = ()) -> str:
    """MADR prose body for *decision* (Context, Decision, Consequences, Alternatives …)."""

    def bullets(items: Sequence[str]) -> str:
        return "\n".join(f"- {item}" for item in items) if items else "- (none recorded)"

    parts = [
        f"# {decision.id}: {decision.title}",
        "",
        f"Status: {decision.status.value}",
        "",
        "## Context",
        "",
        decision.context.strip() or "(describe the forces at play)",
        "",
        "## Decision",
        "",
        decision.decision.strip() or "(state the decision)",
        "",
        "## Consequences",
        "",
        bullets(decision.consequences),
        "",
        "## Alternatives considered",
        "",
        bullets(decision.alternatives),
        "",
    ]
    if decision.supersedes:
        parts += ["## Supersedes", "", f"- {decision.supersedes}", ""]
    body = "\n".join(parts)
    return with_related_section(body, requirement_ids)


def related_requirement_ids(body: str) -> list[str]:
    """Requirement ids listed under :data:`RELATED_SECTION` in *body* (in order)."""
    start = body.find(RELATED_SECTION)
    if start < 0:
        return []
    section = body[start + len(RELATED_SECTION) :]
    next_heading = _HEADING_RE.search(section)
    if next_heading:
        section = section[: next_heading.start()]
    found: list[str] = []
    for req_id in _REQ_RE.findall(section):
        if req_id not in found:
            found.append(req_id)
    return found


def with_related_section(body: str, requirement_ids: Sequence[str]) -> str:
    """Return *body* with the related-requirements section set to *requirement_ids*.

    An existing section is replaced in place; otherwise it is appended. With no ids the
    section is removed.
    """
    section_text = ""
    if requirement_ids:
        section_text = (
            RELATED_SECTION + "\n\n" + "\n".join(f"- {req}" for req in requirement_ids) + "\n"
        )
    start = body.find(RELATED_SECTION)
    if start < 0:
        if not section_text:
            return body
        if body and not body.endswith("\n"):
            body += "\n"
        if body and not body.endswith("\n\n"):
            body += "\n"
        return body + section_text
    rest = body[start + len(RELATED_SECTION) :]
    next_heading = _HEADING_RE.search(rest)
    end = start + len(RELATED_SECTION) + (next_heading.start() if next_heading else len(rest))
    tail = body[end:]
    if section_text and tail and not tail.startswith("\n"):
        section_text += "\n"
    return body[:start] + section_text + tail


def render_adr(doc: AdrDocument) -> str:
    """Render an ADR document to markdown (front-matter + body with related section)."""
    body = doc.body if doc.body.strip() else madr_body(doc.decision, doc.requirement_ids)
    body = with_related_section(body, doc.requirement_ids)
    return md.adr_to_markdown(doc.decision, body)


def parse_adr(text: str) -> AdrDocument:
    """Parse ADR markdown into an :class:`AdrDocument`."""
    try:
        decision, body = md.adr_from_markdown(text)
    except (md.FrontMatterError, ValidationError) as exc:
        raise AdrError(str(exc)) from exc
    return AdrDocument(decision=decision, requirement_ids=related_requirement_ids(body), body=body)


# --------------------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------------------


def adr_path(package_dir: str | Path, adr_id: str) -> Path:
    """``<package>/architecture/decisions/<ADR-id>.md``."""
    ids.validate_id("ADR", adr_id)
    return Path(package_dir) / DECISIONS_DIR / f"{adr_id}.md"


def write_adr(package_dir: str | Path, doc: AdrDocument) -> Path:
    """Write *doc* into the package's decisions directory and return the path."""
    path = adr_path(package_dir, doc.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_adr(doc), encoding="utf-8")
    return path


def read_adr(path: str | Path) -> AdrDocument:
    """Read one ADR file."""
    file = Path(path)
    try:
        doc = parse_adr(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AdrError(f"{file}: {exc}") from exc
    except AdrError as exc:
        raise AdrError(f"{file}: {exc}") from exc
    if file.stem != doc.id:
        raise AdrError(f"{file}: file name does not match ADR id {doc.id}")
    return doc


def list_adrs(package_dir: str | Path) -> list[AdrDocument]:
    """All ADR documents of a package, sorted by id."""
    directory = Path(package_dir) / DECISIONS_DIR
    if not directory.is_dir():
        return []
    return [read_adr(p) for p in sorted(directory.glob("ADR-*.md"))]


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------


def _issue(
    code: str,
    message: str,
    *,
    severity: IssueSeverity = IssueSeverity.ERROR,
    artifact_id: str | None = None,
) -> ValidationIssue:
    return ValidationIssue(code=code, severity=severity, message=message, artifact_id=artifact_id)


def validate_adr(
    decision: ArchitectureDecision,
    *,
    requirement_ids: Iterable[str] = (),
    known_adrs: Iterable[ArchitectureDecision] | None = None,
    known_requirements: Iterable[str] | None = None,
) -> list[ValidationIssue]:
    """Validate one ADR.

    Codes: ``ADR_TITLE_EMPTY``, ``ADR_CONTEXT_EMPTY``, ``ADR_DECISION_EMPTY`` (errors for
    accepted ADRs, warnings otherwise), ``ADR_NO_CONSEQUENCES``, ``ADR_NO_ALTERNATIVES``,
    ``ADR_NO_DECIDERS``, ``ADR_NO_DATE`` (warnings for accepted), ``ADR_SUPERSEDES_SELF``,
    ``ADR_SUPERSEDES_UNKNOWN``, ``ADR_SUPERSEDED_TARGET_STATUS``,
    ``ADR_SUPERSEDED_NO_SUCCESSOR``, ``ADR_UNKNOWN_REQUIREMENT``, ``ADR_NO_REQUIREMENTS``.
    """
    issues: list[ValidationIssue] = []
    accepted = decision.status is AdrStatus.ACCEPTED
    strict = IssueSeverity.ERROR if accepted else IssueSeverity.WARNING
    aid = decision.id

    if not decision.title.strip():
        issues.append(_issue("ADR_TITLE_EMPTY", "ADR has no title", artifact_id=aid))
    if not decision.context.strip():
        issues.append(
            _issue("ADR_CONTEXT_EMPTY", "context is empty", severity=strict, artifact_id=aid)
        )
    if not decision.decision.strip():
        issues.append(
            _issue("ADR_DECISION_EMPTY", "decision is empty", severity=strict, artifact_id=aid)
        )
    if not decision.consequences:
        issues.append(
            _issue(
                "ADR_NO_CONSEQUENCES",
                "no consequences recorded",
                severity=IssueSeverity.WARNING,
                artifact_id=aid,
            )
        )
    if accepted and not decision.alternatives:
        issues.append(
            _issue(
                "ADR_NO_ALTERNATIVES",
                "accepted ADR records no alternatives considered",
                severity=IssueSeverity.WARNING,
                artifact_id=aid,
            )
        )
    if accepted and not decision.deciders:
        issues.append(
            _issue(
                "ADR_NO_DECIDERS",
                "accepted ADR names no deciders",
                severity=IssueSeverity.WARNING,
                artifact_id=aid,
            )
        )
    if accepted and decision.date is None:
        issues.append(
            _issue(
                "ADR_NO_DATE",
                "accepted ADR has no date",
                severity=IssueSeverity.WARNING,
                artifact_id=aid,
            )
        )

    if decision.supersedes is not None:
        if decision.supersedes == decision.id:
            issues.append(_issue("ADR_SUPERSEDES_SELF", "ADR supersedes itself", artifact_id=aid))
        elif known_adrs is not None:
            by_id = {a.id: a for a in known_adrs}
            target = by_id.get(decision.supersedes)
            if target is None:
                issues.append(
                    _issue(
                        "ADR_SUPERSEDES_UNKNOWN",
                        f"supersedes unknown {decision.supersedes}",
                        artifact_id=aid,
                    )
                )
            elif accepted and target.status not in (AdrStatus.SUPERSEDED, AdrStatus.DEPRECATED):
                issues.append(
                    _issue(
                        "ADR_SUPERSEDED_TARGET_STATUS",
                        f"{target.id} is superseded by this ADR but its status is "
                        f"{target.status.value}",
                        severity=IssueSeverity.WARNING,
                        artifact_id=aid,
                    )
                )
    if decision.status is AdrStatus.SUPERSEDED and known_adrs is not None:
        successors = [a.id for a in known_adrs if a.supersedes == decision.id]
        if not successors:
            issues.append(
                _issue(
                    "ADR_SUPERSEDED_NO_SUCCESSOR",
                    "status is superseded but no other ADR supersedes it",
                    severity=IssueSeverity.WARNING,
                    artifact_id=aid,
                )
            )

    req_list = list(requirement_ids)
    if known_requirements is not None:
        known = set(known_requirements)
        for req_id in req_list:
            if req_id not in known:
                issues.append(
                    _issue(
                        "ADR_UNKNOWN_REQUIREMENT",
                        f"relates to unknown requirement {req_id}",
                        artifact_id=aid,
                    )
                )
    if not req_list:
        issues.append(
            _issue(
                "ADR_NO_REQUIREMENTS",
                "ADR is not linked to any requirement",
                severity=IssueSeverity.WARNING,
                artifact_id=aid,
            )
        )
    return issues


def validate_adrs(
    docs: Sequence[AdrDocument], *, known_requirements: Iterable[str] | None = None
) -> list[ValidationIssue]:
    """Validate a set of ADRs together (duplicate ids, supersedes chains)."""
    issues: list[ValidationIssue] = []
    seen: set[str] = set()
    for doc in docs:
        if doc.id in seen:
            issues.append(_issue("ADR_DUPLICATE_ID", "duplicate ADR id", artifact_id=doc.id))
        seen.add(doc.id)
    known = [d.decision for d in docs]
    known_reqs = list(known_requirements) if known_requirements is not None else None
    for doc in docs:
        issues.extend(
            validate_adr(
                doc.decision,
                requirement_ids=doc.requirement_ids,
                known_adrs=known,
                known_requirements=known_reqs,
            )
        )
    return issues
