"""Cross-artifact consistency analysis (Spec Kit ``/analyze`` equivalent).

Checks requirements against scenarios, tasks, the plan, ADRs, interfaces and the threat
model and reports :class:`AnalysisFinding` records with a :class:`~aisdlc.schema.models.Severity`.
This module also hosts the deterministic text utilities (normalisation, similarity,
quantity extraction, terminology drift) shared by the other intake modules.

Everything here is pure: no I/O, no network, no model calls.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from difflib import SequenceMatcher
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.schema.models import ChangePackage, Requirement, RiskClass, Severity

__all__ = [
    "STOPWORDS",
    "SYNONYM_GROUPS",
    "Quantity",
    "QuantifierConflict",
    "DuplicatePair",
    "TerminologyDrift",
    "AnalysisFinding",
    "AnalysisReport",
    "content_words",
    "normalize_text",
    "similarity",
    "is_negated",
    "extract_quantities",
    "find_conflicting_quantifiers",
    "find_duplicates",
    "find_contradictions",
    "find_terminology_drift",
    "artifact_texts",
    "analyze",
]

# --------------------------------------------------------------------------------------
# Text normalisation and similarity
# --------------------------------------------------------------------------------------

STOPWORDS: Final[frozenset[str]] = frozenset(
    """
    a an the and or but if then else when while where given of to in on at by for from
    with without into onto over under as is are was were be been being has have had do
    does did shall must should may might can could will would not no nor so that this
    these those it its they them their there here than too very each every all any some
    such only own same also via per about above after again against before below between
    both during further more most other out up down off once through system change user
    users
    """.split()
)
"""Words ignored by :func:`content_words`. Includes modals and generic nouns."""

_WORD_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z][A-Za-z0-9'-]*")
_SUFFIXES: Final[tuple[str, ...]] = ("ing", "ies", "es", "ed", "s")


def _stem(word: str) -> str:
    for suffix in _SUFFIXES:
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            stem = word[: -len(suffix)]
            return stem + "y" if suffix == "ies" else stem
    return word


def content_words(text: str) -> list[str]:
    """Lower-cased, lightly stemmed content words of *text* (stopwords removed)."""
    out: list[str] = []
    for match in _WORD_RE.finditer(text):
        word = match.group(0).lower().strip("'-")
        if len(word) < 3 or word in STOPWORDS:
            continue
        out.append(_stem(word))
    return out


def normalize_text(text: str) -> str:
    """Canonical form used for similarity: content words joined by single spaces."""
    return " ".join(content_words(text))


def similarity(a: str, b: str) -> float:
    """Similarity of two statements in [0, 1].

    The maximum of the Jaccard overlap of content words and the ``difflib`` ratio of the
    normalised texts, so both re-ordered and lightly re-worded duplicates score high.
    """
    words_a, words_b = set(content_words(a)), set(content_words(b))
    if not words_a and not words_b:
        return 1.0 if a.strip() == b.strip() else 0.0
    if not words_a or not words_b:
        return 0.0
    jaccard = len(words_a & words_b) / len(words_a | words_b)
    ratio = SequenceMatcher(None, normalize_text(a), normalize_text(b)).ratio()
    return round(max(jaccard, ratio), 4)


_NEGATED: Final[re.Pattern[str]] = re.compile(r"\b(SHALL|MUST)\s+NOT\b")


def is_negated(text: str) -> bool:
    """``True`` when the statement is a prohibition (``SHALL NOT`` / ``MUST NOT``)."""
    return _NEGATED.search(text) is not None


# --------------------------------------------------------------------------------------
# Quantities
# --------------------------------------------------------------------------------------

_UNITS: Final[dict[str, str]] = {
    "%": "%",
    "percent": "%",
    "ms": "ms",
    "millisecond": "ms",
    "milliseconds": "ms",
    "s": "s",
    "sec": "s",
    "secs": "s",
    "second": "s",
    "seconds": "s",
    "min": "min",
    "mins": "min",
    "minute": "min",
    "minutes": "min",
    "h": "h",
    "hr": "h",
    "hrs": "h",
    "hour": "h",
    "hours": "h",
    "day": "d",
    "days": "d",
    "week": "w",
    "weeks": "w",
    "month": "mo",
    "months": "mo",
    "year": "y",
    "years": "y",
    "kb": "KB",
    "mb": "MB",
    "gb": "GB",
    "tb": "TB",
    "byte": "B",
    "bytes": "B",
    "user": "users",
    "users": "users",
    "request": "requests",
    "requests": "requests",
    "rps": "rps",
    "qps": "rps",
    "tps": "rps",
    "record": "records",
    "records": "records",
    "item": "items",
    "items": "items",
    "retry": "retries",
    "retries": "retries",
    "attempt": "attempts",
    "attempts": "attempts",
    "character": "chars",
    "characters": "chars",
    "char": "chars",
    "chars": "chars",
}
_UNIT_ALTERNATION: Final[str] = "|".join(
    re.escape(u) for u in sorted(_UNITS, key=len, reverse=True)
)
_QUANTITY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<value>\d+(?:[.,]\d+)?)\s*(?P<unit>{_UNIT_ALTERNATION})(?![A-Za-z])",
    re.I,
)
_UPPER_BOUND: Final[re.Pattern[str]] = re.compile(
    r"\b(within|under|below|at most|no more than|not more than|maximum|max|up to|less than|"
    r"not exceed|no later than|faster than|shorter than|newer than|fewer than)\b\s*$",
    re.I,
)
_LOWER_BOUND: Final[re.Pattern[str]] = re.compile(
    r"\b(at least|more than|over|minimum|min|no less than|not less than|exceeds?|greater than|"
    r"older than|longer than|later than|slower than)\b\s*$",
    re.I,
)


class Quantity(BaseModel):
    """A numeric quantity with a unit found in an artifact."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    value: float
    unit: str = Field(description="Canonical unit (``ms``, ``s``, ``%``, ``users`` …).")
    raw: str = Field(description="Surface text as written, e.g. ``200 ms``.")
    bound: str | None = Field(
        default=None, description="``upper``, ``lower`` or ``None`` (unqualified)."
    )
    context: str = Field(default="", description="Statement with the quantity removed.")


def extract_quantities(text: str, artifact_id: str = "") -> list[Quantity]:
    """Find every ``<number> <unit>`` occurrence in *text*."""
    found: list[Quantity] = []
    for match in _QUANTITY_RE.finditer(text):
        before = text[: match.start()]
        bound: str | None = None
        if _UPPER_BOUND.search(before):
            bound = "upper"
        elif _LOWER_BOUND.search(before):
            bound = "lower"
        value = float(match.group("value").replace(",", "."))
        found.append(
            Quantity(
                artifact_id=artifact_id,
                value=value,
                unit=_UNITS[match.group("unit").lower()],
                raw=match.group(0),
                bound=bound,
                context=normalize_text(_QUANTITY_RE.sub(" ", text)),
            )
        )
    return found


class QuantifierConflict(BaseModel):
    """Two similar statements that disagree on a quantity of the same unit."""

    model_config = ConfigDict(extra="forbid")

    left: Quantity
    right: Quantity
    similarity: float

    @property
    def artifact_ids(self) -> list[str]:
        """Ids of the two statements involved."""
        return [self.left.artifact_id, self.right.artifact_id]


def find_conflicting_quantifiers(
    statements: Iterable[tuple[str, str]], *, min_similarity: float = 0.4
) -> list[QuantifierConflict]:
    """Detect conflicting quantities across similar statements.

    Two quantities conflict when they share a unit, differ in value, sit in statements
    whose remaining content is similar (>= *min_similarity*) and are not an explicit
    range (one lower bound and one upper bound). Unbounded values inside scenarios
    (``SCN-…``) are concrete test data (``a link issued 16 minutes ago``) and are never
    treated as limits.
    """
    quantities: list[Quantity] = []
    for artifact_id, text in statements:
        quantities.extend(extract_quantities(text, artifact_id))
    conflicts: list[QuantifierConflict] = []
    for i, left in enumerate(quantities):
        for right in quantities[i + 1 :]:
            if left.artifact_id == right.artifact_id or left.unit != right.unit:
                continue
            if left.value == right.value:
                continue
            if {left.bound, right.bound} == {"upper", "lower"}:
                continue
            if any(q.bound is None and ids.kind_of(q.artifact_id) == "SCN" for q in (left, right)):
                continue
            score = similarity(left.context, right.context)
            if score >= min_similarity:
                conflicts.append(QuantifierConflict(left=left, right=right, similarity=score))
    return conflicts


# --------------------------------------------------------------------------------------
# Duplicates and contradictions
# --------------------------------------------------------------------------------------


class DuplicatePair(BaseModel):
    """Two requirements whose normalised text is (near-)identical."""

    model_config = ConfigDict(extra="forbid")

    left_id: str
    right_id: str
    similarity: float


def find_duplicates(
    requirements: Sequence[Requirement], *, threshold: float = 0.8
) -> list[DuplicatePair]:
    """Pairs of requirements with normalised-text similarity >= *threshold*."""
    pairs: list[DuplicatePair] = []
    for i, left in enumerate(requirements):
        for right in requirements[i + 1 :]:
            if is_negated(left.text) != is_negated(right.text):
                continue
            score = similarity(left.text, right.text)
            if score >= threshold:
                pairs.append(DuplicatePair(left_id=left.id, right_id=right.id, similarity=score))
    return pairs


def find_contradictions(
    requirements: Sequence[Requirement], *, threshold: float = 0.6
) -> list[DuplicatePair]:
    """Pairs of similar requirements where exactly one is a ``SHALL NOT`` prohibition."""
    pairs: list[DuplicatePair] = []
    for i, left in enumerate(requirements):
        for right in requirements[i + 1 :]:
            if is_negated(left.text) == is_negated(right.text):
                continue
            score = similarity(left.text, right.text)
            if score >= threshold:
                pairs.append(DuplicatePair(left_id=left.id, right_id=right.id, similarity=score))
    return pairs


# --------------------------------------------------------------------------------------
# Terminology drift
# --------------------------------------------------------------------------------------

SYNONYM_GROUPS: Final[tuple[tuple[str, ...], ...]] = (
    ("log in", "login", "log on", "logon", "sign in", "signin", "sign on"),
    ("log out", "logout", "sign out", "signout"),
    ("e-mail", "email", "mail"),
    ("administrator", "admin"),
    ("configuration", "config"),
    ("repository", "repo"),
    ("authentication", "auth"),
    ("authorisation", "authorization", "authz"),
    ("database", "db"),
    ("multi-factor authentication", "multifactor authentication", "mfa", "2fa", "two-factor"),
    ("single sign-on", "single sign on", "sso"),
    ("web site", "website"),
    ("data set", "dataset"),
    ("time out", "timeout"),
    ("file name", "filename"),
    ("user name", "username"),
    ("back end", "back-end", "backend"),
    ("front end", "front-end", "frontend"),
    ("pull request", "merge request", "pr"),
    ("customer", "client", "end user", "end-user"),
)
"""Known synonym clusters; using two variants of one cluster is terminology drift."""

_SYNONYM_PATTERNS: Final[list[tuple[str, str, re.Pattern[str]]]] = [
    (group[0], variant, re.compile(rf"(?<![\w-]){re.escape(variant)}(?![\w-])", re.I))
    for group in SYNONYM_GROUPS
    for variant in group
]


class TerminologyDrift(BaseModel):
    """One concept written in several ways across artifacts."""

    model_config = ConfigDict(extra="forbid")

    concept: str = Field(description="Canonical spelling or synonym-group head.")
    variants: dict[str, list[str]] = Field(
        description="Surface form -> artifact ids using it (sorted)."
    )

    @property
    def artifact_ids(self) -> list[str]:
        """All artifacts touched by this drift."""
        return sorted({a for used in self.variants.values() for a in used})


def _spelling_variants(statements: Sequence[tuple[str, str]]) -> dict[str, dict[str, set[str]]]:
    """Group hyphen/space spelling variants: key -> surface -> artifact ids."""
    forms: dict[str, dict[str, set[str]]] = {}
    for artifact_id, text in statements:
        words = [w.lower().strip("'-") for w in _WORD_RE.findall(text)]
        candidates = list(words) + [f"{a} {b}" for a, b in zip(words, words[1:], strict=False)]
        for surface in candidates:
            key = re.sub(r"[^a-z0-9]", "", surface)
            if len(key) < 6 or not (("-" in surface) or (" " in surface) or key == surface):
                continue
            forms.setdefault(key, {}).setdefault(surface, set()).add(artifact_id)
    return forms


def find_terminology_drift(statements: Sequence[tuple[str, str]]) -> list[TerminologyDrift]:
    """Detect inconsistent terminology across ``(artifact id, text)`` statements.

    Two detectors: (1) several members of one :data:`SYNONYM_GROUPS` cluster in use, and
    (2) the same token written with different hyphenation/spacing (``multi-factor`` vs
    ``multifactor`` vs ``multi factor``).
    """
    drifts: list[TerminologyDrift] = []
    by_group: dict[str, dict[str, set[str]]] = {}
    for head, variant, pattern in _SYNONYM_PATTERNS:
        for artifact_id, text in statements:
            if pattern.search(text):
                by_group.setdefault(head, {}).setdefault(variant, set()).add(artifact_id)
    for head, variants in sorted(by_group.items()):
        if len(variants) >= 2:
            drifts.append(
                TerminologyDrift(
                    concept=head,
                    variants={v: sorted(a) for v, a in sorted(variants.items())},
                )
            )
    synonym_surfaces = {v for group in SYNONYM_GROUPS for v in group}
    for key, surfaces in sorted(_spelling_variants(statements).items()):
        distinct = {s for s in surfaces if s not in synonym_surfaces}
        if len(distinct) >= 2:
            drifts.append(
                TerminologyDrift(
                    concept=key,
                    variants={s: sorted(surfaces[s]) for s in sorted(distinct)},
                )
            )
    return drifts


# --------------------------------------------------------------------------------------
# Package analysis
# --------------------------------------------------------------------------------------


def artifact_texts(pkg: ChangePackage) -> list[tuple[str, str]]:
    """``(artifact id, text)`` pairs for every prose-bearing artifact of the package."""
    out: list[tuple[str, str]] = []
    kernel = pkg.intent.kernel
    kernel_text = " ".join(
        [kernel.why, kernel.success_signal, *kernel.capabilities]
        + [*kernel.constraints, *kernel.non_goals]
    ).strip()
    if kernel_text:
        out.append((pkg.intent.id, kernel_text))
    for requirement in pkg.requirements:
        out.append((requirement.id, requirement.text))
        out.extend((s.id, s.text) for s in requirement.scenarios)
    out.extend((a.id, a.text) for a in pkg.assumptions)
    out.extend((q.id, q.question) for q in pkg.open_questions)
    for adr in pkg.decisions:
        out.append((adr.id, " ".join([adr.title, adr.context, adr.decision, *adr.consequences])))
    for ifc in pkg.interfaces:
        out.append((ifc.id, f"{ifc.name} {ifc.description}"))
    if pkg.threat_model is not None:
        out.extend((t.id, f"{t.title} {t.description}") for t in pkg.threat_model.threats)
    out.extend((t.id, f"{t.title} {t.description}") for t in pkg.tasks)
    return out


class AnalysisFinding(BaseModel):
    """One cross-artifact inconsistency."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(description="Stable code, e.g. ``ORPHAN_REQUIREMENT``.")
    severity: Severity
    message: str
    artifact_ids: list[str] = Field(default_factory=list)
    remediation: str = ""

    @property
    def blocking(self) -> bool:
        """High or critical findings block the corresponding gate."""
        return self.severity.rank >= Severity.HIGH.rank

    def __str__(self) -> str:
        where = f" [{', '.join(self.artifact_ids)}]" if self.artifact_ids else ""
        return f"{self.severity.value.upper()} {self.code}{where}: {self.message}"


class AnalysisReport(BaseModel):
    """Result of :func:`analyze`."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    findings: list[AnalysisFinding] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        """``True`` when no finding is high or critical."""
        return not any(f.blocking for f in self.findings)

    @property
    def max_severity(self) -> Severity | None:
        """Highest severity present, if any."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def counts(self) -> dict[str, int]:
        """Number of findings per severity value."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def at_least(self, severity: Severity) -> list[AnalysisFinding]:
        """Findings with severity >= *severity*."""
        return [f for f in self.findings if f.severity.rank >= severity.rank]


def _mentions(haystack: str, needle: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(needle)}(?![\w-])", haystack, re.I) is not None


def _task_text(pkg: ChangePackage) -> str:
    parts: list[str] = []
    for task in pkg.tasks:
        parts.extend([task.title, task.description, *task.files])
        if task.verification is not None:
            parts.append(task.verification.command)
            parts.append(task.verification.expect_output_regex or "")
    for test in pkg.evidence.tests:
        parts.extend([test.command, test.report_uri or ""])
    return "\n".join(parts)


def _analyze_traceability(pkg: ChangePackage, findings: list[AnalysisFinding]) -> None:
    requirement_ids = {r.id for r in pkg.requirements}
    covered: set[str] = set()
    for task in pkg.tasks:
        if not task.requirement_ids:
            findings.append(
                AnalysisFinding(
                    code="TASK_WITHOUT_REQUIREMENT",
                    severity=Severity.MEDIUM,
                    message=f"{task.id} is not traced to any requirement",
                    artifact_ids=[task.id],
                    remediation="Add the REQ ids this task implements to requirement_ids.",
                )
            )
        for req_id in task.requirement_ids:
            if req_id in requirement_ids:
                covered.add(req_id)
            else:
                findings.append(
                    AnalysisFinding(
                        code="TASK_UNKNOWN_REQUIREMENT",
                        severity=Severity.HIGH,
                        message=f"{task.id} references unknown requirement {req_id}",
                        artifact_ids=[task.id, req_id],
                        remediation="Point the task at an existing requirement or add it.",
                    )
                )
    if pkg.tasks:
        for requirement in pkg.requirements:
            if requirement.id not in covered:
                findings.append(
                    AnalysisFinding(
                        code="ORPHAN_REQUIREMENT",
                        severity=Severity.MEDIUM,
                        message=f"{requirement.id} is not implemented by any task",
                        artifact_ids=[requirement.id],
                        remediation="Plan a task for this requirement or mark it wont.",
                    )
                )
        tests_text = _task_text(pkg)
        for scenario in pkg.scenarios():
            if not _mentions(tests_text, scenario.id):
                findings.append(
                    AnalysisFinding(
                        code="SCENARIO_WITHOUT_TEST",
                        severity=Severity.LOW,
                        message=f"{scenario.id} is not referenced by any task verification or "
                        "test evidence",
                        artifact_ids=[scenario.id],
                        remediation="Reference the scenario id from the task that verifies it.",
                    )
                )


def _analyze_plan(pkg: ChangePackage, findings: list[AnalysisFinding]) -> None:
    if pkg.plan is None or not pkg.plan.waves:
        return
    task_ids = {t.id for t in pkg.tasks}
    scheduled = set(pkg.plan.task_ids)
    for tid in pkg.plan.task_ids:
        if tid not in task_ids:
            findings.append(
                AnalysisFinding(
                    code="PLAN_UNKNOWN_TASK",
                    severity=Severity.HIGH,
                    message=f"plan schedules unknown task {tid}",
                    artifact_ids=[tid],
                    remediation="Remove the task from the plan or add it to tasks.md.",
                )
            )
    for task in pkg.tasks:
        if task.id not in scheduled:
            findings.append(
                AnalysisFinding(
                    code="TASK_NOT_SCHEDULED",
                    severity=Severity.MEDIUM,
                    message=f"{task.id} is not scheduled in any wave",
                    artifact_ids=[task.id],
                    remediation="Add the task to a plan wave.",
                )
            )
            continue
        wave = pkg.plan.wave_of(task.id)
        for dep in task.depends_on:
            dep_wave = pkg.plan.wave_of(dep)
            if dep_wave is not None and wave is not None and dep_wave >= wave:
                findings.append(
                    AnalysisFinding(
                        code="WAVE_DEPENDENCY_ORDER",
                        severity=Severity.HIGH,
                        message=f"{task.id} (wave {wave}) depends on {dep} scheduled in wave "
                        f"{dep_wave}",
                        artifact_ids=[task.id, dep],
                        remediation="Move the dependency to an earlier wave.",
                    )
                )


_REQ_REF: Final[re.Pattern[str]] = re.compile(r"\bREQ-\d{3,}\b")
_ADR_REF: Final[re.Pattern[str]] = re.compile(r"\bADR-\d{4,}\b")
_IFC_REF: Final[re.Pattern[str]] = re.compile(r"\bIFC-\d{3,}\b")


def _analyze_architecture(pkg: ChangePackage, findings: list[AnalysisFinding]) -> None:
    requirement_ids = {r.id for r in pkg.requirements}
    adr_ids = {d.id for d in pkg.decisions}
    interface_ids = {i.id for i in pkg.interfaces}
    for adr in pkg.decisions:
        rel = f"architecture/decisions/{adr.id}.md"
        text = " ".join(
            [adr.title, adr.context, adr.decision, *adr.consequences, *adr.alternatives]
            + [pkg.bodies.get(rel, "")]
        )
        for ref in sorted(set(_REQ_REF.findall(text)) - requirement_ids):
            findings.append(
                AnalysisFinding(
                    code="ADR_UNKNOWN_REQUIREMENT",
                    severity=Severity.HIGH,
                    message=f"{adr.id} references unknown requirement {ref}",
                    artifact_ids=[adr.id, ref],
                    remediation="Fix the reference or add the requirement.",
                )
            )
        if adr.supersedes is not None and adr.supersedes not in adr_ids:
            findings.append(
                AnalysisFinding(
                    code="ADR_UNKNOWN_SUPERSEDES",
                    severity=Severity.MEDIUM,
                    message=f"{adr.id} supersedes unknown decision {adr.supersedes}",
                    artifact_ids=[adr.id, adr.supersedes],
                    remediation="Reference an existing ADR id.",
                )
            )
    all_text = "\n".join(text for _, text in artifact_texts(pkg)) + "\n".join(pkg.bodies.values())
    for ifc in pkg.interfaces:
        rel = f"architecture/interfaces/{ifc.id}.md"
        text = " ".join([ifc.name, ifc.description, ifc.contract or "", pkg.bodies.get(rel, "")])
        for ref in sorted(set(_REQ_REF.findall(text)) - requirement_ids):
            findings.append(
                AnalysisFinding(
                    code="INTERFACE_UNKNOWN_REQUIREMENT",
                    severity=Severity.HIGH,
                    message=f"{ifc.id} references unknown requirement {ref}",
                    artifact_ids=[ifc.id, ref],
                    remediation="Fix the reference or add the requirement.",
                )
            )
        for ref in sorted(set(_ADR_REF.findall(text)) - adr_ids):
            findings.append(
                AnalysisFinding(
                    code="INTERFACE_UNKNOWN_ADR",
                    severity=Severity.MEDIUM,
                    message=f"{ifc.id} references unknown decision {ref}",
                    artifact_ids=[ifc.id, ref],
                    remediation="Fix the reference or add the ADR.",
                )
            )
        referenced = _mentions(all_text.replace(text, ""), ifc.id) or _mentions(
            "\n".join(t for aid, t in artifact_texts(pkg) if aid != ifc.id), ifc.name
        )
        if not referenced:
            findings.append(
                AnalysisFinding(
                    code="INTERFACE_NOT_REFERENCED",
                    severity=Severity.LOW,
                    message=f"{ifc.id} ({ifc.name}) is not referenced by any requirement, task "
                    "or decision",
                    artifact_ids=[ifc.id],
                    remediation="Reference the interface from the requirement that needs it.",
                )
            )
    for requirement in pkg.requirements:
        text = requirement.text + " " + (requirement.rationale or "")
        for ref in sorted(set(_IFC_REF.findall(text)) - interface_ids):
            findings.append(
                AnalysisFinding(
                    code="REQUIREMENT_UNKNOWN_INTERFACE",
                    severity=Severity.MEDIUM,
                    message=f"{requirement.id} references unknown interface {ref}",
                    artifact_ids=[requirement.id, ref],
                    remediation="Add the interface under architecture/interfaces/.",
                )
            )


def _analyze_threat_model(pkg: ChangePackage, findings: list[AnalysisFinding]) -> None:
    model = pkg.threat_model
    if model is None:
        return
    agentic = pkg.intent.risk_class is RiskClass.AI_AGENT
    threat_text = "\n".join(
        " ".join([t.title, t.description, *t.assets]) for t in model.threats
    ) + "\n".join(m.description for m in model.mitigations)
    manifest = model.tool_data_manifest
    for label, code, items in (
        ("tool", "THREAT_UNCOVERED_TOOL", manifest.tools),
        ("data source", "THREAT_UNCOVERED_DATA_SOURCE", manifest.data_sources),
        ("network egress", "THREAT_UNCOVERED_EGRESS", manifest.network_egress),
    ):
        for item in items:
            if not _mentions(threat_text, item):
                findings.append(
                    AnalysisFinding(
                        code=code,
                        severity=Severity.HIGH if agentic else Severity.MEDIUM,
                        message=f"manifest {label} '{item}' is not covered by any threat",
                        artifact_ids=[],
                        remediation=f"Add a threat (and mitigation) that names '{item}'.",
                    )
                )
    mitigation_ids = {m.id for m in model.mitigations}
    for threat in model.threats:
        for mid in threat.mitigation_ids:
            if mid not in mitigation_ids:
                findings.append(
                    AnalysisFinding(
                        code="THREAT_UNKNOWN_MITIGATION",
                        severity=Severity.HIGH,
                        message=f"{threat.id} references unknown mitigation {mid}",
                        artifact_ids=[threat.id],
                        remediation="Declare the mitigation in the threat model.",
                    )
                )
        if threat.is_unresolved_high_risk:
            findings.append(
                AnalysisFinding(
                    code="THREAT_UNRESOLVED_HIGH_RISK",
                    severity=threat.severity,
                    message=f"{threat.id} ({threat.severity.value}) is open without resolution",
                    artifact_ids=[threat.id],
                    remediation="Mitigate or explicitly accept the threat before G1.",
                )
            )
    if agentic and not (manifest.tools or manifest.data_sources or manifest.network_egress):
        findings.append(
            AnalysisFinding(
                code="MANIFEST_EMPTY",
                severity=Severity.HIGH,
                message="ai_agent change declares no tools, data sources or network egress",
                artifact_ids=[pkg.intent.id],
                remediation="Fill the tool/data manifest in architecture/threat-model.md.",
            )
        )


def _analyze_requirements(pkg: ChangePackage, findings: list[AnalysisFinding]) -> None:
    for pair in find_duplicates(pkg.requirements):
        findings.append(
            AnalysisFinding(
                code="DUPLICATE_REQUIREMENT",
                severity=Severity.MEDIUM,
                message=f"{pair.left_id} and {pair.right_id} are near-duplicates "
                f"(similarity {pair.similarity:.2f})",
                artifact_ids=[pair.left_id, pair.right_id],
                remediation="Merge the two requirements or make their difference explicit.",
            )
        )
    for pair in find_contradictions(pkg.requirements):
        findings.append(
            AnalysisFinding(
                code="CONTRADICTION",
                severity=Severity.HIGH,
                message=f"{pair.left_id} and {pair.right_id} state SHALL and SHALL NOT for "
                f"similar behaviour (similarity {pair.similarity:.2f})",
                artifact_ids=[pair.left_id, pair.right_id],
                remediation="Decide which behaviour is required and rewrite the other.",
            )
        )
    statements = [(rid, text) for rid, text in artifact_texts(pkg) if ids.kind_of(rid) != "OQ"]
    for conflict in find_conflicting_quantifiers(statements):
        findings.append(
            AnalysisFinding(
                code="CONFLICTING_QUANTIFIER",
                severity=Severity.HIGH,
                message=f"{conflict.left.artifact_id} says '{conflict.left.raw}' but "
                f"{conflict.right.artifact_id} says '{conflict.right.raw}' for similar "
                "statements",
                artifact_ids=conflict.artifact_ids,
                remediation="Pick one value and update both statements.",
            )
        )
    for drift in find_terminology_drift(statements):
        variants = ", ".join(f"'{v}' ({', '.join(a)})" for v, a in drift.variants.items())
        findings.append(
            AnalysisFinding(
                code="TERMINOLOGY_DRIFT",
                severity=Severity.LOW,
                message=f"'{drift.concept}' is written several ways: {variants}",
                artifact_ids=drift.artifact_ids,
                remediation="Pick one term and use it everywhere (add it to the glossary).",
            )
        )


def analyze(pkg: ChangePackage) -> AnalysisReport:
    """Run every cross-artifact consistency check over *pkg*.

    Codes: ``TASK_WITHOUT_REQUIREMENT``, ``TASK_UNKNOWN_REQUIREMENT``, ``ORPHAN_REQUIREMENT``,
    ``SCENARIO_WITHOUT_TEST``, ``PLAN_UNKNOWN_TASK``, ``TASK_NOT_SCHEDULED``,
    ``WAVE_DEPENDENCY_ORDER``, ``ADR_UNKNOWN_REQUIREMENT``, ``ADR_UNKNOWN_SUPERSEDES``,
    ``INTERFACE_UNKNOWN_REQUIREMENT``, ``INTERFACE_UNKNOWN_ADR``, ``INTERFACE_NOT_REFERENCED``,
    ``REQUIREMENT_UNKNOWN_INTERFACE``, ``THREAT_UNCOVERED_TOOL``,
    ``THREAT_UNCOVERED_DATA_SOURCE``, ``THREAT_UNCOVERED_EGRESS``, ``THREAT_UNKNOWN_MITIGATION``,
    ``THREAT_UNRESOLVED_HIGH_RISK``, ``MANIFEST_EMPTY``, ``DUPLICATE_REQUIREMENT``,
    ``CONTRADICTION``, ``CONFLICTING_QUANTIFIER``, ``TERMINOLOGY_DRIFT``.
    Findings are ordered most severe first, then by code and artifact ids.
    """
    findings: list[AnalysisFinding] = []
    _analyze_traceability(pkg, findings)
    _analyze_plan(pkg, findings)
    _analyze_architecture(pkg, findings)
    _analyze_threat_model(pkg, findings)
    _analyze_requirements(pkg, findings)
    findings.sort(key=lambda f: (-f.severity.rank, f.code, f.artifact_ids, f.message))
    return AnalysisReport(change_id=pkg.change_id, findings=findings)
