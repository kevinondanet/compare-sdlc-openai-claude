"""Requirement grammar and ambiguity analysis (ARCHITECTURE.md §2.3).

All checks return structured :class:`ValidationIssue` lists instead of raising, so callers
(gates, CLI, intake) can aggregate and rank them.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids

if TYPE_CHECKING:
    from aisdlc.schema.models import ChangePackage, Requirement, Scenario, Task

__all__ = [
    "IssueSeverity",
    "ValidationIssue",
    "AmbiguityMarker",
    "AmbiguityReport",
    "EarsForm",
    "NORMATIVE_PATTERN",
    "VAGUE_TERMS",
    "EXPLICIT_MARKERS",
    "ears_form",
    "validate_requirement_text",
    "validate_scenario",
    "validate_requirement",
    "validate_requirements",
    "find_ambiguity_markers",
    "ambiguity_report",
    "ambiguity_score",
    "check_task_numbering",
    "check_verification_executable",
    "validate_tasks",
    "validate_package",
]


class IssueSeverity(StrEnum):
    """Severity of a validation issue. ``error`` issues fail G0/G1 checks."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BaseModel):
    """A single structured finding from a grammar/consistency check."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(description="Stable machine-readable code, e.g. ``REQ_NO_MODAL``.")
    severity: IssueSeverity = IssueSeverity.ERROR
    message: str
    artifact_id: str | None = None
    location: str | None = Field(default=None, description="File/field hint for humans.")

    def __str__(self) -> str:
        where = f" [{self.artifact_id}]" if self.artifact_id else ""
        return f"{self.severity.value.upper()} {self.code}{where}: {self.message}"


def _issue(
    code: str,
    message: str,
    *,
    severity: IssueSeverity = IssueSeverity.ERROR,
    artifact_id: str | None = None,
    location: str | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        code=code, severity=severity, message=message, artifact_id=artifact_id, location=location
    )


# --------------------------------------------------------------------------------------
# Requirement text
# --------------------------------------------------------------------------------------


class EarsForm(StrEnum):
    """EARS requirement forms."""

    UBIQUITOUS = "ubiquitous"  # The <system> SHALL <response>
    EVENT_DRIVEN = "event_driven"  # WHEN <trigger>, the <system> SHALL <response>
    STATE_DRIVEN = "state_driven"  # WHILE <state>, the <system> SHALL <response>
    UNWANTED = "unwanted_behaviour"  # IF <condition>, THEN the <system> SHALL <response>
    OPTIONAL = "optional_feature"  # WHERE <feature>, the <system> SHALL <response>
    COMPLEX = "complex"  # combinations of the above


NORMATIVE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(SHALL|MUST)(\s+NOT)?\b")
"""Uppercase normative modal required by OpenSpec/EARS."""

_LOWER_MODAL: Final[re.Pattern[str]] = re.compile(r"\b(shall|must)\b")
_WEAK_MODAL: Final[re.Pattern[str]] = re.compile(r"\b(should|may|could|might|can)\b", re.I)
_SYSTEM_SHALL: Final[str] = r".+?\b(SHALL|MUST)\b"
_EARS: Final[dict[EarsForm, re.Pattern[str]]] = {
    EarsForm.EVENT_DRIVEN: re.compile(rf"^\s*WHEN\b[^,]+,\s*{_SYSTEM_SHALL}", re.S),
    EarsForm.STATE_DRIVEN: re.compile(rf"^\s*WHILE\b[^,]+,\s*{_SYSTEM_SHALL}", re.S),
    EarsForm.UNWANTED: re.compile(rf"^\s*IF\b.+?,?\s*THEN\b\s*{_SYSTEM_SHALL}", re.S),
    EarsForm.OPTIONAL: re.compile(rf"^\s*WHERE\b[^,]+,\s*{_SYSTEM_SHALL}", re.S),
}
_EARS_KEYWORD: Final[re.Pattern[str]] = re.compile(r"^\s*(WHEN|WHILE|IF|WHERE)\b")


def ears_form(text: str) -> EarsForm | None:
    """Classify *text* into an EARS form, or ``None`` if it is not normative.

    Text starting with two EARS keywords (``WHILE … WHEN …``) is ``complex``.
    """
    if NORMATIVE_PATTERN.search(text) is None:
        return None
    matches = [form for form, pattern in _EARS.items() if pattern.match(text)]
    keyword_count = len(re.findall(r"\b(WHEN|WHILE|IF|WHERE)\b", text.split("SHALL")[0]))
    if keyword_count >= 2 and _EARS_KEYWORD.match(text):
        return EarsForm.COMPLEX
    if matches:
        return matches[0]
    if _EARS_KEYWORD.match(text):
        # Starts like EARS but the clause structure is off — still normative (has SHALL).
        return EarsForm.COMPLEX
    return EarsForm.UBIQUITOUS


def validate_requirement_text(
    text: str, requirement_id: str | None = None
) -> list[ValidationIssue]:
    """Check that *text* is a normative statement (SHALL/MUST or EARS form).

    Issues:

    * ``REQ_EMPTY`` (error) — blank text.
    * ``REQ_NO_MODAL`` (error) — neither ``SHALL``/``MUST`` nor an EARS form.
    * ``REQ_LOWERCASE_MODAL`` (warning) — ``shall``/``must`` present only in lowercase.
    * ``REQ_WEAK_MODAL`` (warning) — ``should``/``may``/``can`` used alongside the modal.
    * ``REQ_EARS_MALFORMED`` (warning) — starts with an EARS keyword but the clause does
      not follow ``<keyword> <clause>, the <system> SHALL <response>``.
    """
    issues: list[ValidationIssue] = []
    stripped = text.strip()
    if not stripped:
        issues.append(_issue("REQ_EMPTY", "requirement text is empty", artifact_id=requirement_id))
        return issues
    if NORMATIVE_PATTERN.search(stripped) is None:
        if _LOWER_MODAL.search(stripped):
            issues.append(
                _issue(
                    "REQ_LOWERCASE_MODAL",
                    "use uppercase SHALL/MUST for the normative modal",
                    severity=IssueSeverity.WARNING,
                    artifact_id=requirement_id,
                )
            )
        issues.append(
            _issue(
                "REQ_NO_MODAL",
                "requirement must contain SHALL or MUST, or follow an EARS form "
                "(WHEN/WHILE/IF…THEN/WHERE …, the <system> SHALL …)",
                artifact_id=requirement_id,
            )
        )
        return issues
    if _WEAK_MODAL.search(stripped):
        issues.append(
            _issue(
                "REQ_WEAK_MODAL",
                "avoid should/may/could/can in a normative requirement",
                severity=IssueSeverity.WARNING,
                artifact_id=requirement_id,
            )
        )
    if _EARS_KEYWORD.match(stripped) and not any(p.match(stripped) for p in _EARS.values()):
        keyword_count = len(re.findall(r"\b(WHEN|WHILE|IF|WHERE)\b", stripped.split("SHALL")[0]))
        if keyword_count < 2:
            issues.append(
                _issue(
                    "REQ_EARS_MALFORMED",
                    "EARS form expected: '<KEYWORD> <clause>, the <system> SHALL <response>'",
                    severity=IssueSeverity.WARNING,
                    artifact_id=requirement_id,
                )
            )
    return issues


# --------------------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------------------

_WHEN_THEN: Final[re.Pattern[str]] = re.compile(r"\bWHEN\b.+?\bTHEN\b.+", re.S | re.I)
_GWT: Final[re.Pattern[str]] = re.compile(r"\bGIVEN\b.+?\bWHEN\b.+?\bTHEN\b.+", re.S | re.I)


def validate_scenario(scenario: Scenario) -> list[ValidationIssue]:
    """Check that a scenario is in ``WHEN … THEN …`` or ``Given/When/Then`` form.

    Issues: ``SCN_MALFORMED`` (error) when neither structured fields nor raw text form a
    valid scenario; ``SCN_EMPTY_CLAUSE`` (error) when a structured clause is blank.
    """
    issues: list[ValidationIssue] = []
    if scenario.when is not None or scenario.then is not None:
        for name, value in (("when", scenario.when), ("then", scenario.then)):
            if not (value or "").strip():
                issues.append(
                    _issue(
                        "SCN_EMPTY_CLAUSE",
                        f"scenario clause '{name}' is empty",
                        artifact_id=scenario.id,
                    )
                )
        if issues:
            return issues
        return issues
    raw = scenario.raw.strip()
    if _GWT.search(raw) or _WHEN_THEN.search(raw):
        return issues
    issues.append(
        _issue(
            "SCN_MALFORMED",
            "scenario must use 'WHEN … THEN …' or 'Given … When … Then …'",
            artifact_id=scenario.id,
        )
    )
    return issues


def validate_requirement(requirement: Requirement) -> list[ValidationIssue]:
    """Text grammar + scenario presence/validity for one requirement.

    Adds ``REQ_NO_SCENARIO`` (error) when the requirement has no scenario.
    """
    issues = validate_requirement_text(requirement.text, requirement.id)
    if not requirement.scenarios:
        issues.append(
            _issue(
                "REQ_NO_SCENARIO",
                "every requirement needs at least one WHEN/THEN scenario",
                artifact_id=requirement.id,
            )
        )
    for scenario in requirement.scenarios:
        issues.extend(validate_scenario(scenario))
    return issues


def validate_requirements(requirements: Sequence[Requirement]) -> list[ValidationIssue]:
    """Validate a list of requirements, including duplicate-id detection."""
    issues: list[ValidationIssue] = []
    seen: set[str] = set()
    for requirement in requirements:
        if requirement.id in seen:
            issues.append(
                _issue("REQ_DUPLICATE_ID", "duplicate requirement id", artifact_id=requirement.id)
            )
        seen.add(requirement.id)
        issues.extend(validate_requirement(requirement))
    return issues


# --------------------------------------------------------------------------------------
# Ambiguity
# --------------------------------------------------------------------------------------

EXPLICIT_MARKERS: Final[tuple[str, ...]] = ("[NEEDS CLARIFICATION]", "TBD", "TODO", "FIXME", "XXX")
"""Explicit placeholders; weight 1.0 each."""

VAGUE_TERMS: Final[tuple[str, ...]] = (
    "fast",
    "quick",
    "quickly",
    "slow",
    "some",
    "several",
    "many",
    "few",
    "appropriate",
    "appropriately",
    "adequate",
    "reasonable",
    "sufficient",
    "etc",
    "etc.",
    "and/or",
    "as needed",
    "as required",
    "if possible",
    "where possible",
    "as appropriate",
    "user-friendly",
    "easy",
    "easily",
    "simple",
    "efficient",
    "efficiently",
    "robust",
    "flexible",
    "scalable",
    "approximately",
    "roughly",
    "about",
    "minimal",
    "optimal",
    "best",
    "normally",
    "usually",
    "often",
    "typically",
    "various",
    "relevant",
    "significant",
    "large",
    "small",
    "soon",
    "timely",
    "seamless",
    "intuitive",
)
"""Vague quantifiers/qualifiers; weight 0.25 each."""

_WEIGHTS: Final[dict[str, float]] = {"explicit": 1.0, "question": 0.5, "vague": 0.25}
_EXPLICIT_RE: Final[re.Pattern[str]] = re.compile(
    "|".join(re.escape(m) for m in EXPLICIT_MARKERS), re.I
)
_VAGUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])("
    + "|".join(re.escape(t) for t in sorted(VAGUE_TERMS, key=len, reverse=True))
    + r")(?![\w-])",
    re.I,
)
_QUESTION_RE: Final[re.Pattern[str]] = re.compile(r"\?")


class AmbiguityMarker(BaseModel):
    """One ambiguity marker occurrence."""

    model_config = ConfigDict(extra="forbid")

    marker: str
    category: str = Field(description="``explicit``, ``question`` or ``vague``.")
    start: int
    end: int
    weight: float
    artifact_id: str | None = None


def find_ambiguity_markers(text: str, artifact_id: str | None = None) -> list[AmbiguityMarker]:
    """Locate ambiguity markers in *text*, ordered by position.

    Explicit placeholders (``[NEEDS CLARIFICATION]``, ``TBD``, ``TODO`` …), question marks
    and vague quantifiers (``fast``, ``some``, ``appropriate``, ``etc.`` …) are detected.
    """
    found: list[AmbiguityMarker] = []
    for category, pattern in (
        ("explicit", _EXPLICIT_RE),
        ("question", _QUESTION_RE),
        ("vague", _VAGUE_RE),
    ):
        for match in pattern.finditer(text):
            found.append(
                AmbiguityMarker(
                    marker=match.group(0),
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    weight=_WEIGHTS[category],
                    artifact_id=artifact_id,
                )
            )
    found.sort(key=lambda m: (m.start, m.end))
    return found


class AmbiguityReport(BaseModel):
    """Breakdown of :func:`ambiguity_score`."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0, le=1)
    marker_density: float = Field(ge=0, le=1)
    unresolved_ratio: float = Field(ge=0, le=1)
    statements: int = Field(ge=0)
    weighted_markers: float = Field(ge=0)
    markers: list[AmbiguityMarker] = Field(default_factory=list)


def _statements(pkg: ChangePackage) -> list[tuple[str, str]]:
    """(artifact id, text) pairs that carry specification meaning."""
    out: list[tuple[str, str]] = []
    kernel = pkg.intent.kernel
    if kernel.why.strip():
        out.append((pkg.intent.id, kernel.why))
    if kernel.success_signal.strip():
        out.append((pkg.intent.id, kernel.success_signal))
    for bucket in (kernel.capabilities, kernel.constraints, kernel.non_goals):
        out.extend((pkg.intent.id, item) for item in bucket if item.strip())
    for requirement in pkg.requirements:
        out.append((requirement.id, requirement.text))
        out.extend((s.id, s.text) for s in requirement.scenarios)
    out.extend((a.id, a.text) for a in pkg.assumptions)
    return out


def ambiguity_report(pkg: ChangePackage) -> AmbiguityReport:
    """Compute the ambiguity score of a package with its breakdown.

    Formula (all terms clipped to [0, 1])::

        statements       = kernel parts + requirement texts + scenarios + assumptions
        weighted_markers = Σ weight(marker)   explicit=1.0, "?"=0.5, vague term=0.25
        marker_density   = min(1, weighted_markers / max(1, statements))
        unresolved_ratio = (open_blocking + 0.5 · open_non_blocking) / max(1, questions)
        score            = min(1, 0.6 · marker_density + 0.4 · unresolved_ratio)

    A package with no markers and no open questions scores 0.0; one explicit placeholder
    per statement or all questions open-and-blocking scores 0.6 / 0.4 respectively.
    Question text itself is not scanned for ``?`` (questions are expected to ask).
    """
    statements = _statements(pkg)
    markers: list[AmbiguityMarker] = []
    for artifact_id, text in statements:
        markers.extend(find_ambiguity_markers(text, artifact_id))
    weighted = sum(m.weight for m in markers)
    density = min(1.0, weighted / max(1, len(statements)))
    questions = pkg.open_questions
    open_blocking = sum(1 for q in questions if q.is_open_blocking)
    open_non_blocking = sum(1 for q in questions if q.status.value == "open" and not q.blocking)
    unresolved = min(1.0, (open_blocking + 0.5 * open_non_blocking) / max(1, len(questions)))
    score = min(1.0, 0.6 * density + 0.4 * unresolved)
    return AmbiguityReport(
        score=round(score, 4),
        marker_density=round(density, 4),
        unresolved_ratio=round(unresolved, 4),
        statements=len(statements),
        weighted_markers=weighted,
        markers=markers,
    )


def ambiguity_score(pkg: ChangePackage) -> float:
    """Ambiguity score in [0, 1]; see :func:`ambiguity_report` for the formula."""
    return ambiguity_report(pkg).score


# --------------------------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------------------------


def check_task_numbering(tasks: Sequence[Task]) -> list[ValidationIssue]:
    """Task ids must be ``TASK-001``, ``TASK-002`` … with no gaps or duplicates.

    Issues: ``TASK_DUPLICATE_ID``, ``TASK_NUMBERING_GAP`` (both error).
    """
    issues: list[ValidationIssue] = []
    numbers: list[int] = []
    seen: set[str] = set()
    for task in tasks:
        if task.id in seen:
            issues.append(_issue("TASK_DUPLICATE_ID", "duplicate task id", artifact_id=task.id))
            continue
        seen.add(task.id)
        numbers.append(ids.numeric_suffix(task.id))
    expected = list(range(1, len(numbers) + 1))
    if sorted(numbers) != expected:
        missing = sorted(set(expected) - set(numbers))
        issues.append(
            _issue(
                "TASK_NUMBERING_GAP",
                "task ids must be sequential from TASK-001"
                + (f"; missing {', '.join(f'TASK-{n:03d}' for n in missing)}" if missing else ""),
            )
        )
    return issues


def check_verification_executable(task: Task) -> list[ValidationIssue]:
    """A task's verification block must be executable.

    Issues: ``TASK_NO_VERIFICATION``, ``TASK_VERIFICATION_EMPTY_COMMAND``,
    ``TASK_VERIFICATION_UNPARSEABLE`` (shell quoting), ``TASK_VERIFICATION_BAD_REGEX``,
    ``TASK_VERIFICATION_EXIT_CODE`` (outside 0..255).
    """
    issues: list[ValidationIssue] = []
    verification = task.verification
    if verification is None:
        issues.append(
            _issue("TASK_NO_VERIFICATION", "task has no verification block", artifact_id=task.id)
        )
        return issues
    if not verification.command.strip():
        issues.append(
            _issue(
                "TASK_VERIFICATION_EMPTY_COMMAND",
                "verification command is empty",
                artifact_id=task.id,
            )
        )
    else:
        try:
            shlex.split(verification.command)
        except ValueError as exc:
            issues.append(
                _issue(
                    "TASK_VERIFICATION_UNPARSEABLE",
                    f"verification command cannot be parsed: {exc}",
                    artifact_id=task.id,
                )
            )
    if not 0 <= verification.expect_exit_code <= 255:
        issues.append(
            _issue(
                "TASK_VERIFICATION_EXIT_CODE",
                "expect_exit_code must be in 0..255",
                artifact_id=task.id,
            )
        )
    if verification.expect_output_regex is not None:
        try:
            re.compile(verification.expect_output_regex)
        except re.error as exc:
            issues.append(
                _issue(
                    "TASK_VERIFICATION_BAD_REGEX",
                    f"expect_output_regex does not compile: {exc}",
                    artifact_id=task.id,
                )
            )
    return issues


def _dependency_cycles(tasks: Sequence[Task]) -> list[list[str]]:
    graph = {t.id: list(t.depends_on) for t in tasks}
    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for dep in graph.get(node, []):
            if dep not in graph:
                continue
            if state.get(dep, 0) == 1:
                cycles.append(stack[stack.index(dep) :] + [dep])
            elif state.get(dep, 0) == 0:
                visit(dep)
        stack.pop()
        state[node] = 2

    for task_id in graph:
        if state.get(task_id, 0) == 0:
            visit(task_id)
    return cycles


def validate_tasks(
    tasks: Sequence[Task], known_requirements: Iterable[str] | None = None
) -> list[ValidationIssue]:
    """Numbering, verification, dangling references and dependency cycles."""
    issues = check_task_numbering(tasks)
    task_ids = {t.id for t in tasks}
    known_reqs = set(known_requirements) if known_requirements is not None else None
    for task in tasks:
        issues.extend(check_verification_executable(task))
        for dep in task.depends_on:
            if dep not in task_ids:
                issues.append(
                    _issue(
                        "TASK_UNKNOWN_DEPENDENCY",
                        f"depends on unknown task {dep}",
                        artifact_id=task.id,
                    )
                )
        if known_reqs is not None:
            for req in task.requirement_ids:
                if req not in known_reqs:
                    issues.append(
                        _issue(
                            "TASK_UNKNOWN_REQUIREMENT",
                            f"references unknown requirement {req}",
                            artifact_id=task.id,
                        )
                    )
        if not task.requirement_ids:
            issues.append(
                _issue(
                    "TASK_NO_REQUIREMENT",
                    "task is not traced to any requirement",
                    severity=IssueSeverity.WARNING,
                    artifact_id=task.id,
                )
            )
    for cycle in _dependency_cycles(tasks):
        issues.append(_issue("TASK_DEPENDENCY_CYCLE", "dependency cycle: " + " -> ".join(cycle)))
    return issues


# --------------------------------------------------------------------------------------
# Whole package
# --------------------------------------------------------------------------------------


def validate_package(pkg: ChangePackage) -> list[ValidationIssue]:
    """Run every grammar/consistency check over a package.

    Covers: intent owner and kernel completeness (``INTENT_NO_OWNER`` error,
    ``INTENT_KERNEL_INCOMPLETE`` warning), requirement grammar and scenarios, task
    numbering/verification/references, plan-task consistency (``PLAN_UNKNOWN_TASK``,
    ``PLAN_TASK_NOT_SCHEDULED`` warning), and blocking open questions
    (``OQ_OPEN_BLOCKING`` warning — G0 decides whether it blocks).
    """
    issues: list[ValidationIssue] = []
    if not (pkg.intent.owner or "").strip():
        issues.append(_issue("INTENT_NO_OWNER", "intent has no owner", artifact_id=pkg.intent.id))
    if not pkg.intent.kernel.is_complete():
        issues.append(
            _issue(
                "INTENT_KERNEL_INCOMPLETE",
                "kernel needs why, capabilities, non_goals and success_signal",
                severity=IssueSeverity.WARNING,
                artifact_id=pkg.intent.id,
            )
        )
    issues.extend(validate_requirements(pkg.requirements))
    issues.extend(validate_tasks(pkg.tasks, (r.id for r in pkg.requirements)))
    if pkg.plan is not None:
        task_ids = {t.id for t in pkg.tasks}
        for tid in pkg.plan.task_ids:
            if tid not in task_ids:
                issues.append(
                    _issue(
                        "PLAN_UNKNOWN_TASK", f"plan schedules unknown task {tid}", artifact_id=tid
                    )
                )
        scheduled = set(pkg.plan.task_ids)
        for task in pkg.tasks:
            if task.id not in scheduled:
                issues.append(
                    _issue(
                        "PLAN_TASK_NOT_SCHEDULED",
                        "task is not in any plan wave",
                        severity=IssueSeverity.WARNING,
                        artifact_id=task.id,
                    )
                )
    for question in pkg.open_questions:
        if question.is_open_blocking:
            issues.append(
                _issue(
                    "OQ_OPEN_BLOCKING",
                    f"blocking open question: {question.question}",
                    severity=IssueSeverity.WARNING,
                    artifact_id=question.id,
                )
            )
    return issues
