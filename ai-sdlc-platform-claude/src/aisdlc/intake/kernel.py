"""BMAD five-part kernel: build, validate and judge intent readiness (G0 inputs).

The kernel is the minimum a change must state before anything else is written:
*why*, *capabilities*, *constraints*, *non-goals* and a *success signal*. Readiness adds
the mandatory companions — explicit assumptions and open questions — and evaluates the
G0 criteria (owner, ambiguity, blocking questions) without deciding the gate itself
(that is ``aisdlc.gates``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.intake.analyze import content_words
from aisdlc.schema import grammar
from aisdlc.schema.grammar import IssueSeverity, ValidationIssue
from aisdlc.schema.models import ChangePackage, Kernel

__all__ = [
    "KernelPart",
    "KERNEL_PROMPTS",
    "REQUIRED_PARTS",
    "MEASURABLE_PATTERN",
    "ASSUMPTION_CUES",
    "split_items",
    "build_kernel",
    "missing_parts",
    "is_measurable",
    "validate_kernel",
    "UnstatedAssumption",
    "find_unstated_assumptions",
    "ReadinessCriterion",
    "ReadinessReport",
    "readiness",
    "default_ambiguity_threshold",
]


class KernelPart(StrEnum):
    """The five parts of the BMAD kernel."""

    WHY = "why"
    CAPABILITIES = "capabilities"
    CONSTRAINTS = "constraints"
    NON_GOALS = "non_goals"
    SUCCESS_SIGNAL = "success_signal"


KERNEL_PROMPTS: Final[dict[KernelPart, str]] = {
    KernelPart.WHY: "Why does this change exist? What problem or opportunity motivates it?",
    KernelPart.CAPABILITIES: "What will people or systems be able to do once it is done?",
    KernelPart.CONSTRAINTS: "What hard limits must it honour (deadline, budget, tech, rules)?",
    KernelPart.NON_GOALS: "What is explicitly out of scope, even though people might assume it?",
    KernelPart.SUCCESS_SIGNAL: "What observable, ideally measurable, signal shows it worked?",
}
"""Plain-language prompt per kernel part (used by clarification and discovery)."""

REQUIRED_PARTS: Final[tuple[KernelPart, ...]] = (
    KernelPart.WHY,
    KernelPart.CAPABILITIES,
    KernelPart.NON_GOALS,
    KernelPart.SUCCESS_SIGNAL,
)
"""Parts whose absence makes the kernel incomplete (matches ``Kernel.is_complete``)."""

MEASURABLE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(\d|%|\bpercent\b|\bp(50|90|95|99)\b|\bat least\b|\bat most\b|\bwithin\b|\bunder\b|"
    r"\bno more than\b|\bzero\b|\bevery\b|\bnever\b|\balways\b|\bcount\b|\brate\b|"
    r"\bmeasured\b|\bmetric\b|\bdrops?\b|\bincreases?\b|\bdecreases?\b|\breduc\w+\b|<|>|≤|≥)",
    re.I,
)
"""Signals that a success statement is measurable (numbers, comparatives, metrics)."""

_ITEM_SPLIT: Final[re.Pattern[str]] = re.compile(r"\r?\n|;|^\s*[-*•]\s+", re.M)
_BULLET: Final[re.Pattern[str]] = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")


def split_items(text: str | Iterable[str]) -> list[str]:
    """Split free text into list items (newlines, ``;`` or bullets), de-duplicated."""
    chunks: list[str] = []
    if isinstance(text, str):
        chunks = _ITEM_SPLIT.split(text)
    else:
        for item in text:
            chunks.extend(_ITEM_SPLIT.split(item))
    out: list[str] = []
    seen: set[str] = set()
    for chunk in chunks:
        item = _BULLET.sub("", chunk).strip().rstrip(".").strip()
        key = item.lower()
        if item and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def build_kernel(
    *,
    why: str = "",
    capabilities: str | Iterable[str] = (),
    constraints: str | Iterable[str] = (),
    non_goals: str | Iterable[str] = (),
    success_signal: str = "",
) -> Kernel:
    """Build a normalised :class:`~aisdlc.schema.models.Kernel`.

    List parts accept free text (split on newlines/semicolons/bullets) or iterables;
    items are stripped and de-duplicated case-insensitively.
    """
    return Kernel(
        why=" ".join(why.split()),
        capabilities=split_items(capabilities),
        constraints=split_items(constraints),
        non_goals=split_items(non_goals),
        success_signal=" ".join(success_signal.split()),
    )


def missing_parts(kernel: Kernel, *, include_optional: bool = False) -> list[KernelPart]:
    """Kernel parts that are empty (constraints only when *include_optional*)."""
    missing: list[KernelPart] = []
    if not kernel.why.strip():
        missing.append(KernelPart.WHY)
    if not kernel.capabilities:
        missing.append(KernelPart.CAPABILITIES)
    if include_optional and not kernel.constraints:
        missing.append(KernelPart.CONSTRAINTS)
    if not kernel.non_goals:
        missing.append(KernelPart.NON_GOALS)
    if not kernel.success_signal.strip():
        missing.append(KernelPart.SUCCESS_SIGNAL)
    return missing


def is_measurable(text: str) -> bool:
    """``True`` when *text* contains a number, comparative or metric vocabulary."""
    return MEASURABLE_PATTERN.search(text) is not None


def validate_kernel(kernel: Kernel, artifact_id: str | None = None) -> list[ValidationIssue]:
    """Validate a kernel and return structured issues (never raises).

    Codes: ``KERNEL_MISSING_WHY``, ``KERNEL_MISSING_CAPABILITIES``,
    ``KERNEL_MISSING_NON_GOALS``, ``KERNEL_MISSING_SUCCESS_SIGNAL`` (errors),
    ``KERNEL_NO_CONSTRAINTS``, ``KERNEL_SUCCESS_NOT_MEASURABLE``, ``KERNEL_AMBIGUOUS``
    (warnings).
    """
    issues: list[ValidationIssue] = []
    for part in missing_parts(kernel):
        issues.append(
            ValidationIssue(
                code=f"KERNEL_MISSING_{part.value.upper()}",
                severity=IssueSeverity.ERROR,
                message=f"kernel part '{part.value}' is empty — {KERNEL_PROMPTS[part]}",
                artifact_id=artifact_id,
                location=f"intent.md:kernel.{part.value}",
            )
        )
    if not kernel.constraints:
        issues.append(
            ValidationIssue(
                code="KERNEL_NO_CONSTRAINTS",
                severity=IssueSeverity.WARNING,
                message="no constraints recorded; state 'none known' explicitly if so",
                artifact_id=artifact_id,
                location="intent.md:kernel.constraints",
            )
        )
    if kernel.success_signal.strip() and not is_measurable(kernel.success_signal):
        issues.append(
            ValidationIssue(
                code="KERNEL_SUCCESS_NOT_MEASURABLE",
                severity=IssueSeverity.WARNING,
                message="success signal has no number, comparative or metric — how is it measured?",
                artifact_id=artifact_id,
                location="intent.md:kernel.success_signal",
            )
        )
    for part, texts in (
        (KernelPart.WHY, [kernel.why]),
        (KernelPart.CAPABILITIES, kernel.capabilities),
        (KernelPart.CONSTRAINTS, kernel.constraints),
        (KernelPart.NON_GOALS, kernel.non_goals),
        (KernelPart.SUCCESS_SIGNAL, [kernel.success_signal]),
    ):
        for text in texts:
            markers = grammar.find_ambiguity_markers(text)
            if markers:
                listed = ", ".join(sorted({m.marker for m in markers}))
                issues.append(
                    ValidationIssue(
                        code="KERNEL_AMBIGUOUS",
                        severity=IssueSeverity.WARNING,
                        message=f"kernel part '{part.value}' contains ambiguity markers: {listed}",
                        artifact_id=artifact_id,
                        location=f"intent.md:kernel.{part.value}",
                    )
                )
    return issues


# --------------------------------------------------------------------------------------
# Unstated assumptions
# --------------------------------------------------------------------------------------

ASSUMPTION_CUES: Final[tuple[str, ...]] = (
    r"assum\w*",
    r"presum\w*",
    r"expected to",
    r"already (?:exists?|has|have|available|in place)",
    r"existing",
    r"legacy",
    r"third[- ]party",
    r"external (?:service|system|api|provider|vendor)",
    r"always",
    r"never",
    r"all (?:users|customers|clients|requests)",
    r"every (?:user|customer|client|request)",
    r"as (?:today|before|usual)",
    r"currently",
    r"upstream",
    r"downstream",
)
"""Phrases that usually hide an assumption about the environment or the users."""

_CUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![\w-])(" + "|".join(ASSUMPTION_CUES) + r")(?![\w-])", re.I
)
_SENTENCE_SPLIT: Final[re.Pattern[str]] = re.compile(r"(?<=[.!?])\s+|\n+")


class UnstatedAssumption(BaseModel):
    """A statement that leans on something no recorded assumption covers."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    cue: str
    excerpt: str
    suggested_text: str


def _statements(pkg: ChangePackage) -> list[tuple[str, str]]:
    kernel = pkg.intent.kernel
    out: list[tuple[str, str]] = [
        (pkg.intent.id, kernel.why),
        (pkg.intent.id, kernel.success_signal),
    ]
    out.extend((pkg.intent.id, t) for t in [*kernel.capabilities, *kernel.constraints])
    for requirement in pkg.requirements:
        out.append((requirement.id, requirement.text))
        out.extend((s.id, s.text) for s in requirement.scenarios)
    return [(aid, text) for aid, text in out if text.strip()]


def _covered(excerpt: str, assumptions: Sequence[str]) -> bool:
    words = set(content_words(excerpt))
    if not words:
        return True
    needed = 1 if len(words) < 4 else 2
    for text in assumptions:
        if len(words & set(content_words(text))) >= needed:
            return True
    return False


def find_unstated_assumptions(pkg: ChangePackage) -> list[UnstatedAssumption]:
    """Statements with assumption cues that no recorded assumption covers.

    A cue is *covered* when some assumption shares at least two content words with the
    sentence containing it (one word for very short sentences).
    """
    recorded = [a.text for a in pkg.assumptions]
    found: list[UnstatedAssumption] = []
    seen: set[tuple[str, str]] = set()
    for artifact_id, text in _statements(pkg):
        for sentence in _SENTENCE_SPLIT.split(text):
            for match in _CUE_RE.finditer(sentence):
                cue = match.group(0).lower()
                key = (artifact_id, cue)
                if key in seen or _covered(sentence, recorded):
                    continue
                seen.add(key)
                excerpt = " ".join(sentence.split())
                found.append(
                    UnstatedAssumption(
                        artifact_id=artifact_id,
                        cue=cue,
                        excerpt=excerpt,
                        suggested_text=f"It is assumed that: {excerpt}",
                    )
                )
    return found


# --------------------------------------------------------------------------------------
# Readiness
# --------------------------------------------------------------------------------------


class ReadinessCriterion(BaseModel):
    """One G0 readiness criterion with its outcome."""

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    satisfied: bool
    blocking: bool = Field(description="Unsatisfied blocking criteria make the change not ready.")
    details: list[str] = Field(default_factory=list)
    remediation: str = ""


class ReadinessReport(BaseModel):
    """Result of :func:`readiness`."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    ready: bool
    missing_kernel_parts: list[KernelPart] = Field(default_factory=list)
    blocking_questions: list[str] = Field(default_factory=list, description="Open blocking OQ ids.")
    unstated_assumptions: list[UnstatedAssumption] = Field(default_factory=list)
    ambiguity_score: float = Field(ge=0, le=1)
    ambiguity_threshold: float = Field(ge=0, le=1)
    criteria: list[ReadinessCriterion] = Field(default_factory=list)
    issues: list[ValidationIssue] = Field(default_factory=list, description="Kernel issues.")

    def failed(self, *, blocking_only: bool = False) -> list[ReadinessCriterion]:
        """Unsatisfied criteria (optionally only the blocking ones)."""
        return [c for c in self.criteria if not c.satisfied and (c.blocking or not blocking_only)]

    def summary(self) -> str:
        """One-line human summary."""
        failed = self.failed()
        state = "READY" if self.ready else "NOT READY"
        return (
            f"{self.change_id}: {state} — {len(self.criteria) - len(failed)}/{len(self.criteria)} "
            f"criteria met, ambiguity {self.ambiguity_score:.2f} "
            f"(threshold {self.ambiguity_threshold:.2f})"
        )


def default_ambiguity_threshold() -> float:
    """Ambiguity threshold from the default organization policy (0.20 unless changed)."""
    from aisdlc.policy import default_org_policy

    return default_org_policy().security_baselines.ambiguity_threshold


def readiness(pkg: ChangePackage, *, ambiguity_threshold: float | None = None) -> ReadinessReport:
    """Evaluate the G0 intent-readiness criteria for *pkg*.

    Blocking criteria (all must hold for ``ready``): owner assigned; kernel complete;
    at least one requirement; every requirement has a scenario; no requirement grammar
    errors; no open blocking question; ambiguity score <= threshold. Advisory criteria:
    constraints stated; assumptions recorded; no unstated-assumption cues; success signal
    measurable; no open non-blocking questions.
    """
    threshold = (
        ambiguity_threshold if ambiguity_threshold is not None else default_ambiguity_threshold()
    )
    kernel = pkg.intent.kernel
    kernel_issues = validate_kernel(kernel, pkg.intent.id)
    missing = missing_parts(kernel)
    report = grammar.ambiguity_report(pkg)
    blocking_questions = [q.id for q in pkg.open_questions if q.is_open_blocking]
    non_blocking_open = [
        q.id for q in pkg.open_questions if q.status.value == "open" and not q.blocking
    ]
    unstated = find_unstated_assumptions(pkg)
    grammar_errors = [
        i
        for i in grammar.validate_requirements(pkg.requirements)
        if i.severity is IssueSeverity.ERROR and i.code != "REQ_NO_SCENARIO"
    ]
    without_scenario = [r.id for r in pkg.requirements if not r.scenarios]

    criteria = [
        ReadinessCriterion(
            id="owner",
            description="An accountable human owner is named",
            satisfied=bool((pkg.intent.owner or "").strip()),
            blocking=True,
            remediation="Set intent.owner.",
        ),
        ReadinessCriterion(
            id="kernel_complete",
            description="Kernel states why, capabilities, non-goals and a success signal",
            satisfied=not missing,
            blocking=True,
            details=[f"missing: {p.value}" for p in missing],
            remediation="Fill every kernel part in intent.md.",
        ),
        ReadinessCriterion(
            id="requirements_present",
            description="At least one requirement is written",
            satisfied=bool(pkg.requirements),
            blocking=True,
            remediation="Add SHALL/MUST requirements to requirements.md.",
        ),
        ReadinessCriterion(
            id="scenarios_present",
            description="Every requirement has at least one WHEN/THEN scenario",
            satisfied=bool(pkg.requirements) and not without_scenario,
            blocking=True,
            details=[f"{rid} has no scenario" for rid in without_scenario],
            remediation="Write a WHEN … THEN … scenario for each requirement.",
        ),
        ReadinessCriterion(
            id="grammar",
            description="Requirements and scenarios follow the normative grammar",
            satisfied=not grammar_errors,
            blocking=True,
            details=[str(i) for i in grammar_errors],
            remediation="Use uppercase SHALL/MUST (or an EARS form) and WHEN/THEN scenarios.",
        ),
        ReadinessCriterion(
            id="no_blocking_questions",
            description="No open blocking question",
            satisfied=not blocking_questions,
            blocking=True,
            details=blocking_questions,
            remediation="Resolve each blocking question and record the decision.",
        ),
        ReadinessCriterion(
            id="ambiguity",
            description=f"Ambiguity score <= {threshold:.2f}",
            satisfied=report.score <= threshold,
            blocking=True,
            details=[f"score {report.score:.2f}"]
            + [f"{m.artifact_id}: '{m.marker}'" for m in report.markers[:10]],
            remediation="Run `aisdlc intake clarify` and answer the ranked questions.",
        ),
        ReadinessCriterion(
            id="constraints_stated",
            description="Constraints are stated (or explicitly 'none known')",
            satisfied=bool(kernel.constraints),
            blocking=False,
            remediation="Add constraints to the kernel.",
        ),
        ReadinessCriterion(
            id="assumptions_recorded",
            description="At least one explicit assumption is recorded",
            satisfied=bool(pkg.assumptions),
            blocking=False,
            remediation="Record the bets you are making in assumptions.md.",
        ),
        ReadinessCriterion(
            id="no_unstated_assumptions",
            description="No statement leans on an unrecorded assumption",
            satisfied=not unstated,
            blocking=False,
            details=[f"{u.artifact_id}: '{u.cue}' in \"{u.excerpt}\"" for u in unstated],
            remediation="Record each suggested assumption or rewrite the statement.",
        ),
        ReadinessCriterion(
            id="success_measurable",
            description="Success signal is measurable",
            satisfied=bool(kernel.success_signal.strip()) and is_measurable(kernel.success_signal),
            blocking=False,
            remediation="Add a number, threshold or metric to the success signal.",
        ),
        ReadinessCriterion(
            id="no_open_questions",
            description="No open non-blocking questions",
            satisfied=not non_blocking_open,
            blocking=False,
            details=non_blocking_open,
            remediation="Answer or explicitly defer the remaining questions.",
        ),
    ]
    ready = all(c.satisfied for c in criteria if c.blocking)
    return ReadinessReport(
        change_id=pkg.change_id,
        ready=ready,
        missing_kernel_parts=missing,
        blocking_questions=blocking_questions,
        unstated_assumptions=unstated,
        ambiguity_score=report.score,
        ambiguity_threshold=threshold,
        criteria=criteria,
        issues=kernel_issues,
    )
