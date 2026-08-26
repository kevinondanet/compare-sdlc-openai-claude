"""Requirements-quality checklist (Spec Kit ``/checklist``).

Each item is a pass/fail check with details and a remediation hint. ``error`` items are
the ones G0 cares about; ``warning`` items improve the spec but do not block.
"""

from __future__ import annotations

import re
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.intake import kernel as kernel_mod
from aisdlc.intake.analyze import (
    artifact_texts,
    content_words,
    find_conflicting_quantifiers,
    find_contradictions,
    find_duplicates,
)
from aisdlc.schema import grammar
from aisdlc.schema.grammar import IssueSeverity
from aisdlc.schema.models import ChangePackage, Priority, RequirementKind

__all__ = [
    "CHECKLIST_ITEMS",
    "ChecklistItem",
    "ChecklistReport",
    "run_checklist",
]

CHECKLIST_ITEMS: Final[tuple[tuple[str, str, IssueSeverity], ...]] = (
    ("owner_assigned", "An accountable owner is named", IssueSeverity.ERROR),
    ("normative_grammar", "Requirements use SHALL/MUST or an EARS form", IssueSeverity.ERROR),
    ("testable", "Requirements and scenarios are testable", IssueSeverity.ERROR),
    ("unambiguous", "No placeholders, open questions or excess ambiguity", IssueSeverity.ERROR),
    (
        "complete",
        "Kernel complete, requirements present, no blocking questions",
        IssueSeverity.ERROR,
    ),
    ("consistent", "No contradictions or conflicting quantities", IssueSeverity.ERROR),
    ("traceable", "Requirements trace to the intent and to tasks", IssueSeverity.WARNING),
    ("non_goals_present", "Non-goals are stated", IssueSeverity.ERROR),
    ("nfrs_present", "At least one non-functional requirement", IssueSeverity.WARNING),
    ("success_signal_measurable", "Success signal is measurable", IssueSeverity.WARNING),
    ("requirements_have_scenarios", "Every requirement has >= 1 scenario", IssueSeverity.ERROR),
    (
        "scenarios_reference_requirements",
        "Every scenario belongs to a requirement",
        IssueSeverity.ERROR,
    ),
    ("no_duplicates", "No near-duplicate requirements", IssueSeverity.WARNING),
    (
        "priorities_meaningful",
        "Priorities are set and at least one MUST exists",
        IssueSeverity.WARNING,
    ),
)
"""``(id, title, severity)`` of every checklist item, in report order."""

_SCN_REF: Final[re.Pattern[str]] = re.compile(r"\bSCN-\d{3,}-\d{2,}\b")


class ChecklistItem(BaseModel):
    """One checklist item with its outcome."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    passed: bool
    severity: IssueSeverity
    details: list[str] = Field(default_factory=list)
    remediation: str = ""
    artifact_ids: list[str] = Field(default_factory=list)

    def __str__(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"[{mark}] {self.id}: {self.title}"


class ChecklistReport(BaseModel):
    """Result of :func:`run_checklist`."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    items: list[ChecklistItem] = Field(default_factory=list)
    ambiguity_score: float = Field(ge=0, le=1)

    @property
    def passed(self) -> bool:
        """``True`` when every ``error``-severity item passes."""
        return all(i.passed for i in self.items if i.severity is IssueSeverity.ERROR)

    @property
    def score(self) -> float:
        """Fraction of items passed."""
        return round(sum(1 for i in self.items if i.passed) / max(1, len(self.items)), 4)

    def failures(self, *, errors_only: bool = False) -> list[ChecklistItem]:
        """Items that failed (optionally only ``error`` ones)."""
        return [
            i
            for i in self.items
            if not i.passed and (not errors_only or i.severity is IssueSeverity.ERROR)
        ]

    def summary(self) -> str:
        """One-line human summary."""
        state = "PASS" if self.passed else "FAIL"
        passed = sum(1 for i in self.items if i.passed)
        return f"{self.change_id}: {state} — {passed}/{len(self.items)} items passed"


def _item(
    item_id: str,
    passed: bool,
    details: list[str],
    remediation: str,
    artifact_ids: list[str] | None = None,
) -> ChecklistItem:
    title, severity = next((t, s) for i, t, s in CHECKLIST_ITEMS if i == item_id)
    return ChecklistItem(
        id=item_id,
        title=title,
        passed=passed,
        severity=severity,
        details=details,
        remediation=remediation,
        artifact_ids=sorted(set(artifact_ids or [])),
    )


def run_checklist(
    pkg: ChangePackage, *, ambiguity_threshold: float | None = None
) -> ChecklistReport:
    """Run the requirements-quality checklist over *pkg*.

    Item ids: ``owner_assigned``, ``normative_grammar``, ``testable``, ``unambiguous``,
    ``complete``, ``consistent``, ``traceable``, ``non_goals_present``, ``nfrs_present``,
    ``success_signal_measurable``, ``requirements_have_scenarios``,
    ``scenarios_reference_requirements``, ``no_duplicates``, ``priorities_meaningful``.
    """
    threshold = (
        ambiguity_threshold
        if ambiguity_threshold is not None
        else kernel_mod.default_ambiguity_threshold()
    )
    kernel = pkg.intent.kernel
    requirement_ids = {r.id for r in pkg.requirements}
    grammar_issues = grammar.validate_requirements(pkg.requirements)
    ambiguity = grammar.ambiguity_report(pkg)
    items: list[ChecklistItem] = []

    # owner
    items.append(
        _item(
            "owner_assigned",
            bool((pkg.intent.owner or "").strip()),
            [],
            "Set intent.owner to the accountable person.",
        )
    )

    # normative grammar
    text_codes = {"REQ_EMPTY", "REQ_NO_MODAL", "REQ_LOWERCASE_MODAL", "REQ_EARS_MALFORMED"}
    text_issues = [i for i in grammar_issues if i.code in text_codes]
    items.append(
        _item(
            "normative_grammar",
            not [i for i in text_issues if i.severity is IssueSeverity.ERROR],
            [str(i) for i in text_issues],
            "Write each requirement as 'The <system> SHALL …' or an EARS form.",
            [i.artifact_id for i in text_issues if i.artifact_id],
        )
    )

    # testable: well-formed scenarios and no vague qualifiers in requirement text
    scenario_issues = [i for i in grammar_issues if i.code in {"SCN_MALFORMED", "SCN_EMPTY_CLAUSE"}]
    vague: list[str] = []
    vague_ids: list[str] = []
    for requirement in pkg.requirements:
        markers = [
            m for m in grammar.find_ambiguity_markers(requirement.text) if m.category == "vague"
        ]
        if markers:
            vague.append(
                f"{requirement.id} uses vague terms: "
                + ", ".join(sorted({m.marker for m in markers}))
            )
            vague_ids.append(requirement.id)
    items.append(
        _item(
            "testable",
            not scenario_issues and not vague,
            [str(i) for i in scenario_issues] + vague,
            "Replace vague terms with measurable thresholds; fix WHEN/THEN scenarios.",
            [i.artifact_id for i in scenario_issues if i.artifact_id] + vague_ids,
        )
    )

    # unambiguous
    hard = [m for m in ambiguity.markers if m.category in {"explicit", "question"}]
    details = [f"{m.artifact_id}: '{m.marker}'" for m in hard]
    if ambiguity.score > threshold:
        details.append(f"ambiguity score {ambiguity.score:.2f} > threshold {threshold:.2f}")
    items.append(
        _item(
            "unambiguous",
            not details,
            details,
            "Answer the ranked clarification questions (`aisdlc intake clarify`).",
            [m.artifact_id for m in hard if m.artifact_id],
        )
    )

    # complete
    missing = kernel_mod.missing_parts(kernel)
    blocking = [q.id for q in pkg.open_questions if q.is_open_blocking]
    details = [f"kernel part '{p.value}' is empty" for p in missing]
    if not pkg.requirements:
        details.append("no requirements recorded")
    details.extend(f"{q} is open and blocking" for q in blocking)
    items.append(
        _item(
            "complete",
            not details,
            details,
            "Fill the kernel, add requirements and resolve blocking questions.",
            blocking,
        )
    )

    # consistent
    contradictions = find_contradictions(pkg.requirements)
    statements = [(aid, t) for aid, t in artifact_texts(pkg) if ids.kind_of(aid) != "OQ"]
    conflicts = find_conflicting_quantifiers(statements)
    details = [
        f"{p.left_id} and {p.right_id} contradict (SHALL vs SHALL NOT)" for p in contradictions
    ]
    details.extend(
        f"{c.left.artifact_id} '{c.left.raw}' vs {c.right.artifact_id} '{c.right.raw}'"
        for c in conflicts
    )
    involved = [x for p in contradictions for x in (p.left_id, p.right_id)]
    involved.extend(x for c in conflicts for x in c.artifact_ids)
    items.append(
        _item(
            "consistent",
            not details,
            details,
            "Decide the intended behaviour/value and rewrite the conflicting statements.",
            involved,
        )
    )

    # traceable
    intent_words = set(content_words(" ".join([kernel.why, *kernel.capabilities])))
    untraced: list[str] = []
    for requirement in pkg.requirements:
        anchored = bool(requirement.rationale) or bool(requirement.tags)
        overlap = intent_words & set(content_words(requirement.text))
        if not anchored and not overlap:
            untraced.append(f"{requirement.id} shares no term with the kernel and has no rationale")
    task_gaps: list[str] = []
    if pkg.tasks:
        covered = {rid for t in pkg.tasks for rid in t.requirement_ids}
        task_gaps.extend(f"{r.id} has no task" for r in pkg.requirements if r.id not in covered)
        task_gaps.extend(f"{t.id} has no requirement" for t in pkg.tasks if not t.requirement_ids)
    items.append(
        _item(
            "traceable",
            not untraced and not task_gaps,
            untraced + task_gaps,
            "Add a rationale/tag linking each requirement to the intent; trace tasks to REQs.",
            [d.split()[0] for d in untraced + task_gaps],
        )
    )

    # non-goals
    items.append(
        _item(
            "non_goals_present",
            bool(kernel.non_goals),
            [],
            "List what is explicitly out of scope in the kernel.",
        )
    )

    # NFRs
    items.append(
        _item(
            "nfrs_present",
            any(r.kind is RequirementKind.NON_FUNCTIONAL for r in pkg.requirements),
            [],
            "Add performance, availability, security or cost requirements.",
        )
    )

    # measurable success
    items.append(
        _item(
            "success_signal_measurable",
            bool(kernel.success_signal.strip()) and kernel_mod.is_measurable(kernel.success_signal),
            [] if kernel.success_signal.strip() else ["success signal is empty"],
            "State a number, threshold or metric in the success signal.",
        )
    )

    # scenarios per requirement
    without = [r.id for r in pkg.requirements if not r.scenarios]
    items.append(
        _item(
            "requirements_have_scenarios",
            bool(pkg.requirements) and not without,
            [f"{rid} has no scenario" for rid in without]
            + ([] if pkg.requirements else ["no requirements recorded"]),
            "Write at least one WHEN … THEN … scenario per requirement.",
            without,
        )
    )

    # scenarios reference requirements
    orphan: list[str] = []
    for scenario in pkg.scenarios():
        if scenario.requirement_id not in requirement_ids:
            orphan.append(f"{scenario.id} belongs to unknown {scenario.requirement_id}")
    known_scn = {s.id for s in pkg.scenarios()}
    for rel, body in sorted(pkg.bodies.items()):
        for ref in sorted(set(_SCN_REF.findall(body)) - known_scn):
            orphan.append(f"{rel} mentions unknown scenario {ref}")
    items.append(
        _item(
            "scenarios_reference_requirements",
            not orphan,
            orphan,
            "Give every scenario the id of an existing requirement (SCN-<req>-<nn>).",
        )
    )

    # duplicates
    duplicates = find_duplicates(pkg.requirements)
    items.append(
        _item(
            "no_duplicates",
            not duplicates,
            [f"{p.left_id} ~ {p.right_id} ({p.similarity:.2f})" for p in duplicates],
            "Merge near-duplicate requirements or make the difference explicit.",
            [x for p in duplicates for x in (p.left_id, p.right_id)],
        )
    )

    # priorities
    has_must = any(r.priority is Priority.MUST for r in pkg.requirements)
    items.append(
        _item(
            "priorities_meaningful",
            bool(pkg.requirements) and has_must,
            [] if has_must else ["no MUST requirement"],
            "Mark the essential requirements as must.",
        )
    )

    return ChecklistReport(change_id=pkg.change_id, items=items, ambiguity_score=ambiguity.score)
