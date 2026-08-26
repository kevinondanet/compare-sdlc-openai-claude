"""Ranked clarification questions (Spec Kit ``/clarify``) and deterministic answers.

:func:`generate_questions` mines a change package for the things most likely to derail
implementation — ambiguity markers, missing scenarios, undefined terms, conflicting
quantities, open questions, missing NFRs and kernel gaps — ranks them by impact and caps
the list (Spec Kit asks five at a time). :func:`apply_answer` folds an answer back into
the package deterministically and records the decision as a resolved open question so
the trail survives in ``assumptions.md``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.intake import kernel as kernel_mod
from aisdlc.intake.analyze import extract_quantities, find_conflicting_quantifiers
from aisdlc.schema import grammar
from aisdlc.schema.models import (
    ChangePackage,
    OpenQuestion,
    Priority,
    QuestionStatus,
    Requirement,
    RequirementKind,
    Scenario,
    utcnow,
)
from aisdlc.schema.package import REQUIREMENTS_FILE

__all__ = [
    "DEFAULT_LIMIT",
    "PRIORITY_WEIGHT",
    "QuestionCategory",
    "ClarificationQuestion",
    "ClarificationSet",
    "AnswerError",
    "AnswerResult",
    "find_undefined_terms",
    "generate_questions",
    "apply_answer",
    "apply_answers",
]

DEFAULT_LIMIT: Final[int] = 5
"""Spec Kit asks at most five clarification questions per round."""

PRIORITY_WEIGHT: Final[dict[Priority, float]] = {
    Priority.MUST: 1.0,
    Priority.SHOULD: 0.8,
    Priority.COULD: 0.6,
    Priority.WONT: 0.3,
}
"""Impact multiplier by MoSCoW priority of the affected requirement."""


class QuestionCategory(StrEnum):
    """Why a clarification is being asked (drives ranking and how answers apply)."""

    OPEN_QUESTION = "open_question"
    CONFLICTING_QUANTIFIER = "conflicting_quantifier"
    AMBIGUITY = "ambiguity"
    MISSING_SCENARIO = "missing_scenario"
    KERNEL = "kernel"
    NON_FUNCTIONAL = "non_functional"
    UNDEFINED_TERM = "undefined_term"


_CATEGORY_RANK: Final[dict[QuestionCategory, int]] = {c: i for i, c in enumerate(QuestionCategory)}


class ClarificationQuestion(BaseModel):
    """One ranked clarification question."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="``CQ-nnn``, assigned after ranking.")
    category: QuestionCategory
    question: str
    impact: float = Field(ge=0, le=1)
    requirement_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    marker: str | None = Field(default=None, description="Ambiguity marker text, if any.")
    marker_category: str | None = Field(default=None, description="explicit/question/vague.")
    target: str | None = Field(
        default=None, description="Kernel part, open-question id or undefined term."
    )
    options: list[str] = Field(default_factory=list, description="Suggested answers.")
    rationale: str = ""
    details: dict[str, str] = Field(
        default_factory=dict, description="Artifact id -> conflicting quantity text."
    )


class ClarificationSet(BaseModel):
    """Ranked, capped clarification questions for one package."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    ambiguity_score: float = Field(ge=0, le=1)
    candidates: int = Field(ge=0, description="Questions found before capping.")
    questions: list[ClarificationQuestion] = Field(default_factory=list)

    def get(self, question_id: str) -> ClarificationQuestion | None:
        """Question by id."""
        return next((q for q in self.questions if q.id == question_id), None)


# --------------------------------------------------------------------------------------
# Candidate discovery
# --------------------------------------------------------------------------------------

_TIME_VAGUE: Final[frozenset[str]] = frozenset(
    {"fast", "quick", "quickly", "slow", "soon", "timely", "efficient", "efficiently"}
)
_QUANTITY_VAGUE: Final[frozenset[str]] = frozenset(
    {
        "some",
        "several",
        "many",
        "few",
        "various",
        "large",
        "small",
        "minimal",
        "approximately",
        "roughly",
        "about",
        "significant",
    }
)
_ACRONYM_RE: Final[re.Pattern[str]] = re.compile(r"\b[A-Z][A-Z0-9]{1,7}\b")
_EXPLICIT_RE: Final[re.Pattern[str]] = re.compile(
    "|".join(re.escape(m) for m in grammar.EXPLICIT_MARKERS), re.I
)
_ACRONYM_IGNORE: Final[frozenset[str]] = frozenset(
    {
        "SHALL",
        "MUST",
        "NOT",
        "WHEN",
        "THEN",
        "GIVEN",
        "IF",
        "WHILE",
        "WHERE",
        "AND",
        "OR",
        "THE",
        "TBD",
        "TODO",
        "FIXME",
        "XXX",
        "API",
        "HTTP",
        "HTTPS",
        "JSON",
        "YAML",
        "URL",
        "URI",
        "ID",
        "UI",
        "CLI",
        "SQL",
        "TLS",
        "SSL",
        "REST",
        "XML",
        "CSV",
        "PDF",
        "UTC",
        "USD",
        "EUR",
        "GBP",
        "OK",
        "IO",
        "OS",
        "PR",
        "CI",
        "CD",
        "KB",
        "MB",
        "GB",
        "MS",
        "AI",
        "US",
        "UK",
        "EU",
        *ids.KINDS,
    }
)


def _priority_weight(pkg: ChangePackage, artifact_id: str) -> float:
    kind = ids.kind_of(artifact_id)
    if kind == "REQ":
        requirement = pkg.requirement(artifact_id)
        return PRIORITY_WEIGHT[requirement.priority] if requirement else 1.0
    if kind == "SCN":
        return _priority_weight(pkg, ids.scenario_parent(artifact_id))
    if kind == "ASM":
        return 0.6
    return 1.0


def _requirement_ids_for(artifact_id: str) -> list[str]:
    kind = ids.kind_of(artifact_id)
    if kind == "REQ":
        return [artifact_id]
    if kind == "SCN":
        return [ids.scenario_parent(artifact_id)]
    return []


def _statements(pkg: ChangePackage) -> list[tuple[str, str]]:
    kernel = pkg.intent.kernel
    out: list[tuple[str, str]] = [
        (pkg.intent.id, kernel.why),
        (pkg.intent.id, kernel.success_signal),
    ]
    out.extend(
        (pkg.intent.id, t) for t in [*kernel.capabilities, *kernel.constraints, *kernel.non_goals]
    )
    for requirement in pkg.requirements:
        out.append((requirement.id, requirement.text))
        out.extend((s.id, s.text) for s in requirement.scenarios)
    out.extend((a.id, a.text) for a in pkg.assumptions)
    return [(aid, text) for aid, text in out if text.strip()]


def _definition_corpus(pkg: ChangePackage) -> str:
    kernel = pkg.intent.kernel
    parts = [*pkg.bodies.values(), kernel.why, kernel.success_signal, *kernel.capabilities]
    parts.extend([*kernel.constraints, *kernel.non_goals])
    parts.extend(a.text for a in pkg.assumptions)
    parts.extend(r.rationale or "" for r in pkg.requirements)
    return "\n".join(parts)


def _is_defined(term: str, corpus: str) -> bool:
    escaped = re.escape(term)
    patterns = (
        rf"\*\*{escaped}\*\*\s*[:—–-]",
        rf"(?<![\w-]){escaped}\s*[:—–]",
        rf"\({escaped}\)",
        rf"(?<![\w-]){escaped}\s*\(",
    )
    return any(re.search(p, corpus) for p in patterns)


def find_undefined_terms(pkg: ChangePackage) -> dict[str, list[str]]:
    """Acronyms used in requirements/scenarios with no definition anywhere.

    A term counts as defined when a glossary-style entry (``**TERM**:``, ``TERM:``,
    ``TERM (expansion)`` or ``(TERM)``) appears in any prose body, kernel part, assumption
    or requirement rationale. Returns ``term -> requirement ids using it``.
    """
    corpus = _definition_corpus(pkg)
    usage: dict[str, list[str]] = {}
    for requirement in pkg.requirements:
        texts = [requirement.text, *(s.text for s in requirement.scenarios)]
        for text in texts:
            for match in _ACRONYM_RE.finditer(_EXPLICIT_RE.sub(" ", text)):
                term = match.group(0)
                if term in _ACRONYM_IGNORE or term.isdigit() or _is_defined(term, corpus):
                    continue
                users = usage.setdefault(term, [])
                if requirement.id not in users:
                    users.append(requirement.id)
    return dict(sorted(usage.items()))


def _marker_question(
    pkg: ChangePackage, artifact_id: str, marker: str, category: str
) -> ClarificationQuestion:
    weight = _priority_weight(pkg, artifact_id)
    lowered = marker.lower()
    if category == "explicit":
        base, options = (
            1.0,
            [
                "Provide the missing text",
                "Record as a blocking open question",
                "Drop the statement",
            ],
        )
        question = f"{artifact_id} contains the placeholder '{marker}': what should it say?"
        rationale = "Explicit placeholders cannot be implemented or tested."
    elif category == "question":
        base, options = (
            0.7,
            [
                "Rewrite as a SHALL statement with the decision",
                "Record as a blocking open question",
            ],
        )
        question = f"{artifact_id} still asks a question: what is the decision?"
        rationale = "A requirement that asks a question has not been decided."
    else:
        base = 0.5
        if lowered in _TIME_VAGUE:
            options = ["within 200 ms at p95", "within 1 s at p95", "within 5 s at p95"]
            question = f"{artifact_id} says '{marker}': what is the measurable time limit?"
        elif lowered in _QUANTITY_VAGUE:
            options = ["exactly <N>", "at least <N>", "at most <N>"]
            question = f"{artifact_id} says '{marker}': what is the exact number or bound?"
        else:
            options = [
                "Replace with a measurable statement",
                "Delete the qualifier",
                "Record the intent as an assumption",
            ]
            question = f"{artifact_id} uses the vague term '{marker}': what does it mean precisely?"
        rationale = "Vague qualifiers cannot be verified by a test."
    return ClarificationQuestion(
        id="CQ-000",
        category=QuestionCategory.AMBIGUITY,
        question=question,
        impact=round(min(1.0, base * weight), 4),
        requirement_ids=_requirement_ids_for(artifact_id),
        artifact_ids=[artifact_id],
        marker=marker,
        marker_category=category,
        options=options,
        rationale=rationale,
    )


def _candidates(pkg: ChangePackage) -> list[ClarificationQuestion]:
    out: list[ClarificationQuestion] = []
    statements = _statements(pkg)

    # 1. Ambiguity markers, one question per (artifact, marker).
    seen: set[tuple[str, str]] = set()
    for artifact_id, text in statements:
        for marker in grammar.find_ambiguity_markers(text, artifact_id):
            key = (artifact_id, marker.marker.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(_marker_question(pkg, artifact_id, marker.marker, marker.category))

    # 2. Requirements without scenarios.
    for requirement in pkg.requirements:
        if requirement.scenarios:
            continue
        weight = PRIORITY_WEIGHT[requirement.priority]
        out.append(
            ClarificationQuestion(
                id="CQ-000",
                category=QuestionCategory.MISSING_SCENARIO,
                question=f"{requirement.id} has no acceptance scenario: WHEN what happens, "
                "THEN what is observable?",
                impact=round(0.9 * weight, 4),
                requirement_ids=[requirement.id],
                artifact_ids=[requirement.id],
                options=[
                    "WHEN <trigger> THEN <observable result>",
                    "GIVEN <state> WHEN <action> THEN <observable result>",
                ],
                rationale="Every requirement needs at least one WHEN/THEN scenario (G0).",
            )
        )

    # 3. Undefined terms.
    for term, requirement_ids in find_undefined_terms(pkg).items():
        weight = max(_priority_weight(pkg, rid) for rid in requirement_ids)
        out.append(
            ClarificationQuestion(
                id="CQ-000",
                category=QuestionCategory.UNDEFINED_TERM,
                question=f"'{term}' is used in {', '.join(requirement_ids)} but never defined: "
                "what does it stand for?",
                impact=round(0.45 * weight, 4),
                requirement_ids=requirement_ids,
                artifact_ids=list(requirement_ids),
                target=term,
                options=["Add a glossary definition", "Replace the acronym with its expansion"],
                rationale="Undefined terms are read differently by every implementer.",
            )
        )

    # 4. Conflicting quantities.
    for conflict in find_conflicting_quantifiers(statements):
        left, right = conflict.left, conflict.right
        weight = max(
            _priority_weight(pkg, left.artifact_id), _priority_weight(pkg, right.artifact_id)
        )
        out.append(
            ClarificationQuestion(
                id="CQ-000",
                category=QuestionCategory.CONFLICTING_QUANTIFIER,
                question=f"{left.artifact_id} says '{left.raw}' but {right.artifact_id} says "
                f"'{right.raw}' for the same limit: which value applies?",
                impact=round(0.85 * weight, 4),
                requirement_ids=sorted(
                    {
                        *_requirement_ids_for(left.artifact_id),
                        *_requirement_ids_for(right.artifact_id),
                    }
                ),
                artifact_ids=[left.artifact_id, right.artifact_id],
                options=[left.raw, right.raw],
                rationale="Two statements disagree on the same quantity.",
                details={left.artifact_id: left.raw, right.artifact_id: right.raw},
            )
        )

    # 5. Open questions.
    for question in pkg.open_questions:
        if question.status is not QuestionStatus.OPEN:
            continue
        out.append(
            ClarificationQuestion(
                id="CQ-000",
                category=QuestionCategory.OPEN_QUESTION,
                question=question.question,
                impact=0.95 if question.blocking else 0.55,
                artifact_ids=[question.id],
                target=question.id,
                rationale="Blocking open questions fail G0."
                if question.blocking
                else "Open questions leave room for divergent implementations.",
            )
        )

    # 6. No non-functional requirements.
    if pkg.requirements and not any(
        r.kind is RequirementKind.NON_FUNCTIONAL for r in pkg.requirements
    ):
        out.append(
            ClarificationQuestion(
                id="CQ-000",
                category=QuestionCategory.NON_FUNCTIONAL,
                question="No non-functional requirements are recorded: what are the performance, "
                "availability and security expectations?",
                impact=0.5,
                options=[
                    "The system SHALL respond within <N> ms at p95",
                    "The system SHALL be available 99.9% of each month",
                    "The system SHALL log every privileged action",
                ],
                rationale="NFRs decide architecture and are needed for G1.",
            )
        )

    # 7. Kernel gaps.
    kernel_impact = {
        kernel_mod.KernelPart.WHY: 0.8,
        kernel_mod.KernelPart.SUCCESS_SIGNAL: 0.8,
        kernel_mod.KernelPart.CAPABILITIES: 0.75,
        kernel_mod.KernelPart.NON_GOALS: 0.7,
        kernel_mod.KernelPart.CONSTRAINTS: 0.4,
    }
    for part in kernel_mod.missing_parts(pkg.intent.kernel, include_optional=True):
        out.append(
            ClarificationQuestion(
                id="CQ-000",
                category=QuestionCategory.KERNEL,
                question=kernel_mod.KERNEL_PROMPTS[part],
                impact=kernel_impact[part],
                artifact_ids=[pkg.intent.id],
                target=part.value,
                rationale=f"Kernel part '{part.value}' is empty.",
            )
        )
    return out


def generate_questions(
    pkg: ChangePackage, *, limit: int | None = DEFAULT_LIMIT
) -> ClarificationSet:
    """Rank clarification questions for *pkg* and keep the top *limit* (``None`` = all).

    Ranking key: impact (descending), then category order, then artifact ids — so ids
    are stable across runs and across different limits.
    """
    candidates = _candidates(pkg)
    candidates.sort(
        key=lambda q: (
            -q.impact,
            _CATEGORY_RANK[q.category],
            q.artifact_ids,
            q.marker or "",
            q.question,
        )
    )
    ranked = [q.model_copy(update={"id": f"CQ-{i:03d}"}) for i, q in enumerate(candidates, 1)]
    kept = ranked if limit is None else ranked[: max(0, limit)]
    return ClarificationSet(
        change_id=pkg.change_id,
        ambiguity_score=grammar.ambiguity_score(pkg),
        candidates=len(ranked),
        questions=kept,
    )


# --------------------------------------------------------------------------------------
# Applying answers
# --------------------------------------------------------------------------------------


class AnswerError(ValueError):
    """The answer cannot be applied deterministically (wrong form or unknown question)."""


class AnswerResult(BaseModel):
    """What :func:`apply_answer` changed."""

    model_config = ConfigDict(extra="forbid")

    question_id: str
    category: QuestionCategory
    changes: list[str] = Field(default_factory=list)
    open_question_id: str | None = Field(
        default=None, description="Resolved OQ recording the decision, when one was written."
    )
    created_ids: list[str] = Field(default_factory=list)


_SCENARIO_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:GIVEN\s+(?P<given>.+?)\s*,?\s+)?WHEN\s+(?P<when>.+?)\s*,?\s+THEN\s+(?P<then>.+?)\s*$",
    re.I | re.S,
)


def _is_normative(text: str) -> bool:
    return grammar.NORMATIVE_PATTERN.search(text) is not None


def _replace_marker(text: str, marker: str, replacement: str, category: str) -> str:
    if category == "vague":
        pattern = rf"(?<![\w-]){re.escape(marker)}(?![\w-])"
    else:
        pattern = re.escape(marker)
    return re.sub(pattern, lambda _m: replacement, text, count=1, flags=re.I)


def _edit_artifact(pkg: ChangePackage, artifact_id: str, edit: Callable[[str], str]) -> list[str]:
    """Apply *edit* to every text field of the artifact; return the fields changed."""
    changed: list[str] = []
    kind = ids.kind_of(artifact_id)

    def apply(label: str, value: str | None) -> str | None:
        if value is None:
            return None
        new = edit(value)
        if new != value:
            changed.append(label)
        return new

    if kind == "CHG":
        kernel = pkg.intent.kernel
        kernel.why = apply("kernel.why", kernel.why) or ""
        kernel.success_signal = apply("kernel.success_signal", kernel.success_signal) or ""
        for name in ("capabilities", "constraints", "non_goals"):
            items = [apply(f"kernel.{name}", item) or "" for item in getattr(kernel, name)]
            setattr(kernel, name, items)
    elif kind == "REQ":
        requirement = pkg.requirement(artifact_id)
        if requirement is None:
            raise AnswerError(f"unknown requirement {artifact_id}")
        requirement.text = apply(f"{artifact_id}.text", requirement.text) or ""
    elif kind == "SCN":
        requirement = pkg.requirement(ids.scenario_parent(artifact_id))
        scenario = next(
            (s for s in (requirement.scenarios if requirement else []) if s.id == artifact_id),
            None,
        )
        if scenario is None:
            raise AnswerError(f"unknown scenario {artifact_id}")
        updates = {
            "given": apply(f"{artifact_id}.given", scenario.given),
            "when": apply(f"{artifact_id}.when", scenario.when),
            "then": apply(f"{artifact_id}.then", scenario.then),
            "raw": apply(f"{artifact_id}.raw", scenario.raw) or "",
        }
        assert requirement is not None
        requirement.scenarios = [
            Scenario(**{**s.model_dump(), **updates}) if s.id == artifact_id else s
            for s in requirement.scenarios
        ]
    elif kind == "ASM":
        assumption = next((a for a in pkg.assumptions if a.id == artifact_id), None)
        if assumption is None:
            raise AnswerError(f"unknown assumption {artifact_id}")
        assumption.text = apply(f"{artifact_id}.text", assumption.text) or ""
    else:
        raise AnswerError(f"cannot edit artifact {artifact_id}")
    return changed


def _record_decision(pkg: ChangePackage, question: ClarificationQuestion, answer: str) -> str:
    oq_id = ids.next_id("OQ", pkg.all_ids())
    pkg.open_questions.append(
        OpenQuestion(
            id=oq_id,
            question=f"[{question.id}] {question.question}",
            status=QuestionStatus.RESOLVED,
            blocking=False,
            owner=pkg.intent.owner,
            decision=answer,
            resolved_at=utcnow(),
        )
    )
    return oq_id


def _apply_ambiguity(pkg: ChangePackage, q: ClarificationQuestion, answer: str) -> list[str]:
    artifact_id = q.artifact_ids[0]
    marker = q.marker or ""
    if q.marker_category == "question":
        if _is_normative(answer) and ids.kind_of(artifact_id) in {"REQ", "ASM"}:
            return _edit_artifact(pkg, artifact_id, lambda _t: answer)
        return _edit_artifact(pkg, artifact_id, lambda t: t.replace("?", "", 1).rstrip())
    return _edit_artifact(
        pkg, artifact_id, lambda t: _replace_marker(t, marker, answer, q.marker_category or "")
    )


def _apply_missing_scenario(
    pkg: ChangePackage, q: ClarificationQuestion, answer: str
) -> tuple[list[str], list[str]]:
    match = _SCENARIO_RE.match(answer)
    if match is None:
        raise AnswerError(
            "scenario answers must be 'WHEN <trigger> THEN <result>' "
            "(optionally 'GIVEN <state> ...')"
        )
    requirement = pkg.requirement(q.requirement_ids[0])
    if requirement is None:
        raise AnswerError(f"unknown requirement {q.requirement_ids[0]}")
    scenario_id = ids.next_id("SCN", pkg.all_ids(), parent=requirement.id)
    scenario = Scenario(
        id=scenario_id,
        name="clarified",
        given=(match.group("given") or "").strip() or None,
        when=match.group("when").strip(),
        then=match.group("then").strip(),
    )
    requirement.scenarios = [*requirement.scenarios, scenario]
    return [f"{requirement.id}.scenarios += {scenario_id}"], [scenario_id]


def _apply_glossary(pkg: ChangePackage, q: ClarificationQuestion, answer: str) -> list[str]:
    term = q.target or ""
    body = pkg.bodies.get(REQUIREMENTS_FILE, "")
    if "## Glossary" not in body:
        body = body.rstrip("\n") + ("\n\n" if body.strip() else "") + "## Glossary\n\n"
    body = body.rstrip("\n") + f"\n- **{term}**: {answer}\n"
    pkg.bodies[REQUIREMENTS_FILE] = body
    return [f"{REQUIREMENTS_FILE}: glossary entry for {term}"]


def _apply_quantity(pkg: ChangePackage, q: ClarificationQuestion, answer: str) -> list[str]:
    quantities = extract_quantities(answer)
    if len(quantities) != 1:
        raise AnswerError("answer must be exactly one quantity with a unit, e.g. '200 ms'")
    value = quantities[0].raw
    changes: list[str] = []
    for artifact_id, old in q.details.items():

        def replace(text: str, old: str = old) -> str:
            return text.replace(old, value, 1)

        changes.extend(_edit_artifact(pkg, artifact_id, replace))
    return changes


def _apply_open_question(pkg: ChangePackage, q: ClarificationQuestion, answer: str) -> list[str]:
    target = q.target or ""
    for index, existing in enumerate(pkg.open_questions):
        if existing.id == target:
            pkg.open_questions[index] = OpenQuestion(
                **{
                    **existing.model_dump(),
                    "status": QuestionStatus.RESOLVED,
                    "decision": answer,
                    "resolved_at": utcnow(),
                }
            )
            return [f"{target} resolved"]
    raise AnswerError(f"unknown open question {target}")


def _apply_non_functional(pkg: ChangePackage, answer: str) -> tuple[list[str], list[str]]:
    if not _is_normative(answer):
        raise AnswerError("non-functional requirement answers must contain SHALL or MUST")
    req_id = ids.next_id("REQ", pkg.all_ids())
    pkg.requirements.append(
        Requirement(
            id=req_id,
            text=answer,
            kind=RequirementKind.NON_FUNCTIONAL,
            priority=Priority.MUST,
            tags=["clarified"],
        )
    )
    return [f"requirements += {req_id}"], [req_id]


def _apply_kernel(pkg: ChangePackage, q: ClarificationQuestion, answer: str) -> list[str]:
    part = kernel_mod.KernelPart(q.target or "")
    kernel = pkg.intent.kernel
    if part in (kernel_mod.KernelPart.WHY, kernel_mod.KernelPart.SUCCESS_SIGNAL):
        setattr(kernel, part.value, " ".join(answer.split()))
    else:
        existing: list[str] = list(getattr(kernel, part.value))
        setattr(kernel, part.value, kernel_mod.split_items([*existing, answer]))
    return [f"kernel.{part.value}"]


def _resolve(
    pkg: ChangePackage,
    question: ClarificationQuestion | str,
    questions: ClarificationSet | None,
) -> ClarificationQuestion:
    if isinstance(question, ClarificationQuestion):
        return question
    source = questions if questions is not None else generate_questions(pkg, limit=None)
    found = source.get(question)
    if found is None:
        raise AnswerError(f"unknown clarification question {question}")
    return found


def apply_answer(
    pkg: ChangePackage,
    question: ClarificationQuestion | str,
    answer: str,
    *,
    questions: ClarificationSet | None = None,
) -> AnswerResult:
    """Fold *answer* into *pkg* for *question* (object or ``CQ-nnn`` id) in place.

    Behaviour per category:

    * ``ambiguity`` — the marker is replaced by the answer (a ``?`` is removed, or the
      whole statement replaced when the answer is itself normative);
    * ``missing_scenario`` — the answer must read ``[GIVEN …] WHEN … THEN …`` and becomes
      a new scenario of the requirement;
    * ``undefined_term`` — a glossary entry is appended to the ``requirements.md`` body;
    * ``conflicting_quantifier`` — the answer (one quantity) replaces both values;
    * ``open_question`` — the open question is resolved with the answer as decision;
    * ``non_functional`` — the answer (SHALL/MUST text) becomes a new NFR;
    * ``kernel`` — the answer fills the missing kernel part.

    Every applied answer (except scenario creation) is also recorded as a resolved open
    question so the decision trail lives in ``assumptions.md``. Raises
    :class:`AnswerError` when the answer has the wrong form; the package is untouched.
    """
    resolved = _resolve(pkg, question, questions)
    text = answer.strip()
    if not text:
        raise AnswerError("answer is empty")
    created: list[str] = []
    record = True
    if resolved.category is QuestionCategory.AMBIGUITY:
        changes = _apply_ambiguity(pkg, resolved, text)
    elif resolved.category is QuestionCategory.MISSING_SCENARIO:
        changes, created = _apply_missing_scenario(pkg, resolved, text)
        record = False
    elif resolved.category is QuestionCategory.UNDEFINED_TERM:
        changes = _apply_glossary(pkg, resolved, text)
    elif resolved.category is QuestionCategory.CONFLICTING_QUANTIFIER:
        changes = _apply_quantity(pkg, resolved, text)
    elif resolved.category is QuestionCategory.OPEN_QUESTION:
        changes = _apply_open_question(pkg, resolved, text)
        record = False
    elif resolved.category is QuestionCategory.NON_FUNCTIONAL:
        changes, created = _apply_non_functional(pkg, text)
    else:
        changes = _apply_kernel(pkg, resolved, text)
    oq_id = _record_decision(pkg, resolved, text) if record else None
    return AnswerResult(
        question_id=resolved.id,
        category=resolved.category,
        changes=changes,
        open_question_id=oq_id,
        created_ids=created,
    )


def apply_answers(
    pkg: ChangePackage, answers: Mapping[str, str], *, limit: int | None = None
) -> list[AnswerResult]:
    """Apply several ``CQ id -> answer`` pairs against one generated question set.

    All ids are resolved from a single :func:`generate_questions` call (with *limit*)
    before anything is modified, so later answers are not confused by id shifts. Applied
    in ascending question-id order.
    """
    question_set = generate_questions(pkg, limit=limit)
    resolved = [(qid, _resolve(pkg, qid, question_set)) for qid in sorted(answers)]
    return [apply_answer(pkg, q, answers[qid]) for qid, q in resolved]
