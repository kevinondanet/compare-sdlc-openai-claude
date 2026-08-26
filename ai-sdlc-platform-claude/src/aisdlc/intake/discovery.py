"""Coached discovery for non-developers (HVE/BMAD-style plain-language intake).

A :class:`DiscoverySession` walks a fixed script of plain-language questions (problem,
users, current pain, desired outcome, out of scope, must-not-do, success measure,
constraints, data sensitivity, integrations, owner). From the answers it derives an
:class:`~aisdlc.schema.models.Intent` with a full kernel, draft SHALL requirements with
scenarios, personas, assumptions, open questions and draft interfaces, plus a BRD/PRD
style markdown summary. Answers can be supplied as a dict (tests, ``--answers`` file) or
gathered interactively through a callback.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.intake import kernel as kernel_mod
from aisdlc.intake.analyze import extract_quantities
from aisdlc.schema import grammar
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    Assumption,
    ChangePackage,
    Intent,
    Interface,
    InterfaceKind,
    OpenQuestion,
    Priority,
    Requirement,
    RequirementKind,
    RiskClass,
    Scenario,
    utcnow,
)

__all__ = [
    "DiscoveryError",
    "DiscoveryQuestion",
    "DISCOVERY_SCRIPT",
    "Persona",
    "DiscoveryResult",
    "DiscoverySession",
    "classify_risk",
    "load_answers",
    "draft_requirement_text",
]


class DiscoveryError(ValueError):
    """The session cannot produce a result (missing required answers)."""


class DiscoveryQuestion(BaseModel):
    """One plain-language question of the discovery script."""

    model_config = ConfigDict(extra="forbid")

    key: str
    prompt: str
    help: str = ""
    required: bool = True
    multi: bool = Field(default=False, description="Answer is a list (one item per line/';').")
    example: str = ""


DISCOVERY_SCRIPT: Final[tuple[DiscoveryQuestion, ...]] = (
    DiscoveryQuestion(
        key="title",
        prompt="What would you call this change, in a few words?",
        example="Self-service password reset",
    ),
    DiscoveryQuestion(
        key="problem",
        prompt="What problem are you trying to solve? Describe it as you would to a colleague.",
        help="No technical detail needed — who is stuck, and on what.",
        example="Staff wait a day for the help desk to reset a forgotten password.",
    ),
    DiscoveryQuestion(
        key="users",
        prompt="Who will use this or be affected by it? One kind of person per line, "
        "optionally 'name: what they need'.",
        multi=True,
        example="Employee: reset my password without calling anyone\n"
        "Help desk agent: fewer tickets",
    ),
    DiscoveryQuestion(
        key="current_pain",
        prompt="What happens today without it? What is slow, manual, error-prone or impossible?",
        example="Every reset is a phone call and a manual check; about 40 tickets a week.",
    ),
    DiscoveryQuestion(
        key="desired_outcome",
        prompt="When this is done, what will people be able to do that they cannot today? "
        "One outcome per line.",
        multi=True,
        example="Employees can reset their password from the login page in under 5 minutes",
    ),
    DiscoveryQuestion(
        key="out_of_scope",
        prompt="What is explicitly NOT part of this change, even if people might assume it is?",
        multi=True,
        example="Changing the password policy; single sign-on",
    ),
    DiscoveryQuestion(
        key="must_not_do",
        prompt="What must the system never do? (safety rails, e.g. 'email the old password')",
        required=False,
        multi=True,
        example="Reveal whether an email address has an account",
    ),
    DiscoveryQuestion(
        key="success_measure",
        prompt="How will you know it worked? Give a number where you can.",
        help="e.g. 'reset tickets drop by 80% within 3 months'.",
        example="Password reset tickets drop from 40 to under 8 per week within 3 months",
    ),
    DiscoveryQuestion(
        key="constraints",
        prompt="Any hard constraints: deadlines, budget, technology that must or must not be "
        "used, regulations?",
        required=False,
        multi=True,
        example="Must ship before the audit on 30 September; "
        "must use the existing identity provider",
    ),
    DiscoveryQuestion(
        key="data_sensitivity",
        prompt="What kind of data is involved? Does it include personal, financial, health or "
        "otherwise sensitive data?",
        example="Employee email addresses and phone numbers (personal data)",
    ),
    DiscoveryQuestion(
        key="integrations",
        prompt="Which other systems, services or teams does this need to talk to or depend on?",
        required=False,
        multi=True,
        example="Corporate identity provider; SMS gateway",
    ),
    DiscoveryQuestion(
        key="owner",
        prompt="Who is accountable for this change (name or email)?",
        required=False,
        example="jane.doe@example.com",
    ),
)
"""The discovery script, asked in order."""

_SCRIPT_BY_KEY: Final[dict[str, DiscoveryQuestion]] = {q.key: q for q in DISCOVERY_SCRIPT}


class Persona(BaseModel):
    """A kind of user or stakeholder discovered during intake."""

    model_config = ConfigDict(extra="forbid")

    name: str
    needs: str = ""


# --------------------------------------------------------------------------------------
# Text heuristics
# --------------------------------------------------------------------------------------

_PERSONA_SPLIT: Final[re.Pattern[str]] = re.compile(r"\s*(?::|—|–| - )\s*", re.M)
_LEADING_SUBJECT: Final[re.Pattern[str]] = re.compile(
    r"^(?P<subject>(?:an?\s+|the\s+)?[\w /-]{1,40}?)\s+"
    r"(?:can|could|should|will|would like to|wants? to|needs? to|must be able to|"
    r"are able to|is able to|be able to)\s+(?P<action>.+)$",
    re.I,
)
_LEADING_FILLER: Final[re.Pattern[str]] = re.compile(
    r"^(?:i want to|we want to|i need to|we need to|i'd like to|we'd like to|ability to|"
    r"be able to|allow(?:ing)? (?:users|people|staff) to|let (?:users|people|staff)|"
    r"enable (?:users|people|staff) to|to)\s+",
    re.I,
)
_NO_SENSITIVE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:no\b|none\b|n/?a\b|nothing\b|not sensitive|public\b|no sensitive|no personal)",
    re.I,
)
_SENSITIVE: Final[re.Pattern[str]] = re.compile(
    r"\b(personal|pii|gdpr|hipaa|health|medical|patient|financial|payment|card|bank|salary|"
    r"payroll|password|credential|secret|confidential|private|customer data|email address|"
    r"phone number|home address|biometric|ssn|social security|identity|sensitive)\b",
    re.I,
)
_AI_AGENT: Final[re.Pattern[str]] = re.compile(
    r"\b(ai|llm|llms|agent|agents|agentic|chatbot|chat bot|copilot|gpt|claude|generative|"
    r"prompt|prompts)\b",
    re.I,
)


def _lower_first(text: str) -> str:
    return text[:1].lower() + text[1:] if text else text


def _clean(text: str) -> str:
    return " ".join(text.split()).strip().rstrip(".").strip()


def _action_phrase(item: str) -> str:
    """Strip a leading subject/filler so the item reads as a verb phrase."""
    text = _clean(item)
    match = _LEADING_SUBJECT.match(text)
    if match:
        return _lower_first(match.group("action").strip())
    return _lower_first(_LEADING_FILLER.sub("", text))


def draft_requirement_text(item: str, *, prohibition: bool = False) -> str:
    """Turn a plain-language outcome into a SHALL statement.

    ``"Users can export reports"`` -> ``"The system SHALL allow users to export reports"``;
    ``"I want to see totals"`` -> ``"The system SHALL see totals"`` is avoided by mapping
    first-person subjects to ``users``. Text that already contains SHALL/MUST is kept.
    """
    text = _clean(item)
    if grammar.NORMATIVE_PATTERN.search(text):
        return text
    modal = "SHALL NOT" if prohibition else "SHALL"
    match = _LEADING_SUBJECT.match(text)
    if match and not prohibition:
        subject = _clean(match.group("subject")).lower()
        if subject in {"i", "we", "a user", "the user", "user", "users", "people"}:
            subject = "users"
        return f"The system SHALL allow {subject} to {_lower_first(match.group('action').strip())}"
    return f"The system {modal} {_action_phrase(text)}"


def classify_risk(answers: Mapping[str, str]) -> RiskClass:
    """Risk class from the answers: ``ai_agent`` > ``high`` (sensitive data) > ``standard``."""
    probe = " ".join(
        answers.get(k, "") for k in ("title", "problem", "desired_outcome", "integrations")
    )
    if _AI_AGENT.search(probe):
        return RiskClass.AI_AGENT
    sensitivity = answers.get("data_sensitivity", "")
    if sensitivity and not _NO_SENSITIVE.match(sensitivity) and _SENSITIVE.search(sensitivity):
        return RiskClass.HIGH
    return RiskClass.STANDARD


def _personas(text: str) -> list[Persona]:
    personas: list[Persona] = []
    for item in kernel_mod.split_items(text):
        parts = _PERSONA_SPLIT.split(item, maxsplit=1)
        name = _clean(parts[0])
        needs = _clean(parts[1]) if len(parts) > 1 else ""
        if name:
            personas.append(Persona(name=name, needs=needs))
    return personas or [Persona(name="user")]


# --------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------


class DiscoveryResult(BaseModel):
    """Everything derived from a completed discovery session."""

    model_config = ConfigDict(extra="forbid")

    intent: Intent
    requirements: list[Requirement] = Field(default_factory=list)
    personas: list[Persona] = Field(default_factory=list)
    assumptions: list[Assumption] = Field(default_factory=list)
    open_questions: list[OpenQuestion] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    answers: dict[str, str] = Field(default_factory=dict)

    @property
    def change_id(self) -> str:
        """The derived ``CHG-…`` id."""
        return self.intent.id

    def apply_to(self, pkg: ChangePackage) -> None:
        """Replace the intake artifacts of *pkg* with this result (in place)."""
        pkg.intent = self.intent
        pkg.requirements = [r.model_copy(deep=True) for r in self.requirements]
        pkg.assumptions = [a.model_copy() for a in self.assumptions]
        pkg.open_questions = [q.model_copy() for q in self.open_questions]
        pkg.interfaces = [i.model_copy() for i in self.interfaces]
        pkg.bodies[pkgio.INTENT_FILE] = self.to_markdown()

    def to_package(self, root: str | Path, *, exist_ok: bool = False) -> ChangePackage:
        """Create ``<root>/changes/<change-id>/`` from this result and return it."""
        pkg = pkgio.create(root, self.intent.id, self.intent, exist_ok=exist_ok)
        self.apply_to(pkg)
        pkg.save(base_fingerprint=pkg.base_fingerprint)
        return pkg

    def to_markdown(self) -> str:
        """BRD/PRD-style summary of the discovery."""
        a = self.answers
        kernel = self.intent.kernel

        def bullets(items: list[str]) -> str:
            return "\n".join(f"- {i}" for i in items) if items else "- (none stated)"

        lines: list[str] = [
            f"# {self.intent.title}",
            "",
            f"**Change:** {self.intent.id}  ",
            f"**Owner:** {self.intent.owner or '(unassigned)'}  ",
            f"**Risk class:** {self.intent.risk_class.value}",
            "",
            "## 1. Problem statement",
            "",
            a.get("problem", "").strip(),
            "",
            "## 2. Users and personas",
            "",
            "| Persona | Needs |",
            "| --- | --- |",
        ]
        lines.extend(f"| {p.name} | {p.needs or '—'} |" for p in self.personas)
        lines += [
            "",
            "## 3. Current pain",
            "",
            a.get("current_pain", "").strip(),
            "",
            "## 4. Desired outcomes (capabilities)",
            "",
            bullets(kernel.capabilities),
            "",
            "## 5. Out of scope (non-goals)",
            "",
            bullets(kernel.non_goals),
            "",
            "## 6. Must never",
            "",
            bullets(kernel_mod.split_items(a.get("must_not_do", ""))),
            "",
            "## 7. Success measure",
            "",
            kernel.success_signal or "(none stated)",
            "",
            "## 8. Constraints",
            "",
            bullets(kernel.constraints),
            "",
            "## 9. Data sensitivity",
            "",
            a.get("data_sensitivity", "").strip() or "(not stated)",
            "",
            "## 10. Integrations",
            "",
            bullets([i.name for i in self.interfaces]),
            "",
            "## 11. Draft requirements",
            "",
            "| ID | Kind | Priority | Requirement |",
            "| --- | --- | --- | --- |",
        ]
        lines.extend(
            f"| {r.id} | {r.kind.value} | {r.priority.value} | {r.text} |"
            for r in self.requirements
        )
        lines += ["", "## 12. Assumptions", "", bullets([x.text for x in self.assumptions])]
        lines += [
            "",
            "## 13. Open questions",
            "",
            bullets(
                [
                    f"{q.id}{' (blocking)' if q.blocking else ''}: {q.question}"
                    for q in self.open_questions
                ]
            ),
            "",
        ]
        return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------------------


def load_answers(path: str | Path) -> dict[str, str]:
    """Load a ``key -> answer`` mapping from a JSON or YAML file.

    List values are joined with newlines (one item per line) so multi-answers may be
    written as YAML lists.
    """
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    raw: Any = json.loads(text) if file.suffix.lower() == ".json" else yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise DiscoveryError(f"{file}: answers must be a mapping of question key to answer")
    answers: dict[str, str] = {}
    for key, value in raw.items():
        if isinstance(value, list):
            answers[str(key)] = "\n".join(str(v) for v in value)
        elif value is None:
            answers[str(key)] = ""
        else:
            answers[str(key)] = str(value)
    return answers


class DiscoverySession:
    """Stateful walk through :data:`DISCOVERY_SCRIPT`.

    ``DiscoverySession(answers).build()`` is the non-interactive path;
    :meth:`run` drives an interactive loop through an ``ask`` callback.
    """

    def __init__(
        self,
        answers: Mapping[str, str] | None = None,
        *,
        script: tuple[DiscoveryQuestion, ...] = DISCOVERY_SCRIPT,
    ) -> None:
        self.script = script
        self.answers: dict[str, str] = {}
        for key, value in (answers or {}).items():
            self.answer(key, value)

    def question(self, key: str) -> DiscoveryQuestion:
        """The script question for *key*."""
        for q in self.script:
            if q.key == key:
                return q
        raise DiscoveryError(f"unknown discovery question {key!r}")

    def answer(self, key: str, text: str) -> None:
        """Record an answer (blank answers to optional questions mark them as skipped)."""
        self.question(key)
        self.answers[key] = text.strip()

    def pending(self) -> list[DiscoveryQuestion]:
        """Questions not yet answered (blank required answers count as pending)."""
        out: list[DiscoveryQuestion] = []
        for q in self.script:
            value = self.answers.get(q.key)
            if value is None or (q.required and not value):
                out.append(q)
        return out

    def next_question(self) -> DiscoveryQuestion | None:
        """The next pending question, if any."""
        remaining = self.pending()
        return remaining[0] if remaining else None

    def missing_required(self) -> list[str]:
        """Keys of required questions without a non-blank answer."""
        return [q.key for q in self.pending() if q.required]

    @property
    def is_complete(self) -> bool:
        """``True`` when every required question has an answer."""
        return not self.missing_required()

    def run(
        self, ask: Callable[[DiscoveryQuestion], str], *, max_retries: int = 3
    ) -> DiscoveryResult:
        """Ask every pending question through *ask* and build the result.

        Required questions are re-asked up to *max_retries* times when the answer is
        blank; optional questions are asked once (blank = skipped).
        """
        for q in list(self.pending()):
            attempts = 0
            while True:
                text = ask(q).strip()
                attempts += 1
                if text or not q.required:
                    self.answer(q.key, text)
                    break
                if attempts > max_retries:
                    raise DiscoveryError(f"no answer for required question {q.key!r}")
        return self.build()

    # -- derivation ------------------------------------------------------------------

    def build(self) -> DiscoveryResult:
        """Derive intent, kernel, requirements, personas, assumptions and questions."""
        missing = self.missing_required()
        if missing:
            raise DiscoveryError("missing required answers: " + ", ".join(missing))
        a = {k: v for k, v in self.answers.items() if v}
        title = _clean(a["title"])
        change_id = ids.change_id(title)
        owner = a.get("owner") or None
        personas = _personas(a["users"])
        primary = personas[0]
        outcomes = kernel_mod.split_items(a["desired_outcome"])
        prohibitions = kernel_mod.split_items(a.get("must_not_do", ""))
        constraints = kernel_mod.split_items(a.get("constraints", ""))
        success = _clean(a["success_measure"])
        kernel = kernel_mod.build_kernel(
            why=f"{_clean(a['problem'])}. Today: {_clean(a['current_pain'])}.",
            capabilities=outcomes,
            constraints=constraints,
            non_goals=a["out_of_scope"],
            success_signal=success,
        )
        intent = Intent(
            id=change_id,
            title=title,
            kernel=kernel,
            owner=owner,
            risk_class=classify_risk(a),
            stakeholders=[p.name for p in personas],
            created_at=utcnow(),
            labels=["discovery"],
        )

        requirements: list[Requirement] = []
        known: list[str] = []

        def add_requirement(
            text: str,
            *,
            kind: RequirementKind,
            when: str,
            then: str,
            given: str | None = None,
            tags: list[str] | None = None,
            rationale: str | None = None,
        ) -> Requirement:
            req_id = ids.next_id("REQ", known)
            known.append(req_id)
            scenario = Scenario(
                id=ids.next_id("SCN", known, parent=req_id),
                name="draft acceptance",
                given=given,
                when=when,
                then=then,
            )
            known.append(scenario.id)
            requirement = Requirement(
                id=req_id,
                text=text,
                kind=kind,
                priority=Priority.MUST,
                scenarios=[scenario],
                rationale=rationale,
                tags=tags or [],
            )
            requirements.append(requirement)
            return requirement

        for outcome in outcomes:
            action = _action_phrase(outcome)
            add_requirement(
                draft_requirement_text(outcome),
                kind=RequirementKind.FUNCTIONAL,
                given=f"{primary.name} is using the system",
                when=f"{primary.name} attempts to {action}",
                then=f"'{_clean(outcome)}' is achieved and the result is visible to {primary.name}",
                tags=["discovery"],
                rationale=f"Desired outcome stated during discovery: {_clean(outcome)}",
            )
        for prohibition in prohibitions:
            action = _action_phrase(prohibition)
            add_requirement(
                draft_requirement_text(prohibition, prohibition=True),
                kind=RequirementKind.FUNCTIONAL,
                when=f"any user or process attempts to {action}",
                then="the system refuses and records the attempt",
                tags=["discovery", "safety"],
                rationale="Stated as something the system must never do.",
            )
        if kernel_mod.is_measurable(success):
            add_requirement(
                f"The system SHALL achieve the success measure: {success}",
                kind=RequirementKind.NON_FUNCTIONAL,
                when="the success measure is evaluated after release",
                then=success,
                tags=["discovery", "success"],
                rationale="Success measure stated during discovery.",
            )
        for constraint in constraints:
            if extract_quantities(constraint):
                add_requirement(
                    f"The system SHALL satisfy the constraint: {constraint}",
                    kind=RequirementKind.NON_FUNCTIONAL,
                    when="the constraint is checked before release",
                    then=f"'{constraint}' holds",
                    tags=["discovery", "constraint"],
                    rationale="Quantified constraint stated during discovery.",
                )

        assumptions: list[Assumption] = []
        open_questions: list[OpenQuestion] = []
        interfaces: list[Interface] = []

        def add_assumption(text: str, *, validated: bool = False) -> None:
            assumptions.append(
                Assumption(
                    id=ids.next_id("ASM", [x.id for x in assumptions]),
                    text=text,
                    owner=owner,
                    validated=validated,
                    source="discovery",
                )
            )

        def add_question(text: str, *, blocking: bool) -> None:
            open_questions.append(
                OpenQuestion(
                    id=ids.next_id("OQ", [x.id for x in open_questions]),
                    question=text,
                    blocking=blocking,
                    owner=owner,
                )
            )

        add_assumption(
            "The primary users are: " + "; ".join(p.name for p in personas) + ".",
            validated=True,
        )
        sensitivity = _clean(a["data_sensitivity"])
        if _NO_SENSITIVE.match(sensitivity):
            add_assumption("No personal or otherwise sensitive data is processed by this change.")
        elif _SENSITIVE.search(sensitivity):
            add_assumption(
                f"Sensitive data is involved as described by the requester: {sensitivity}."
            )
            add_requirement(
                f"The system SHALL restrict access to the sensitive data ({sensitivity}) to "
                "authorised users and SHALL NOT expose it in logs, error messages or exports",
                kind=RequirementKind.NON_FUNCTIONAL,
                when="an unauthorised user or process requests the sensitive data",
                then="the request is denied and the attempt is logged",
                tags=["discovery", "security"],
                rationale="Data sensitivity stated during discovery.",
            )
        else:
            add_assumption(f"Data involved as described by the requester: {sensitivity}.")
            add_question(
                f"Is any of the data described ('{sensitivity}') personal, financial, health or "
                "otherwise sensitive?",
                blocking=False,
            )
        for name in kernel_mod.split_items(a.get("integrations", "")):
            interfaces.append(
                Interface(
                    id=ids.next_id("IFC", [i.id for i in interfaces]),
                    name=name,
                    kind=InterfaceKind.API,
                    description=f"Integration with {name} identified during discovery.",
                    provider=name,
                    consumers=[title],
                )
            )
            add_assumption(
                f"{name} is available in the target environment and its interface is stable for "
                "the duration of this change."
            )
            add_question(
                f"Who owns the {name} integration and where is its contract documented?",
                blocking=False,
            )
        if intent.risk_class is RiskClass.AI_AGENT:
            add_assumption(
                "This change introduces or modifies an AI agent; PyRIT trials and tool/data "
                "manifest validation apply."
            )
        if not kernel_mod.is_measurable(success):
            add_question(
                f"The success measure '{success}' has no number: what is the target value and "
                "when is it measured?",
                blocking=False,
            )
        if not owner:
            add_question("Who is the accountable owner of this change?", blocking=True)
        for q in self.script:
            if not q.required and not a.get(q.key) and q.key != "owner":
                add_question(f"({q.key}) {q.prompt}", blocking=False)

        return DiscoveryResult(
            intent=intent,
            requirements=requirements,
            personas=personas,
            assumptions=assumptions,
            open_questions=open_questions,
            interfaces=interfaces,
            answers=dict(a),
        )
