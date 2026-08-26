"""Tests for aisdlc.schema.grammar."""

from __future__ import annotations

import pytest

from aisdlc.schema import grammar
from aisdlc.schema.grammar import EarsForm, IssueSeverity
from aisdlc.schema.models import (
    Assumption,
    ChangePackage,
    Intent,
    Kernel,
    OpenQuestion,
    Plan,
    Requirement,
    Scenario,
    Task,
    Verification,
    Wave,
)


def codes(issues: list[grammar.ValidationIssue]) -> list[str]:
    return [i.code for i in issues]


@pytest.mark.parametrize(
    "text",
    [
        "The system SHALL reject expired tokens.",
        "The service MUST NOT log secrets.",
        "WHEN a token expires, the system SHALL reject it.",
        "WHILE in maintenance mode, the API SHALL return 503.",
        "IF the signature is invalid, THEN the gateway SHALL drop the request.",
        "WHERE MFA is enabled, the login flow SHALL require a second factor.",
    ],
)
def test_valid_requirement_text(text: str) -> None:
    assert [i for i in grammar.validate_requirement_text(text) if i.severity == "error"] == []


def test_requirement_text_issues() -> None:
    assert codes(grammar.validate_requirement_text("")) == ["REQ_EMPTY"]
    assert codes(grammar.validate_requirement_text("Users can log in")) == ["REQ_NO_MODAL"]
    lower = grammar.validate_requirement_text("The system shall log in", "REQ-001")
    assert codes(lower) == ["REQ_LOWERCASE_MODAL", "REQ_NO_MODAL"]
    assert all(i.artifact_id == "REQ-001" for i in lower)
    weak = grammar.validate_requirement_text("The system SHALL and may retry")
    assert codes(weak) == ["REQ_WEAK_MODAL"]
    assert weak[0].severity is IssueSeverity.WARNING
    malformed = grammar.validate_requirement_text("WHEN something the system SHALL act")
    assert codes(malformed) == ["REQ_EARS_MALFORMED"]
    assert "REQ_EARS_MALFORMED" in str(malformed[0])


def test_ears_form_classification() -> None:
    assert grammar.ears_form("The system SHALL x") is EarsForm.UBIQUITOUS
    assert grammar.ears_form("WHEN a, the b SHALL c") is EarsForm.EVENT_DRIVEN
    assert grammar.ears_form("WHILE a, the b SHALL c") is EarsForm.STATE_DRIVEN
    assert grammar.ears_form("IF a, THEN the b SHALL c") is EarsForm.UNWANTED
    assert grammar.ears_form("WHERE a, the b SHALL c") is EarsForm.OPTIONAL
    assert grammar.ears_form("WHILE a, WHEN b, the c SHALL d") is EarsForm.COMPLEX
    assert grammar.ears_form("WHEN a the b SHALL c") is EarsForm.COMPLEX
    assert grammar.ears_form("no modal here") is None


def test_validate_scenario() -> None:
    ok = Scenario(id="SCN-001-01", when="w", then="t")
    assert grammar.validate_scenario(ok) == []
    assert grammar.validate_scenario(Scenario(id="SCN-001-02", raw="WHEN x THEN y")) == []
    assert grammar.validate_scenario(Scenario(id="SCN-001-03", raw="Given a\nWhen b\nThen c")) == []
    bad = grammar.validate_scenario(Scenario(id="SCN-001-04", raw="something happens"))
    assert codes(bad) == ["SCN_MALFORMED"]
    empty = grammar.validate_scenario(Scenario(id="SCN-001-05", when=" ", then="t", raw="x"))
    assert codes(empty) == ["SCN_EMPTY_CLAUSE"]


def test_validate_requirement_and_list() -> None:
    no_scn = Requirement(id="REQ-001", text="The system SHALL x")
    assert codes(grammar.validate_requirement(no_scn)) == ["REQ_NO_SCENARIO"]
    dup = grammar.validate_requirements([no_scn, no_scn])
    assert "REQ_DUPLICATE_ID" in codes(dup)


def test_find_ambiguity_markers() -> None:
    text = "Respond fast [NEEDS CLARIFICATION] to some users? TBD etc."
    markers = grammar.find_ambiguity_markers(text, "REQ-001")
    cats = [(m.marker, m.category) for m in markers]
    assert ("[NEEDS CLARIFICATION]", "explicit") in cats
    assert ("TBD", "explicit") in cats
    assert ("?", "question") in cats
    assert ("fast", "vague") in cats
    assert ("some", "vague") in cats
    assert ("etc.", "vague") in cats
    assert markers == sorted(markers, key=lambda m: m.start)
    assert all(m.artifact_id == "REQ-001" for m in markers)
    assert grammar.find_ambiguity_markers("The system SHALL respond within 200 ms.") == []
    # no partial-word matches
    assert grammar.find_ambiguity_markers("breakfast is somewhat easyish") == []


def _pkg(**kwargs: object) -> ChangePackage:
    intent = Intent(id="CHG-x", title="x", owner="o", kernel=Kernel(why="clear why"))
    return ChangePackage(intent=intent, **kwargs)  # type: ignore[arg-type]


def test_ambiguity_score_formula() -> None:
    clean = _pkg(
        requirements=[
            Requirement(
                id="REQ-001",
                text="The system SHALL respond within 200 ms.",
                scenarios=[Scenario(id="SCN-001-01", when="a request arrives", then="200 ms")],
            )
        ]
    )
    assert grammar.ambiguity_score(clean) == 0.0

    # statements: why(1) + requirement(1) + scenario(1) + assumption(1) = 4
    # markers: TBD (1.0) + "?" (0.5) + "fast" (0.25) = 1.75 -> density 0.4375
    # questions: 1 open blocking + 1 open non-blocking + 1 resolved -> (1 + 0.5)/3 = 0.5
    # score = 0.6*0.4375 + 0.4*0.5 = 0.2625 + 0.2 = 0.4625
    fuzzy = _pkg(
        requirements=[
            Requirement(
                id="REQ-001",
                text="The system SHALL be fast.",
                scenarios=[Scenario(id="SCN-001-01", raw="WHEN TBD THEN ok?")],
            )
        ],
        assumptions=[Assumption(id="ASM-001", text="plain")],
        open_questions=[
            OpenQuestion(id="OQ-001", question="a?", blocking=True),
            OpenQuestion(id="OQ-002", question="b?"),
            OpenQuestion(id="OQ-003", question="c?", status="resolved", decision="d"),
        ],
    )
    report = grammar.ambiguity_report(fuzzy)
    assert report.statements == 4
    assert report.weighted_markers == pytest.approx(1.75)
    assert report.marker_density == pytest.approx(0.4375)
    assert report.unresolved_ratio == pytest.approx(0.5)
    assert report.score == pytest.approx(0.4625)
    assert 0.0 <= grammar.ambiguity_score(fuzzy) <= 1.0

    saturated = _pkg(
        requirements=[Requirement(id="REQ-001", text="TODO TBD FIXME [NEEDS CLARIFICATION]")],
        open_questions=[OpenQuestion(id="OQ-001", question="?", blocking=True)],
    )
    assert grammar.ambiguity_score(saturated) == 1.0


def test_check_task_numbering() -> None:
    t = [Task(id="TASK-001", title="a"), Task(id="TASK-003", title="c")]
    issues = grammar.check_task_numbering(t)
    assert codes(issues) == ["TASK_NUMBERING_GAP"]
    assert "TASK-002" in issues[0].message
    dup = [Task(id="TASK-001", title="a"), Task(id="TASK-001", title="b")]
    assert codes(grammar.check_task_numbering(dup)) == ["TASK_DUPLICATE_ID"]
    assert grammar.check_task_numbering([]) == []
    assert grammar.check_task_numbering([Task(id="TASK-001", title="a")]) == []


def test_check_verification_executable() -> None:
    def task(**kw: object) -> Task:
        return Task(id="TASK-001", title="t", verification=Verification(**kw))  # type: ignore[arg-type]

    assert codes(grammar.check_verification_executable(Task(id="TASK-001", title="t"))) == [
        "TASK_NO_VERIFICATION"
    ]
    assert grammar.check_verification_executable(task(command="pytest -q")) == []
    assert codes(grammar.check_verification_executable(task(command="  "))) == [
        "TASK_VERIFICATION_EMPTY_COMMAND"
    ]
    assert codes(grammar.check_verification_executable(task(command="echo 'unterminated"))) == [
        "TASK_VERIFICATION_UNPARSEABLE"
    ]
    assert codes(
        grammar.check_verification_executable(task(command="x", expect_exit_code=300))
    ) == ["TASK_VERIFICATION_EXIT_CODE"]
    assert codes(
        grammar.check_verification_executable(task(command="x", expect_output_regex="("))
    ) == ["TASK_VERIFICATION_BAD_REGEX"]


def test_validate_tasks_references_and_cycles() -> None:
    tasks = [
        Task(
            id="TASK-001",
            title="a",
            requirement_ids=["REQ-009"],
            depends_on=["TASK-002"],
            verification=Verification(command="true"),
        ),
        Task(
            id="TASK-002",
            title="b",
            depends_on=["TASK-001", "TASK-007"],
            verification=Verification(command="true"),
        ),
    ]
    issues = grammar.validate_tasks(tasks, ["REQ-001"])
    found = codes(issues)
    assert "TASK_UNKNOWN_REQUIREMENT" in found
    assert "TASK_UNKNOWN_DEPENDENCY" in found
    assert "TASK_NO_REQUIREMENT" in found
    assert "TASK_DEPENDENCY_CYCLE" in found
    cycle = next(i for i in issues if i.code == "TASK_DEPENDENCY_CYCLE")
    assert "TASK-001" in cycle.message and "TASK-002" in cycle.message


def test_validate_package_cross_checks() -> None:
    pkg = ChangePackage(
        intent=Intent(id="CHG-x", title="x"),
        requirements=[
            Requirement(
                id="REQ-001",
                text="The system SHALL x.",
                scenarios=[Scenario(id="SCN-001-01", when="w", then="t")],
            )
        ],
        tasks=[
            Task(
                id="TASK-001",
                title="t",
                requirement_ids=["REQ-001"],
                verification=Verification(command="true"),
            ),
            Task(
                id="TASK-002",
                title="u",
                requirement_ids=["REQ-001"],
                verification=Verification(command="true"),
            ),
        ],
        plan=Plan(waves=[Wave(index=0, task_ids=["TASK-001", "TASK-099"])]),
        open_questions=[OpenQuestion(id="OQ-001", question="q?", blocking=True)],
    )
    found = codes(grammar.validate_package(pkg))
    assert "INTENT_NO_OWNER" in found
    assert "INTENT_KERNEL_INCOMPLETE" in found
    assert "PLAN_UNKNOWN_TASK" in found
    assert "PLAN_TASK_NOT_SCHEDULED" in found
    assert "OQ_OPEN_BLOCKING" in found
    assert "REQ_NO_MODAL" not in found
