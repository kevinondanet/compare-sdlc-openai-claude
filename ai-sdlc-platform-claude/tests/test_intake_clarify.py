"""Tests for aisdlc.intake.clarify."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.intake import clarify as cl
from aisdlc.schema import grammar
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import QuestionStatus, RequirementKind
from tests.intake_fixtures import ambiguous_package, clean_package


def _by_category(
    questions: cl.ClarificationSet, category: cl.QuestionCategory
) -> list[cl.ClarificationQuestion]:
    return [q for q in questions.questions if q.category is category]


def test_clean_package_has_no_questions() -> None:
    result = cl.generate_questions(clean_package())
    assert result.candidates == 0
    assert result.questions == []
    assert result.ambiguity_score == 0.0


def test_ranking_and_cap() -> None:
    pkg = ambiguous_package()
    full = cl.generate_questions(pkg, limit=None)
    assert full.candidates >= 15
    impacts = [q.impact for q in full.questions]
    assert impacts == sorted(impacts, reverse=True)
    assert [q.id for q in full.questions][:3] == ["CQ-001", "CQ-002", "CQ-003"]
    # Explicit placeholders outrank everything; blocking OQ outranks non-blocking.
    assert full.questions[0].marker_category == "explicit"
    assert full.questions[1].marker_category == "explicit"
    blocking = next(q for q in full.questions if q.target == "OQ-001")
    non_blocking = next(q for q in full.questions if q.target == "OQ-002")
    assert blocking.impact > non_blocking.impact
    capped = cl.generate_questions(pkg)
    assert len(capped.questions) == cl.DEFAULT_LIMIT
    assert capped.candidates == full.candidates
    assert capped.questions == full.questions[: cl.DEFAULT_LIMIT]
    assert capped.get("CQ-001") is not None and capped.get("CQ-999") is None
    categories = {q.category for q in full.questions}
    assert categories == set(cl.QuestionCategory)


def test_question_details() -> None:
    full = cl.generate_questions(ambiguous_package(), limit=None)
    time_vague = next(q for q in full.questions if q.marker == "fast")
    assert time_vague.requirement_ids == ["REQ-001"]
    assert any("within" in o for o in time_vague.options)
    quantity = next(q for q in full.questions if q.marker == "some")
    assert quantity.options[0].startswith("exactly")
    assert quantity.impact == pytest.approx(0.5 * 0.8)  # priority should
    conflict = _by_category(full, cl.QuestionCategory.CONFLICTING_QUANTIFIER)[0]
    assert conflict.details == {"REQ-002": "200 ms", "SCN-002-01": "500 ms"}
    assert conflict.options == ["200 ms", "500 ms"]
    assert conflict.requirement_ids == ["REQ-002"]
    scenario_qs = _by_category(full, cl.QuestionCategory.MISSING_SCENARIO)
    assert {q.requirement_ids[0] for q in scenario_qs} == {"REQ-001", "REQ-006"}
    kernel_qs = _by_category(full, cl.QuestionCategory.KERNEL)
    assert {q.target for q in kernel_qs} == {
        "capabilities",
        "non_goals",
        "success_signal",
        "constraints",
    }


def test_find_undefined_terms_respects_glossary() -> None:
    pkg = ambiguous_package()
    assert cl.find_undefined_terms(pkg) == {"SSO": ["REQ-003"]}
    pkg.bodies["requirements.md"] = "## Glossary\n\n- **SSO**: single sign-on\n"
    assert cl.find_undefined_terms(pkg) == {}
    pkg.bodies = {}
    pkg.assumptions = []
    pkg.intent.kernel.why = "We rely on single sign-on (SSO)."
    assert cl.find_undefined_terms(pkg) == {}


def test_apply_explicit_marker_and_question_marker() -> None:
    pkg = ambiguous_package()
    qs = cl.generate_questions(pkg, limit=None)
    placeholder = next(q for q in qs.questions if q.marker == "[NEEDS CLARIFICATION]")
    result = cl.apply_answer(pkg, placeholder, "within 3 seconds at p95")
    assert result.changes == ["REQ-001.text"]
    assert pkg.requirement("REQ-001").text.endswith("within 3 seconds at p95")
    assert result.open_question_id == "OQ-003"
    recorded = pkg.open_questions[-1]
    assert recorded.status is QuestionStatus.RESOLVED
    assert recorded.decision == "within 3 seconds at p95"
    assert recorded.question.startswith(f"[{placeholder.id}]")

    question_marker = next(q for q in qs.questions if q.marker == "?")
    cl.apply_answer(pkg, question_marker, "The system SHALL send notifications through SSO")
    assert pkg.requirement("REQ-003").text == "The system SHALL send notifications through SSO"

    pkg2 = ambiguous_package()
    cl.apply_answer(pkg2, question_marker, "yes, through SSO")
    assert "?" not in pkg2.requirement("REQ-003").text
    assert pkg2.requirement("REQ-003").text.endswith("through SSO")

    kernel_tbd = next(q for q in qs.questions if q.marker == "TBD")
    cl.apply_answer(pkg, kernel_tbd, "Reports must render in under 3 seconds")
    assert "TBD" not in pkg.intent.kernel.why
    assert pkg.intent.kernel.why.endswith("under 3 seconds")


def test_apply_vague_term_replaces_whole_word_only() -> None:
    pkg = ambiguous_package()
    pkg.requirement("REQ-001").text = "The system SHALL serve breakfast fast [NEEDS CLARIFICATION]"
    qs = cl.generate_questions(pkg, limit=None)
    fast = next(q for q in qs.questions if q.marker == "fast" and q.artifact_ids == ["REQ-001"])
    cl.apply_answer(pkg, fast, "within 2 s")
    assert pkg.requirement("REQ-001").text.startswith("The system SHALL serve breakfast within 2 s")


def test_apply_missing_scenario() -> None:
    pkg = ambiguous_package()
    qs = cl.generate_questions(pkg, limit=None)
    question = next(q for q in _by_category(qs, cl.QuestionCategory.MISSING_SCENARIO))
    assert question.requirement_ids == ["REQ-001"]
    with pytest.raises(cl.AnswerError):
        cl.apply_answer(pkg, question, "it just works")
    assert pkg.requirement("REQ-001").scenarios == []
    result = cl.apply_answer(
        pkg, question, "GIVEN 10,000 rows WHEN a user requests it THEN it renders within 3 s"
    )
    assert result.created_ids == ["SCN-001-01"]
    assert result.open_question_id is None
    scenario = pkg.requirement("REQ-001").scenarios[0]
    assert (scenario.given, scenario.when, scenario.then) == (
        "10,000 rows",
        "a user requests it",
        "it renders within 3 s",
    )
    assert grammar.validate_scenario(scenario) == []


def test_apply_conflicting_quantifier() -> None:
    pkg = ambiguous_package()
    qs = cl.generate_questions(pkg, limit=None)
    question = _by_category(qs, cl.QuestionCategory.CONFLICTING_QUANTIFIER)[0]
    with pytest.raises(cl.AnswerError):
        cl.apply_answer(pkg, question, "faster")
    result = cl.apply_answer(pkg, question, "300 ms")
    assert set(result.changes) == {"REQ-002.text", "SCN-002-01.then"}
    assert pkg.requirement("REQ-002").text.endswith("within 300 ms")
    assert pkg.requirement("REQ-002").scenarios[0].then.endswith("within 300 ms")
    assert not _by_category(
        cl.generate_questions(pkg, limit=None), cl.QuestionCategory.CONFLICTING_QUANTIFIER
    )


def test_apply_open_question_non_functional_kernel_and_glossary() -> None:
    pkg = ambiguous_package()
    qs = cl.generate_questions(pkg, limit=None)
    oq = next(q for q in qs.questions if q.target == "OQ-001")
    cl.apply_answer(pkg, oq, "CSV and PDF")
    resolved = next(q for q in pkg.open_questions if q.id == "OQ-001")
    assert resolved.status is QuestionStatus.RESOLVED
    assert resolved.decision == "CSV and PDF"
    assert not resolved.is_open_blocking

    nfr = _by_category(qs, cl.QuestionCategory.NON_FUNCTIONAL)[0]
    with pytest.raises(cl.AnswerError):
        cl.apply_answer(pkg, nfr, "be available a lot")
    result = cl.apply_answer(pkg, nfr, "The system SHALL be available 99.9% of each month")
    assert result.created_ids == ["REQ-007"]
    assert pkg.requirement("REQ-007").kind is RequirementKind.NON_FUNCTIONAL

    success = next(q for q in qs.questions if q.target == "success_signal")
    cl.apply_answer(pkg, success, "Report p95 drops below 3 seconds")
    assert pkg.intent.kernel.success_signal == "Report p95 drops below 3 seconds"
    non_goals = next(q for q in qs.questions if q.target == "non_goals")
    cl.apply_answer(pkg, non_goals, "Dashboards; Scheduling")
    assert pkg.intent.kernel.non_goals == ["Dashboards", "Scheduling"]

    sso = next(q for q in qs.questions if q.target == "SSO")
    cl.apply_answer(pkg, sso, "Single sign-on")
    assert "- **SSO**: Single sign-on" in pkg.bodies["requirements.md"]
    assert "## Glossary" in pkg.bodies["requirements.md"]
    assert "SSO" not in cl.find_undefined_terms(pkg)

    before = qs.ambiguity_score
    after = cl.generate_questions(pkg).ambiguity_score
    assert after < before


def test_apply_by_id_and_batch_and_errors() -> None:
    pkg = ambiguous_package()
    result = cl.apply_answer(pkg, "CQ-001", "Reports must render in under 3 seconds")
    assert result.question_id == "CQ-001"
    with pytest.raises(cl.AnswerError):
        cl.apply_answer(pkg, "CQ-999", "x")
    with pytest.raises(cl.AnswerError):
        cl.apply_answer(pkg, "CQ-001", "   ")
    pkg = ambiguous_package()
    results = cl.apply_answers(
        pkg, {"CQ-003": "CSV and PDF", "CQ-001": "Reports must render in under 3 seconds"}
    )
    assert [r.question_id for r in results] == ["CQ-001", "CQ-003"]
    assert "TBD" not in pkg.intent.kernel.why
    assert next(q for q in pkg.open_questions if q.id == "OQ-001").decision == "CSV and PDF"


def test_answers_survive_save_and_load(tmp_path: Path) -> None:
    pkg = ambiguous_package()
    directory = tmp_path / "changes" / pkg.change_id
    pkgio.save(pkg, directory)
    pkg = pkgio.load(directory)
    qs = cl.generate_questions(pkg, limit=None)
    sso = next(q for q in qs.questions if q.target == "SSO")
    cl.apply_answer(pkg, sso, "Single sign-on")
    cl.apply_answer(pkg, "CQ-001", "Reports must render in under 3 seconds", questions=qs)
    pkg.save()
    reloaded = pkgio.load(directory)
    assert "- **SSO**: Single sign-on" in reloaded.bodies["requirements.md"]
    assert "TBD" not in reloaded.intent.kernel.why
    assert sum(1 for q in reloaded.open_questions if q.status is QuestionStatus.RESOLVED) == 2
    assert "SSO" not in cl.find_undefined_terms(reloaded)
