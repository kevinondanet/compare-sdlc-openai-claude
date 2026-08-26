"""Tests for aisdlc.intake.discovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from aisdlc.intake import checklist, clarify, kernel
from aisdlc.intake import discovery as dm
from aisdlc.schema import grammar
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import RequirementKind, RiskClass

ANSWERS: dict[str, str] = {
    "title": "Self-service password reset",
    "problem": "Staff wait a day for the help desk to reset a forgotten password",
    "users": "Employee: reset my password without calling anyone\nHelp desk agent: fewer tickets",
    "current_pain": "Every reset is a phone call; 40 tickets a week",
    "desired_outcome": "Employees can reset their password from the login page\n"
    "I want to see the number of resets per day",
    "out_of_scope": "Changing the password policy; single sign-on",
    "must_not_do": "Reveal whether an email address has an account",
    "success_measure": "Reset tickets drop from 40 to under 8 per week within 3 months",
    "constraints": "Must ship before 30 September; response under 2 seconds",
    "data_sensitivity": "Employee email addresses (personal data)",
    "integrations": "Corporate identity provider; SMS gateway",
    "owner": "kevin",
}


def test_script_shape() -> None:
    keys = [q.key for q in dm.DISCOVERY_SCRIPT]
    assert keys == [
        "title",
        "problem",
        "users",
        "current_pain",
        "desired_outcome",
        "out_of_scope",
        "must_not_do",
        "success_measure",
        "constraints",
        "data_sensitivity",
        "integrations",
        "owner",
    ]
    optional = {q.key for q in dm.DISCOVERY_SCRIPT if not q.required}
    assert optional == {"must_not_do", "constraints", "integrations", "owner"}
    assert all(q.example for q in dm.DISCOVERY_SCRIPT)


def test_draft_requirement_text() -> None:
    assert (
        dm.draft_requirement_text("Users can export reports")
        == "The system SHALL allow users to export reports"
    )
    assert (
        dm.draft_requirement_text("Managers can approve leave.")
        == "The system SHALL allow managers to approve leave"
    )
    assert (
        dm.draft_requirement_text("I want to see totals")
        == "The system SHALL allow users to see totals"
    )
    assert dm.draft_requirement_text("ability to export CSV") == "The system SHALL export CSV"
    assert (
        dm.draft_requirement_text("The API MUST reject expired tokens")
        == "The API MUST reject expired tokens"
    )
    assert (
        dm.draft_requirement_text("email the old password", prohibition=True)
        == "The system SHALL NOT email the old password"
    )
    for text in ("Users can export reports", "send invoices"):
        assert grammar.validate_requirement_text(dm.draft_requirement_text(text)) == []


def test_classify_risk() -> None:
    assert dm.classify_risk(ANSWERS) is RiskClass.HIGH
    assert dm.classify_risk({**ANSWERS, "data_sensitivity": "none"}) is RiskClass.STANDARD
    assert (
        dm.classify_risk({**ANSWERS, "data_sensitivity": "public catalogue"}) is RiskClass.STANDARD
    )
    assert (
        dm.classify_risk({**ANSWERS, "problem": "An LLM agent triages tickets"})
        is RiskClass.AI_AGENT
    )


def test_session_progress_and_validation() -> None:
    session = dm.DiscoverySession()
    assert not session.is_complete
    assert session.next_question() is not None and session.next_question().key == "title"
    assert len(session.pending()) == len(dm.DISCOVERY_SCRIPT)
    with pytest.raises(dm.DiscoveryError):
        session.answer("bogus", "x")
    with pytest.raises(dm.DiscoveryError, match="missing required"):
        session.build()
    session = dm.DiscoverySession({k: v for k, v in ANSWERS.items() if k != "owner"})
    assert session.is_complete
    assert [q.key for q in session.pending()] == ["owner"]
    session.answer("title", "   ")
    assert session.missing_required() == ["title"]


def test_session_run_with_callback() -> None:
    asked: list[str] = []
    attempts: dict[str, int] = {}

    def ask(question: dm.DiscoveryQuestion) -> str:
        asked.append(question.key)
        attempts[question.key] = attempts.get(question.key, 0) + 1
        if question.key == "problem" and attempts[question.key] == 1:
            return ""  # required: re-asked
        if question.key in {"constraints", "owner"}:
            return ""  # optional: skipped
        return ANSWERS[question.key]

    result = dm.DiscoverySession().run(ask)
    assert asked.count("problem") == 2
    assert asked.count("constraints") == 1
    assert result.intent.owner is None
    assert any(q.blocking and "owner" in q.question for q in result.open_questions)
    assert any("(constraints)" in q.question for q in result.open_questions)
    with pytest.raises(dm.DiscoveryError):
        dm.DiscoverySession().run(lambda _q: "", max_retries=1)


def test_build_derives_intent_requirements_and_companions() -> None:
    result = dm.DiscoverySession(ANSWERS).build()
    intent = result.intent
    assert result.change_id == "CHG-self-service-password-reset"
    assert intent.owner == "kevin"
    assert intent.risk_class is RiskClass.HIGH
    assert intent.stakeholders == ["Employee", "Help desk agent"]
    assert intent.kernel.is_complete()
    assert intent.kernel.capabilities == [
        "Employees can reset their password from the login page",
        "I want to see the number of resets per day",
    ]
    assert intent.kernel.non_goals == ["Changing the password policy", "single sign-on"]
    assert intent.kernel.constraints == [
        "Must ship before 30 September",
        "response under 2 seconds",
    ]
    assert intent.kernel.why.startswith("Staff wait a day")
    assert kernel.is_measurable(intent.kernel.success_signal)

    texts = {r.id: r.text for r in result.requirements}
    assert texts["REQ-001"] == (
        "The system SHALL allow employees to reset their password from the login page"
    )
    assert texts["REQ-002"] == "The system SHALL allow users to see the number of resets per day"
    assert texts["REQ-003"] == "The system SHALL NOT reveal whether an email address has an account"
    kinds = {r.id: r.kind for r in result.requirements}
    assert kinds["REQ-004"] is RequirementKind.NON_FUNCTIONAL  # success measure
    assert "under 2 seconds" in texts["REQ-005"]  # quantified constraint only
    assert "SHALL NOT expose it in logs" in texts["REQ-006"]  # sensitive data
    assert len(result.requirements) == 6
    assert all(r.scenarios for r in result.requirements)
    assert all(grammar.validate_requirement(r) == [] for r in result.requirements)
    assert result.requirements[0].scenarios[0].id == "SCN-001-01"
    assert "Employee" in result.requirements[0].scenarios[0].when

    assert [p.name for p in result.personas] == ["Employee", "Help desk agent"]
    assert result.personas[1].needs == "fewer tickets"
    assert [i.name for i in result.interfaces] == ["Corporate identity provider", "SMS gateway"]
    assert result.interfaces[1].id == "IFC-002"
    assumption_texts = [a.text for a in result.assumptions]
    assert assumption_texts[0] == "The primary users are: Employee; Help desk agent."
    assert any("Sensitive data" in t for t in assumption_texts)
    assert any("SMS gateway is available" in t for t in assumption_texts)
    assert all(a.source == "discovery" for a in result.assumptions)
    assert [q.blocking for q in result.open_questions] == [False, False]
    assert all("integration" in q.question for q in result.open_questions)


def test_sensitivity_branches_and_ai_agent() -> None:
    none = dm.DiscoverySession({**ANSWERS, "data_sensitivity": "None"}).build()
    assert none.intent.risk_class is RiskClass.STANDARD
    assert any("No personal" in a.text for a in none.assumptions)
    assert len(none.requirements) == 5
    unclear = dm.DiscoverySession({**ANSWERS, "data_sensitivity": "product catalogue"}).build()
    assert any("otherwise sensitive" in q.question for q in unclear.open_questions)
    agent = dm.DiscoverySession(
        {**ANSWERS, "problem": "An AI agent should triage reset requests"}
    ).build()
    assert agent.intent.risk_class is RiskClass.AI_AGENT
    assert any("AI agent" in a.text for a in agent.assumptions)
    vague = dm.DiscoverySession({**ANSWERS, "success_measure": "people are happier"}).build()
    assert any("has no number" in q.question for q in vague.open_questions)
    assert not any(
        r.kind is RequirementKind.NON_FUNCTIONAL and "success" in r.tags for r in vague.requirements
    )


def test_markdown_summary() -> None:
    text = dm.DiscoverySession(ANSWERS).build().to_markdown()
    for heading in (
        "# Self-service password reset",
        "## 1. Problem statement",
        "## 2. Users and personas",
        "| Employee | reset my password without calling anyone |",
        "## 5. Out of scope (non-goals)",
        "## 7. Success measure",
        "## 11. Draft requirements",
        "| REQ-001 | functional | must |",
        "## 12. Assumptions",
        "## 13. Open questions",
        "**Risk class:** high",
    ):
        assert heading in text


def test_to_package_round_trip_and_readiness(tmp_path: Path) -> None:
    result = dm.DiscoverySession(ANSWERS).build()
    pkg = result.to_package(tmp_path)
    assert pkg.root == tmp_path / "changes" / "CHG-self-service-password-reset"
    loaded = pkgio.load(pkg.root)
    assert loaded.intent == result.intent
    assert [r.id for r in loaded.requirements] == [f"REQ-00{i}" for i in range(1, 7)]
    assert len(loaded.interfaces) == 2
    assert loaded.bodies["intent.md"].startswith("# Self-service password reset")
    assert [i for i in grammar.validate_package(loaded) if i.severity.value == "error"] == []
    report = kernel.readiness(loaded)
    assert report.ready, report.failed()
    assert checklist.run_checklist(loaded).passed
    assert clarify.generate_questions(loaded).candidates == 2  # the two integration questions
    with pytest.raises(pkgio.PackageError):
        result.to_package(tmp_path)
    again = result.to_package(tmp_path, exist_ok=True)
    assert again.root == pkg.root


def test_apply_to_existing_package(tmp_path: Path) -> None:
    result = dm.DiscoverySession(ANSWERS).build()
    pkg = pkgio.create(tmp_path, result.change_id, result.intent)
    result.apply_to(pkg)
    assert pkg.requirements == result.requirements
    assert pkg.requirements is not result.requirements
    pkg.save()
    assert pkgio.load(pkg.root).assumptions == result.assumptions


def test_load_answers_json_and_yaml(tmp_path: Path) -> None:
    json_file = tmp_path / "a.json"
    json_file.write_text(json.dumps({"title": "T", "users": ["a", "b"], "owner": None}))
    assert dm.load_answers(json_file) == {"title": "T", "users": "a\nb", "owner": ""}
    yaml_file = tmp_path / "a.yaml"
    yaml_file.write_text(yaml.safe_dump({"title": "T", "desired_outcome": ["x", "y"]}))
    assert dm.load_answers(yaml_file) == {"title": "T", "desired_outcome": "x\ny"}
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a list\n")
    with pytest.raises(dm.DiscoveryError):
        dm.load_answers(bad)
