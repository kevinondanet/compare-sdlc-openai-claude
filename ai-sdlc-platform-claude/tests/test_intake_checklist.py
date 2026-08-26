"""Tests for aisdlc.intake.checklist."""

from __future__ import annotations

from aisdlc.intake import checklist as ck
from aisdlc.schema.grammar import IssueSeverity
from aisdlc.schema.models import RequirementKind
from tests.intake_fixtures import ambiguous_package, clean_package


def test_items_are_unique_and_ordered() -> None:
    ids = [i for i, _, _ in ck.CHECKLIST_ITEMS]
    assert len(ids) == len(set(ids)) == 14
    report = ck.run_checklist(clean_package())
    assert [i.id for i in report.items] == ids
    assert {i.severity for i in report.items} == {IssueSeverity.ERROR, IssueSeverity.WARNING}


def test_clean_package_passes_everything() -> None:
    report = ck.run_checklist(clean_package())
    assert report.passed
    assert report.score == 1.0
    assert report.failures() == []
    assert report.ambiguity_score == 0.0
    assert report.summary().endswith("14/14 items passed")


def test_ambiguous_package_fails_expected_items() -> None:
    report = ck.run_checklist(ambiguous_package())
    assert not report.passed
    failed = {i.id: i for i in report.failures()}
    assert set(failed) == {
        "owner_assigned",
        "normative_grammar",
        "testable",
        "unambiguous",
        "complete",
        "consistent",
        "traceable",
        "non_goals_present",
        "nfrs_present",
        "success_signal_measurable",
        "requirements_have_scenarios",
    }
    assert 0 < len(report.failures(errors_only=True)) < len(report.failures())
    assert failed["testable"].artifact_ids == ["REQ-001", "REQ-003", "REQ-005"]
    assert any("[NEEDS CLARIFICATION]" in d for d in failed["unambiguous"].details)
    assert any("SHALL vs SHALL NOT" in d for d in failed["consistent"].details)
    assert any("200 ms" in d for d in failed["consistent"].details)
    assert failed["requirements_have_scenarios"].artifact_ids == ["REQ-001", "REQ-006"]
    assert all(i.remediation for i in report.failures())
    assert str(failed["complete"]).startswith("[FAIL] complete")
    assert 0 < report.score < 1


def test_warning_items_do_not_fail_report() -> None:
    pkg = clean_package()
    for requirement in pkg.requirements:
        requirement.kind = RequirementKind.FUNCTIONAL
    report = ck.run_checklist(pkg)
    assert report.passed
    assert [i.id for i in report.failures()] == ["nfrs_present"]
    assert report.failures(errors_only=True) == []


def test_body_reference_to_unknown_scenario_fails() -> None:
    pkg = clean_package()
    pkg.bodies["requirements.md"] = "See SCN-009-01 for the edge case."
    item = next(
        i for i in ck.run_checklist(pkg).items if i.id == "scenarios_reference_requirements"
    )
    assert not item.passed
    assert item.details == ["requirements.md mentions unknown scenario SCN-009-01"]


def test_threshold_override_affects_unambiguous_only() -> None:
    pkg = ambiguous_package()
    strict = ck.run_checklist(pkg, ambiguity_threshold=0.0)
    lenient = ck.run_checklist(pkg, ambiguity_threshold=1.0)
    strict_item = next(i for i in strict.items if i.id == "unambiguous")
    lenient_item = next(i for i in lenient.items if i.id == "unambiguous")
    assert any("threshold" in d for d in strict_item.details)
    assert not any("threshold" in d for d in lenient_item.details)
    assert not lenient_item.passed  # explicit markers still fail it
