"""Tests for aisdlc.intake.kernel."""

from __future__ import annotations

from aisdlc.intake import kernel as km
from aisdlc.schema.models import Kernel
from tests.intake_fixtures import ambiguous_package, clean_package


def test_split_items_handles_lines_semicolons_bullets_and_dedupes() -> None:
    assert km.split_items("a; b\n- c\n* d\nA.") == ["a", "b", "c", "d"]
    assert km.split_items(["x;y", "z"]) == ["x", "y", "z"]
    assert km.split_items("") == []


def test_build_kernel_normalises_parts() -> None:
    kernel = km.build_kernel(
        why="  why   here ",
        capabilities="one\ntwo; two",
        non_goals=["n1", "n1"],
        success_signal="tickets  drop 50%",
    )
    assert kernel.why == "why here"
    assert kernel.capabilities == ["one", "two"]
    assert kernel.non_goals == ["n1"]
    assert kernel.constraints == []
    assert kernel.success_signal == "tickets drop 50%"
    assert kernel.is_complete()


def test_missing_parts_matches_kernel_is_complete() -> None:
    empty = Kernel()
    assert km.missing_parts(empty) == [
        km.KernelPart.WHY,
        km.KernelPart.CAPABILITIES,
        km.KernelPart.NON_GOALS,
        km.KernelPart.SUCCESS_SIGNAL,
    ]
    assert km.KernelPart.CONSTRAINTS in km.missing_parts(empty, include_optional=True)
    assert km.missing_parts(clean_package().intent.kernel) == []


def test_is_measurable() -> None:
    assert km.is_measurable("tickets drop by 50% within 3 months")
    assert km.is_measurable("p95 latency under 200 ms")
    assert not km.is_measurable("people are happier")


def test_validate_kernel_codes() -> None:
    codes = {i.code for i in km.validate_kernel(Kernel())}
    assert codes == {
        "KERNEL_MISSING_WHY",
        "KERNEL_MISSING_CAPABILITIES",
        "KERNEL_MISSING_NON_GOALS",
        "KERNEL_MISSING_SUCCESS_SIGNAL",
        "KERNEL_NO_CONSTRAINTS",
    }
    fuzzy = Kernel(
        why="Because TBD",
        capabilities=["do things"],
        constraints=["none known"],
        non_goals=["everything else"],
        success_signal="people are happier",
    )
    issues = km.validate_kernel(fuzzy, "CHG-x")
    codes = {i.code for i in issues}
    assert codes == {"KERNEL_SUCCESS_NOT_MEASURABLE", "KERNEL_AMBIGUOUS"}
    assert all(i.severity.value == "warning" for i in issues)
    assert all(i.artifact_id == "CHG-x" for i in issues)
    assert km.validate_kernel(clean_package().intent.kernel) == []


def test_find_unstated_assumptions() -> None:
    assert km.find_unstated_assumptions(clean_package()) == []
    found = km.find_unstated_assumptions(ambiguous_package())
    assert [(u.artifact_id, u.cue) for u in found] == [("REQ-006", "existing")]
    assert found[0].suggested_text.startswith("It is assumed that:")
    # Removing the covering assumption exposes the constraint's 'existing' cue too.
    pkg = clean_package()
    pkg.assumptions = []
    cues = {(u.artifact_id, u.cue) for u in km.find_unstated_assumptions(pkg)}
    assert (pkg.intent.id, "existing") in cues


def test_readiness_clean_is_ready() -> None:
    report = km.readiness(clean_package())
    assert report.ready
    assert report.failed() == []
    assert report.missing_kernel_parts == []
    assert report.blocking_questions == []
    assert report.ambiguity_score == 0.0
    assert report.ambiguity_threshold == 0.2
    assert "READY" in report.summary()
    assert {c.id for c in report.criteria} >= {"owner", "kernel_complete", "ambiguity"}


def test_readiness_ambiguous_is_not_ready() -> None:
    report = km.readiness(ambiguous_package())
    assert not report.ready
    failed = {c.id for c in report.failed(blocking_only=True)}
    assert failed == {
        "owner",
        "kernel_complete",
        "scenarios_present",
        "grammar",
        "no_blocking_questions",
        "ambiguity",
    }
    advisory = {c.id for c in report.failed()} - failed
    assert advisory >= {"assumptions_recorded", "no_unstated_assumptions", "success_measurable"}
    assert report.blocking_questions == ["OQ-001"]
    assert km.KernelPart.SUCCESS_SIGNAL in report.missing_kernel_parts
    assert report.ambiguity_score > report.ambiguity_threshold
    assert "NOT READY" in report.summary()
    assert any(i.code == "KERNEL_MISSING_CAPABILITIES" for i in report.issues)


def test_readiness_threshold_override() -> None:
    report = km.readiness(ambiguous_package(), ambiguity_threshold=1.0)
    ambiguity = next(c for c in report.criteria if c.id == "ambiguity")
    assert ambiguity.satisfied
    assert report.ambiguity_threshold == 1.0


def test_default_threshold_comes_from_org_policy() -> None:
    assert km.default_ambiguity_threshold() == 0.2
