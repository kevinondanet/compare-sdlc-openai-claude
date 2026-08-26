"""Tests for aisdlc.intake.analyze."""

from __future__ import annotations

from aisdlc.intake import analyze as an
from aisdlc.schema.models import (
    Requirement,
    RiskClass,
    Scenario,
    Severity,
    ThreatModel,
    ToolDataManifest,
)
from tests.intake_fixtures import ambiguous_package, clean_package, planned_package


def test_content_words_and_similarity() -> None:
    assert an.content_words("The system SHALL export the reports quickly") == [
        "export",
        "report",
        "quickly",
    ]
    assert an.content_words("Policies were exported") == ["policy", "export"]
    assert an.similarity("export reports", "export reports") == 1.0
    assert an.similarity("The system SHALL export a report", "A report SHALL be exported") >= 0.8
    assert an.similarity("export reports", "rotate secrets nightly") < 0.3
    assert an.similarity("", "") == 1.0
    assert an.similarity("the", "of") == 0.0
    assert an.is_negated("The system SHALL NOT log passwords")
    assert not an.is_negated("The system SHALL log requests")


def test_extract_quantities() -> None:
    found = an.extract_quantities("respond within 200 ms; retry at least 3 attempts; 99.9%", "X")
    assert [(q.value, q.unit, q.bound, q.raw) for q in found] == [
        (200.0, "ms", "upper", "200 ms"),
        (3.0, "attempts", "lower", "3 attempts"),
        (99.9, "%", None, "99.9%"),
    ]
    assert found[0].artifact_id == "X"
    assert an.extract_quantities("5s and 2,5 minutes")[0].unit == "s"
    assert an.extract_quantities("version 2 of the API") == []


def test_conflicting_quantifiers() -> None:
    conflicts = an.find_conflicting_quantifiers(
        [
            ("REQ-001", "The system SHALL export a report within 200 ms"),
            ("REQ-002", "The system SHALL export a report within 500 ms"),
        ]
    )
    assert len(conflicts) == 1
    assert conflicts[0].artifact_ids == ["REQ-001", "REQ-002"]
    # A range (lower + upper bound) is not a conflict.
    assert (
        an.find_conflicting_quantifiers(
            [
                ("REQ-001", "The system SHALL support at least 100 users"),
                ("REQ-002", "The system SHALL support at most 1000 users"),
            ]
        )
        == []
    )
    # Unbounded scenario values are test data.
    assert (
        an.find_conflicting_quantifiers(
            [
                (
                    "REQ-002",
                    "WHEN a reset link is older than 15 minutes, the system SHALL reject it",
                ),
                (
                    "SCN-002-01",
                    "GIVEN a reset link issued 16 minutes ago WHEN opened THEN reject it",
                ),
            ]
        )
        == []
    )
    # Dissimilar statements do not conflict.
    assert (
        an.find_conflicting_quantifiers(
            [
                ("REQ-001", "The system SHALL export a report within 200 ms"),
                ("REQ-002", "The backup job SHALL finish within 30 ms of midnight"),
            ]
        )
        == []
    )


def test_duplicates_and_contradictions() -> None:
    reqs = [
        Requirement(id="REQ-001", text="The system SHALL export a report as CSV"),
        Requirement(id="REQ-002", text="The system MUST export the report as CSV"),
        Requirement(id="REQ-003", text="The system SHALL NOT export a report as CSV"),
        Requirement(id="REQ-004", text="The system SHALL rotate secrets nightly"),
    ]
    duplicates = an.find_duplicates(reqs)
    assert [(d.left_id, d.right_id) for d in duplicates] == [("REQ-001", "REQ-002")]
    contradictions = an.find_contradictions(reqs)
    assert {(c.left_id, c.right_id) for c in contradictions} == {
        ("REQ-001", "REQ-003"),
        ("REQ-002", "REQ-003"),
    }


def test_terminology_drift() -> None:
    drifts = an.find_terminology_drift(
        [
            ("REQ-001", "Users log in with multi-factor authentication"),
            ("REQ-002", "After login the multifactor prompt is shown"),
            ("REQ-003", "The 'login page' must load"),
        ]
    )
    concepts = {d.concept: d.variants for d in drifts}
    assert set(concepts["log in"]) == {"log in", "login"}
    assert concepts["log in"]["login"] == ["REQ-002", "REQ-003"]
    assert set(concepts["multifactor"]) == {"multi-factor", "multifactor"}
    assert drifts[0].artifact_ids == ["REQ-001", "REQ-002", "REQ-003"]
    assert (
        an.find_terminology_drift([("REQ-001", "Users log in"), ("REQ-002", "log in again")]) == []
    )


def test_artifact_texts_covers_every_artifact() -> None:
    ids = {aid for aid, _ in an.artifact_texts(planned_package())}
    assert {"CHG-password-reset", "REQ-001", "SCN-001-01", "ASM-001", "OQ-001"} <= ids
    assert {"ADR-0001", "IFC-001", "THR-001", "TASK-001"} <= ids


def test_analyze_clean_and_ambiguous() -> None:
    clean = an.analyze(clean_package())
    assert clean.passed and clean.findings == [] and clean.max_severity is None
    report = an.analyze(ambiguous_package())
    assert not report.passed
    assert report.max_severity is Severity.HIGH
    codes = {f.code for f in report.findings}
    assert codes == {"CONFLICTING_QUANTIFIER", "CONTRADICTION", "TERMINOLOGY_DRIFT"}
    contradiction = next(f for f in report.findings if f.code == "CONTRADICTION")
    assert contradiction.artifact_ids == ["REQ-002", "REQ-004"]
    assert contradiction.blocking
    drift = next(f for f in report.findings if f.code == "TERMINOLOGY_DRIFT")
    assert not drift.blocking and "login" in drift.message
    assert report.counts()["high"] == 2 and report.counts()["low"] == 1
    assert len(report.at_least(Severity.HIGH)) == 2
    assert str(contradiction).startswith("HIGH CONTRADICTION [REQ-002, REQ-004]")


def test_analyze_planned_package_cross_artifact_codes() -> None:
    report = an.analyze(planned_package())
    by_code: dict[str, list[an.AnalysisFinding]] = {}
    for finding in report.findings:
        by_code.setdefault(finding.code, []).append(finding)
    expected = {
        "ADR_UNKNOWN_REQUIREMENT": Severity.HIGH,
        "PLAN_UNKNOWN_TASK": Severity.HIGH,
        "TASK_UNKNOWN_REQUIREMENT": Severity.HIGH,
        "THREAT_UNCOVERED_DATA_SOURCE": Severity.HIGH,
        "THREAT_UNCOVERED_TOOL": Severity.HIGH,
        "THREAT_UNKNOWN_MITIGATION": Severity.HIGH,
        "THREAT_UNRESOLVED_HIGH_RISK": Severity.HIGH,
        "WAVE_DEPENDENCY_ORDER": Severity.HIGH,
        "ORPHAN_REQUIREMENT": Severity.MEDIUM,
        "TASK_WITHOUT_REQUIREMENT": Severity.MEDIUM,
        "INTERFACE_NOT_REFERENCED": Severity.LOW,
        "SCENARIO_WITHOUT_TEST": Severity.LOW,
    }
    assert set(by_code) == set(expected)
    for code, severity in expected.items():
        assert all(f.severity is severity for f in by_code[code]), code
    assert by_code["THREAT_UNCOVERED_TOOL"][0].message.endswith(
        "'shell' is not covered by any threat"
    )
    assert by_code["ORPHAN_REQUIREMENT"][0].artifact_ids == ["REQ-004"]
    assert {f.artifact_ids[0] for f in by_code["SCENARIO_WITHOUT_TEST"]} == {
        "SCN-003-01",
        "SCN-004-01",
    }
    assert by_code["INTERFACE_NOT_REFERENCED"][0].artifact_ids == ["IFC-002"]
    ranks = [f.severity.rank for f in report.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_manifest_severity_depends_on_risk_class() -> None:
    pkg = planned_package()
    pkg.intent.risk_class = RiskClass.STANDARD
    uncovered = [f for f in an.analyze(pkg).findings if f.code == "THREAT_UNCOVERED_TOOL"]
    assert uncovered and uncovered[0].severity is Severity.MEDIUM
    pkg.intent.risk_class = RiskClass.AI_AGENT
    pkg.threat_model = ThreatModel(tool_data_manifest=ToolDataManifest())
    codes = {f.code for f in an.analyze(pkg).findings}
    assert "MANIFEST_EMPTY" in codes


def test_requirement_unknown_interface_and_adr_supersedes() -> None:
    pkg = planned_package()
    pkg.requirements[0].text += " via IFC-777"
    pkg.decisions[0].supersedes = "ADR-0009"
    codes = {f.code for f in an.analyze(pkg).findings}
    assert {"REQUIREMENT_UNKNOWN_INTERFACE", "ADR_UNKNOWN_SUPERSEDES"} <= codes


def test_scenario_referenced_by_verification_counts_as_tested() -> None:
    pkg = planned_package()
    pkg.requirements[2].scenarios = [
        Scenario(id="SCN-003-01", when="load", then="fast enough"),
    ]
    pkg.tasks[1].verification.command = "pytest -k SCN-003-01"  # type: ignore[union-attr]
    untested = {
        f.artifact_ids[0] for f in an.analyze(pkg).findings if f.code == "SCENARIO_WITHOUT_TEST"
    }
    assert untested == {"SCN-004-01"}
