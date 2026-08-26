"""Tests for aisdlc.testing.portfolio (layers, thresholds, evaluation, exceptions, ratchets)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisdlc.policy import default_org_policy
from aisdlc.schema.models import (
    Coverage,
    EvidenceBundle,
    EvidenceStatus,
    Mutation,
    PerformanceEvidence,
    RiskClass,
    SafetySummary,
    SecurityEvidence,
    TestEvidence,
)
from aisdlc.testing import portfolio as pf

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _run(layer: pf.Layer, **kwargs: object) -> pf.LayerRun:
    return pf.LayerRun(layer=layer, **kwargs)  # type: ignore[arg-type]


def _full_evidence(**overrides: object) -> pf.PortfolioEvidence:
    runs = [
        _run(pf.Layer.UNIT, passed=100),
        _run(pf.Layer.PROPERTY, passed=10),
        _run(pf.Layer.INTEGRATION, passed=20, metrics={"acceptance_criteria_with_evidence": 100.0}),
        _run(pf.Layer.CONTRACT, passed=5),
        _run(pf.Layer.E2E, passed=3, metrics={"critical_journeys_e2e": 100.0}),
        _run(pf.Layer.ARCHITECTURE, passed=2),
        _run(pf.Layer.SECURITY, passed=1),
        _run(pf.Layer.AGENT_SAFETY, passed=4, metrics={"agent_safety_scenarios_executed": 100.0}),
        _run(pf.Layer.PROMPT_EVALS, passed=8),
        _run(pf.Layer.PERFORMANCE, passed=1),
    ]
    base = {
        "runs": runs,
        "coverage": Coverage(lines=85.0, branches=75.0, diff_lines=95.0),
        "mutation": Mutation(score=0.7, scope=["src"]),
    }
    base.update(overrides)
    return pf.PortfolioEvidence(**base)  # type: ignore[arg-type]


def test_layers_and_defaults() -> None:
    assert len(pf.LAYERS) == 10
    assert [layer.value for layer in pf.LAYERS] == [
        "unit",
        "property",
        "integration",
        "contract",
        "e2e",
        "architecture",
        "security",
        "agent_safety",
        "prompt_evals",
        "performance",
    ]
    thr = pf.PortfolioThresholds()
    assert (thr.lines, thr.lines_floor, thr.diff_lines, thr.branches) == (78.0, 75.0, 90.0, 70.0)
    assert (thr.critical_modules, thr.mutation_score) == (90.0, 0.60)
    assert thr.acceptance_criteria_with_evidence == 100.0
    assert thr.critical_journeys_e2e == 100.0
    assert thr.agent_safety_scenarios_executed == 100.0
    assert thr.fail_on_incomplete


def test_thresholds_from_org_policy_matches_defaults() -> None:
    thr = pf.PortfolioThresholds.from_org_policy(default_org_policy())
    assert thr == pf.PortfolioThresholds()
    policy = default_org_policy().model_copy(deep=True)
    policy.security_baselines.coverage.lines_floor = 85.0
    policy.security_baselines.coverage.lines = 90.0
    policy.security_baselines.mutation_score = 0.8
    custom = pf.PortfolioThresholds.from_org_policy(policy)
    assert custom.lines == 88.0 and custom.lines_floor == 85.0 and custom.mutation_score == 0.8


def test_risk_profiles() -> None:
    assert pf.risk_profile_for(RiskClass.DOCS_ONLY).required_layers == []
    low = pf.risk_profile_for("low")
    assert low.required_layers == [pf.Layer.UNIT, pf.Layer.INTEGRATION]
    assert not low.mutation_required and low.acceptance_criteria_required
    standard = pf.risk_profile_for(RiskClass.STANDARD)
    assert pf.Layer.SECURITY in standard.required_layers
    assert standard.mutation_required and not standard.critical_journeys_required
    high = pf.risk_profile_for(RiskClass.HIGH)
    assert high.critical_journeys_required and pf.Layer.PERFORMANCE in high.required_layers
    agent = pf.risk_profile_for(RiskClass.AI_AGENT)
    assert agent.required_layers == list(pf.LAYERS) and agent.agent_safety_required


def test_full_evidence_passes_ai_agent_profile() -> None:
    report = pf.evaluate(_full_evidence(), None, RiskClass.AI_AGENT, now=NOW)
    assert report.passed, [b.message for b in report.breaches]
    assert report.missing_layers == []
    assert all(item.status is pf.LayerStatus.PASSED for item in report.layers)
    assert report.layer(pf.Layer.UNIT).required


def test_missing_required_layers_are_breaches() -> None:
    evidence = pf.PortfolioEvidence(
        runs=[_run(pf.Layer.UNIT, passed=1, metrics={"acceptance_criteria_with_evidence": 100})],
        coverage=Coverage(lines=90, branches=80, diff_lines=95),
        mutation=Mutation(score=0.9),
    )
    report = pf.evaluate(evidence, risk_profile=RiskClass.STANDARD, now=NOW)
    assert not report.passed
    assert set(report.missing_layers) == {
        pf.Layer.INTEGRATION,
        pf.Layer.CONTRACT,
        pf.Layer.E2E,
        pf.Layer.ARCHITECTURE,
        pf.Layer.SECURITY,
    }
    assert report.layer(pf.Layer.PROPERTY).status is pf.LayerStatus.NOT_REQUIRED
    assert report.layer(pf.Layer.E2E).status is pf.LayerStatus.MISSING
    assert all(b.metric == "layer_present" for b in report.breaches)


def test_incomplete_run_fails_closed_even_when_not_required() -> None:
    evidence = _full_evidence()
    evidence.runs[1] = _run(pf.Layer.PROPERTY, complete=False)
    report = pf.evaluate(evidence, risk_profile=RiskClass.LOW, now=NOW)
    assert report.layer(pf.Layer.PROPERTY).status is pf.LayerStatus.INCOMPLETE
    assert [b.metric for b in report.blocking_breaches] == ["layer_complete"]
    relaxed = pf.evaluate(
        evidence,
        pf.PortfolioThresholds(fail_on_incomplete=False),
        RiskClass.LOW,
        now=NOW,
    )
    assert relaxed.passed


def test_failures_and_threshold_breaches() -> None:
    evidence = _full_evidence(
        coverage=Coverage(lines=70.0, branches=60.0, diff_lines=80.0),
        mutation=Mutation(score=0.5, scope=["src"]),
        critical_module_coverage={"src/auth": 60.0, "src/ok": 95.0},
    )
    evidence.runs[0] = _run(pf.Layer.UNIT, passed=10, failed=2)
    report = pf.evaluate(evidence, risk_profile=RiskClass.HIGH, now=NOW)
    metrics = sorted(b.metric for b in report.breaches)
    assert metrics == [
        "branches",
        "critical_modules",
        "diff_lines",
        "layer_failures",
        "lines",
        "mutation_score",
    ]
    critical = next(b for b in report.breaches if b.metric == "critical_modules")
    assert critical.subject == "src/auth" and critical.actual == 60.0
    assert report.layer(pf.Layer.UNIT).status is pf.LayerStatus.FAILED
    assert "portfolio: FAIL" in report.summary_lines()[0]


def test_unmeasured_required_metrics_fail_closed() -> None:
    evidence = _full_evidence(coverage=Coverage(), mutation=None)
    for run in evidence.runs:
        run.metrics = {}
    report = pf.evaluate(evidence, risk_profile=RiskClass.AI_AGENT, now=NOW)
    metrics = sorted(b.metric for b in report.breaches)
    assert metrics == [
        "acceptance_criteria_with_evidence",
        "agent_safety_scenarios_executed",
        "branches",
        "critical_journeys_e2e",
        "diff_lines",
        "lines",
        "mutation_score",
    ]
    assert all("not measured" in b.message for b in report.breaches)
    # docs_only requires nothing, so nothing is measured and nothing breaches
    assert pf.evaluate(pf.PortfolioEvidence(), risk_profile="docs_only", now=NOW).passed


def test_diff_coverage_requirement_can_be_relaxed() -> None:
    evidence = _full_evidence(coverage=Coverage(lines=85.0, branches=75.0, diff_lines=None))
    strict = pf.evaluate(evidence, risk_profile=RiskClass.LOW, now=NOW)
    assert [b.metric for b in strict.breaches] == ["diff_lines"]
    relaxed = pf.evaluate(
        evidence, pf.PortfolioThresholds(require_diff_coverage=False), RiskClass.LOW, now=NOW
    )
    assert relaxed.passed


def test_documented_exceptions_exempt_breaches_until_expiry() -> None:
    evidence = _full_evidence(mutation=Mutation(score=0.4, scope=["src"]))
    exception = pf.PortfolioException(
        metric="mutation_score",
        reason="legacy module being rewritten",
        approved_by="security-lead",
        expires_at=NOW + timedelta(days=30),
        reference="RISK-42",
    )
    report = pf.evaluate(evidence, risk_profile=RiskClass.STANDARD, exceptions=[exception], now=NOW)
    assert report.passed
    assert report.breaches and report.breaches[0].exempted
    assert report.breaches[0].exception_reference == "RISK-42"
    assert report.exceptions_applied == ["RISK-42"]
    expired = pf.evaluate(
        evidence,
        risk_profile=RiskClass.STANDARD,
        exceptions=[exception],
        now=NOW + timedelta(days=31),
    )
    assert not expired.passed and expired.exceptions_expired == ["RISK-42"]


def test_layer_exception_marks_layer_exempted() -> None:
    evidence = _full_evidence()
    evidence.runs = [r for r in evidence.runs if r.layer is not pf.Layer.PERFORMANCE]
    exc = pf.PortfolioException(
        metric="layer_present",
        layer=pf.Layer.PERFORMANCE,
        reason="no load environment yet",
        approved_by="cto",
        expires_at=NOW + timedelta(days=7),
    )
    report = pf.evaluate(evidence, risk_profile=RiskClass.HIGH, exceptions=[exc], now=NOW)
    assert report.passed
    assert report.layer(pf.Layer.PERFORMANCE).status is pf.LayerStatus.EXEMPTED
    other = exc.model_copy(update={"layer": pf.Layer.E2E})
    assert not pf.evaluate(
        evidence, risk_profile=RiskClass.HIGH, exceptions=[other], now=NOW
    ).passed


def test_exception_validation() -> None:
    with pytest.raises(ValueError, match="unknown metric"):
        pf.PortfolioException(
            metric="bogus", reason="r", approved_by="a", expires_at=NOW + timedelta(days=1)
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        pf.PortfolioException(
            metric="lines", reason="r", approved_by="a", expires_at=datetime(2030, 1, 1)
        )
    with pytest.raises(ValueError):
        pf.PortfolioException(metric="lines", reason="", approved_by="a", expires_at=NOW)


def test_ratchet_never_lowers_floors() -> None:
    previous = pf.PortfolioThresholds(lines=82, lines_floor=80, mutation_score=0.7, branches=75)
    current = pf.PortfolioThresholds(lines=78, lines_floor=75, mutation_score=0.6, diff_lines=95)
    merged = pf.ratchet(previous, current)
    assert (merged.lines, merged.lines_floor, merged.mutation_score) == (82, 80, 0.7)
    assert merged.branches == 75 and merged.diff_lines == 95
    assert merged.fail_on_incomplete


def test_ratchet_to_observed_rounds_down_and_requires_complete_unit_run() -> None:
    previous = pf.PortfolioThresholds()
    evidence = _full_evidence(
        coverage=Coverage(lines=83.7, branches=71.2, diff_lines=96.9),
        mutation=Mutation(score=0.734),
    )
    raised = pf.ratchet_to_observed(previous, evidence)
    assert raised.lines_floor == 83.5 and raised.lines == 83.5
    assert raised.branches == 71.0 and raised.diff_lines == 96.5
    assert raised.mutation_score == pytest.approx(0.73)
    evidence.runs[0] = _run(pf.Layer.UNIT, complete=False)
    assert pf.ratchet_to_observed(previous, evidence) == previous
    worse = _full_evidence(coverage=Coverage(lines=10, branches=10, diff_lines=10))
    assert pf.ratchet_to_observed(raised, worse) == raised


def test_classify_test_evidence() -> None:
    def ev(command: str, produced_by: str = "") -> TestEvidence:
        return TestEvidence(id="EVD-tests-001", command=command, produced_by=produced_by)

    assert pf.classify_test_evidence(ev("pytest -q")) is pf.Layer.UNIT
    assert pf.classify_test_evidence(ev("pytest -m integration")) is pf.Layer.INTEGRATION
    assert pf.classify_test_evidence(ev("npx playwright test")) is pf.Layer.E2E
    assert pf.classify_test_evidence(ev("pytest", "aisdlc layer=contract")) is pf.Layer.CONTRACT
    assert pf.classify_test_evidence(ev("lint-imports")) is pf.Layer.ARCHITECTURE


def test_from_bundle_maps_evidence_to_layers() -> None:
    bundle = EvidenceBundle(
        tests=[
            TestEvidence(
                id="EVD-tests-001",
                command="pytest -q",
                exit_code=0,
                passed=50,
                status=EvidenceStatus.COMPLETE,
                coverage=Coverage(lines=88, branches=72, diff_lines=93),
                mutation=Mutation(score=0.65, scope=["src"]),
            ),
            TestEvidence(
                id="EVD-tests-002",
                command="pytest -m integration",
                exit_code=1,
                passed=5,
                failed=1,
                status=EvidenceStatus.COMPLETE,
            ),
        ],
        security=SecurityEvidence(
            id="EVD-security-001",
            status=EvidenceStatus.COMPLETE,
            critical_open=0,
            high_open=1,
            safety_regression=SafetySummary(complete=True, asr_by_category={"harm": 0.0}),
        ),
        performance=PerformanceEvidence(
            id="EVD-performance-001", status=EvidenceStatus.COMPLETE, slo_met=False
        ),
    )
    evidence = pf.PortfolioEvidence.from_bundle(bundle)
    unit = evidence.run_for(pf.Layer.UNIT)
    assert unit is not None and unit.passed == 50 and unit.complete
    integration = evidence.run_for(pf.Layer.INTEGRATION)
    assert integration is not None and integration.failed == 1
    assert evidence.coverage.lines == 88 and evidence.mutation is not None
    security = evidence.run_for(pf.Layer.SECURITY)
    assert security is not None and security.failed == 1
    safety = evidence.run_for(pf.Layer.AGENT_SAFETY)
    assert safety is not None and safety.metrics["agent_safety_scenarios_executed"] == 100.0
    perf = evidence.run_for(pf.Layer.PERFORMANCE)
    assert perf is not None and perf.failed == 1
    assert evidence.run_for(pf.Layer.E2E) is None


def test_merged_runs_of_same_layer() -> None:
    evidence = pf.PortfolioEvidence(
        runs=[
            _run(pf.Layer.UNIT, passed=3, metrics={"acceptance_criteria_with_evidence": 100}),
            _run(
                pf.Layer.UNIT,
                passed=2,
                complete=False,
                metrics={"acceptance_criteria_with_evidence": 50},
            ),
        ]
    )
    merged = evidence.run_for(pf.Layer.UNIT)
    assert merged is not None
    assert merged.passed == 5 and not merged.complete
    assert merged.metrics["acceptance_criteria_with_evidence"] == 50


def test_report_serialises() -> None:
    report = pf.evaluate(_full_evidence(), risk_profile=RiskClass.AI_AGENT, now=NOW)
    data = report.model_dump(mode="json")
    assert data["risk_class"] == "ai_agent" and len(data["layers"]) == 10
    assert pf.PortfolioReport.model_validate(data).passed
