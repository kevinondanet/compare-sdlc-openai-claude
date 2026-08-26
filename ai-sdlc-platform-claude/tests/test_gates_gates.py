"""Tests for aisdlc.gates.gates: pass / fail / skip paths for G0..G6."""

from __future__ import annotations

from datetime import timedelta

import pytest

from aisdlc.gates import gates as g
from aisdlc.gates.depth import GateDepthProfile, profile_for
from aisdlc.gates.verdict import Approval
from aisdlc.governance.audit import IntegrityReport
from aisdlc.policy import OrgPolicy, default_org_policy
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    ChangePackage,
    Coverage,
    EvidenceStatus,
    Finding,
    GateDepth,
    GateId,
    Kernel,
    OpenQuestion,
    Plan,
    PyritSummary,
    Requirement,
    ReviewVerdict,
    RiskClass,
    SafetySummary,
    ScanResult,
    Scenario,
    SecurityEvidence,
    Severity,
    Task,
    TaskStatus,
    ThreatStatus,
    ToolDataManifest,
    Verification,
    Wave,
)
from aisdlc.security.manifest import DriftReport
from tests.test_gates_fixtures import (
    COMMIT,
    NOW,
    TEST_EVIDENCE_IDS,
    context,
    golden_package,
    policy,
)


def run(
    gate: GateId,
    pkg: ChangePackage,
    *,
    risk: RiskClass = RiskClass.STANDARD,
    pol: OrgPolicy | None = None,
    profile: GateDepthProfile | None = None,
    ctx: g.GateContext | None = None,
) -> g.GateResult:
    pol = pol or policy()
    prof = profile or profile_for(risk, pol)
    return g.evaluate_gate(gate, pkg, pol, prof, ctx or context())


def reasons(result: g.GateResult) -> str:
    return "\n".join(result.reasons)


# --------------------------------------------------------------------------------------
# Common behaviour
# --------------------------------------------------------------------------------------


def test_golden_package_passes_every_gate_at_standard() -> None:
    verdict = g.evaluate_all(golden_package(), policy(), context=context())
    assert [r.gate for r in verdict.gate_results] == list(GateId)
    assert all(r.passed for r in verdict.gate_results), [
        (r.gate.value, r.reasons) for r in verdict.gate_results
    ]
    assert verdict.overall is True
    assert verdict.commit_sha == COMMIT
    assert verdict.produced_at == NOW
    assert verdict.change_id == "CHG-login-mfa"
    assert all(r.depth is GateDepth.STANDARD for r in verdict.gate_results)
    g2 = verdict.result_for(GateId.G2)
    assert g2 is not None and g2.evidence_ids == list(TEST_EVIDENCE_IDS)


def test_golden_package_passes_deep_and_ai_agent() -> None:
    for risk in (RiskClass.HIGH, RiskClass.CRITICAL, RiskClass.AI_AGENT):
        verdict = g.evaluate_all(golden_package(risk), policy(), context=context())
        assert verdict.overall, [(r.gate.value, r.reasons) for r in verdict.gate_results]
        assert all(r.depth is GateDepth.DEEP for r in verdict.gate_results)


def test_unrequired_gates_are_skipped_not_failed() -> None:
    pkg = golden_package(RiskClass.DOCS_ONLY)
    pkg.evidence.security = None
    pkg.evidence.cost = None
    verdict = g.evaluate_all(pkg, policy(), context=context())
    by_gate = {r.gate: r for r in verdict.gate_results}
    for gate in (GateId.G1, GateId.G4, GateId.G5, GateId.G6):
        assert by_gate[gate].passed and by_gate[gate].depth is GateDepth.SKIPPED
        assert by_gate[gate].reasons[0].startswith("skipped")
    for gate in (GateId.G0, GateId.G2, GateId.G3):
        assert by_gate[gate].depth is GateDepth.LIGHT
    assert verdict.overall is True


def test_overall_false_when_required_gate_fails() -> None:
    pkg = golden_package()
    pkg.intent.owner = None
    verdict = g.evaluate_all(pkg, policy(), context=context())
    assert verdict.overall is False
    g0 = verdict.result_for(GateId.G0)
    g6 = verdict.result_for(GateId.G6)
    assert g0 is not None and not g0.passed
    assert g6 is not None and not g6.passed and "G0 failed" in reasons(g6)


def test_gate_protocol_and_registry() -> None:
    for gate_id, gate in g.GATES.items():
        assert isinstance(gate, g.Gate)
        assert gate.id is gate_id
        assert gate.title
    assert g.gate_for("G4").id is GateId.G4
    runner = g.GateRunner()
    result = runner.evaluate(GateId.G0, golden_package(), policy(), context=context())
    assert result.passed


def test_context_from_package_without_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISDLC_SIGNING_KEY", raising=False)
    monkeypatch.delenv("AISDLC_ED25519_PRIVATE_KEY", raising=False)
    ctx = g.GateContext.from_package(golden_package())
    assert ctx.head_commit is None
    assert ctx.signing_available is False
    assert ctx.approvals == []


# --------------------------------------------------------------------------------------
# G0
# --------------------------------------------------------------------------------------


def test_g0_failures() -> None:
    pkg = golden_package()
    pkg.intent.owner = None
    pkg.intent.kernel = Kernel(why="w")
    pkg.assumptions = []
    pkg.requirements[0].scenarios = []
    pkg.open_questions = [OpenQuestion(id="OQ-001", question="Which TOTP window?", blocking=True)]
    result = run(GateId.G0, pkg, risk=RiskClass.HIGH)
    text = reasons(result)
    assert not result.passed
    assert "no owner" in text
    assert "kernel is incomplete" in text
    assert "no non-goals" in text
    assert "no assumptions" in text
    assert "REQ-001 has no acceptance scenario" in text
    assert "blocking open question OQ-001" in text


def test_g0_ambiguity_and_grammar() -> None:
    pkg = golden_package()
    pkg.requirements[0].text = "The system SHALL do TBD [NEEDS CLARIFICATION] TODO"
    pkg.requirements[1].text = "The system responds quickly"
    pkg.assumptions[0].text = "TBD TODO"
    result = run(GateId.G0, pkg)
    assert not result.passed
    text = reasons(result)
    assert "ambiguity score" in text
    assert "grammar REQ_" in text


def test_g0_light_profile_relaxes_kernel_and_non_goals() -> None:
    pkg = golden_package(RiskClass.DOCS_ONLY)
    pkg.intent.kernel = Kernel(why="fix typos")
    result = run(GateId.G0, pkg, risk=RiskClass.DOCS_ONLY)
    assert result.passed, result.reasons
    assert result.depth is GateDepth.LIGHT


def test_g0_no_requirements() -> None:
    pkg = golden_package()
    pkg.requirements = []
    pkg.tasks = []
    result = run(GateId.G0, pkg)
    assert "no requirements" in reasons(result)


# --------------------------------------------------------------------------------------
# G1
# --------------------------------------------------------------------------------------


def test_g1_failures() -> None:
    pkg = golden_package()
    pkg.plan = None
    assert pkg.threat_model is not None
    pkg.threat_model.threats[0].status = ThreatStatus.OPEN
    pkg.requirements = [pkg.requirements[0]]
    pkg.tasks[0].requirement_ids = ["REQ-001"]
    pkg.decisions = []
    result = run(GateId.G1, pkg, risk=RiskClass.HIGH)
    text = reasons(result)
    assert not result.passed
    assert "no plan" in text
    assert "not approved" in text
    assert "unresolved high threat THR-001" in text
    assert "no non-functional requirements" in text
    assert "no architecture decision records" in text


def test_g1_missing_threat_model_and_plan_checker() -> None:
    pkg = golden_package()
    pkg.threat_model = None
    pkg.tasks = [
        Task(id="TASK-001", title="a", requirement_ids=["REQ-001"], depends_on=["TASK-009"]),
        Task(
            id="TASK-003",
            title="b",
            requirement_ids=["REQ-404"],
            verification=Verification(command=""),
        ),
    ]
    pkg.plan = Plan(waves=[Wave(index=0, task_ids=["TASK-001", "TASK-777"])])
    result = run(GateId.G1, pkg)
    text = reasons(result)
    assert "no threat model" in text
    assert "TASK_UNKNOWN_DEPENDENCY" in text
    assert "TASK_UNKNOWN_REQUIREMENT" in text
    assert "TASK_NUMBERING_GAP" in text
    assert "PLAN_UNKNOWN_TASK" in text


def test_g1_light_does_not_require_threat_model() -> None:
    pkg = golden_package(RiskClass.LOW)
    pkg.threat_model = None
    pkg.requirements = [pkg.requirements[0]]
    pkg.tasks[0].requirement_ids = ["REQ-001"]
    result = run(GateId.G1, pkg, risk=RiskClass.LOW)
    assert result.passed, result.reasons


def test_g1_deep_requires_at_least_one_threat() -> None:
    pkg = golden_package(RiskClass.HIGH)
    assert pkg.threat_model is not None
    pkg.threat_model.mitigations = []
    pkg.threat_model.threats = []
    result = run(GateId.G1, pkg, risk=RiskClass.HIGH)
    assert "at least 1 required" in reasons(result)


# --------------------------------------------------------------------------------------
# G2
# --------------------------------------------------------------------------------------


def test_g2_missing_evidence_fails_closed() -> None:
    pkg = golden_package()
    pkg.evidence.tests = []
    result = run(GateId.G2, pkg)
    assert not result.passed and "no test evidence" in reasons(result)


def test_g2_incomplete_and_inadmissible_evidence() -> None:
    pkg = golden_package()
    rec = pkg.evidence.tests[0]
    rec.status = EvidenceStatus.INCOMPLETE
    rec.commit_sha = ""
    rec.report_uri = None
    rec.environment = ""
    result = run(GateId.G2, pkg)
    text = reasons(result)
    assert "EVD-tests-001: evidence is incomplete" in text
    assert "no commit sha" in text
    assert "no report URI" in text
    assert "no environment" in text


def test_g2_exit_code_and_failures() -> None:
    pkg = golden_package()
    pkg.evidence.tests[0].exit_code = 1
    pkg.evidence.tests[0].failed = 3
    pkg.evidence.tests[1].exit_code = None
    result = run(GateId.G2, pkg)
    text = reasons(result)
    assert "exited 1" in text
    assert "3 failing test(s)" in text
    assert "EVD-tests-002: no exit code recorded" in text


def test_g2_coverage_thresholds() -> None:
    pkg = golden_package()
    cov = pkg.evidence.tests[0].coverage
    cov.lines = 70.0
    cov.branches = 60.0
    cov.diff_lines = 80.0
    result = run(GateId.G2, pkg)
    text = reasons(result)
    assert "line coverage 70.0% below 75.0%" in text
    assert "branch coverage 60.0% below 70.0%" in text
    assert "diff coverage 80.0% below 90.0%" in text


def test_g2_coverage_not_measured_when_required() -> None:
    pkg = golden_package()
    pkg.evidence.tests[0].coverage.lines = None
    pkg.evidence.tests[0].coverage.branches = None
    pkg.evidence.tests[0].coverage.diff_lines = None
    result = run(GateId.G2, pkg)
    assert "no coverage evidence" in reasons(result)
    light = run(GateId.G2, pkg, risk=RiskClass.LOW)
    assert light.passed, light.reasons


def test_g2_critical_module_coverage() -> None:
    pol = policy()
    pol.project.critical_modules = ["src/app/"]
    pkg = golden_package(RiskClass.HIGH)
    pkg.evidence.tests[0].coverage.diff_lines = 88.0
    result = run(GateId.G2, pkg, risk=RiskClass.HIGH, pol=pol)
    assert "diff coverage (critical modules touched) 88.0% below 90.0%" in reasons(result)
    pkg.tasks[0].files = ["docs/readme.md"]
    pkg.evidence.tests[0].coverage.diff_lines = 90.0
    assert run(GateId.G2, pkg, risk=RiskClass.HIGH, pol=pol).passed


def test_g2_mutation_rules() -> None:
    pkg = golden_package(RiskClass.HIGH)
    assert pkg.evidence.tests[0].mutation is not None
    pkg.evidence.tests[0].mutation.score = 0.4
    pkg.evidence.tests[0].mutation.scope = []
    result = run(GateId.G2, pkg, risk=RiskClass.HIGH)
    text = reasons(result)
    assert "mutation scope is not disclosed" in text
    assert "mutation score 0.40 below 0.60" in text
    pkg.evidence.tests[0].mutation = None
    deep = run(GateId.G2, pkg, risk=RiskClass.HIGH)
    assert "no mutation testing evidence" in reasons(deep)
    standard = run(GateId.G2, pkg)
    assert standard.passed, standard.reasons


def test_g2_lint_types_build_records() -> None:
    pkg = golden_package()
    pkg.evidence.tests = [pkg.evidence.tests[0]]
    result = run(GateId.G2, pkg)
    text = reasons(result)
    assert "no lint evidence for 'ruff check .'" in text
    assert "no types evidence for 'mypy'" in text
    pol = policy()
    pol.project.test_commands.build = "python -m build"
    deep = run(GateId.G2, golden_package(RiskClass.HIGH), risk=RiskClass.HIGH, pol=pol)
    assert "no build evidence for 'python -m build'" in reasons(deep)
    # Org-only policy has no project commands: no lint/types/build requirement (the
    # portfolio still reports the layers the single unit record does not cover).
    org_only = run(GateId.G2, pkg, pol=default_org_policy())
    assert not any("evidence for" in r for r in org_only.reasons), org_only.reasons
    assert all(r.startswith("portfolio:") for r in org_only.reasons), org_only.reasons


# --------------------------------------------------------------------------------------
# G3
# --------------------------------------------------------------------------------------


def test_g3_missing_review_fails_closed() -> None:
    pkg = golden_package()
    pkg.evidence.reviews = []
    result = run(GateId.G3, pkg)
    assert not result.passed and "no review evidence" in reasons(result)


def test_g3_independence_and_findings() -> None:
    pkg = golden_package()
    review = pkg.evidence.reviews[0]
    review.reviewer_model_family = "anthropic"
    review.findings = [
        Finding(id="FND-001", severity=Severity.HIGH, grounded=True, blocking=True, title="bug"),
        Finding(id="FND-002", grounded=True, blocking=True, overturned=True, title="nope"),
        Finding(id="FND-003", grounded=False, blocking=True, title="hunch"),
    ]
    review.verdict = ReviewVerdict.CHANGES_REQUESTED
    review.scope = []
    result = run(GateId.G3, pkg)
    text = reasons(result)
    assert "not independent" in text
    assert "grounded blocking finding FND-001" in text
    assert "FND-002" not in text and "FND-003" not in text
    assert "verdict is changes_requested" in text
    assert "review scope" in text


def test_g3_same_family_allowed_at_light_depth() -> None:
    pkg = golden_package(RiskClass.LOW)
    pkg.evidence.reviews[0].reviewer_model_family = "anthropic"
    result = run(GateId.G3, pkg, risk=RiskClass.LOW)
    assert result.passed, result.reasons
    pkg.evidence.reviews[0].reviewer_model_family = ""
    assert "reviewer model family not recorded" in reasons(run(GateId.G3, pkg, risk=RiskClass.LOW))


def test_g3_latest_round_decides_and_rounds_are_capped() -> None:
    pkg = golden_package()
    first = pkg.evidence.reviews[0].model_copy(
        update={
            "id": "EVD-reviews-002",
            "round": 1,
            "verdict": ReviewVerdict.CHANGES_REQUESTED,
            "findings": [Finding(id="FND-001", grounded=True, blocking=True)],
        }
    )
    latest = pkg.evidence.reviews[0].model_copy(update={"round": 2})
    pkg.evidence.reviews = [first, latest]
    result = run(GateId.G3, pkg)
    assert result.passed, result.reasons
    assert result.evidence_ids == ["EVD-reviews-001", "EVD-reviews-002"]
    pkg.evidence.reviews[1].round = 4
    assert "4 review rounds exceed" in reasons(run(GateId.G3, pkg))


# --------------------------------------------------------------------------------------
# G4
# --------------------------------------------------------------------------------------


def test_g4_missing_security_fails_closed() -> None:
    pkg = golden_package()
    pkg.evidence.security = None
    result = run(GateId.G4, pkg)
    assert not result.passed and "no security evidence" in reasons(result)


def test_g4_scans_vulns_sbom_provenance() -> None:
    pkg = golden_package()
    sec = pkg.evidence.security
    assert sec is not None
    sec.sast = ScanResult(tool="codeql", ran=True, critical=1)
    sec.sca = None
    sec.secrets = ScanResult(tool="gitleaks", ran=False)
    sec.critical_open = 1
    sec.high_open = 2
    sec.sbom_present = False
    sec.provenance_present = False
    sec.manifest_drift = True
    result = run(GateId.G4, pkg)
    text = reasons(result)
    assert "SAST reports 1 critical" in text
    assert "SCA scan did not run" in text
    assert "secrets scan did not run" in text
    assert "1 open critical vulnerability" in text
    assert "2 open high vulnerability" in text
    assert "SBOM missing" in text
    assert "provenance missing" in text
    assert "drifts from manifest" in text


def test_g4_pyrit_thresholds() -> None:
    pkg = golden_package(RiskClass.AI_AGENT)
    sec = pkg.evidence.security
    assert sec is not None
    sec.pyrit = PyritSummary(
        campaign_id="c",
        asr=0.2,
        undetermined_rate=0.5,
        complete=False,
        baseline_delta=0.1,
        trials=2,
    )
    result = run(GateId.G4, pkg, risk=RiskClass.AI_AGENT)
    text = reasons(result)
    assert "campaign c incomplete" in text
    assert "attack success rate 0.200 exceeds 0.050" in text
    assert "undetermined rate 0.500 exceeds 0.100" in text
    assert "2 PyRIT trial(s), 5 required" in text
    assert "regressed by +0.100" in text
    sec.pyrit = None
    sec.safety_regression = None
    missing = run(GateId.G4, pkg, risk=RiskClass.AI_AGENT)
    assert "PyRIT campaign evidence required but missing" in reasons(missing)
    assert "safety regression evidence required but missing" in reasons(missing)
    standard = run(GateId.G4, pkg)
    assert standard.passed, standard.reasons


def test_g4_safety_regression_breaches() -> None:
    pkg = golden_package()
    sec = pkg.evidence.security
    assert sec is not None
    sec.safety_regression = SafetySummary(
        asr_by_category={"harm": 0.3}, complete=False, threshold_breaches=["harm"]
    )
    text = reasons(run(GateId.G4, pkg))
    assert "safety regression run incomplete" in text
    assert "safety threshold breached: harm" in text
    assert "safety ASR for harm 0.300 exceeds 0.050" in text


def test_g4_manifest_validation_and_privileged_calls() -> None:
    pkg = golden_package(RiskClass.AI_AGENT)
    assert pkg.threat_model is not None
    pkg.threat_model.tool_data_manifest.tools = []
    pkg.threat_model.tool_data_manifest.data_sources = []
    pkg.threat_model.mitigations = []
    pkg.threat_model.threats = []
    result = run(GateId.G4, pkg, risk=RiskClass.AI_AGENT)
    text = reasons(result)
    assert "privileged tool call(s) without a threat model" in text
    assert "tool/data manifest not declared" in text
    pkg.evidence.audit = None
    assert "no audit evidence to validate the manifest" in reasons(
        run(GateId.G4, pkg, risk=RiskClass.AI_AGENT)
    )


# --------------------------------------------------------------------------------------
# G5
# --------------------------------------------------------------------------------------


def test_g5_cost_and_performance() -> None:
    pkg = golden_package(RiskClass.HIGH)
    assert pkg.evidence.cost is not None and pkg.evidence.performance is not None
    pkg.evidence.cost.total_cost_usd = 60.0
    pkg.evidence.performance.slo_met = False
    result = run(GateId.G5, pkg, risk=RiskClass.HIGH)
    text = reasons(result)
    assert "cost $60.00 exceeds budget $50.00" in text
    assert "SLO not met" in text
    assert result.evidence_ids == ["EVD-cost-001", "EVD-performance-001"]


def test_g5_budget_from_policy_and_escalations() -> None:
    pol = policy()
    pol.models.escalation_allowed = False
    pkg = golden_package()
    assert pkg.evidence.cost is not None
    pkg.evidence.cost = pkg.evidence.cost.model_copy(
        update={"budget_usd": None, "total_cost_usd": 51.0, "escalations": 2, "variance": None}
    )
    text = reasons(run(GateId.G5, pkg, pol=pol))
    assert "exceeds budget $50.00" in text
    assert "2 model escalation(s)" in text


def test_g5_missing_evidence() -> None:
    pkg = golden_package(RiskClass.HIGH)
    pkg.evidence.cost = None
    pkg.evidence.performance = None
    text = reasons(run(GateId.G5, pkg, risk=RiskClass.HIGH))
    assert "no cost evidence" in text and "no performance evidence" in text
    standard = run(GateId.G5, pkg)
    assert "no performance evidence" not in reasons(standard)


# --------------------------------------------------------------------------------------
# G6
# --------------------------------------------------------------------------------------


def test_g6_evaluates_predecessors_when_no_prior_results() -> None:
    pkg = golden_package()
    pkg.evidence.reviews = []
    result = run(GateId.G6, pkg)
    assert not result.passed
    assert "G3 failed: no review evidence" in reasons(result)


def test_g6_staleness_commit_and_age() -> None:
    pkg = golden_package()
    pkg.evidence.tests[1].commit_sha = "ffff"
    pkg.evidence.cost = pkg.evidence.cost.model_copy(  # type: ignore[union-attr]
        update={"finished_at": NOW - timedelta(hours=100)}
    )
    pkg.evidence.audit = pkg.evidence.audit.model_copy(  # type: ignore[union-attr]
        update={"finished_at": None, "started_at": None}
    )
    result = run(GateId.G6, pkg)
    text = reasons(result)
    assert "evidence spans 2 different commits" in text
    assert "EVD-tests-002: produced at ffff but HEAD is" in text
    assert "EVD-cost-001: evidence older than 72h" in text
    assert "EVD-audit-001: evidence carries no timestamp" in text


def test_g6_fingerprint_audit_approvals_signing() -> None:
    pkg = golden_package(RiskClass.AI_AGENT)
    assert pkg.evidence.audit is not None
    pkg.evidence.audit.integrity_ok = False
    ctx = context(
        current_fingerprint="a",
        stored_fingerprint="b",
        approvals=[Approval(role="owner", approver="kevin", approved_at=NOW)],
        signing_available=False,
    )
    result = run(GateId.G6, pkg, risk=RiskClass.AI_AGENT, ctx=ctx)
    text = reasons(result)
    assert "fingerprint mismatch" in text
    assert "audit log integrity check failed" in text
    assert "1 human approval(s) recorded, 2 required" in text
    assert "missing human approval for role 'security'" in text
    assert "no signing key available" in text


def test_g6_audit_required_only_at_deep() -> None:
    pkg = golden_package()
    pkg.evidence.audit = None
    assert run(GateId.G6, pkg).passed
    deep = run(GateId.G6, golden_package(RiskClass.HIGH), risk=RiskClass.HIGH)
    assert deep.passed
    pkg_high = golden_package(RiskClass.HIGH)
    pkg_high.evidence.audit = None
    assert "no audit evidence" in reasons(run(GateId.G6, pkg_high, risk=RiskClass.HIGH))


def test_g6_no_evidence_at_all() -> None:
    pkg = golden_package(RiskClass.DOCS_ONLY)
    profile = profile_for(RiskClass.DOCS_ONLY, policy()).model_copy(
        update={"required_gates": [GateId.G6]}
    )
    pkg.evidence.tests = []
    pkg.evidence.reviews = []
    pkg.evidence.security = None
    pkg.evidence.performance = None
    pkg.evidence.cost = None
    pkg.evidence.audit = None
    result = run(GateId.G6, pkg, profile=profile)
    assert "no evidence at all" in reasons(result)


# --------------------------------------------------------------------------------------
# Review findings: plan checker, portfolio, per-scope reviews, derived security facts,
# recomputed SLO, verified audit log, signing-key discovery
# --------------------------------------------------------------------------------------


def test_g1_runs_goal_backward_plan_checker() -> None:
    pkg = golden_package()
    pkg.requirements.append(
        Requirement(
            id="REQ-003",
            text="The system SHALL log every failed TOTP attempt.",
            scenarios=[
                Scenario(id="SCN-003-01", when="a TOTP code is wrong", then="a failure is logged")
            ],
        )
    )
    pkg.tasks = [
        Task(
            id="TASK-001",
            title="Implement TOTP check",
            requirement_ids=["REQ-001", "REQ-002"],
            verification=Verification(command="pytest -q tests/test_totp.py"),
            status=TaskStatus.DONE,
            depends_on=["TASK-002"],
            wave=0,
        ),
        Task(
            id="TASK-002",
            title="Add TOTP secret storage",
            requirement_ids=["REQ-001"],
            verification=Verification(command="pytest -q tests/test_secrets.py"),
            status=TaskStatus.DONE,
            wave=1,
        ),
    ]
    pkg.plan = Plan(
        waves=[Wave(index=0, task_ids=["TASK-001"]), Wave(index=1, task_ids=["TASK-002"])],
        approved_by="kevin",
    )
    result = run(GateId.G1, pkg)
    text = reasons(result)
    assert not result.passed
    assert "plan check REQ_UNCOVERED [REQ-003]" in text
    assert "WAVE_ORDER_VIOLATION" in text
    assert "CHECKPOINT_RELEASE_MISSING" in text
    # each code is reported once even though grammar and the checker both see it
    assert text.count("TASK_UNKNOWN_DEPENDENCY") <= 1


def test_g2_portfolio_layers_and_completeness_are_enforced() -> None:
    pkg = golden_package()
    pkg.evidence.tests = [r for r in pkg.evidence.tests if r.id <= "EVD-tests-003"]
    text = reasons(run(GateId.G2, pkg))
    assert "portfolio: required layer integration was not executed" in text
    assert "portfolio: required layer contract was not executed" in text
    assert "portfolio: required layer architecture was not executed" in text
    # completeness metrics come from the persisted portfolio inputs; none -> not measured
    without_inputs = run(GateId.G2, golden_package(), ctx=context(portfolio_inputs=None))
    assert "portfolio: acceptance_criteria_with_evidence not measured" in reasons(without_inputs)
    unreadable = run(GateId.G2, golden_package(), ctx=context(portfolio_inputs_error="bad json"))
    assert "portfolio inputs unreadable: bad json" in reasons(unreadable)
    # light depth checks no coverage/mutation thresholds, so unmeasured coverage is fine
    low = golden_package(RiskClass.LOW)
    low.evidence.tests[0].coverage = Coverage()
    low.evidence.tests[0].mutation = None
    assert run(GateId.G2, low, risk=RiskClass.LOW).passed, run(GateId.G2, low, risk=RiskClass.LOW)
    # critical-module coverage from the inputs is enforced at deep depth
    inputs = context().portfolio_inputs
    assert inputs is not None
    strict = context(
        portfolio_inputs=inputs.model_copy(update={"critical_module_coverage": {"src/auth": 50.0}})
    )
    deep = run(GateId.G2, golden_package(RiskClass.HIGH), risk=RiskClass.HIGH, ctx=strict)
    assert "critical module src/auth line coverage 50.00 < 90.00" in reasons(deep)


def test_g2_docs_only_requires_link_check_evidence() -> None:
    docs = golden_package(RiskClass.DOCS_ONLY)
    assert run(GateId.G2, docs, risk=RiskClass.DOCS_ONLY).passed
    docs.evidence.tests = [r for r in docs.evidence.tests if r.id != "EVD-tests-011"]
    text = reasons(run(GateId.G2, docs, risk=RiskClass.DOCS_ONLY))
    assert "no link-check evidence" in text
    assert "no link-check evidence" not in reasons(run(GateId.G2, golden_package()))


def test_g3_blocking_findings_on_other_tasks_are_not_hidden() -> None:
    pkg = golden_package()
    base = pkg.evidence.reviews[0]
    blocking = [
        Finding(id="FND-001", severity=Severity.HIGH, grounded=True, blocking=True, title="bug")
    ]
    task_b = base.model_copy(
        update={
            "id": "EVD-reviews-001",
            "round": 1,
            "scope": ["src/app/b.py"],
            "verdict": ReviewVerdict.CHANGES_REQUESTED,
            "findings": blocking,
        }
    )
    task_a = base.model_copy(
        update={"id": "EVD-reviews-002", "round": 2, "scope": ["src/app/a.py"]}
    )
    pkg.evidence.reviews = [task_b, task_a]
    result = run(GateId.G3, pkg)
    assert not result.passed
    assert "EVD-reviews-001: grounded blocking finding FND-001" in reasons(result)

    # the whole-change review (round 1 but newest) overrides an earlier task approval
    final = base.model_copy(
        update={
            "id": "EVD-reviews-003",
            "round": 1,
            "scope": ["src/app/a.py", "src/app/b.py"],
            "verdict": ReviewVerdict.CHANGES_REQUESTED,
            "findings": blocking,
            "finished_at": NOW + timedelta(minutes=5),
        }
    )
    pkg.evidence.reviews = [task_a, final]
    result = run(GateId.G3, pkg)
    assert not result.passed and "EVD-reviews-003: grounded blocking finding" in reasons(result)
    assert [r.id for r in g.effective_reviews(pkg.evidence.reviews)] == ["EVD-reviews-003"]

    # a scoped re-review of task B replaces the round it fixes
    fixed = task_b.model_copy(
        update={
            "id": "EVD-reviews-004",
            "round": 2,
            "verdict": ReviewVerdict.APPROVED,
            "findings": [],
            "finished_at": NOW + timedelta(minutes=1),
        }
    )
    pkg.evidence.reviews = [task_b, task_a, fixed]
    assert run(GateId.G3, pkg).passed, run(GateId.G3, pkg).reasons
    assert [r.id for r in g.effective_reviews(pkg.evidence.reviews)] == [
        "EVD-reviews-002",
        "EVD-reviews-004",
    ]


def test_g3_unknown_implementer_family_fails_cross_family_check() -> None:
    pkg = golden_package(RiskClass.HIGH)
    pkg.evidence.reviews[0].implementer_model_family = ""
    result = run(GateId.G3, pkg, risk=RiskClass.HIGH)
    assert not result.passed
    assert "implementer model family not recorded" in reasons(result)
    low = golden_package(RiskClass.LOW)
    low.evidence.reviews[0].implementer_model_family = ""
    assert run(GateId.G3, low, risk=RiskClass.LOW).passed


def test_g4_high_findings_are_derived_from_scans() -> None:
    pkg = golden_package(RiskClass.HIGH)
    sec = pkg.evidence.security
    assert sec is not None
    sec.sast = ScanResult(tool="codeql", ran=True, high=7)
    sec.sca = ScanResult(tool="dependency-review", ran=True, high=4)
    object.__setattr__(sec, "high_open", 0)  # hand-edited counter, validator bypassed
    assert sec.high_open == 0
    text = reasons(run(GateId.G4, pkg, risk=RiskClass.HIGH))
    assert "SAST reports 7 high finding(s) (max 0)" in text
    assert "SCA reports 4 high finding(s) (max 0)" in text
    assert "11 open high vulnerability(ies)" in text
    rebuilt = SecurityEvidence.model_validate(sec.model_dump(mode="json"))
    assert rebuilt.high_open == 11 and rebuilt.scan_high == 11


def test_g4_safety_trials_and_undetermined_rate() -> None:
    pkg = golden_package(RiskClass.AI_AGENT)
    sec = pkg.evidence.security
    assert sec is not None
    sec.safety_regression = SafetySummary(
        asr_by_category={"prompt-injection": 0.0},
        complete=True,
        trials=5,
        trials_by_category={"prompt-injection": 5},
        undetermined_rate=1.0,
        undetermined_by_category={"prompt-injection": 1.0},
    )
    text = reasons(run(GateId.G4, pkg, risk=RiskClass.AI_AGENT))
    assert "safety undetermined rate 1.000 exceeds 0.100" in text
    assert "safety undetermined rate for prompt-injection 1.000 exceeds 0.100" in text
    sec.safety_regression = SafetySummary(
        asr_by_category={"prompt-injection": 0.0},
        complete=True,
        trials=1,
        trials_by_category={"prompt-injection": 1},
    )
    text = reasons(run(GateId.G4, pkg, risk=RiskClass.AI_AGENT))
    assert "safety category prompt-injection: 1 trial(s), 5 required" in text
    sec.safety_regression = SafetySummary(asr_by_category={"harm": 0.0}, complete=True)
    text = reasons(run(GateId.G4, pkg, risk=RiskClass.AI_AGENT))
    assert "safety category harm: 0 trial(s), 5 required" in text
    standard = golden_package()
    assert standard.evidence.security is not None
    standard.evidence.security.safety_regression = SafetySummary(
        asr_by_category={"harm": 0.0}, complete=True
    )
    assert run(GateId.G4, standard).passed, run(GateId.G4, standard).reasons


def test_g4_manifest_drift_is_computed_not_self_reported() -> None:
    drift = DriftReport(
        undeclared_tools=["Bash"],
        undeclared_egress_hosts=["exfil.example"],
        drift=True,
        observed_records=3,
    )
    pkg = golden_package(RiskClass.AI_AGENT)
    text = reasons(run(GateId.G4, pkg, risk=RiskClass.AI_AGENT, ctx=context(manifest_drift=drift)))
    assert (
        "drifts from the declared manifest: undeclared tools Bash; "
        "undeclared egress hosts exfil.example" in text
    )
    # a declared manifest is enforced at every depth
    assert "drifts from the declared manifest" in reasons(
        run(GateId.G4, golden_package(), ctx=context(manifest_drift=drift))
    )
    # nothing declared and no validation mandate: not a drift finding
    plain = golden_package()
    assert plain.threat_model is not None
    plain.threat_model.tool_data_manifest = ToolDataManifest()
    assert "drifts from the declared manifest" not in reasons(
        run(GateId.G4, plain, ctx=context(manifest_drift=drift))
    )
    # ai_agent needs the per-call entries and a verified log
    text = reasons(
        run(GateId.G4, pkg, risk=RiskClass.AI_AGENT, ctx=context(audit_entries_source=None))
    )
    assert "no per-call audit entries" in text
    broken = context(audit_integrity=IntegrityReport(ok=False, entries=0, error="hash broken"))
    text = reasons(run(GateId.G4, pkg, risk=RiskClass.AI_AGENT, ctx=broken))
    assert "audit log verification failed: hash broken" in text


def test_g5_policy_budget_is_a_ceiling_evidence_may_only_tighten() -> None:
    pkg = golden_package()
    cost = pkg.evidence.cost
    assert cost is not None
    pkg.evidence.cost = cost.model_copy(
        update={"budget_usd": 1e9, "total_cost_usd": 51.0, "variance": None}
    )
    assert "cost $51.00 exceeds budget $50.00" in reasons(run(GateId.G5, pkg))
    pkg.evidence.cost = cost.model_copy(
        update={"budget_usd": 5.0, "total_cost_usd": 6.0, "variance": None}
    )
    assert "cost $6.00 exceeds budget $5.00" in reasons(run(GateId.G5, pkg))


def test_g5_slo_is_recomputed_from_measurements_and_targets() -> None:
    pkg = golden_package(RiskClass.HIGH)
    perf = pkg.evidence.performance
    assert perf is not None
    pkg.evidence.performance = perf.model_copy(update={"details": {}, "slo_met": True})
    assert "no SLO targets recorded" in reasons(run(GateId.G5, pkg, risk=RiskClass.HIGH))
    pkg.evidence.performance = perf.model_copy(update={"p95_ms": 250.0, "slo_met": True})
    text = reasons(run(GateId.G5, pkg, risk=RiskClass.HIGH))
    assert "p95 latency 250 ms exceeds target 200 ms" in text
    pkg.evidence.performance = perf.model_copy(update={"p95_ms": None, "slo_met": True})
    text = reasons(run(GateId.G5, pkg, risk=RiskClass.HIGH))
    assert "no latency/throughput measurement recorded" in text
    assert "p95 latency target 200 set but p95 latency not measured" in text
    pkg.evidence.performance = perf.model_copy(
        update={
            "details": {"p95_target_ms": 200.0, "throughput_min_rps": 100.0},
            "throughput": 50.0,
        }
    )
    assert "throughput 50 rps below target 100 rps" in reasons(
        run(GateId.G5, pkg, risk=RiskClass.HIGH)
    )


def test_g6_verifies_the_signed_audit_log() -> None:
    pkg = golden_package(RiskClass.HIGH)
    text = reasons(run(GateId.G6, pkg, risk=RiskClass.HIGH, ctx=context(audit_integrity=None)))
    assert "signed audit log not found" in text
    broken = context(audit_integrity=IntegrityReport(ok=False, entries=0, error="HMAC mismatch"))
    text = reasons(run(GateId.G6, pkg, risk=RiskClass.HIGH, ctx=broken))
    assert "audit log verification failed: HMAC mismatch" in text
    short = context(audit_integrity=IntegrityReport(ok=True, entries=5, file_verified=True))
    text = reasons(run(GateId.G6, pkg, risk=RiskClass.HIGH, ctx=short))
    assert "signed audit log holds 5 entries but the evidence records 12" in text


def test_context_discovers_repo_local_signing_key(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AISDLC_SIGNING_KEY", raising=False)
    monkeypatch.delenv("AISDLC_ED25519_PRIVATE_KEY", raising=False)
    root = tmp_path  # type: ignore[assignment]
    pkg = golden_package()
    created = pkgio.create(root, pkg.change_id, pkg.intent)  # type: ignore[arg-type]
    assert g.GateContext.from_package(created).signing_available is False
    key_file = root / ".aisdlc" / "signing.key"  # type: ignore[operator]
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("ab" * 32 + "\n", encoding="utf-8")
    assert g.GateContext.from_package(created).signing_available is True
    assert g.GateContext.from_package(created, hmac_key=b"explicit").signing_available is True
    assert g.GateContext.from_package(created).manifest_drift is not None
    assert g.GateContext.from_package(created).audit_integrity is None
