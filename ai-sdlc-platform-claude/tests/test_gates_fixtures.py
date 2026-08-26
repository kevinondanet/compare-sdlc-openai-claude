"""Shared builders for the gate tests: a synthetic change package that passes every gate
at standard depth, plus helpers to derive failing variants.

Named ``test_gates_fixtures`` so it sits with the gate tests; it defines no tests itself.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from aisdlc.gates.gates import GateContext
from aisdlc.gates.verdict import Approval
from aisdlc.governance.audit import IntegrityReport
from aisdlc.policy import (
    EffectivePolicy,
    default_org_policy,
    default_project_config,
    effective_policy,
)
from aisdlc.schema.models import (
    AdrStatus,
    ArchitectureDecision,
    Assumption,
    AuditEvidence,
    ChangePackage,
    CostEvidence,
    Coverage,
    EvidenceBundle,
    EvidenceStatus,
    Intent,
    Kernel,
    Mitigation,
    Mutation,
    PerformanceEvidence,
    Plan,
    PyritSummary,
    Requirement,
    RequirementKind,
    ReviewEvidence,
    ReviewVerdict,
    RiskClass,
    SafetySummary,
    ScanResult,
    Scenario,
    SecurityEvidence,
    Severity,
    Task,
    TaskStatus,
    TestEvidence,
    Threat,
    ThreatModel,
    ThreatStatus,
    ToolDataManifest,
    Verification,
    Wave,
)
from aisdlc.security.manifest import DriftReport
from aisdlc.testing.portfolio import Layer, LayerRun, PortfolioInputs

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
COMMIT = "abc123def4567890abc123def4567890abc123de"


def policy() -> EffectivePolicy:
    """Default org policy narrowed by the default project config."""
    return effective_policy(default_org_policy(), default_project_config())


def _base(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "commit_sha": COMMIT,
        "environment": "ci",
        "produced_by": "tests",
        "started_at": NOW,
        "finished_at": NOW,
        "report_uri": "file:///reports/x",
        "status": EvidenceStatus.COMPLETE,
    }
    data.update(overrides)
    return data


LAYER_RUNS: tuple[tuple[str, str, str], ...] = (
    ("EVD-tests-004", "pytest -m integration", "layer=integration"),
    ("EVD-tests-005", "pytest tests/contract", "layer=contract"),
    ("EVD-tests-006", "playwright test", "layer=e2e"),
    ("EVD-tests-007", "lint-imports", "layer=architecture"),
    ("EVD-tests-008", "pytest -m property", "layer=property"),
    ("EVD-tests-009", "k6 run perf.js", "layer=performance"),
    ("EVD-tests-010", "promptfoo eval", "layer=prompt_evals"),
    ("EVD-tests-011", "lychee docs/", "links"),
)
"""Portfolio layer runs (and the docs_only link check) the golden package carries."""

TEST_EVIDENCE_IDS: tuple[str, ...] = (
    "EVD-tests-001",
    "EVD-tests-002",
    "EVD-tests-003",
    *(row[0] for row in LAYER_RUNS),
)


def unit_test_evidence() -> list[TestEvidence]:
    """Unit run with coverage + mutation, lint, types, one run per portfolio layer, links."""
    records = [
        TestEvidence(
            id="EVD-tests-001",
            command="pytest -q",
            exit_code=0,
            passed=42,
            coverage=Coverage(lines=85.0, branches=75.0, diff_lines=95.0),
            mutation=Mutation(score=0.7, scope=["src/app"], excluded=["src/app/cli"]),
            **_base(),  # type: ignore[arg-type]
        ),
        TestEvidence(
            id="EVD-tests-002",
            command="ruff check .",
            exit_code=0,
            **_base(produced_by="lint"),  # type: ignore[arg-type]
        ),
        TestEvidence(
            id="EVD-tests-003",
            command="mypy",
            exit_code=0,
            **_base(produced_by="types"),  # type: ignore[arg-type]
        ),
    ]
    for evidence_id, command, tag in LAYER_RUNS:
        records.append(
            TestEvidence(
                id=evidence_id,
                command=command,
                exit_code=0,
                passed=3,
                **_base(produced_by=tag),  # type: ignore[arg-type]
            )
        )
    return records


def portfolio_inputs() -> PortfolioInputs:
    """Completeness metrics the bundle cannot derive (as ``aisdlc test portfolio`` persists)."""
    return PortfolioInputs(
        runs=[
            LayerRun(
                layer=Layer.E2E,
                passed=3,
                metrics={
                    "acceptance_criteria_with_evidence": 100.0,
                    "critical_journeys_e2e": 100.0,
                },
            )
        ]
    )


def review_evidence() -> ReviewEvidence:
    """An approved cross-family review."""
    return ReviewEvidence(
        id="EVD-reviews-001",
        reviewer_model_family="openai",
        implementer_model_family="anthropic",
        verdict=ReviewVerdict.APPROVED,
        round=1,
        scope=["src/app/login.py"],
        **_base(produced_by="reviewer"),  # type: ignore[arg-type]
    )


def security_evidence() -> SecurityEvidence:
    """Clean scans, SBOM + provenance, complete PyRIT + safety runs, no drift."""
    ran = ScanResult(tool="x", ran=True)
    return SecurityEvidence(
        id="EVD-security-001",
        sast=ran,
        sca=ran,
        secrets=ran,
        sbom_present=True,
        provenance_present=True,
        pyrit=PyritSummary(
            campaign_id="camp-1",
            asr=0.0,
            undetermined_rate=0.0,
            complete=True,
            baseline_delta=0.0,
            trials=10,
        ),
        safety_regression=SafetySummary(
            asr_by_category={"harm": 0.0},
            complete=True,
            trials=10,
            trials_by_category={"harm": 10},
        ),
        **_base(produced_by="security"),  # type: ignore[arg-type]
    )


def evidence() -> EvidenceBundle:
    """Complete, admissible evidence for every kind."""
    return EvidenceBundle(
        tests=unit_test_evidence(),
        reviews=[review_evidence()],
        security=security_evidence(),
        performance=PerformanceEvidence(
            id="EVD-performance-001",
            p95_ms=120.0,
            slo_met=True,
            details={"p95_target_ms": 200.0},
            **_base(produced_by="perf"),  # type: ignore[arg-type]
        ),
        cost=CostEvidence(
            id="EVD-cost-001",
            total_cost_usd=10.0,
            budget_usd=50.0,
            **_base(produced_by="ledger"),  # type: ignore[arg-type]
        ),
        audit=AuditEvidence(
            id="EVD-audit-001",
            entries=12,
            integrity_ok=True,
            privileged_calls=2,
            **_base(produced_by="agt"),  # type: ignore[arg-type]
        ),
    )


def golden_package(risk: RiskClass = RiskClass.STANDARD) -> ChangePackage:
    """A package that passes G0..G6 at standard depth (and deep with the fixture context)."""
    return ChangePackage(
        intent=Intent(
            id="CHG-login-mfa",
            title="Login MFA",
            owner="kevin",
            risk_class=risk,
            kernel=Kernel(
                why="Accounts need a second factor at login.",
                capabilities=["TOTP second factor at login"],
                constraints=["No SMS"],
                non_goals=["Passkeys"],
                success_signal="MFA enrolment rate above 90 percent within 30 days.",
            ),
        ),
        requirements=[
            Requirement(
                id="REQ-001",
                text="The system SHALL require a TOTP code after a valid password.",
                scenarios=[
                    Scenario(
                        id="SCN-001-01",
                        when="a user submits a valid password",
                        then="the system prompts for a TOTP code",
                    )
                ],
            ),
            Requirement(
                id="REQ-002",
                text="The system SHALL verify a TOTP code within 200 ms at p95.",
                kind=RequirementKind.NON_FUNCTIONAL,
                scenarios=[
                    Scenario(
                        id="SCN-002-01",
                        when="a TOTP code is submitted",
                        then="the verification completes within 200 ms at p95",
                    )
                ],
            ),
        ],
        assumptions=[Assumption(id="ASM-001", text="Users own a TOTP-capable device.")],
        decisions=[
            ArchitectureDecision(id="ADR-0001", title="Use TOTP", status=AdrStatus.ACCEPTED)
        ],
        threat_model=ThreatModel(
            assets=["credentials"],
            threats=[
                Threat(
                    id="THR-001",
                    title="TOTP brute force",
                    severity=Severity.HIGH,
                    status=ThreatStatus.MITIGATED,
                    mitigation_ids=["MIT-1"],
                )
            ],
            mitigations=[Mitigation(id="MIT-1", description="rate limit", threat_ids=["THR-001"])],
            tool_data_manifest=ToolDataManifest(tools=["Bash"], data_sources=["users-db"]),
        ),
        plan=Plan(
            summary="one wave",
            waves=[Wave(index=0, task_ids=["TASK-001"], checkpoint=True)],
            approved_by="kevin",
        ),
        tasks=[
            Task(
                id="TASK-001",
                title="Implement TOTP check",
                requirement_ids=["REQ-001", "REQ-002"],
                verification=Verification(command="pytest -q tests/test_totp.py"),
                status=TaskStatus.DONE,
                wave=0,
                files=["src/app/login.py"],
            )
        ],
        evidence=evidence(),
    )


def context(**overrides: object) -> GateContext:
    """A context under which the golden package passes every gate.

    Pins the on-disk facts the runner would otherwise gather: no manifest drift, audit
    entries present, the signed audit log verified with the recorded entry count, and the
    portfolio completeness metrics.
    """
    ctx = GateContext(
        now=NOW,
        head_commit=COMMIT,
        current_fingerprint="fp",
        stored_fingerprint="fp",
        approvals=[
            Approval(role="owner", approver="kevin", approved_at=NOW),
            Approval(role="security", approver="sec", approved_at=NOW),
        ],
        signing_available=True,
        manifest_drift=DriftReport(observed_records=2),
        audit_entries_source=Path("evidence/audit-entries.json"),
        audit_integrity=IntegrityReport(ok=True, entries=12, file_verified=True),
        portfolio_inputs=portfolio_inputs(),
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx
