"""Fixture packages for the intake tests: one clean spec, one ambiguous spec."""

from __future__ import annotations

from aisdlc.schema.models import (
    ArchitectureDecision,
    Assumption,
    ChangePackage,
    Intent,
    Interface,
    Kernel,
    Mitigation,
    OpenQuestion,
    Plan,
    Priority,
    QuestionStatus,
    Requirement,
    RequirementKind,
    RiskClass,
    Scenario,
    Severity,
    Task,
    Threat,
    ThreatModel,
    ToolDataManifest,
    Verification,
    Wave,
)


def clean_package() -> ChangePackage:
    """A well-formed specification that should be G0-ready."""
    intent = Intent(
        id="CHG-password-reset",
        title="Self-service password reset",
        owner="kevin",
        risk_class=RiskClass.STANDARD,
        kernel=Kernel(
            why="Staff wait a day for the help desk to reset a forgotten password.",
            capabilities=["Employees reset their own password from the login page"],
            constraints=["Must use the existing identity provider"],
            non_goals=["Changing the password policy"],
            success_signal="Reset tickets drop from 40 to under 8 per week within 3 months",
        ),
    )
    requirements = [
        Requirement(
            id="REQ-001",
            text="The system SHALL allow employees to reset their password from the login page",
            scenarios=[
                Scenario(
                    id="SCN-001-01",
                    when="an employee requests a reset from the login page",
                    then="a single-use reset link is emailed to the employee",
                )
            ],
            rationale="Core capability of the change.",
        ),
        Requirement(
            id="REQ-002",
            text="WHEN a reset link is older than 15 minutes, the system SHALL reject it",
            scenarios=[
                Scenario(
                    id="SCN-002-01",
                    given="a reset link issued 16 minutes ago",
                    when="the employee opens the link",
                    then="the system rejects it and offers a new request",
                )
            ],
            tags=["security"],
        ),
        Requirement(
            id="REQ-003",
            text="The system SHALL complete a password reset within 5 minutes at p95",
            kind=RequirementKind.NON_FUNCTIONAL,
            scenarios=[
                Scenario(
                    id="SCN-003-01",
                    when="100 employees reset their password in one hour",
                    then="the p95 end-to-end duration is below 5 minutes",
                )
            ],
            tags=["performance"],
        ),
        Requirement(
            id="REQ-004",
            text="The system SHALL NOT reveal whether an email address has an account",
            priority=Priority.SHOULD,
            scenarios=[
                Scenario(
                    id="SCN-004-01",
                    raw="WHEN an unknown email address requests a reset THEN the same "
                    "confirmation message is shown",
                )
            ],
            tags=["security"],
        ),
    ]
    return ChangePackage(
        intent=intent,
        requirements=requirements,
        assumptions=[
            Assumption(
                id="ASM-001",
                text="The existing identity provider exposes a password reset API.",
                owner="kevin",
            )
        ],
        open_questions=[
            OpenQuestion(
                id="OQ-001",
                question="Do contractors get self-service reset?",
                status=QuestionStatus.RESOLVED,
                decision="Yes, every account in the identity provider.",
            )
        ],
        threat_model=ThreatModel(),
        plan=Plan(),
    )


def ambiguous_package() -> ChangePackage:
    """A draft full of placeholders, gaps, conflicts and drift."""
    intent = Intent(
        id="CHG-reporting-tbd",
        title="Faster reporting",
        owner=None,
        kernel=Kernel(why="Login is slow and reports take ages. TBD"),
    )
    requirements = [
        Requirement(
            id="REQ-001",
            text="The system SHALL generate reports fast [NEEDS CLARIFICATION]",
        ),
        Requirement(
            id="REQ-002",
            text="The system SHALL export a report within 200 ms",
            scenarios=[
                Scenario(
                    id="SCN-002-01",
                    when="a user exports a report",
                    then="the report is exported within 500 ms",
                )
            ],
        ),
        Requirement(
            id="REQ-003",
            text="The system SHALL send some notifications through SSO?",
            priority=Priority.SHOULD,
            scenarios=[
                Scenario(id="SCN-003-01", when="a report is ready", then="a notification is sent")
            ],
        ),
        Requirement(
            id="REQ-004",
            text="The system SHALL NOT export a report",
            scenarios=[Scenario(id="SCN-004-01", when="export is requested", then="it is refused")],
        ),
        Requirement(
            id="REQ-005",
            text="Users should be able to log in quickly",
            scenarios=[Scenario(id="SCN-005-01", when="a user logs in", then="it is quick")],
        ),
        Requirement(
            id="REQ-006",
            text="The system SHALL integrate with the existing data warehouse",
        ),
    ]
    return ChangePackage(
        intent=intent,
        requirements=requirements,
        open_questions=[
            OpenQuestion(id="OQ-001", question="Which report formats are required?", blocking=True),
            OpenQuestion(id="OQ-002", question="Should exports be scheduled?", blocking=False),
        ],
        threat_model=ThreatModel(),
        plan=Plan(),
    )


def planned_package() -> ChangePackage:
    """The clean package with architecture, plan, tasks and an ai_agent threat model."""
    pkg = clean_package()
    pkg.intent.risk_class = RiskClass.AI_AGENT
    pkg.decisions = [
        ArchitectureDecision(
            id="ADR-0001",
            title="Use the identity provider reset API",
            context="REQ-001 and REQ-009 need a reset flow.",
            decision="Call the provider API described in IFC-001.",
        )
    ]
    pkg.interfaces = [
        Interface(id="IFC-001", name="Identity provider reset API", description="See ADR-0001."),
        Interface(id="IFC-002", name="Audit sink", description="Unused so far."),
    ]
    pkg.threat_model = ThreatModel(
        assets=["password reset links"],
        threats=[
            Threat(
                id="THR-001",
                title="Reset link interception via email tool",
                severity=Severity.HIGH,
                mitigation_ids=["MIT-001", "MIT-999"],
            )
        ],
        mitigations=[Mitigation(id="MIT-001", description="Single-use, 15 minute links")],
        tool_data_manifest=ToolDataManifest(
            tools=["email tool", "shell"], data_sources=["hr database"], network_egress=[]
        ),
    )
    pkg.tasks = [
        Task(
            id="TASK-001",
            title="Reset endpoint",
            description="Implements SCN-001-01 and SCN-002-01",
            requirement_ids=["REQ-001", "REQ-002"],
            verification=Verification(command="pytest tests/test_reset.py"),
        ),
        Task(
            id="TASK-002",
            title="Load test",
            requirement_ids=["REQ-003", "REQ-042"],
            depends_on=["TASK-003"],
            verification=Verification(command="pytest tests/test_perf.py"),
        ),
        Task(
            id="TASK-003",
            title="Untraced task",
            verification=Verification(command="true"),
        ),
    ]
    pkg.plan = Plan(
        waves=[
            Wave(index=0, task_ids=["TASK-001", "TASK-002"]),
            Wave(index=1, task_ids=["TASK-003", "TASK-004"]),
        ]
    )
    return pkg
