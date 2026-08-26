"""Tests for OpenSpec import/export."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.adapters import openspec
from aisdlc.schema import grammar
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    ChangePackage,
    Intent,
    Kernel,
    Plan,
    Priority,
    Requirement,
    RequirementKind,
    Scenario,
    Task,
    TaskStatus,
    Verification,
    Wave,
)

PROPOSAL = """# Change: Add login MFA

## Why
Accounts are being taken over with stolen passwords.

## What Changes
- Add TOTP enrolment
- Require a second factor on new devices

## Impact
- Affected specs: auth, billing
- Affected code: src/auth

## Non-Goals
- Hardware keys

## Assumptions
- Users have a phone

## Open Questions
- [ ] Which TOTP library? (blocking)
- [x] SMS fallback? — no, TOTP only
"""

TASKS = """# Tasks

## 1. Implementation
- [x] 1.1 Add TOTP secret model
  - verify: `pytest tests/test_totp.py -q` (exit 0)
  - files: `src/auth/totp.py`
- [ ] 1.2 Enrolment endpoint
  - depends: 1.1

## 2. Rollout
- [ ] 2.1 Feature flag
Some free-form note that is not a task.
"""

AUTH_SPEC = """# auth Specification

## Purpose
Authentication capability.

## ADDED Requirements

### Requirement: TOTP enrolment
The system SHALL let a user enrol a TOTP authenticator.

#### Scenario: Successful enrolment
- **GIVEN** a logged-in user without MFA
- **WHEN** the user scans the QR code and enters a valid code
- **THEN** MFA is enabled
- **AND** a recovery code set is shown

#### Scenario: Invalid code
- **WHEN** the code is invalid
- **THEN** enrolment is rejected

## MODIFIED Requirements

### Requirement: Login
The system MUST require the second factor on unrecognised devices.

#### Scenario: New device
- **WHEN** a user logs in from a new device
- **THEN** a TOTP challenge is shown

## RENAMED Requirements
- FROM: `### Requirement: Sign in`
- TO: `### Requirement: Login`
"""

BILLING_SPEC = """## Requirements

### requirement: Invoice note
The system SHALL show an MFA note on the invoice.

#### scenario: note shown
WHEN an invoice is rendered
THEN the MFA note is present

#### Scenario: Free text only
Given/When/Then written as prose only.
"""


@pytest.fixture
def openspec_dir(tmp_path: Path) -> Path:
    change = tmp_path / "openspec" / "changes" / "add-login-mfa"
    (change / "specs" / "auth").mkdir(parents=True)
    (change / "specs" / "billing").mkdir(parents=True)
    (change / "proposal.md").write_text(PROPOSAL)
    (change / "tasks.md").write_text(TASKS)
    (change / "design.md").write_text("# Design\n\nUse pyotp.\n")
    (change / "README.md").write_text("not part of openspec\n")
    (change / "specs" / "auth" / "spec.md").write_text(AUTH_SPEC)
    (change / "specs" / "billing" / "spec.md").write_text(BILLING_SPEC)
    return change


def test_import_maps_proposal_specs_and_tasks(openspec_dir: Path) -> None:
    result = openspec.import_change(openspec_dir, owner="kev")
    pkg = result.package
    assert pkg.change_id == "CHG-add-login-mfa"
    assert pkg.intent.title == "Add login MFA"
    assert pkg.intent.owner == "kev"
    assert pkg.intent.kernel.why.startswith("Accounts are being taken over")
    assert pkg.intent.kernel.capabilities == [
        "Add TOTP enrolment",
        "Require a second factor on new devices",
    ]
    assert pkg.intent.kernel.non_goals == ["Hardware keys"]
    assert [a.text for a in pkg.assumptions] == ["Users have a phone"]
    assert [(q.question, q.blocking, q.status.value) for q in pkg.open_questions] == [
        ("Which TOTP library?", True, "open"),
        ("SMS fallback?", False, "resolved"),
    ]
    assert pkg.open_questions[1].decision == "no, TOTP only"

    assert [r.id for r in pkg.requirements] == ["REQ-001", "REQ-002", "REQ-003"]
    totp = pkg.requirements[0]
    assert totp.text == "The system SHALL let a user enrol a TOTP authenticator."
    assert "capability:auth" in totp.tags and "openspec:added" in totp.tags
    assert "name:TOTP enrolment" in totp.tags
    assert [s.id for s in totp.scenarios] == ["SCN-001-01", "SCN-001-02"]
    first = totp.scenarios[0]
    assert first.name == "Successful enrolment"
    assert first.given == "a logged-in user without MFA"
    assert first.when == "the user scans the QR code and enters a valid code"
    assert first.then == "MFA is enabled AND a recovery code set is shown"
    assert first.raw.startswith("- **GIVEN**")
    login = pkg.requirements[1]
    assert "openspec:modified" in login.tags and login.text.startswith("The system MUST")
    billing = pkg.requirements[2]
    assert "capability:billing" in billing.tags
    assert billing.scenarios[0].when == "an invoice is rendered"
    assert billing.scenarios[0].then == "the MFA note is present"
    prose = billing.scenarios[1]
    assert prose.when is None and prose.raw == "Given/When/Then written as prose only."

    assert [t.id for t in pkg.tasks] == ["TASK-001", "TASK-002", "TASK-003"]
    t1, t2, t3 = pkg.tasks
    assert t1.status is TaskStatus.DONE and t1.verification is not None
    assert t1.verification.command == "pytest tests/test_totp.py -q"
    assert t1.files == ["src/auth/totp.py"]
    assert t2.depends_on == ["TASK-001"] and t2.wave == 0
    assert t3.wave == 1 and t3.description == "Rollout"
    assert pkg.plan is not None
    assert [w.task_ids for w in pkg.plan.waves] == [["TASK-001", "TASK-002"], ["TASK-003"]]

    assert result.id_map["TOTP enrolment"] == "REQ-001"
    assert result.id_map["1.2"] == "TASK-002"
    dispositions = {(u.source, u.location): u.disposition for u in result.unmapped}
    assert dispositions[("proposal.md", "Impact")] == "kept_in_body"
    assert dispositions[("specs/auth/spec.md", "Purpose")] == "kept_in_body"
    assert dispositions[("specs/auth/spec.md", "RENAMED Requirements")] == "kept_in_body"
    assert dispositions[("tasks.md", "line 12")] == "kept_in_body"
    assert dispositions[("README.md", "(file)")] == "not_imported"
    assert dispositions[("design.md", "(file)")] == "kept_in_body"
    assert "## Impact" in pkg.bodies["intent.md"]
    assert "Purpose" in pkg.bodies["requirements.md"] and "RENAMED" in pkg.bodies["requirements.md"]
    assert "free-form note" in pkg.bodies["tasks.md"]
    assert pkg.bodies["architecture/context.md"].startswith("# Design")


def test_imported_package_saves_loads_and_validates(openspec_dir: Path, tmp_path: Path) -> None:
    result = openspec.import_change(openspec_dir, owner="kev")
    pkg = result.package
    created = pkgio.create(tmp_path, pkg.change_id, pkg.intent)
    pkg.bodies = {**created.bodies, **pkg.bodies}
    pkg.threat_model = created.threat_model
    pkg.save(created.root)
    loaded = pkgio.load(created.root)
    assert loaded.requirements == pkg.requirements
    assert loaded.tasks == pkg.tasks
    assert "## Impact" in loaded.bodies["intent.md"]
    codes = {i.code for i in grammar.validate_package(loaded) if i.severity.value == "error"}
    # imported requirements are normative and have scenarios; only draft-task issues remain
    assert not codes & {"REQ_NO_MODAL", "REQ_NO_SCENARIO", "SCN_MALFORMED"}


def test_round_trip_openspec_to_package_to_openspec(openspec_dir: Path, tmp_path: Path) -> None:
    first = openspec.import_change(openspec_dir, owner="kev")
    out = tmp_path / "export" / "add-login-mfa"
    exported = openspec.export_change(first.package, out)
    names = {p.relative_to(out).as_posix() for p in exported.files}
    assert names == {
        "proposal.md",
        "tasks.md",
        "design.md",
        "specs/auth/spec.md",
        "specs/billing/spec.md",
    }
    auth = (out / "specs/auth/spec.md").read_text()
    assert "## ADDED Requirements" in auth and "## MODIFIED Requirements" in auth
    assert "### Requirement: TOTP enrolment" in auth
    assert "<!-- aisdlc-id: REQ-001 kind=functional priority=must -->" in auth
    assert "<!-- aisdlc-id: SCN-001-01 -->" in auth
    assert "## Purpose" in auth  # preserved prose
    second = openspec.import_change(out)
    a, b = first.package, second.package
    assert b.change_id == a.change_id and b.intent.owner == "kev"
    assert b.intent.kernel == a.intent.kernel
    assert [r.id for r in b.requirements] == [r.id for r in a.requirements]
    for ra, rb in zip(a.requirements, b.requirements, strict=True):
        assert rb.text == ra.text and rb.priority == ra.priority and rb.kind == ra.kind
        assert [s.id for s in rb.scenarios] == [s.id for s in ra.scenarios]
        for sa, sb in zip(ra.scenarios, rb.scenarios, strict=True):
            assert (sb.name, sb.given, sb.when, sb.then) == (sa.name, sa.given, sa.when, sa.then)
            assert sb.render() == sa.render()
    assert [(t.id, t.title, t.status, t.depends_on, t.files) for t in b.tasks] == [
        (t.id, t.title, t.status, t.depends_on, t.files) for t in a.tasks
    ]
    assert b.tasks[0].verification == a.tasks[0].verification
    assert b.plan is not None and a.plan is not None
    assert [w.task_ids for w in b.plan.waves] == [w.task_ids for w in a.plan.waves]
    assert [x.text for x in b.assumptions] == [x.text for x in a.assumptions]
    assert [(q.id, q.question, q.blocking, q.status) for q in b.open_questions] == [
        (q.id, q.question, q.blocking, q.status) for q in a.open_questions
    ]
    assert "## Impact" in b.bodies["intent.md"]


def _package() -> ChangePackage:
    reqs = [
        Requirement(
            id="REQ-003",
            text="WHEN a request arrives, the gateway SHALL authenticate it.",
            kind=RequirementKind.NON_FUNCTIONAL,
            priority=Priority.SHOULD,
            scenarios=[
                Scenario(
                    id="SCN-003-01",
                    name="Valid token",
                    given="a valid token",
                    when="a request arrives",
                    then="it is accepted",
                ),
                Scenario(
                    id="SCN-003-02",
                    name="Prose",
                    raw="WHEN the token is expired THEN 401 is returned",
                ),
            ],
            tags=["capability:gateway", "name:Authenticate requests"],
        ),
        Requirement(
            id="REQ-007",
            text="The system MUST log every denial.",
            scenarios=[
                Scenario(id="SCN-007-01", when="a request is denied", then="an audit entry exists")
            ],
        ),
    ]
    tasks = [
        Task(
            id="TASK-001",
            title="Add auth middleware",
            requirement_ids=["REQ-003"],
            files=["src/gw/auth.py", "tests/test_auth.py"],
            verification=Verification(
                command="pytest -q tests/test_auth.py",
                expect_exit_code=0,
                expect_output_regex="passed",
            ),
            status=TaskStatus.DONE,
            wave=0,
        ),
        Task(
            id="TASK-002",
            title="Audit denials",
            requirement_ids=["REQ-007"],
            depends_on=["TASK-001"],
            status=TaskStatus.BLOCKED,
            wave=1,
        ),
    ]
    return ChangePackage(
        intent=Intent(
            id="CHG-gateway-auth",
            title="Gateway auth",
            owner="kev",
            kernel=Kernel(
                why="Unauthenticated traffic reaches services",
                capabilities=["authn"],
                non_goals=["authz"],
                success_signal="0 unauthenticated hits",
            ),
        ),
        requirements=reqs,
        tasks=tasks,
        plan=Plan(
            waves=[
                Wave(index=0, task_ids=["TASK-001"], checkpoint=True),
                Wave(index=1, task_ids=["TASK-002"]),
            ]
        ),
    )


def test_round_trip_package_to_openspec_to_package(tmp_path: Path) -> None:
    pkg = _package()
    out = tmp_path / "gateway-auth"
    exported = openspec.export_change(pkg, out)
    assert not exported.unmapped
    spec_files = sorted(
        p.relative_to(out).as_posix() for p in exported.files if p.name == "spec.md"
    )
    assert spec_files == ["specs/gateway-auth/spec.md", "specs/gateway/spec.md"]
    tasks_md = (out / "tasks.md").read_text()
    assert "- [x] 1.1 Add auth middleware <!-- aisdlc-id: TASK-001 -->" in tasks_md
    assert "  - verify: `pytest -q tests/test_auth.py` (exit 0) /passed/" in tasks_md
    assert "  - status: blocked" in tasks_md
    assert "(checkpoint)" in tasks_md
    proposal = (out / "proposal.md").read_text()
    assert proposal.startswith("---\n") and "owner: kev" in proposal
    back = openspec.import_change(out).package
    assert back.change_id == "CHG-gateway-auth" and back.intent.owner == "kev"
    assert back.intent.kernel == pkg.intent.kernel
    assert [r.id for r in back.requirements] == ["REQ-003", "REQ-007"]
    r3 = back.requirement("REQ-003")
    assert r3 is not None
    assert r3.kind is RequirementKind.NON_FUNCTIONAL and r3.priority is Priority.SHOULD
    assert r3.text == pkg.requirements[0].text
    assert "name:Authenticate requests" in r3.tags and "capability:gateway" in r3.tags
    assert [s.id for s in r3.scenarios] == ["SCN-003-01", "SCN-003-02"]
    assert r3.scenarios[0].given == "a valid token" and r3.scenarios[0].then == "it is accepted"
    assert r3.scenarios[1].render() == "WHEN the token is expired THEN 401 is returned"
    r7 = back.requirement("REQ-007")
    assert r7 is not None and r7.scenarios[0].when == "a request is denied"
    t1 = back.task("TASK-001")
    assert t1 is not None and t1.verification == pkg.tasks[0].verification
    assert t1.files == pkg.tasks[0].files and t1.requirement_ids == ["REQ-003"]
    t2 = back.task("TASK-002")
    assert t2 is not None and t2.status is TaskStatus.BLOCKED and t2.depends_on == ["TASK-001"]
    assert back.plan is not None
    assert [w.task_ids for w in back.plan.waves] == [["TASK-001"], ["TASK-002"]]


def test_export_reports_unmapped_evidence_and_verdict(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from aisdlc.schema.models import EvidenceKind, EvidenceStatus, FinalVerdict, TestEvidence

    pkg = _package()
    pkg.evidence.tests.append(
        TestEvidence(
            id="EVD-tests-001",
            kind=EvidenceKind.TESTS,
            commit_sha="abc",
            environment="ci",
            produced_by="pytest",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            report_uri="file://x",
            status=EvidenceStatus.COMPLETE,
            command="pytest",
            exit_code=0,
            passed=1,
            failed=0,
            skipped=0,
        )
    )
    pkg.final_verdict = FinalVerdict(change_id=pkg.change_id, overall=False)
    pkg.bodies["plan.md"] = "Hand-written plan notes.\n"
    result = openspec.export_change(pkg, tmp_path / "out")
    kinds = {(u.kind, u.disposition) for u in result.unmapped}
    assert ("evidence", "not_exported") in kinds
    assert ("verdict", "not_exported") in kinds
    assert ("prose", "not_exported") in kinds


def test_tolerant_parsing_and_id_reassignment() -> None:
    text = """## Requirements

### Requirement: REQ-005 Dup
The system SHALL a.

#### Scenario: SCN-005-01 first
- WHEN: x
- THEN: y

### Requirement: Also five
<!-- aisdlc-id: REQ-005 -->
The system SHALL b.

#### Scenario: orphan-check
<!-- aisdlc-id: SCN-009-01 -->
- **When** p
- **Then** q

#### Scenario: empty

### Requirement: No scenario
The system SHALL c.
"""
    reqs, unmapped = openspec.parse_spec(text, capability="x")
    assert [r.id for r in reqs] == ["REQ-005", "REQ-005", None]
    assert reqs[0].name == "Dup" and reqs[0].scenarios[0].id == "SCN-005-01"
    assert reqs[0].scenarios[0].when == "x" and reqs[0].scenarios[0].then == "y"
    assert reqs[1].scenarios[0].id == "SCN-009-01"
    canonical, warnings, id_map = openspec.to_requirements(reqs)
    assert [r.id for r in canonical] == ["REQ-005", "REQ-006", "REQ-007"]
    assert any("REQ-005" in w and "reassigned" in w for w in warnings)
    assert canonical[1].scenarios[0].id == "SCN-006-01"  # foreign scenario id reassigned
    assert canonical[1].scenarios[1].raw == "empty"  # empty scenario keeps its name as text
    assert canonical[2].scenarios == []
    assert id_map["No scenario"] == "REQ-007"
    orphan, extra = openspec.parse_spec(
        "## ADDED Requirements\n\n#### Scenario: lost\n- WHEN a\n- THEN b\n"
    )
    assert orphan == [] and extra[0].kind == "scenario" and extra[0].disposition == "skipped"


def test_import_rejects_non_openspec_dirs(tmp_path: Path) -> None:
    with pytest.raises(openspec.OpenSpecError):
        openspec.import_change(tmp_path / "missing")
    (tmp_path / "empty").mkdir()
    with pytest.raises(openspec.OpenSpecError):
        openspec.import_change(tmp_path / "empty")


def test_import_change_id_and_title_fallbacks(tmp_path: Path) -> None:
    change = tmp_path / "CHG-explicit-id"
    change.mkdir()
    (change / "proposal.md").write_text("## Why\nBecause.\n")
    pkg = openspec.import_change(change).package
    assert pkg.change_id == "CHG-explicit-id" and pkg.intent.title == "Explicit id"
    other = tmp_path / "Weird Name!"
    other.mkdir()
    (other / "proposal.md").write_text("# Proposal: Better name CHG-ignored\n\n## Why\nx\n")
    pkg = openspec.import_change(other, change_id="CHG-forced").package
    assert pkg.change_id == "CHG-forced" and pkg.intent.title == "Better name"
