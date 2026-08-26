# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the canonical AI-SDLC change contract."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_sre.sdlc.canonical import DuplicateJSONKeyError
from agent_sre.sdlc.change_contract import (
    AcceptanceScenario,
    Architecture,
    ArchitectureDecision,
    Assumption,
    AssumptionStatus,
    ChangeArtifactStore,
    ChangePackage,
    ConcurrentChangeError,
    Intent,
    InterfaceContract,
    OpenQuestion,
    QuestionStatus,
    Requirement,
    RequirementKind,
    RiskClass,
    Task,
    ThreatModel,
)


def make_change(*, risk_class: RiskClass = RiskClass.STANDARD) -> ChangePackage:
    """Build a complete, traceable change contract for tests."""
    timestamp = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    return ChangePackage(
        change_id="CHG-001",
        title="Governed email agent",
        application="email-agent",
        repository="contoso/email-agent",
        source_revision="abcdef123456",
        owner="team-ai-platform",
        risk_class=risk_class,
        intent=Intent(
            goal="Prevent external email side effects without an approved policy decision.",
            non_goals=["Replace the mail delivery provider."],
            success_signals=["All external-recipient adversarial trials are blocked."],
        ),
        assumptions=[
            Assumption(
                assumption_id="ASM-001",
                text="The host mediates every send_email call.",
                status=AssumptionStatus.VALIDATED,
                validation_method="pytest tests/test_host_mediation.py",
            )
        ],
        open_questions=[
            OpenQuestion(
                question_id="QST-001",
                text="Who owns the recipient allowlist?",
                owner="security",
                status=QuestionStatus.ANSWERED,
                answer="The messaging security team.",
            )
        ],
        requirements=[
            Requirement(
                requirement_id="REQ-001",
                title="Block external recipient",
                statement="The host MUST block messages to external recipients.",
                kind=RequirementKind.FUNCTIONAL,
                acceptance_scenario_ids=["SCN-001"],
                architecture_decision_ids=["ADR-001"],
                task_ids=["TASK-001"],
                verification="pytest tests/test_email_policy.py",
            ),
            Requirement(
                requirement_id="REQ-002",
                title="Audit latency",
                statement="The policy path SHALL keep p95 latency below 50 ms.",
                kind=RequirementKind.NON_FUNCTIONAL,
                acceptance_scenario_ids=["SCN-002"],
                architecture_decision_ids=["ADR-001"],
                task_ids=["TASK-002"],
                verification="pytest tests/test_email_performance.py",
            ),
        ],
        scenarios=[
            AcceptanceScenario(
                scenario_id="SCN-001",
                title="External recipient is denied",
                requirement_ids=["REQ-001"],
                when="an agent requests send_email to partner@example.net",
                then="the policy returns deny and the mail function is not invoked",
            ),
            AcceptanceScenario(
                scenario_id="SCN-002",
                title="Policy latency remains bounded",
                requirement_ids=["REQ-002"],
                when="the policy evaluates 100 representative tool calls",
                then="p95 latency is below 50 ms",
            ),
        ],
        architecture=Architecture(
            context="The host owns side effects and evaluates ACS before invoking tools.",
            non_functional_requirements=["p95 policy latency below 50 ms"],
            decisions=[
                ArchitectureDecision(
                    decision_id="ADR-001",
                    title="Mediate email in the host",
                    status="accepted",
                    context="The model cannot be trusted to self-enforce tool policy.",
                    decision="Evaluate send_email at the pre-tool intervention point.",
                    consequences=["Denied calls never reach the side-effect function."],
                    requirement_ids=["REQ-001", "REQ-002"],
                )
            ],
            interfaces=[
                InterfaceContract(
                    interface_id="IFC-001",
                    name="send_email",
                    version="1",
                    kind="tool",
                    compatibility="backward",
                    specification={"required": ["to", "body"]},
                    requirement_ids=["REQ-001"],
                )
            ],
            threat_model=ThreatModel(
                assets=["customer messages"],
                trust_boundaries=["model-to-host tool boundary"],
                threats=["prompt-induced exfiltration"],
                controls=["ACS pre-tool deny policy"],
                residual_risks=["mail provider outage"],
                privileged_tools=(
                    ["send_email"] if risk_class is RiskClass.TOOL_ENABLED_AGENT else []
                ),
                data_classifications=["confidential"],
            ),
        ),
        tasks=[
            Task(
                task_id="TASK-001",
                title="Implement host policy mediation",
                requirement_ids=["REQ-001"],
                verification_command="pytest tests/test_email_policy.py",
                owner_role="implementation",
                risk_tier=3,
            ),
            Task(
                task_id="TASK-002",
                title="Measure policy latency",
                requirement_ids=["REQ-002"],
                depends_on=["TASK-001"],
                verification_command="pytest tests/test_email_performance.py",
                owner_role="verification",
                risk_tier=2,
            ),
        ],
        implementation_model_family="family-a",
        created_at=timestamp,
        updated_at=timestamp,
    )


def test_contract_is_deterministic_and_traceable() -> None:
    first = make_change()
    second = ChangePackage.model_validate_json(first.canonical_bytes())

    assert first.digest == second.digest
    assert first.contract_issues() == []
    assert first.dependency_waves() == [["TASK-001"], ["TASK-002"]]
    with pytest.raises(AttributeError):
        first.requirements.append(first.requirements[0])  # type: ignore[attr-defined]


def test_contract_collects_normative_reference_and_ambiguity_issues() -> None:
    change = make_change()
    payload = change.model_dump(mode="json")
    payload["requirements"][0]["statement"] = "TODO decide how email is blocked"
    payload["requirements"][0]["acceptance_scenario_ids"] = ["SCN-999"]
    payload["open_questions"][0]["status"] = "open"
    payload["open_questions"][0]["answer"] = None
    invalid = ChangePackage.model_validate(payload)

    codes = [issue.code for issue in invalid.contract_issues()]
    assert "intent.requirement_not_normative" in codes
    assert "intent.ambiguity_marker" in codes
    assert "intent.blocking_question_open" in codes
    assert "traceability.missing_reference" in codes


def test_dependency_cycle_is_reported_and_cannot_be_scheduled() -> None:
    payload = make_change().model_dump(mode="json")
    payload["tasks"][0]["depends_on"] = ["TASK-002"]
    cyclic = ChangePackage.model_validate(payload)

    assert {issue.code for issue in cyclic.contract_issues()} >= {"plan.dependency_cycle"}
    with pytest.raises(ValueError, match="dependency graph contains a cycle"):
        cyclic.dependency_waves()


def test_contract_rejects_unready_assumptions_and_asymmetric_traceability() -> None:
    payload = make_change().model_dump(mode="json")
    payload["assumptions"][0]["status"] = "unvalidated"
    payload["assumptions"][0]["validation_method"] = None
    payload["scenarios"][0]["requirement_ids"] = ["REQ-002"]
    invalid = ChangePackage.model_validate(payload)

    assert {issue.code for issue in invalid.contract_issues()} >= {
        "intent.assumption_unvalidated",
        "traceability.asymmetric_reference",
    }


def test_contract_reports_noncanonical_artifact_order() -> None:
    payload = make_change().model_dump(mode="json")
    payload["requirements"].reverse()
    invalid = ChangePackage.model_validate(payload)

    assert "contract.non_canonical_order" in {issue.code for issue in invalid.contract_issues()}


def test_artifact_store_materializes_exact_layout_and_round_trips(tmp_path) -> None:
    store = ChangeArtifactStore(tmp_path / "change")
    change = make_change()

    change_dir = store.create(change)

    assert store.load(change.change_id) == change
    assert (change_dir / "change.json").is_file()
    assert (change_dir / "intent.md").is_file()
    assert (change_dir / "requirements.md").is_file()
    assert (change_dir / "scenarios" / "SCN-001.md").is_file()
    assert (change_dir / "assumptions.md").is_file()
    assert (change_dir / "architecture" / "context.md").is_file()
    assert (change_dir / "architecture" / "decisions" / "ADR-001.md").is_file()
    assert (change_dir / "architecture" / "interfaces" / "IFC-001.json").is_file()
    assert (change_dir / "architecture" / "threat-model.md").is_file()
    assert (change_dir / "plan.md").is_file()
    assert (change_dir / "tasks.md").is_file()
    assert (change_dir / "evidence").is_dir()
    assumptions = (change_dir / "assumptions.md").read_text(encoding="utf-8")
    assert "pytest tests/test_host_mediation.py" in assumptions
    assert "The messaging security team." in assumptions
    threat_model = (change_dir / "architecture" / "threat-model.md").read_text(encoding="utf-8")
    assert "## Privileged tools\n- None declared" in threat_model
    assert "## Data classifications\n- confidential" in threat_model

    canonical = json.loads((change_dir / "change.json").read_text(encoding="utf-8"))
    assert canonical["schema_version"] == "agt.change/v1"
    assert canonical["change_id"] == "CHG-001"


def test_artifact_store_uses_optimistic_concurrency(tmp_path) -> None:
    store = ChangeArtifactStore(tmp_path / "change")
    original = make_change()
    store.create(original)
    updated = original.model_copy(update={"title": "Updated governed email agent"})

    store.update(updated, expected_digest=original.digest)
    assert store.load(original.change_id).title == "Updated governed email agent"

    with pytest.raises(ConcurrentChangeError, match="stale change base"):
        store.update(original, expected_digest=original.digest)


def test_artifact_store_rejects_cross_change_symlink_alias(tmp_path) -> None:
    store = ChangeArtifactStore(tmp_path / "change")
    original = make_change()
    original_dir = store.create(original)
    alias = original.model_copy(update={"change_id": "CHG-ALIAS"})
    (store.root / alias.change_id).symlink_to(original_dir, target_is_directory=True)

    with pytest.raises(ValueError, match="must not traverse a symlink"):
        store.update(alias, expected_digest=original.digest)

    assert store.load(original.change_id) == original


def test_artifact_store_load_rejects_duplicate_keys_and_type_coercion(tmp_path) -> None:
    store = ChangeArtifactStore(tmp_path / "change")
    change = make_change()
    change_dir = store.create(change)
    contract_path = change_dir / "change.json"

    canonical = contract_path.read_text(encoding="utf-8")
    duplicate = canonical.replace(
        '"change_id":"CHG-001"',
        '"change_id":"CHG-001","change_id":"CHG-FORGED"',
        1,
    )
    contract_path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(DuplicateJSONKeyError, match="duplicate JSON key"):
        store.load(change.change_id)

    payload = change.model_dump(mode="json")
    payload["tasks"][0]["risk_tier"] = "3"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError):
        store.load(change.change_id)


def test_artifact_store_excludes_simultaneous_writer_and_prunes_projections(tmp_path) -> None:
    store = ChangeArtifactStore(tmp_path / "change")
    payload = make_change().model_dump(mode="json")
    payload["requirements"][0]["acceptance_scenario_ids"].append("SCN-003")
    payload["scenarios"].append(
        {
            "scenario_id": "SCN-003",
            "title": "Delivery remains mediated",
            "requirement_ids": ["REQ-001"],
            "when": "the provider retries delivery",
            "then": "the host evaluates policy again",
            "and_then": [],
        }
    )
    extended = ChangePackage.model_validate(payload)
    change_dir = store.create(extended)
    assert (change_dir / "scenarios" / "SCN-003.md").exists()

    lock = change_dir / ".change-write.lock"
    lock.write_text("another writer", encoding="utf-8")
    with pytest.raises(ConcurrentChangeError, match="already being updated"):
        store.update(make_change(), expected_digest=extended.digest)
    lock.unlink()

    store.update(make_change(), expected_digest=extended.digest)
    assert not (change_dir / "scenarios" / "SCN-003.md").exists()


@pytest.mark.parametrize("change_id", ["../escape", "CHG-a/../../escape", "bad"])
def test_artifact_store_rejects_path_escape(tmp_path, change_id: str) -> None:
    store = ChangeArtifactStore(tmp_path / "change")
    with pytest.raises(ValueError, match="invalid change_id"):
        store.load(change_id)
