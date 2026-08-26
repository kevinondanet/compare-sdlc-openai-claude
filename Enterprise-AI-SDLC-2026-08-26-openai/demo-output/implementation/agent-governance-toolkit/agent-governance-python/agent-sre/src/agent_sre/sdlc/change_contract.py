# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical, git-native change contract for governed AI delivery.

The JSON document defined here is the single machine-readable source of truth for
an engineering change.  Human-readable Markdown files are deterministic
projections produced by :class:`ChangeArtifactStore`; workflow state is derived
from the contract and evidence rather than stored as mutable flags.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.canonical import load_json_file_strict

SCHEMA_VERSION: Literal["agt.change/v1"] = "agt.change/v1"

_CHANGE_ID = re.compile(r"^CHG-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ARTIFACT_IDS: dict[str, re.Pattern[str]] = {
    "assumption": re.compile(r"^ASM-[0-9]{3,}$"),
    "question": re.compile(r"^QST-[0-9]{3,}$"),
    "requirement": re.compile(r"^REQ-[0-9]{3,}$"),
    "scenario": re.compile(r"^SCN-[0-9]{3,}$"),
    "decision": re.compile(r"^ADR-[0-9]{3,}$"),
    "interface": re.compile(r"^IFC-[0-9]{3,}$"),
    "task": re.compile(r"^TASK-[0-9]{3,}$"),
}
_AMBIGUITY_MARKERS = re.compile(
    r"(?i)(?:\bTBD\b|\bTODO\b|\bFIXME\b|\?\?\?|<[^>]*placeholder[^>]*>)"
)
_NORMATIVE_LANGUAGE = re.compile(r"\b(?:SHALL|MUST)\b")
_TOOL_SCOPES = frozenset({"read", "workspace_write", "execute", "network", "administrative"})


class ContractModel(BaseModel):
    """Strict base model shared by every contract object."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RiskClass(str, Enum):
    """Risk-selected evidence depth for a change."""

    DOCUMENTATION = "documentation"
    SIMPLE = "simple"
    STANDARD = "standard"
    HIGH = "high"
    TOOL_ENABLED_AGENT = "tool_enabled_agent"


class RequirementKind(str, Enum):
    """Functional or non-functional requirement classification."""

    FUNCTIONAL = "functional"
    NON_FUNCTIONAL = "non_functional"


class AssumptionStatus(str, Enum):
    """Lifecycle of an explicitly declared assumption."""

    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    INVALIDATED = "invalidated"


class QuestionStatus(str, Enum):
    """Disposition of a clarification question."""

    OPEN = "open"
    ANSWERED = "answered"
    ACCEPTED_RISK = "accepted_risk"


class TaskStatus(str, Enum):
    """Execution status derived from implementation activity."""

    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"


class Intent(ContractModel):
    """BMAD-style Why, non-goals, and success signals."""

    goal: str = Field(min_length=1)
    non_goals: tuple[str, ...] = Field(min_length=1)
    success_signals: tuple[str, ...] = Field(min_length=1)


class Assumption(ContractModel):
    """Explicit assumption that can be validated before release."""

    assumption_id: str
    text: str = Field(min_length=1)
    status: AssumptionStatus = AssumptionStatus.UNVALIDATED
    validation_method: str | None = None

    @field_validator("assumption_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="assumption")


class OpenQuestion(ContractModel):
    """Clarification question with explicit ownership and blocking semantics."""

    question_id: str
    text: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    blocking: bool = True
    status: QuestionStatus = QuestionStatus.OPEN
    answer: str | None = None

    @field_validator("question_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="question")


class AcceptanceScenario(ContractModel):
    """Executable-style WHEN/THEN acceptance scenario."""

    scenario_id: str
    title: str = Field(min_length=1)
    requirement_ids: tuple[str, ...] = Field(min_length=1)
    when: str = Field(min_length=1)
    then: str = Field(min_length=1)
    and_then: tuple[str, ...] = ()

    @field_validator("scenario_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="scenario")


class Requirement(ContractModel):
    """Normative requirement and its complete traceability links."""

    requirement_id: str
    title: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    kind: RequirementKind = RequirementKind.FUNCTIONAL
    acceptance_scenario_ids: tuple[str, ...] = Field(min_length=1)
    architecture_decision_ids: tuple[str, ...] = Field(min_length=1)
    task_ids: tuple[str, ...] = Field(min_length=1)
    verification: str = Field(min_length=1)

    @field_validator("requirement_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="requirement")


class ArchitectureDecision(ContractModel):
    """Architecture decision record bound to requirements."""

    decision_id: str
    title: str = Field(min_length=1)
    status: Literal["proposed", "accepted", "superseded"] = "proposed"
    context: str = Field(min_length=1)
    decision: str = Field(min_length=1)
    consequences: tuple[str, ...] = Field(min_length=1)
    requirement_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("decision_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="decision")


class InterfaceContract(ContractModel):
    """Versioned API, message, schema, or tool contract."""

    interface_id: str
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    kind: Literal["api", "message", "schema", "tool", "data"]
    compatibility: Literal["backward", "forward", "full", "breaking"]
    specification: dict[str, Any] = Field(default_factory=dict)
    requirement_ids: tuple[str, ...] = ()

    @field_validator("interface_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="interface")


class ThreatModel(ContractModel):
    """Change-specific threats, controls, and privileged behavior."""

    assets: tuple[str, ...] = ()
    trust_boundaries: tuple[str, ...] = ()
    threats: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    residual_risks: tuple[str, ...] = ()
    privileged_tools: tuple[str, ...] = ()
    data_classifications: tuple[str, ...] = ()


class Architecture(ContractModel):
    """Architecture context, decisions, interfaces, NFRs, and threats."""

    context: str = Field(min_length=1)
    non_functional_requirements: tuple[str, ...] = ()
    decisions: tuple[ArchitectureDecision, ...] = ()
    interfaces: tuple[InterfaceContract, ...] = ()
    threat_model: ThreatModel = Field(default_factory=ThreatModel)


class Task(ContractModel):
    """Narrow implementation unit with dependencies and executable verification."""

    task_id: str
    title: str = Field(min_length=1)
    requirement_ids: tuple[str, ...] = Field(min_length=1)
    depends_on: tuple[str, ...] = ()
    verification_command: str = Field(min_length=1)
    owner_role: str = Field(min_length=1)
    tool_scopes: tuple[str, ...] = ("read", "workspace_write")
    risk_tier: int = Field(default=1, ge=0, le=4)
    status: TaskStatus = TaskStatus.PLANNED

    @field_validator("task_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _validated_id(value=value, kind="task")

    @field_validator("tool_scopes")
    @classmethod
    def _validate_tool_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        invalid = sorted(set(value) - _TOOL_SCOPES)
        if invalid:
            raise ValueError(f"unknown tool scopes: {', '.join(invalid)}")
        if value != tuple(sorted(set(value))):
            raise ValueError("tool_scopes must be sorted and unique")
        return value


class ChangePackage(ContractModel):
    """Canonical change contract with stable cross-artifact identifiers."""

    schema_version: Literal["agt.change/v1"] = SCHEMA_VERSION
    change_id: str
    title: str = Field(min_length=1)
    application: str = Field(min_length=1)
    repository: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    risk_class: RiskClass = RiskClass.STANDARD
    intent: Intent
    assumptions: tuple[Assumption, ...] = ()
    open_questions: tuple[OpenQuestion, ...] = ()
    requirements: tuple[Requirement, ...] = Field(min_length=1)
    scenarios: tuple[AcceptanceScenario, ...] = Field(min_length=1)
    architecture: Architecture
    tasks: tuple[Task, ...] = Field(min_length=1)
    implementation_model_family: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("change_id")
    @classmethod
    def _validate_change_id(cls, value: str) -> str:
        if not _CHANGE_ID.fullmatch(value):
            raise ValueError("change_id must match CHG-[A-Za-z0-9._-]+")
        return value

    @field_validator("created_at", "updated_at")
    @classmethod
    def _validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("change timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_lifecycle(self) -> ChangePackage:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 JSON used for hashing and signing."""
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        """Return the SHA-256 digest of the canonical contract."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def contract_issues(self) -> list[ContractIssue]:
        """Collect semantic and traceability defects without short-circuiting."""
        issues: list[ContractIssue] = []

        _check_unique_ids(issues, "assumption", [item.assumption_id for item in self.assumptions])
        _check_unique_ids(issues, "question", [item.question_id for item in self.open_questions])
        _check_unique_ids(
            issues, "requirement", [item.requirement_id for item in self.requirements]
        )
        _check_unique_ids(issues, "scenario", [item.scenario_id for item in self.scenarios])
        _check_unique_ids(
            issues,
            "decision",
            [item.decision_id for item in self.architecture.decisions],
        )
        _check_unique_ids(
            issues,
            "interface",
            [item.interface_id for item in self.architecture.interfaces],
        )
        _check_unique_ids(issues, "task", [item.task_id for item in self.tasks])

        requirement_ids = {item.requirement_id for item in self.requirements}
        scenario_ids = {item.scenario_id for item in self.scenarios}
        decision_ids = {item.decision_id for item in self.architecture.decisions}
        task_ids = {item.task_id for item in self.tasks}
        requirements_by_id = {item.requirement_id: item for item in self.requirements}
        scenarios_by_id = {item.scenario_id: item for item in self.scenarios}
        decisions_by_id = {item.decision_id: item for item in self.architecture.decisions}
        tasks_by_id = {item.task_id: item for item in self.tasks}

        _check_identifier_order(
            issues,
            "assumptions",
            [item.assumption_id for item in self.assumptions],
        )
        _check_identifier_order(
            issues,
            "open_questions",
            [item.question_id for item in self.open_questions],
        )
        _check_identifier_order(
            issues,
            "requirements",
            [item.requirement_id for item in self.requirements],
        )
        _check_identifier_order(
            issues,
            "scenarios",
            [item.scenario_id for item in self.scenarios],
        )
        _check_identifier_order(
            issues,
            "decisions",
            [item.decision_id for item in self.architecture.decisions],
        )
        _check_identifier_order(
            issues,
            "interfaces",
            [item.interface_id for item in self.architecture.interfaces],
        )
        _check_identifier_order(issues, "tasks", [item.task_id for item in self.tasks])

        for assumption in self.assumptions:
            if assumption.status is AssumptionStatus.UNVALIDATED:
                issues.append(
                    ContractIssue(
                        code="intent.assumption_unvalidated",
                        location=assumption.assumption_id,
                        message="Assumption must be validated or explicitly invalidated before implementation.",
                    )
                )
            elif assumption.status is AssumptionStatus.INVALIDATED:
                issues.append(
                    ContractIssue(
                        code="intent.assumption_invalidated",
                        location=assumption.assumption_id,
                        message="Invalidated assumption requires the change contract to be revised.",
                    )
                )
            elif not assumption.validation_method:
                issues.append(
                    ContractIssue(
                        code="intent.assumption_validation_missing",
                        location=assumption.assumption_id,
                        message="Validated assumption must preserve its verification method.",
                    )
                )

        for requirement in self.requirements:
            if not _NORMATIVE_LANGUAGE.search(requirement.statement):
                issues.append(
                    ContractIssue(
                        code="intent.requirement_not_normative",
                        location=requirement.requirement_id,
                        message="Requirement statement must contain SHALL or MUST.",
                    )
                )
            _check_references(
                issues,
                location=requirement.requirement_id,
                relation="scenario",
                references=requirement.acceptance_scenario_ids,
                valid=scenario_ids,
            )
            _check_references(
                issues,
                location=requirement.requirement_id,
                relation="decision",
                references=requirement.architecture_decision_ids,
                valid=decision_ids,
            )
            _check_references(
                issues,
                location=requirement.requirement_id,
                relation="task",
                references=requirement.task_ids,
                valid=task_ids,
            )
            for scenario_id in requirement.acceptance_scenario_ids:
                scenario = scenarios_by_id.get(scenario_id)
                if (
                    scenario is not None
                    and requirement.requirement_id not in scenario.requirement_ids
                ):
                    _add_asymmetric_issue(issues, requirement.requirement_id, scenario_id)
            for decision_id in requirement.architecture_decision_ids:
                decision = decisions_by_id.get(decision_id)
                if (
                    decision is not None
                    and requirement.requirement_id not in decision.requirement_ids
                ):
                    _add_asymmetric_issue(issues, requirement.requirement_id, decision_id)
            for task_id in requirement.task_ids:
                task = tasks_by_id.get(task_id)
                if task is not None and requirement.requirement_id not in task.requirement_ids:
                    _add_asymmetric_issue(issues, requirement.requirement_id, task_id)

        for scenario in self.scenarios:
            _check_references(
                issues,
                location=scenario.scenario_id,
                relation="requirement",
                references=scenario.requirement_ids,
                valid=requirement_ids,
            )
            for requirement_id in scenario.requirement_ids:
                linked_requirement = requirements_by_id.get(requirement_id)
                if (
                    linked_requirement is not None
                    and scenario.scenario_id not in linked_requirement.acceptance_scenario_ids
                ):
                    _add_asymmetric_issue(issues, scenario.scenario_id, requirement_id)

        for decision in self.architecture.decisions:
            _check_references(
                issues,
                location=decision.decision_id,
                relation="requirement",
                references=decision.requirement_ids,
                valid=requirement_ids,
            )
            for requirement_id in decision.requirement_ids:
                linked_requirement = requirements_by_id.get(requirement_id)
                if (
                    linked_requirement is not None
                    and decision.decision_id not in linked_requirement.architecture_decision_ids
                ):
                    _add_asymmetric_issue(issues, decision.decision_id, requirement_id)

        for interface in self.architecture.interfaces:
            _check_references(
                issues,
                location=interface.interface_id,
                relation="requirement",
                references=interface.requirement_ids,
                valid=requirement_ids,
            )

        for task in self.tasks:
            _check_references(
                issues,
                location=task.task_id,
                relation="requirement",
                references=task.requirement_ids,
                valid=requirement_ids,
            )
            _check_references(
                issues,
                location=task.task_id,
                relation="dependency",
                references=task.depends_on,
                valid=task_ids - {task.task_id},
            )
            for requirement_id in task.requirement_ids:
                linked_requirement = requirements_by_id.get(requirement_id)
                if (
                    linked_requirement is not None
                    and task.task_id not in linked_requirement.task_ids
                ):
                    _add_asymmetric_issue(issues, task.task_id, requirement_id)

        issues.extend(_dependency_cycle_issues(self.tasks))
        issues.extend(self._ambiguity_issues())
        return sorted(issues, key=lambda item: (item.code, item.location, item.message))

    def dependency_waves(self) -> list[list[str]]:
        """Return deterministic dependency waves, raising for a cyclic graph."""
        dependencies = {task.task_id: set(task.depends_on) for task in self.tasks}
        waves: list[list[str]] = []
        completed: set[str] = set()
        while len(completed) < len(dependencies):
            wave = sorted(
                task_id
                for task_id, required in dependencies.items()
                if task_id not in completed and required <= completed
            )
            if not wave:
                remaining = sorted(set(dependencies) - completed)
                raise ValueError(f"task dependency graph contains a cycle: {', '.join(remaining)}")
            waves.append(wave)
            completed.update(wave)
        return waves

    def _ambiguity_issues(self) -> list[ContractIssue]:
        issues: list[ContractIssue] = []
        for question in self.open_questions:
            if question.blocking and question.status is QuestionStatus.OPEN:
                issues.append(
                    ContractIssue(
                        code="intent.blocking_question_open",
                        location=question.question_id,
                        message="Blocking owner decision remains open.",
                    )
                )
            if (
                question.status in {QuestionStatus.ANSWERED, QuestionStatus.ACCEPTED_RISK}
                and not question.answer
            ):
                issues.append(
                    ContractIssue(
                        code="intent.answered_question_missing_answer",
                        location=question.question_id,
                        message="Answered question must preserve its answer.",
                    )
                )

        searchable: list[tuple[str, str]] = [
            ("intent.goal", self.intent.goal),
            *[
                (requirement.requirement_id, requirement.statement)
                for requirement in self.requirements
            ],
            *[(task.task_id, task.verification_command) for task in self.tasks],
            ("architecture.context", self.architecture.context),
        ]
        for location, text in searchable:
            if _AMBIGUITY_MARKERS.search(text):
                issues.append(
                    ContractIssue(
                        code="intent.ambiguity_marker",
                        location=location,
                        message="Unresolved ambiguity marker found.",
                    )
                )
        return issues


class ContractIssue(ContractModel):
    """Stable semantic validation issue emitted by the contract checker."""

    code: str
    location: str
    message: str


class ConcurrentChangeError(RuntimeError):
    """Raised when optimistic concurrency detects a stale base digest."""


class ChangeArtifactStore:
    """Path-confined, atomic repository for canonical change packages."""

    def __init__(self, root: str | Path) -> None:
        requested_root = Path(root).expanduser()
        if requested_root.is_symlink():
            raise ValueError("change store root must not be a symlink")
        self.root = requested_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, package: ChangePackage) -> Path:
        """Create a new change directory and deterministic human projections."""
        change_dir = self._change_dir(package.change_id)
        if change_dir.exists():
            raise FileExistsError(f"change package already exists: {package.change_id}")
        change_dir.mkdir(parents=False)
        with self._exclusive_change_lock(change_dir):
            self._write_package(change_dir=change_dir, package=package)
        return change_dir

    def load(self, change_id: str) -> ChangePackage:
        """Load and strictly validate a canonical change package."""
        path = self._safe_child(self._change_dir(change_id), "change.json")
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"canonical change contract not found: {path}")
        payload = load_json_file_strict(path)
        return ChangePackage.model_validate_json(canonical_json_bytes(payload), strict=True)

    def update(self, package: ChangePackage, *, expected_digest: str) -> Path:
        """Atomically update a package if its base digest is still current."""
        change_dir = self._change_dir(package.change_id)
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise ValueError("expected_digest must be a lowercase SHA-256 value")
        with self._exclusive_change_lock(change_dir):
            current = self.load(package.change_id)
            if current.change_id != package.change_id:
                raise ValueError(
                    "stored change identity does not match the requested change directory"
                )
            if current.digest != expected_digest:
                raise ConcurrentChangeError(
                    f"stale change base for {package.change_id}: expected {expected_digest}, "
                    f"current {current.digest}"
                )
            if package.updated_at < current.updated_at:
                raise ValueError("updated package timestamp precedes the stored package")
            self._write_package(change_dir=change_dir, package=package)
        return change_dir

    def _write_package(self, *, change_dir: Path, package: ChangePackage) -> None:
        if change_dir.is_symlink():
            raise ValueError("change directory must not be a symlink")
        self._materialize_markdown(change_dir=change_dir, package=package)
        # Commit the canonical source of truth last. If a projection fails, readers
        # continue to see the prior contract rather than a partially materialized update.
        self._atomic_write(self._safe_child(change_dir, "change.json"), package.canonical_bytes())

    def _materialize_markdown(self, *, change_dir: Path, package: ChangePackage) -> None:
        architecture_dir = self._safe_child(change_dir, "architecture")
        decisions_dir = self._safe_child(architecture_dir, "decisions")
        interfaces_dir = self._safe_child(architecture_dir, "interfaces")
        scenarios_dir = self._safe_child(change_dir, "scenarios")
        evidence_dir = self._safe_child(change_dir, "evidence")
        for directory in (
            architecture_dir,
            decisions_dir,
            interfaces_dir,
            scenarios_dir,
            evidence_dir,
        ):
            if directory.exists() and directory.is_symlink():
                raise ValueError(f"artifact directory must not be a symlink: {directory}")
            directory.mkdir(parents=True, exist_ok=True)

        self._prune_generated_files(
            scenarios_dir,
            expected={f"{item.scenario_id}.md" for item in package.scenarios},
            pattern=re.compile(r"SCN-[0-9]{3,}\.md"),
        )
        self._prune_generated_files(
            decisions_dir,
            expected={f"{item.decision_id}.md" for item in package.architecture.decisions},
            pattern=re.compile(r"ADR-[0-9]{3,}\.md"),
        )
        self._prune_generated_files(
            interfaces_dir,
            expected={f"{item.interface_id}.json" for item in package.architecture.interfaces},
            pattern=re.compile(r"IFC-[0-9]{3,}\.json"),
        )

        intent = [
            f"# {package.title}",
            "",
            "## Goal",
            "",
            package.intent.goal,
            "",
            "## Non-goals",
            "",
            *[f"- {item}" for item in package.intent.non_goals],
            "",
            "## Success signals",
            "",
            *[f"- {item}" for item in package.intent.success_signals],
            "",
        ]
        self._write_text(change_dir, "intent.md", intent)

        requirements = ["# Requirements", ""]
        for requirement in package.requirements:
            requirements.extend(
                [
                    f"## {requirement.requirement_id} — {requirement.title}",
                    "",
                    requirement.statement,
                    "",
                    f"- Kind: `{requirement.kind.value}`",
                    f"- Scenarios: {', '.join(requirement.acceptance_scenario_ids)}",
                    f"- Decisions: {', '.join(requirement.architecture_decision_ids)}",
                    f"- Tasks: {', '.join(requirement.task_ids)}",
                    f"- Verification: `{requirement.verification}`",
                    "",
                ]
            )
        self._write_text(change_dir, "requirements.md", requirements)

        assumptions = ["# Assumptions and open questions", "", "## Assumptions", ""]
        for assumption in package.assumptions:
            assumptions.extend(
                (
                    f"- **{assumption.assumption_id}** [{assumption.status.value}] "
                    f"{assumption.text}",
                    f"  - Validation: {assumption.validation_method or 'not recorded'}",
                )
            )
        assumptions.extend(["", "## Open questions", ""])
        for question in package.open_questions:
            assumptions.extend(
                (
                    f"- **{question.question_id}** [{question.status.value}; "
                    f"owner={question.owner}; blocking={str(question.blocking).lower()}] "
                    f"{question.text}",
                    f"  - Answer: {question.answer or 'not answered'}",
                )
            )
        assumptions.append("")
        self._write_text(change_dir, "assumptions.md", assumptions)

        self._write_text(
            architecture_dir,
            "context.md",
            [
                "# Architecture context",
                "",
                package.architecture.context,
                "",
                "## Non-functional requirements",
                "",
                *[f"- {item}" for item in package.architecture.non_functional_requirements],
                "",
            ],
        )
        for decision in package.architecture.decisions:
            self._write_text(
                decisions_dir,
                f"{decision.decision_id}.md",
                [
                    f"# {decision.decision_id} — {decision.title}",
                    "",
                    f"Status: {decision.status}",
                    "",
                    "## Context",
                    "",
                    decision.context,
                    "",
                    "## Decision",
                    "",
                    decision.decision,
                    "",
                    "## Consequences",
                    "",
                    *[f"- {item}" for item in decision.consequences],
                    "",
                ],
            )
        for interface in package.architecture.interfaces:
            self._atomic_write(
                self._safe_child(interfaces_dir, f"{interface.interface_id}.json"),
                canonical_json_bytes(interface.model_dump(mode="json")),
            )

        threat = package.architecture.threat_model
        self._write_text(
            architecture_dir,
            "threat-model.md",
            [
                "# Threat model",
                "",
                "## Assets",
                *[f"- {item}" for item in threat.assets],
                "",
                "## Trust boundaries",
                *[f"- {item}" for item in threat.trust_boundaries],
                "",
                "## Threats",
                *[f"- {item}" for item in threat.threats],
                "",
                "## Controls",
                *[f"- {item}" for item in threat.controls],
                "",
                "## Residual risks",
                *[f"- {item}" for item in threat.residual_risks],
                "",
                "## Privileged tools",
                *([f"- {item}" for item in threat.privileged_tools] or ["- None declared"]),
                "",
                "## Data classifications",
                *([f"- {item}" for item in threat.data_classifications] or ["- None declared"]),
                "",
            ],
        )

        for scenario in package.scenarios:
            self._write_text(
                scenarios_dir,
                f"{scenario.scenario_id}.md",
                [
                    f"# {scenario.scenario_id} — {scenario.title}",
                    "",
                    f"**WHEN** {scenario.when}",
                    "",
                    f"**THEN** {scenario.then}",
                    *[f"\n**AND THEN** {item}" for item in scenario.and_then],
                    "",
                ],
            )

        plan = ["# Plan", ""]
        for wave_number, wave in enumerate(package.dependency_waves(), start=1):
            plan.extend([f"## Wave {wave_number}", "", *[f"- {task_id}" for task_id in wave], ""])
        self._write_text(change_dir, "plan.md", plan)

        tasks = ["# Tasks", ""]
        for task in package.tasks:
            tasks.extend(
                [
                    f"## {task.task_id} — {task.title}",
                    "",
                    f"- Requirements: {', '.join(task.requirement_ids)}",
                    f"- Depends on: {', '.join(task.depends_on) or 'none'}",
                    f"- Owner role: {task.owner_role}",
                    f"- Risk tier: {task.risk_tier}",
                    f"- Tool scopes: {', '.join(task.tool_scopes)}",
                    f"- Verification: `{task.verification_command}`",
                    "",
                ]
            )
        self._write_text(change_dir, "tasks.md", tasks)

    def _write_text(self, parent: Path, name: str, lines: list[str]) -> None:
        self._atomic_write(self._safe_child(parent, name), "\n".join(lines).encode("utf-8"))

    def _change_dir(self, change_id: str) -> Path:
        if not _CHANGE_ID.fullmatch(change_id):
            raise ValueError("invalid change_id")
        return self._safe_child(self.root, change_id)

    def _safe_child(self, parent: Path, name: str) -> Path:
        if not name or Path(name).name != name or name in {".", ".."}:
            raise ValueError(f"artifact name must be a single path component: {name!r}")
        try:
            relative_parent = parent.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"artifact parent escapes change store: {parent}") from exc
        if ".." in relative_parent.parts:
            raise ValueError(f"artifact parent escapes change store: {parent}")
        candidate = parent / name
        try:
            relative_candidate = candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"artifact path escapes change store: {candidate}") from exc
        current = self.root
        for component in relative_candidate.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError(f"artifact path must not traverse a symlink: {current}")
        return candidate

    @contextmanager
    def _exclusive_change_lock(self, change_dir: Path) -> Iterator[None]:
        """Prevent same-base concurrent writers from passing the digest check together."""
        lock_path = self._safe_child(change_dir, ".change-write.lock")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except FileExistsError as exc:
            raise ConcurrentChangeError(
                f"change package is already being updated: {change_dir.name}"
            ) from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(f"pid={os.getpid()}\n")
                stream.flush()
                os.fsync(stream.fileno())
            yield
        finally:
            with suppress(FileNotFoundError):
                lock_path.unlink()

    @staticmethod
    def _prune_generated_files(
        directory: Path,
        *,
        expected: set[str],
        pattern: re.Pattern[str],
    ) -> None:
        for candidate in directory.iterdir():
            if candidate.name in expected or not pattern.fullmatch(candidate.name):
                continue
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError(f"generated artifact path is not a regular file: {candidate}")
            candidate.unlink()

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(file_descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically without non-standard numeric values."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validated_id(*, value: str, kind: str) -> str:
    pattern = _ARTIFACT_IDS[kind]
    if not pattern.fullmatch(value):
        raise ValueError(f"{kind} id must match {pattern.pattern}")
    return value


def _check_unique_ids(
    issues: list[ContractIssue],
    kind: str,
    identifiers: Sequence[str],
) -> None:
    seen: set[str] = set()
    for identifier in identifiers:
        if identifier in seen:
            issues.append(
                ContractIssue(
                    code="contract.duplicate_id",
                    location=identifier,
                    message=f"Duplicate {kind} identifier.",
                )
            )
        seen.add(identifier)


def _check_identifier_order(
    issues: list[ContractIssue],
    collection: str,
    identifiers: Sequence[str],
) -> None:
    if list(identifiers) != sorted(identifiers):
        issues.append(
            ContractIssue(
                code="contract.non_canonical_order",
                location=collection,
                message="Artifact collections must be sorted by stable identifier.",
            )
        )


def _add_asymmetric_issue(
    issues: list[ContractIssue],
    source: str,
    target: str,
) -> None:
    issues.append(
        ContractIssue(
            code="traceability.asymmetric_reference",
            location=source,
            message=f"Traceability link to {target} is not reciprocated.",
        )
    )


def _check_references(
    issues: list[ContractIssue],
    *,
    location: str,
    relation: str,
    references: Sequence[str],
    valid: set[str],
) -> None:
    if list(references) != sorted(set(references)):
        issues.append(
            ContractIssue(
                code="contract.non_canonical_reference_set",
                location=location,
                message=f"{relation.capitalize()} references must be sorted and unique.",
            )
        )
    for reference in references:
        if reference not in valid:
            issues.append(
                ContractIssue(
                    code="traceability.missing_reference",
                    location=location,
                    message=f"Unknown {relation} reference: {reference}.",
                )
            )


def _dependency_cycle_issues(tasks: Sequence[Task]) -> list[ContractIssue]:
    dependencies = {task.task_id: set(task.depends_on) for task in tasks}
    completed: set[str] = set()
    while len(completed) < len(dependencies):
        ready = {
            task_id
            for task_id, required in dependencies.items()
            if task_id not in completed and required <= completed
        }
        if not ready:
            return [
                ContractIssue(
                    code="plan.dependency_cycle",
                    location=task_id,
                    message="Task participates in a dependency cycle.",
                )
                for task_id in sorted(set(dependencies) - completed)
            ]
        completed.update(ready)
    return []
