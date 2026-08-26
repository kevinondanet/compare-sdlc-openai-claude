# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deterministic G0-G3 development gates backed by executable evidence."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, NoReturn, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.change_contract import (
    ChangePackage,
    ContractIssue,
    RiskClass,
    canonical_json_bytes,
)
from agent_sre.sdlc.review_loop import ReviewVerdict
from agent_sre.sdlc.review_validation import validate_runtime_review_history

if TYPE_CHECKING:
    from agent_sre.sdlc.orchestration import OrchestrationManifest
    from agent_sre.sdlc.orchestration_runtime import ExecutionReceipt

EVIDENCE_SCHEMA_VERSION: Literal["agt.execution-evidence/v1"] = "agt.execution-evidence/v1"


class _FrozenDict(dict[str, Any]):
    """JSON-serializable mapping that prevents post-digest mutation."""

    @staticmethod
    def _immutable(*_args: Any, **_kwargs: Any) -> NoReturn:
        raise TypeError("evidence mappings are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


class GateModel(BaseModel):
    """Strict immutable base model for gate artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class EvidenceKind(str, Enum):
    """Deterministic and semantic evidence categories for G2-G3."""

    BUILD = "build"
    FORMAT = "format"
    LINT = "lint"
    TYPECHECK = "typecheck"
    COMPLEXITY = "complexity"
    DUPLICATION = "duplication"
    CONTRACT = "contract"
    TEST = "test"
    COVERAGE = "coverage"
    MUTATION = "mutation"
    ARCHITECTURE = "architecture"
    DRIFT = "drift"
    REVIEW = "review"
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    SBOM = "sbom"
    PROVENANCE = "provenance"
    TOOL_MANIFEST = "tool_manifest"
    AGENT_SAFETY = "agent_safety"
    JUDGE_CALIBRATION = "judge_calibration"
    PERFORMANCE = "performance"
    COST = "cost"


class VerificationLayer(str, Enum):
    """Portable test-portfolio layers represented by executable test evidence."""

    DOCUMENTATION = "documentation"
    UNIT = "unit"
    PROPERTY = "property"
    INTEGRATION = "integration"
    CONTRACT = "contract"
    END_TO_END = "end_to_end"
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    AGENT_SAFETY = "agent_safety"
    PERFORMANCE = "performance"


class EvidenceStatus(str, Enum):
    """Completion state of one evidence-producing command or review."""

    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class GateStatus(str, Enum):
    """Result of evaluating one progressive development gate."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class CommandEvidence(GateModel):
    """Machine evidence from a real command or independent review."""

    schema_version: Literal["agt.execution-evidence/v1"] = EVIDENCE_SCHEMA_VERSION
    evidence_id: str = Field(pattern=r"^EVD-[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
    change_id: str
    source_revision: str = Field(min_length=1)
    change_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: EvidenceKind
    status: EvidenceStatus
    generated_at: datetime
    producer: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    command: str = Field(min_length=1)
    exit_code: int | None
    requirement_ids: tuple[str, ...] = ()
    scenario_ids: tuple[str, ...] = ()
    task_ids: tuple[str, ...] = ()
    test_layers: tuple[VerificationLayer, ...] = ()
    metrics: dict[str, Any] = Field(default_factory=dict)
    artifacts: dict[str, str] = Field(default_factory=dict)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("generated_at")
    @classmethod
    def _aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _verify_digest(self) -> CommandEvidence:
        for field_name in ("requirement_ids", "scenario_ids", "task_ids"):
            identifiers = getattr(self, field_name)
            if identifiers != tuple(sorted(set(identifiers))):
                raise ValueError(f"{field_name} must be sorted and unique")
        if self.kind is EvidenceKind.TEST and not self.test_layers:
            raise ValueError("test evidence must declare at least one test portfolio layer")
        if self.kind is not EvidenceKind.TEST and self.test_layers:
            raise ValueError("test_layers are only valid for test evidence")
        if self.test_layers != tuple(sorted(set(self.test_layers), key=lambda item: item.value)):
            raise ValueError("test_layers must be sorted and unique")
        if self.evidence_sha256 != self.computed_digest:
            raise ValueError("evidence_sha256 does not match the canonical evidence payload")
        return self

    @field_validator("metrics", "artifacts")
    @classmethod
    def _freeze_mappings(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _FrozenDict({str(key): _freeze_json(item) for key, item in value.items()})

    @property
    def computed_digest(self) -> str:
        """Return the digest after excluding the self-referential digest field."""
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    def strict_revalidate(self) -> CommandEvidence | None:
        """Re-run the full canonical contract and digest checks at a trust boundary."""

        try:
            canonical = canonical_json_bytes(self.model_dump(mode="json", warnings="error"))
            return CommandEvidence.model_validate_json(canonical, strict=True)
        except (TypeError, ValueError):
            return None

    @classmethod
    def create(
        cls,
        *,
        evidence_id: str,
        change_id: str,
        source_revision: str,
        change_digest: str,
        kind: EvidenceKind,
        status: EvidenceStatus,
        producer: str,
        command: str,
        exit_code: int | None,
        environment: str = "ci",
        requirement_ids: list[str] | None = None,
        scenario_ids: list[str] | None = None,
        task_ids: list[str] | None = None,
        test_layers: list[VerificationLayer] | None = None,
        metrics: dict[str, Any] | None = None,
        artifacts: dict[str, str] | None = None,
        generated_at: datetime | None = None,
    ) -> CommandEvidence:
        """Build evidence and stamp its deterministic integrity digest."""
        timestamp = (generated_at or datetime.now(UTC)).astimezone(UTC)
        provisional = cls.model_construct(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            evidence_id=evidence_id,
            change_id=change_id,
            source_revision=source_revision,
            change_digest=change_digest,
            kind=kind,
            status=status,
            generated_at=timestamp,
            producer=producer,
            environment=environment,
            command=command,
            exit_code=exit_code,
            requirement_ids=tuple(requirement_ids or ()),
            scenario_ids=tuple(scenario_ids or ()),
            task_ids=tuple(task_ids or ()),
            test_layers=tuple(test_layers or ()),
            metrics=metrics or {},
            artifacts=artifacts or {},
            evidence_sha256="0" * 64,
        )
        payload = provisional.model_dump(mode="json")
        payload["evidence_sha256"] = provisional.computed_digest
        return cls.model_validate(payload)


class DevelopmentGatePolicy(GateModel):
    """Organization policy for specification, quality, and review gates."""

    schema_version: Literal["agt.development-policy/v1"] = "agt.development-policy/v1"
    max_ambiguity_score: Decimal = Field(default=Decimal("0"), ge=0, le=1)
    min_line_coverage: Decimal = Field(default=Decimal("0.75"), ge=0, le=1)
    min_diff_coverage: Decimal = Field(default=Decimal("0.90"), ge=0, le=1)
    min_branch_coverage: Decimal = Field(default=Decimal("0.70"), ge=0, le=1)
    min_critical_coverage: Decimal = Field(default=Decimal("0.90"), ge=0, le=1)
    min_mutation_score: Decimal = Field(default=Decimal("0.60"), ge=0, le=1)
    max_cyclomatic_complexity: int = Field(default=15, gt=0)
    max_duplication_ratio: Decimal = Field(default=Decimal("0.03"), ge=0, le=1)
    evidence_max_age_seconds: int = Field(default=86_400, gt=0)
    future_clock_skew_seconds: int = Field(default=300, ge=0)
    allowed_evidence_environments: tuple[str, ...] = ("ci",)
    require_report_uri: bool = True
    require_provider_diverse_review_for_material_changes: bool = True

    @field_validator("allowed_evidence_environments")
    @classmethod
    def _validate_environments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))) or any(not item for item in value):
            raise ValueError("allowed_evidence_environments must be sorted, unique, and non-empty")
        return value

    @property
    def digest(self) -> str:
        """Return a stable policy digest included in every gate result."""
        return hashlib.sha256(canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()


class GateCheck(GateModel):
    """One stable, independently evaluated gate condition."""

    code: str
    passed: bool
    message: str
    actual: Any = None
    threshold: Any = None
    evidence_ids: tuple[str, ...] = ()

    @field_validator("actual", "threshold")
    @classmethod
    def _freeze_values(cls, value: Any) -> Any:
        return _freeze_json(value)


class DevelopmentEvidenceReference(GateModel):
    """Digest-only reference to evidence considered by a development gate."""

    evidence_id: str
    schema_version: str
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class DevelopmentGateResult(GateModel):
    """Deterministic G0-G3 result with complete blocking reasons."""

    schema_version: Literal["agt.development-gate-result/v1"] = "agt.development-gate-result/v1"
    gate_id: Literal["G0", "G1", "G2", "G3"]
    status: GateStatus
    change_id: str
    source_revision: str
    change_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    risk_class: RiskClass
    evaluated_at: datetime
    checks: tuple[GateCheck, ...]
    evidence: tuple[DevelopmentEvidenceReference, ...]
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evaluated_at")
    @classmethod
    def _validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_result(self) -> DevelopmentGateResult:
        ordered_checks = tuple(
            sorted(
                self.checks,
                key=lambda item: (item.code, ",".join(item.evidence_ids), item.message),
            )
        )
        if self.checks != ordered_checks:
            raise ValueError("checks must be deterministically sorted")
        ordered_evidence = tuple(
            sorted(self.evidence, key=lambda item: (item.schema_version, item.evidence_id))
        )
        if self.evidence != ordered_evidence or len(
            {item.evidence_id for item in ordered_evidence}
        ) != len(ordered_evidence):
            raise ValueError("evidence references must be sorted with unique identifiers")
        if self.status in {GateStatus.PASS, GateStatus.NOT_APPLICABLE} and any(
            not check.passed for check in self.checks
        ):
            raise ValueError("a passing or not-applicable gate cannot contain a failed check")
        if self.status is GateStatus.FAIL and all(check.passed for check in self.checks):
            raise ValueError("a failed gate must contain at least one failed check")
        payload = self.model_dump(mode="json", exclude={"result_digest"})
        expected = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        if self.result_digest != expected:
            raise ValueError("result_digest does not match the canonical gate result")
        return self

    @property
    def blocking_reason_codes(self) -> list[str]:
        """Return stable reason codes for every failed condition."""
        return [check.code for check in self.checks if not check.passed]

    @classmethod
    def create(
        cls,
        *,
        gate_id: Literal["G0", "G1", "G2", "G3"],
        status: GateStatus,
        change: ChangePackage,
        policy_digest: str,
        evaluated_at: datetime,
        checks: Sequence[GateCheck],
        evidence: Sequence[CommandEvidence] = (),
    ) -> DevelopmentGateResult:
        """Create a canonical result with complete evidence references and digest."""
        ordered_checks = tuple(
            sorted(
                checks,
                key=lambda item: (item.code, ",".join(item.evidence_ids), item.message),
            )
        )
        references = tuple(
            sorted(
                (
                    DevelopmentEvidenceReference(
                        evidence_id=item.evidence_id,
                        schema_version=item.schema_version,
                        digest=item.evidence_sha256,
                    )
                    for item in evidence
                ),
                key=lambda item: (item.schema_version, item.evidence_id),
            )
        )
        payload: dict[str, Any] = {
            "schema_version": "agt.development-gate-result/v1",
            "gate_id": gate_id,
            "status": status,
            "change_id": change.change_id,
            "source_revision": change.source_revision,
            "change_digest": change.digest,
            "policy_digest": policy_digest,
            "risk_class": change.risk_class,
            "evaluated_at": evaluated_at.astimezone(UTC),
            "checks": ordered_checks,
            "evidence": references,
        }
        provisional = cls.model_construct(**payload, result_digest="0" * 64)
        digest_payload = provisional.model_dump(mode="json", exclude={"result_digest"})
        payload["result_digest"] = hashlib.sha256(canonical_json_bytes(digest_payload)).hexdigest()
        return cls.model_validate(payload)


class DevelopmentGateEvaluator:
    """Evaluate G0-G3 without trusting self-attested completion flags."""

    def __init__(self, policy: DevelopmentGatePolicy | None = None) -> None:
        self.policy = policy or DevelopmentGatePolicy()

    def evaluate_all(
        self,
        *,
        change: ChangePackage,
        evidence: list[CommandEvidence],
        evaluated_at: datetime | None = None,
        orchestration_manifest: OrchestrationManifest | None = None,
        execution_receipt: ExecutionReceipt | None = None,
    ) -> dict[str, DevelopmentGateResult]:
        """Evaluate all development gates against one immutable source revision."""
        now = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
        return {
            "G0": self.evaluate_g0(change=change, evaluated_at=now),
            "G1": self.evaluate_g1(change=change, evaluated_at=now),
            "G2": self.evaluate_g2(change=change, evidence=evidence, evaluated_at=now),
            "G3": self.evaluate_g3(
                change=change,
                evidence=evidence,
                evaluated_at=now,
                orchestration_manifest=orchestration_manifest,
                execution_receipt=execution_receipt,
            ),
        }

    def evaluate_g0(
        self,
        *,
        change: ChangePackage,
        evaluated_at: datetime | None = None,
    ) -> DevelopmentGateResult:
        """Evaluate intent readiness, ambiguity, grammar, and traceability."""
        issues = change.contract_issues()
        checks = [_issue_check(issue) for issue in issues]

        ambiguity_issues = [issue for issue in issues if issue.code.startswith("intent.")]
        ambiguity_denominator = max(
            1,
            len(change.requirements) * 2 + len(change.open_questions) * 3,
        )
        ambiguity_score = Decimal(len(ambiguity_issues)) / Decimal(ambiguity_denominator)
        checks.append(
            GateCheck(
                code="intent.ambiguity_score",
                passed=ambiguity_score <= self.policy.max_ambiguity_score,
                message="Specification ambiguity must not exceed organization policy.",
                actual=str(ambiguity_score),
                threshold=str(self.policy.max_ambiguity_score),
            )
        )
        checks.append(
            GateCheck(
                code="intent.non_goals_present",
                passed=bool(change.intent.non_goals),
                message="At least one explicit non-goal is required.",
                actual=len(change.intent.non_goals),
                threshold=1,
            )
        )
        checks.append(
            GateCheck(
                code="intent.success_signals_present",
                passed=bool(change.intent.success_signals),
                message="At least one measurable success signal is required.",
                actual=len(change.intent.success_signals),
                threshold=1,
            )
        )
        return self._result(
            gate_id="G0",
            change=change,
            checks=checks,
            evaluated_at=evaluated_at,
        )

    def evaluate_g1(
        self,
        *,
        change: ChangePackage,
        evaluated_at: datetime | None = None,
    ) -> DevelopmentGateResult:
        """Evaluate architecture, NFR, interface, threat, and plan readiness."""
        privileged_scope_names = {"administrative", "execute", "network"}
        privileged_task_scopes = {
            task.task_id: tuple(sorted(set(task.tool_scopes) & privileged_scope_names))
            for task in change.tasks
            if set(task.tool_scopes) & privileged_scope_names
        }
        privileged_change = bool(
            change.architecture.threat_model.privileged_tools or privileged_task_scopes
        )
        if change.risk_class is RiskClass.DOCUMENTATION and not privileged_change:
            return self._result(
                gate_id="G1",
                change=change,
                checks=[
                    GateCheck(
                        code="architecture.not_applicable",
                        passed=True,
                        message="Documentation-only changes do not require architecture readiness.",
                    )
                ],
                evaluated_at=evaluated_at,
                applicable=False,
            )

        architecture = change.architecture
        high_risk = change.risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}
        agent_change = change.risk_class is RiskClass.TOOL_ENABLED_AGENT

        accepted_decisions = [item for item in architecture.decisions if item.status == "accepted"]
        decisions_by_id = {item.decision_id: item for item in architecture.decisions}
        unresolved_decisions = sorted(
            decision_id
            for requirement in change.requirements
            for decision_id in requirement.architecture_decision_ids
            if decision_id not in decisions_by_id
            or decisions_by_id[decision_id].status != "accepted"
        )
        empty_interfaces = sorted(
            item.interface_id for item in architecture.interfaces if not item.specification
        )
        declared_tool_interfaces = {
            item.name for item in architecture.interfaces if item.kind == "tool"
        }
        undeclared_privileged_tools = sorted(
            set(architecture.threat_model.privileged_tools) - declared_tool_interfaces
        )
        insufficient_scope_tiers = sorted(
            task.task_id
            for task in change.tasks
            if (
                ("administrative" in task.tool_scopes and task.risk_tier < 4)
                or ({"network", "execute"} & set(task.tool_scopes) and task.risk_tier < 2)
            )
        )
        checks = [
            GateCheck(
                code="architecture.accepted_decision_present",
                passed=bool(accepted_decisions),
                message="At least one accepted architecture decision is required.",
                actual=len(accepted_decisions),
                threshold=1,
            ),
            GateCheck(
                code="architecture.all_referenced_decisions_accepted",
                passed=not unresolved_decisions,
                message="Every requirement-linked architecture decision must be accepted.",
                actual=unresolved_decisions,
                threshold=[],
            ),
            GateCheck(
                code="architecture.nfrs_present",
                passed=bool(architecture.non_functional_requirements),
                message="Non-functional requirements must be explicit.",
                actual=len(architecture.non_functional_requirements),
                threshold=1,
            ),
            GateCheck(
                code="architecture.interfaces_declared",
                passed=bool(architecture.interfaces)
                or change.risk_class is RiskClass.DOCUMENTATION,
                message="Material changes must declare affected interfaces or schemas.",
                actual=len(architecture.interfaces),
                threshold=0 if change.risk_class is RiskClass.DOCUMENTATION else 1,
            ),
            GateCheck(
                code="architecture.interfaces_specified",
                passed=not empty_interfaces,
                message="Every declared interface must carry a machine-readable specification.",
                actual=empty_interfaces,
                threshold=[],
            ),
            GateCheck(
                code="architecture.plan_acyclic",
                passed=not any(
                    issue.code == "plan.dependency_cycle" for issue in change.contract_issues()
                ),
                message="Task dependency graph must be acyclic.",
            ),
            GateCheck(
                code="security.threat_model_complete",
                passed=(
                    not (high_risk or privileged_change)
                    or (
                        bool(architecture.threat_model.assets)
                        and bool(architecture.threat_model.trust_boundaries)
                        and bool(architecture.threat_model.threats)
                        and bool(architecture.threat_model.controls)
                    )
                ),
                message="High-risk changes require assets, trust boundaries, threats, and controls.",
                actual={
                    "assets": len(architecture.threat_model.assets),
                    "trust_boundaries": len(architecture.threat_model.trust_boundaries),
                    "threats": len(architecture.threat_model.threats),
                    "controls": len(architecture.threat_model.controls),
                },
            ),
            GateCheck(
                code="security.agent_tool_manifest_present",
                passed=not agent_change or bool(architecture.threat_model.privileged_tools),
                message="Tool-enabled agents must declare privileged tools.",
                actual=len(architecture.threat_model.privileged_tools),
                threshold=1 if agent_change else 0,
            ),
            GateCheck(
                code="security.privileged_tools_require_agent_risk",
                passed=not privileged_change or agent_change,
                message=(
                    "A change that declares privileged product tools or execution scopes must "
                    "use the tool_enabled_agent risk class so the full safety profile cannot "
                    "be bypassed."
                ),
                actual={
                    "risk_class": change.risk_class.value,
                    "privileged_product_tools": architecture.threat_model.privileged_tools,
                    "privileged_task_scopes": privileged_task_scopes,
                },
                threshold=(
                    RiskClass.TOOL_ENABLED_AGENT.value if privileged_change else "not_applicable"
                ),
            ),
            GateCheck(
                code="security.privileged_tools_have_interfaces",
                passed=not undeclared_privileged_tools,
                message="Every privileged tool must have a versioned tool interface contract.",
                actual=undeclared_privileged_tools,
                threshold=[],
            ),
            GateCheck(
                code="security.task_scope_risk_tier",
                passed=not insufficient_scope_tiers,
                message="Execute/network/admin scopes require an adequate task risk tier.",
                actual=insufficient_scope_tiers,
                threshold=[],
            ),
        ]
        return self._result(
            gate_id="G1",
            change=change,
            checks=checks,
            evaluated_at=evaluated_at,
        )

    def evaluate_g2(
        self,
        *,
        change: ChangePackage,
        evidence: list[CommandEvidence],
        evaluated_at: datetime | None = None,
    ) -> DevelopmentGateResult:
        """Evaluate deterministic build, test, coverage, and drift evidence."""
        now = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
        selected = [item for item in evidence if item.kind in _G2_EVIDENCE_KINDS]
        relevant, common_checks = self._validated_evidence(
            change=change,
            evidence=selected,
            evaluated_at=now,
        )
        required_kinds = _required_g2_kinds(change.risk_class)
        if change.architecture.interfaces:
            required_kinds.add(EvidenceKind.CONTRACT)
        by_kind = {kind: [item for item in relevant if item.kind is kind] for kind in EvidenceKind}
        checks = list(common_checks)

        for kind in sorted(required_kinds, key=lambda item: item.value):
            passing = [item for item in by_kind[kind] if _evidence_passed(item)]
            checks.append(
                GateCheck(
                    code=f"quality.{kind.value}_evidence",
                    passed=bool(passing),
                    message=f"Passing {kind.value} evidence is required for this risk profile.",
                    actual=len(passing),
                    threshold=1,
                    evidence_ids=tuple(item.evidence_id for item in passing),
                )
            )

        if EvidenceKind.COVERAGE in required_kinds:
            coverage = _newest_passing(by_kind[EvidenceKind.COVERAGE])
            checks.extend(self._coverage_checks(coverage))

        if EvidenceKind.MUTATION in required_kinds:
            mutation = _newest_passing(by_kind[EvidenceKind.MUTATION])
            score = _decimal_metric(mutation, "mutation_score")
            checks.append(
                GateCheck(
                    code="quality.mutation_score",
                    passed=score is not None and score >= self.policy.min_mutation_score,
                    message="Changed eligible modules must meet the mutation threshold.",
                    actual=str(score) if score is not None else None,
                    threshold=str(self.policy.min_mutation_score),
                    evidence_ids=(mutation.evidence_id,) if mutation else (),
                )
            )

        if EvidenceKind.COMPLEXITY in required_kinds:
            complexity = _newest_passing(by_kind[EvidenceKind.COMPLEXITY])
            maximum = _integer_metric(complexity, "max_cyclomatic_complexity")
            checks.append(
                GateCheck(
                    code="quality.cyclomatic_complexity",
                    passed=(
                        maximum is not None and maximum <= self.policy.max_cyclomatic_complexity
                    ),
                    message="Maximum cyclomatic complexity must remain within policy.",
                    actual=maximum,
                    threshold=self.policy.max_cyclomatic_complexity,
                    evidence_ids=(complexity.evidence_id,) if complexity else (),
                )
            )

        if EvidenceKind.DUPLICATION in required_kinds:
            duplication = _newest_passing(by_kind[EvidenceKind.DUPLICATION])
            ratio = _decimal_metric(duplication, "duplication_ratio")
            checks.append(
                GateCheck(
                    code="quality.duplication_ratio",
                    passed=ratio is not None and ratio <= self.policy.max_duplication_ratio,
                    message="Detected duplication must remain within policy.",
                    actual=str(ratio) if ratio is not None else None,
                    threshold=str(self.policy.max_duplication_ratio),
                    evidence_ids=(duplication.evidence_id,) if duplication else (),
                )
            )

        if EvidenceKind.CONTRACT in required_kinds:
            contract = _newest_passing(by_kind[EvidenceKind.CONTRACT])
            breaking_changes = _integer_metric(contract, "unapproved_breaking_changes")
            checks.append(
                GateCheck(
                    code="quality.api_schema_compatibility",
                    passed=breaking_changes == 0,
                    message="Contract checks must report no unapproved breaking changes.",
                    actual=breaking_changes,
                    threshold=0,
                    evidence_ids=(contract.evidence_id,) if contract else (),
                )
            )

        tests = [item for item in by_kind[EvidenceKind.TEST] if _evidence_passed(item)]
        covered_requirements = {identifier for item in tests for identifier in item.requirement_ids}
        covered_scenarios = {identifier for item in tests for identifier in item.scenario_ids}
        covered_tasks = {identifier for item in tests for identifier in item.task_ids}
        expected_requirements = {item.requirement_id for item in change.requirements}
        expected_scenarios = {item.scenario_id for item in change.scenarios}
        expected_tasks = {item.task_id for item in change.tasks}
        observed_layers = {layer for item in tests for layer in item.test_layers}
        expected_layers = _required_test_layers(change)
        passed_tests = sum(_integer_metric(item, "passed") or 0 for item in tests)
        failed_tests = sum(_integer_metric(item, "failed") or 0 for item in tests)
        incomplete_tests = any(item.metrics.get("incomplete") is not False for item in tests)
        checks.extend(
            [
                GateCheck(
                    code="quality.tests_executed",
                    passed=passed_tests > 0 and failed_tests == 0 and not incomplete_tests,
                    message="Test evidence must report executed tests, zero failures, and a complete run.",
                    actual={
                        "passed": passed_tests,
                        "failed": failed_tests,
                        "incomplete": incomplete_tests,
                    },
                    threshold={"passed": ">0", "failed": 0, "incomplete": False},
                    evidence_ids=tuple(item.evidence_id for item in tests),
                ),
                GateCheck(
                    code="traceability.requirement_test_coverage",
                    passed=expected_requirements <= covered_requirements,
                    message="Every requirement must be referenced by passing executable test evidence.",
                    actual=sorted(covered_requirements),
                    threshold=sorted(expected_requirements),
                    evidence_ids=tuple(item.evidence_id for item in tests),
                ),
                GateCheck(
                    code="traceability.scenario_test_coverage",
                    passed=expected_scenarios <= covered_scenarios,
                    message="Every acceptance scenario must be referenced by passing test evidence.",
                    actual=sorted(covered_scenarios),
                    threshold=sorted(expected_scenarios),
                    evidence_ids=tuple(item.evidence_id for item in tests),
                ),
                GateCheck(
                    code="traceability.task_test_coverage",
                    passed=expected_tasks <= covered_tasks,
                    message="Every implementation task must be referenced by passing test evidence.",
                    actual=sorted(covered_tasks),
                    threshold=sorted(expected_tasks),
                    evidence_ids=tuple(item.evidence_id for item in tests),
                ),
                GateCheck(
                    code="quality.test_portfolio",
                    passed=expected_layers <= observed_layers,
                    message="The risk-selected test portfolio must have executable evidence.",
                    actual=sorted(layer.value for layer in observed_layers),
                    threshold=sorted(layer.value for layer in expected_layers),
                    evidence_ids=tuple(item.evidence_id for item in tests),
                ),
            ]
        )

        drift = _newest_passing(by_kind[EvidenceKind.DRIFT])
        if drift is not None:
            placeholders = _integer_metric(drift, "production_placeholders")
            ambiguity = _integer_metric(drift, "unresolved_ambiguities")
            checks.extend(
                [
                    GateCheck(
                        code="quality.no_production_placeholders",
                        passed=placeholders == 0,
                        message="Production paths must not contain unapproved placeholders.",
                        actual=placeholders,
                        threshold=0,
                        evidence_ids=(drift.evidence_id,),
                    ),
                    GateCheck(
                        code="quality.no_unresolved_spec_ambiguity",
                        passed=ambiguity == 0,
                        message="No unresolved ambiguity markers may remain at implementation completion.",
                        actual=ambiguity,
                        threshold=0,
                        evidence_ids=(drift.evidence_id,),
                    ),
                ]
            )

        architecture = _newest_passing(by_kind[EvidenceKind.ARCHITECTURE])
        if EvidenceKind.ARCHITECTURE in required_kinds:
            violations = _integer_metric(architecture, "boundary_violations")
            checks.append(
                GateCheck(
                    code="quality.architecture_boundaries",
                    passed=violations == 0,
                    message="Architecture tests must report no dependency-boundary violations.",
                    actual=violations,
                    threshold=0,
                    evidence_ids=(architecture.evidence_id,) if architecture else (),
                )
            )

        return self._result(
            gate_id="G2",
            change=change,
            checks=checks,
            evaluated_at=now,
            evidence=selected,
        )

    def evaluate_g3(
        self,
        *,
        change: ChangePackage,
        evidence: list[CommandEvidence],
        evaluated_at: datetime | None = None,
        orchestration_manifest: OrchestrationManifest | None = None,
        execution_receipt: ExecutionReceipt | None = None,
    ) -> DevelopmentGateResult:
        """Evaluate independent semantic review and bounded fix-loop completion."""
        now = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
        selected = [item for item in evidence if item.kind is EvidenceKind.REVIEW]
        reviews, checks = self._validated_evidence(
            change=change,
            evidence=selected,
            evaluated_at=now,
        )
        passing = [item for item in reviews if _evidence_passed(item)]
        checks.append(
            GateCheck(
                code="review.independent_review_present",
                passed=bool(passing),
                message="A completed independent review of the actual diff is required.",
                actual=len(passing),
                threshold=1,
                evidence_ids=tuple(item.evidence_id for item in passing),
            )
        )

        review = _newest_passing(passing)
        metrics = review.metrics if review else {}
        runtime_validation = None
        if orchestration_manifest is not None or execution_receipt is not None:
            if orchestration_manifest is None or execution_receipt is None:
                raise ValueError(
                    "orchestration_manifest and execution_receipt must be supplied together"
                )
            assert orchestration_manifest is not None
            assert execution_receipt is not None
            runtime_validation = validate_runtime_review_history(
                orchestration_manifest,
                execution_receipt,
                require_clean=True,
                evaluated_at=now,
            )
        final_runtime_review = (
            None if runtime_validation is None else runtime_validation.final_review
        )
        if runtime_validation is None:
            independent = metrics.get("independent") is True
            whole_change = metrics.get("whole_change") is True
            blocking_findings = _coerce_non_negative_int(metrics.get("blocking_findings"))
            review_rounds = _coerce_non_negative_int(metrics.get("review_rounds"))
            reviewer_family = metrics.get("reviewer_model_family")
            maximum_review_rounds = 3
        else:
            assert execution_receipt is not None
            assert orchestration_manifest is not None
            independent = bool(runtime_validation.passed and final_runtime_review is not None)
            whole_change = bool(
                final_runtime_review is not None
                and final_runtime_review.semantic_outcome.whole_change
            )
            blocking_findings = (
                None
                if final_runtime_review is None
                else len(final_runtime_review.semantic_outcome.finding_set.findings)
            )
            review_rounds = len(execution_receipt.review_history)
            reviewer_family = (
                None if final_runtime_review is None else final_runtime_review.reviewer_model_family
            )
            maximum_review_rounds = orchestration_manifest.limits.max_review_rounds
        material = change.risk_class in {
            RiskClass.STANDARD,
            RiskClass.HIGH,
            RiskClass.TOOL_ENABLED_AGENT,
        }
        implementation_family = change.implementation_model_family
        diverse = bool(
            isinstance(reviewer_family, str)
            and reviewer_family
            and isinstance(implementation_family, str)
            and implementation_family
            and reviewer_family != implementation_family
        )

        checks.extend(
            [
                *(
                    [
                        GateCheck(
                            code="review.runtime_history_binding",
                            passed=runtime_validation.passed,
                            message=(
                                "Review rounds and fixes must be the exact authenticated "
                                "runtime history."
                            ),
                            actual={"reason_codes": runtime_validation.reason_codes},
                            threshold={"reason_codes": ()},
                            evidence_ids=(review.evidence_id,) if review else (),
                        )
                    ]
                    if runtime_validation is not None
                    else []
                ),
                *(
                    [
                        GateCheck(
                            code="review.runtime_evidence_binding",
                            passed=(
                                review is not None
                                and final_runtime_review is not None
                                and review.artifacts.get("report_sha256")
                                == final_runtime_review.output_digest
                                and metrics.get("orchestration_manifest_digest")
                                == orchestration_manifest.digest
                                and metrics.get("orchestration_run_id")
                                == orchestration_manifest.run_id
                                and metrics.get("review_assignment_id")
                                == final_runtime_review.review_assignment_id
                                and metrics.get("review_outcome_digest")
                                == final_runtime_review.outcome_digest
                                and metrics.get("review_output_digest")
                                == final_runtime_review.output_digest
                                and _coerce_non_negative_int(metrics.get("review_rounds"))
                                == len(execution_receipt.review_history)
                                and _string_tuple_metric(metrics.get("review_round_output_digests"))
                                == tuple(
                                    item.output_digest for item in execution_receipt.review_history
                                )
                                and _string_tuple_metric(metrics.get("fix_round_output_digests"))
                                == tuple(
                                    item.remediation.output_digest
                                    for item in execution_receipt.review_history
                                    if item.remediation is not None
                                )
                            ),
                            message=(
                                "The G3 report must bind the exact final runtime output and "
                                "ordered fix/re-review history."
                            ),
                            actual={
                                "evidence_id": None if review is None else review.evidence_id,
                                "runtime_rounds": len(execution_receipt.review_history),
                            },
                            threshold={"exact_runtime_binding": True},
                            evidence_ids=(review.evidence_id,) if review else (),
                        )
                    ]
                    if runtime_validation is not None
                    and orchestration_manifest is not None
                    and execution_receipt is not None
                    else []
                ),
                GateCheck(
                    code="review.role_independence",
                    passed=independent,
                    message="The reviewer must be independent from the implementation role.",
                    actual=independent,
                    threshold=True,
                    evidence_ids=(review.evidence_id,) if review else (),
                ),
                GateCheck(
                    code="review.whole_change_reviewed",
                    passed=whole_change,
                    message="Review must cover the complete change, not only individual tasks.",
                    actual=whole_change,
                    threshold=True,
                    evidence_ids=(review.evidence_id,) if review else (),
                ),
                GateCheck(
                    code="review.no_blocking_findings",
                    passed=(
                        blocking_findings == 0
                        and (
                            final_runtime_review is None
                            or final_runtime_review.semantic_outcome.verdict is ReviewVerdict.CLEAN
                        )
                    ),
                    message="All grounded blocking findings must be resolved and re-reviewed.",
                    actual=blocking_findings,
                    threshold=0,
                    evidence_ids=(review.evidence_id,) if review else (),
                ),
                GateCheck(
                    code="review.bounded_fix_loop",
                    passed=(
                        review_rounds is not None and 1 <= review_rounds <= maximum_review_rounds
                    ),
                    message="Review must complete within the bounded fix-loop policy.",
                    actual=review_rounds,
                    threshold={"min": 1, "max": maximum_review_rounds},
                    evidence_ids=(review.evidence_id,) if review else (),
                ),
                GateCheck(
                    code="review.provider_diversity",
                    passed=(
                        not material
                        or not self.policy.require_provider_diverse_review_for_material_changes
                        or diverse
                    ),
                    message="Material changes require a different model family for independent review.",
                    actual=reviewer_family,
                    threshold=(
                        "known implementation family and a different reviewer family"
                        if not implementation_family
                        else f"different from {implementation_family}"
                    ),
                    evidence_ids=(review.evidence_id,) if review else (),
                ),
            ]
        )
        return self._result(
            gate_id="G3",
            change=change,
            checks=checks,
            evaluated_at=now,
            evidence=selected,
        )

    def _coverage_checks(self, evidence: CommandEvidence | None) -> list[GateCheck]:
        thresholds = {
            "line_coverage": self.policy.min_line_coverage,
            "diff_coverage": self.policy.min_diff_coverage,
            "branch_coverage": self.policy.min_branch_coverage,
            "critical_module_coverage": self.policy.min_critical_coverage,
        }
        checks: list[GateCheck] = []
        for metric, threshold in thresholds.items():
            value = _decimal_metric(evidence, metric)
            checks.append(
                GateCheck(
                    code=f"quality.{metric}",
                    passed=value is not None and value >= threshold,
                    message=f"{metric.replace('_', ' ').capitalize()} must meet policy.",
                    actual=str(value) if value is not None else None,
                    threshold=str(threshold),
                    evidence_ids=(evidence.evidence_id,) if evidence else (),
                )
            )
        return checks

    def _validated_evidence(
        self,
        *,
        change: ChangePackage,
        evidence: list[CommandEvidence],
        evaluated_at: datetime,
    ) -> tuple[list[CommandEvidence], list[GateCheck]]:
        relevant: list[CommandEvidence] = []
        checks: list[GateCheck] = []
        maximum_age = timedelta(seconds=self.policy.evidence_max_age_seconds)
        future_skew = timedelta(seconds=self.policy.future_clock_skew_seconds)
        for item in sorted(evidence, key=lambda value: value.evidence_id):
            expected_digest: str | None
            try:
                expected_digest = item.computed_digest
            except (TypeError, ValueError):
                expected_digest = None
            validated = item.strict_revalidate()
            integrity_ok = validated is not None
            checks.append(
                GateCheck(
                    code="evidence.integrity",
                    passed=integrity_ok,
                    message=(
                        "Evidence must pass strict canonical schema and digest "
                        "revalidation at the evaluator boundary."
                    ),
                    actual=item.evidence_sha256,
                    threshold=expected_digest,
                    evidence_ids=(item.evidence_id,),
                )
            )
            if validated is None:
                continue
            item = validated
            binding_ok = (
                item.change_id == change.change_id
                and item.source_revision == change.source_revision
                and item.change_digest == change.digest
            )
            freshness_ok = (
                evaluated_at - maximum_age <= item.generated_at <= evaluated_at + future_skew
            )
            completion_ok = _evidence_passed(item)
            environment_ok = item.environment in self.policy.allowed_evidence_environments
            report_uri = item.artifacts.get("report_uri")
            report_sha256 = item.artifacts.get("report_sha256")
            report_ok = not self.policy.require_report_uri or (
                isinstance(report_uri, str)
                and bool(report_uri.strip())
                and isinstance(report_sha256, str)
                and re.fullmatch(r"[0-9a-f]{64}", report_sha256) is not None
            )
            checks.extend(
                [
                    GateCheck(
                        code="evidence.source_binding",
                        passed=binding_ok,
                        message="Evidence must bind the canonical change and source revision.",
                        actual={
                            "change_id": item.change_id,
                            "source_revision": item.source_revision,
                            "change_digest": item.change_digest,
                        },
                        threshold={
                            "change_id": change.change_id,
                            "source_revision": change.source_revision,
                            "change_digest": change.digest,
                        },
                        evidence_ids=(item.evidence_id,),
                    ),
                    GateCheck(
                        code="evidence.freshness",
                        passed=freshness_ok,
                        message="Evidence must be fresh and not materially future-dated.",
                        actual=item.generated_at.isoformat(),
                        threshold={
                            "oldest": (evaluated_at - maximum_age).isoformat(),
                            "newest": (evaluated_at + future_skew).isoformat(),
                        },
                        evidence_ids=(item.evidence_id,),
                    ),
                    GateCheck(
                        code="evidence.environment",
                        passed=environment_ok,
                        message="Evidence must be produced in an organization-approved environment.",
                        actual=item.environment,
                        threshold=list(self.policy.allowed_evidence_environments),
                        evidence_ids=(item.evidence_id,),
                    ),
                    GateCheck(
                        code="evidence.report_uri",
                        passed=report_ok,
                        message="Evidence must preserve a content-addressed report reference.",
                        actual={"report_uri": report_uri, "report_sha256": report_sha256},
                        threshold={
                            "report_uri": "non-empty",
                            "report_sha256": "lowercase SHA-256",
                        },
                        evidence_ids=(item.evidence_id,),
                    ),
                    GateCheck(
                        code="evidence.command_succeeded",
                        passed=completion_ok,
                        message="Incomplete or non-zero command evidence fails closed.",
                        actual={"status": item.status.value, "exit_code": item.exit_code},
                        threshold={"status": "passed", "exit_code": 0},
                        evidence_ids=(item.evidence_id,),
                    ),
                ]
            )
            if binding_ok and freshness_ok:
                relevant.append(item)
        return relevant, checks

    def _result(
        self,
        *,
        gate_id: Literal["G0", "G1", "G2", "G3"],
        change: ChangePackage,
        checks: list[GateCheck],
        evaluated_at: datetime | None,
        applicable: bool = True,
        evidence: Sequence[CommandEvidence] = (),
    ) -> DevelopmentGateResult:
        now = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
        ordered = sorted(
            checks,
            key=lambda item: (item.code, ",".join(item.evidence_ids), item.message),
        )
        status = (
            GateStatus.NOT_APPLICABLE
            if not applicable
            else GateStatus.PASS
            if all(check.passed for check in ordered)
            else GateStatus.FAIL
        )
        return DevelopmentGateResult.create(
            gate_id=gate_id,
            status=status,
            change=change,
            policy_digest=self.policy.digest,
            evaluated_at=now,
            checks=ordered,
            evidence=evidence,
        )


def _required_g2_kinds(risk_class: RiskClass) -> set[EvidenceKind]:
    if risk_class is RiskClass.DOCUMENTATION:
        return {EvidenceKind.LINT, EvidenceKind.TEST, EvidenceKind.DRIFT}
    if risk_class is RiskClass.SIMPLE:
        return {
            EvidenceKind.BUILD,
            EvidenceKind.LINT,
            EvidenceKind.TEST,
            EvidenceKind.COVERAGE,
        }
    required = {
        EvidenceKind.BUILD,
        EvidenceKind.FORMAT,
        EvidenceKind.LINT,
        EvidenceKind.TYPECHECK,
        EvidenceKind.COMPLEXITY,
        EvidenceKind.DUPLICATION,
        EvidenceKind.TEST,
        EvidenceKind.COVERAGE,
        EvidenceKind.ARCHITECTURE,
        EvidenceKind.DRIFT,
    }
    if risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}:
        required.add(EvidenceKind.MUTATION)
    return required


_G2_EVIDENCE_KINDS = frozenset(
    {
        EvidenceKind.BUILD,
        EvidenceKind.FORMAT,
        EvidenceKind.LINT,
        EvidenceKind.TYPECHECK,
        EvidenceKind.COMPLEXITY,
        EvidenceKind.DUPLICATION,
        EvidenceKind.CONTRACT,
        EvidenceKind.TEST,
        EvidenceKind.COVERAGE,
        EvidenceKind.MUTATION,
        EvidenceKind.ARCHITECTURE,
        EvidenceKind.DRIFT,
    }
)


def _required_test_layers(change: ChangePackage) -> set[VerificationLayer]:
    """Select test depth from risk while keeping the layer meanings stable."""
    if change.risk_class is RiskClass.DOCUMENTATION:
        return {VerificationLayer.DOCUMENTATION}

    required = {
        VerificationLayer.UNIT,
        VerificationLayer.PROPERTY,
        VerificationLayer.INTEGRATION,
    }
    if change.architecture.interfaces:
        required.add(VerificationLayer.CONTRACT)
    if change.risk_class in {
        RiskClass.STANDARD,
        RiskClass.HIGH,
        RiskClass.TOOL_ENABLED_AGENT,
    }:
        required.update({VerificationLayer.END_TO_END, VerificationLayer.ARCHITECTURE})
    if change.risk_class in {RiskClass.HIGH, RiskClass.TOOL_ENABLED_AGENT}:
        required.update({VerificationLayer.SECURITY, VerificationLayer.PERFORMANCE})
    if change.risk_class is RiskClass.TOOL_ENABLED_AGENT:
        required.add(VerificationLayer.AGENT_SAFETY)
    return required


def _evidence_passed(evidence: CommandEvidence) -> bool:
    return evidence.status is EvidenceStatus.PASSED and evidence.exit_code == 0


def _newest_passing(evidence: list[CommandEvidence]) -> CommandEvidence | None:
    passing = [item for item in evidence if _evidence_passed(item)]
    return max(passing, key=lambda item: item.generated_at) if passing else None


def _decimal_metric(evidence: CommandEvidence | None, name: str) -> Decimal | None:
    if evidence is None:
        return None
    value = evidence.metrics.get(name)
    try:
        decimal_value = Decimal(str(value))
    except Exception:
        return None
    if not decimal_value.is_finite() or not Decimal("0") <= decimal_value <= Decimal("1"):
        return None
    return decimal_value


def _integer_metric(evidence: CommandEvidence | None, name: str) -> int | None:
    if evidence is None:
        return None
    return _coerce_non_negative_int(evidence.metrics.get(name))


def _coerce_non_negative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return int(value)


def _string_tuple_metric(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list | tuple) or any(not isinstance(item, str) for item in value):
        return None
    return tuple(value)


def _issue_check(issue: ContractIssue) -> GateCheck:
    return GateCheck(
        code=issue.code,
        passed=False,
        message=issue.message,
        actual=issue.location,
    )
