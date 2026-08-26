"""Canonical artifact model (ARCHITECTURE.md §2).

Every model is pydantic v2 with ``extra="forbid"`` and is JSON-serialisable. Identifiers are
validated through :mod:`aisdlc.ids`. Nothing in this module depends on a harness, a model
provider, or one of the governance libraries.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aisdlc import ids
from aisdlc.ids import (
    AdrId,
    AssumptionId,
    ChangeId,
    EvidenceId,
    FindingId,
    InterfaceId,
    OpenQuestionId,
    RequirementId,
    ScenarioId,
    TaskId,
    ThreatId,
)

__all__ = [
    "ArtifactModel",
    "utcnow",
    "RiskClass",
    "Kernel",
    "Intent",
    "RequirementKind",
    "Priority",
    "Scenario",
    "Requirement",
    "Assumption",
    "QuestionStatus",
    "OpenQuestion",
    "AdrStatus",
    "ArchitectureDecision",
    "InterfaceKind",
    "Interface",
    "ThreatCategory",
    "Severity",
    "ThreatStatus",
    "Threat",
    "Mitigation",
    "ToolDataManifest",
    "ThreatModel",
    "Wave",
    "Plan",
    "TaskStatus",
    "ModelTier",
    "Verification",
    "Task",
    "EvidenceKind",
    "EvidenceStatus",
    "EvidenceBase",
    "Coverage",
    "Mutation",
    "TestEvidence",
    "Finding",
    "ReviewVerdict",
    "ReviewEvidence",
    "ScanResult",
    "PyritSummary",
    "SafetySummary",
    "SecurityEvidence",
    "PERFORMANCE_TARGET_KEYS",
    "PerformanceEvidence",
    "CostEvidence",
    "AuditEvidence",
    "Evidence",
    "EvidenceBundle",
    "GateId",
    "GateDepth",
    "GateResult",
    "Signature",
    "FinalVerdict",
    "ChangeState",
    "ScenarioFile",
    "ChangePackage",
]


def utcnow() -> datetime:
    """Timezone-aware current time (UTC)."""
    return datetime.now(UTC)


class ArtifactModel(BaseModel):
    """Base class for every canonical artifact: strict, forbid unknown fields."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=False)


# --------------------------------------------------------------------------------------
# Intent
# --------------------------------------------------------------------------------------


class RiskClass(StrEnum):
    """Risk classification of a change; selects the gate depth profile (§3).

    * ``docs_only`` — documentation/comments only; G0, G2 (lint/links), light G3.
    * ``low`` — isolated, well-tested code with no security surface.
    * ``standard`` — default for product code.
    * ``high`` — touches auth, payments, PII, infrastructure, or shared data.
    * ``critical`` — safety- or compliance-critical; all gates at full depth.
    * ``ai_agent`` — introduces or changes an AI agent; all gates plus PyRIT trials and
      tool/data manifest validation.
    """

    DOCS_ONLY = "docs_only"
    LOW = "low"
    STANDARD = "standard"
    HIGH = "high"
    CRITICAL = "critical"
    AI_AGENT = "ai_agent"


class Kernel(ArtifactModel):
    """BMAD five-part kernel: the minimum intent a change must state."""

    why: str = Field(default="", description="Motivation: the problem or opportunity.")
    capabilities: list[str] = Field(default_factory=list, description="What the change enables.")
    constraints: list[str] = Field(default_factory=list, description="Hard limits to honour.")
    non_goals: list[str] = Field(default_factory=list, description="Explicitly out of scope.")
    success_signal: str = Field(default="", description="Observable signal that the change worked.")

    def is_complete(self) -> bool:
        """``True`` when every kernel part is filled in."""
        return bool(
            self.why.strip()
            and self.capabilities
            and self.non_goals
            and self.success_signal.strip()
        )


class Intent(ArtifactModel):
    """``intent.md`` front-matter: what the change is and who owns it."""

    id: ChangeId
    title: str
    kernel: Kernel = Field(default_factory=Kernel)
    owner: str | None = Field(default=None, description="Accountable human owner.")
    risk_class: RiskClass = RiskClass.STANDARD
    stakeholders: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    labels: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Requirements and scenarios
# --------------------------------------------------------------------------------------


class RequirementKind(StrEnum):
    """Functional or non-functional requirement."""

    FUNCTIONAL = "functional"
    NON_FUNCTIONAL = "non_functional"


class Priority(StrEnum):
    """MoSCoW priority."""

    MUST = "must"
    SHOULD = "should"
    COULD = "could"
    WONT = "wont"


class Scenario(ArtifactModel):
    """Acceptance scenario in ``WHEN … THEN …`` or ``Given/When/Then`` form.

    Either the structured fields (``when`` and ``then``, optionally ``given``) or ``raw``
    text must be provided; both may be present. :meth:`render` yields canonical text.
    """

    id: ScenarioId
    name: str = ""
    given: str | None = None
    when: str | None = None
    then: str | None = None
    raw: str = Field(default="", description="Verbatim scenario text as written by humans.")

    @model_validator(mode="after")
    def _require_content(self) -> Scenario:
        if not (self.when and self.then) and not self.raw.strip():
            raise ValueError(f"scenario {self.id} needs when+then fields or raw text")
        return self

    @property
    def requirement_id(self) -> str:
        """The requirement this scenario belongs to (encoded in the id)."""
        return ids.scenario_parent(self.id)

    def render(self) -> str:
        """Canonical text: structured form when available, else ``raw``."""
        if self.when and self.then:
            parts: list[str] = []
            if self.given:
                parts.append(f"GIVEN {self.given}")
            parts.append(f"WHEN {self.when}")
            parts.append(f"THEN {self.then}")
            return "\n".join(parts)
        return self.raw

    @property
    def text(self) -> str:
        """All human-readable text of the scenario (structured + raw), for analysis."""
        rendered = self.render()
        if self.raw.strip() and rendered != self.raw:
            return f"{rendered}\n{self.raw}"
        return rendered


class Requirement(ArtifactModel):
    """A single normative requirement (SHALL/MUST or EARS) with its scenarios."""

    id: RequirementId
    text: str
    kind: RequirementKind = RequirementKind.FUNCTIONAL
    priority: Priority = Priority.MUST
    scenarios: list[Scenario] = Field(default_factory=list)
    rationale: str | None = None
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _scenarios_belong_here(self) -> Requirement:
        seen: set[str] = set()
        for scenario in self.scenarios:
            if scenario.requirement_id != self.id:
                raise ValueError(f"scenario {scenario.id} does not belong to requirement {self.id}")
            if scenario.id in seen:
                raise ValueError(f"duplicate scenario id {scenario.id} in {self.id}")
            seen.add(scenario.id)
        return self


# --------------------------------------------------------------------------------------
# Assumptions and open questions
# --------------------------------------------------------------------------------------


class Assumption(ArtifactModel):
    """Something taken as true without evidence; must be visible and owned."""

    id: AssumptionId
    text: str
    owner: str | None = None
    validated: bool = False
    source: str | None = None


class QuestionStatus(StrEnum):
    """Lifecycle of an open question."""

    OPEN = "open"
    RESOLVED = "resolved"


class OpenQuestion(ArtifactModel):
    """A question that must be answered; ``blocking`` ones fail G0 while open."""

    id: OpenQuestionId
    question: str
    status: QuestionStatus = QuestionStatus.OPEN
    blocking: bool = False
    owner: str | None = None
    decision: str | None = None
    resolved_at: datetime | None = None

    @model_validator(mode="after")
    def _resolved_needs_decision(self) -> OpenQuestion:
        if self.status is QuestionStatus.RESOLVED and not (self.decision or "").strip():
            raise ValueError(f"{self.id} is resolved but records no decision")
        return self

    @property
    def is_open_blocking(self) -> bool:
        """``True`` when the question is open and blocking."""
        return self.blocking and self.status is QuestionStatus.OPEN


# --------------------------------------------------------------------------------------
# Architecture
# --------------------------------------------------------------------------------------


class AdrStatus(StrEnum):
    """ADR lifecycle (MADR conventions)."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    DEPRECATED = "deprecated"


class ArchitectureDecision(ArtifactModel):
    """``architecture/decisions/ADR-nnnn.md`` front-matter."""

    id: AdrId
    title: str
    status: AdrStatus = AdrStatus.PROPOSED
    context: str = ""
    decision: str = ""
    consequences: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    supersedes: AdrId | None = None
    date: datetime | None = None
    deciders: list[str] = Field(default_factory=list)


class InterfaceKind(StrEnum):
    """Kind of interface contract."""

    API = "api"
    EVENT = "event"
    CLI = "cli"
    LIBRARY = "library"
    DATA = "data"
    UI = "ui"


class Interface(ArtifactModel):
    """``architecture/interfaces/IFC-nnn.md`` front-matter."""

    id: InterfaceId
    name: str
    kind: InterfaceKind = InterfaceKind.API
    description: str = ""
    provider: str | None = None
    consumers: list[str] = Field(default_factory=list)
    contract: str | None = Field(default=None, description="Path/URI of the contract or inline.")
    version: str | None = None


class ThreatCategory(StrEnum):
    """STRIDE plus agent-specific categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SUPPLY_CHAIN = "supply_chain"
    OTHER = "other"


class Severity(StrEnum):
    """Severity ladder shared by threats and findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank (info=0 … critical=4) for comparisons."""
        return list(Severity).index(self)


class ThreatStatus(StrEnum):
    """Whether a threat has been handled."""

    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


class Threat(ArtifactModel):
    """A single threat in the threat model."""

    id: ThreatId
    title: str
    description: str = ""
    category: ThreatCategory = ThreatCategory.OTHER
    severity: Severity = Severity.MEDIUM
    assets: list[str] = Field(default_factory=list)
    mitigation_ids: list[str] = Field(default_factory=list)
    status: ThreatStatus = ThreatStatus.OPEN

    @property
    def is_unresolved_high_risk(self) -> bool:
        """``True`` for open threats of high or critical severity (blocks G1)."""
        return self.status is ThreatStatus.OPEN and self.severity.rank >= Severity.HIGH.rank


class Mitigation(ArtifactModel):
    """A control that addresses one or more threats."""

    id: str
    description: str
    threat_ids: list[ThreatId] = Field(default_factory=list)
    verified: bool = False


class ToolDataManifest(ArtifactModel):
    """Declared tools, data sources and network egress of an agentic change.

    Compared by ``security.manifest`` with observed behaviour from the audit log.
    """

    tools: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    network_egress: list[str] = Field(default_factory=list)


class ThreatModel(ArtifactModel):
    """``architecture/threat-model.md`` front-matter."""

    assets: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    tool_data_manifest: ToolDataManifest = Field(default_factory=ToolDataManifest)

    @model_validator(mode="after")
    def _unique_ids(self) -> ThreatModel:
        threat_ids = [t.id for t in self.threats]
        if len(set(threat_ids)) != len(threat_ids):
            raise ValueError("duplicate threat ids in threat model")
        mitigation_ids = [m.id for m in self.mitigations]
        if len(set(mitigation_ids)) != len(mitigation_ids):
            raise ValueError("duplicate mitigation ids in threat model")
        known = set(threat_ids)
        for mitigation in self.mitigations:
            for tid in mitigation.threat_ids:
                if tid not in known:
                    raise ValueError(f"mitigation {mitigation.id} references unknown {tid}")
        return self

    def unresolved_high_risk(self) -> list[Threat]:
        """Open threats of high/critical severity."""
        return [t for t in self.threats if t.is_unresolved_high_risk]


# --------------------------------------------------------------------------------------
# Plan and tasks
# --------------------------------------------------------------------------------------


class Wave(ArtifactModel):
    """A set of tasks that can run in parallel; waves execute in index order."""

    index: int = Field(ge=0)
    task_ids: list[TaskId] = Field(default_factory=list)
    checkpoint: bool = Field(default=False, description="Human checkpoint after this wave.")
    description: str = ""


class Plan(ArtifactModel):
    """``plan.md`` front-matter."""

    summary: str = ""
    waves: list[Wave] = Field(default_factory=list)
    approved_by: str | None = None
    approved_at: datetime | None = None

    @model_validator(mode="after")
    def _waves_consistent(self) -> Plan:
        indices = [w.index for w in self.waves]
        if indices != sorted(indices) or len(set(indices)) != len(indices):
            raise ValueError("wave indices must be strictly increasing")
        seen: set[str] = set()
        for wave in self.waves:
            for tid in wave.task_ids:
                if tid in seen:
                    raise ValueError(f"task {tid} appears in more than one wave")
                seen.add(tid)
        return self

    def wave_of(self, task_id: str) -> int | None:
        """Index of the wave containing *task_id*, if any."""
        for wave in self.waves:
            if task_id in wave.task_ids:
                return wave.index
        return None

    @property
    def task_ids(self) -> list[str]:
        """All task ids across waves, in wave order."""
        return [tid for wave in self.waves for tid in wave.task_ids]


class TaskStatus(StrEnum):
    """Task lifecycle."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class ModelTier(StrEnum):
    """Routing tier hint (§5)."""

    LOW = "low"
    STANDARD = "standard"
    HIGH = "high"
    INDEPENDENT_REVIEW = "independent_review"
    ESCALATION = "escalation"

    @property
    def rank(self) -> int:
        """Ordering used by policy narrowing (low < standard < high < … < escalation)."""
        return list(ModelTier).index(self)


class Verification(ArtifactModel):
    """Executable verification for a task: a command and its expected outcome."""

    command: str
    expect_exit_code: int = 0
    expect_output_regex: str | None = None


class Task(ArtifactModel):
    """``tasks.md`` entry."""

    id: TaskId
    title: str
    description: str = ""
    requirement_ids: list[RequirementId] = Field(default_factory=list)
    depends_on: list[TaskId] = Field(default_factory=list)
    verification: Verification | None = None
    status: TaskStatus = TaskStatus.PENDING
    wave: int | None = Field(default=None, ge=0)
    model_tier: ModelTier | None = Field(default=None, description="Routing hint, not a mandate.")
    files: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _no_self_dependency(self) -> Task:
        if self.id in self.depends_on:
            raise ValueError(f"task {self.id} depends on itself")
        return self


# --------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------


class EvidenceKind(StrEnum):
    """Evidence file kinds under ``evidence/<kind>.json``."""

    TESTS = "tests"
    REVIEWS = "reviews"
    SECURITY = "security"
    PERFORMANCE = "performance"
    COST = "cost"
    AUDIT = "audit"


class EvidenceStatus(StrEnum):
    """``incomplete`` evidence always fails its gate."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class EvidenceBase(ArtifactModel):
    """Fields shared by every evidence record (§2.4)."""

    id: EvidenceId
    kind: EvidenceKind
    commit_sha: str = ""
    environment: str = ""
    produced_by: str = Field(default="", description="Agent/tool and version.")
    started_at: datetime | None = None
    finished_at: datetime | None = None
    report_uri: str | None = None
    status: EvidenceStatus = EvidenceStatus.INCOMPLETE

    @model_validator(mode="after")
    def _id_matches_kind(self) -> EvidenceBase:
        encoded = ids.evidence_kind_of(self.id)
        if encoded != self.kind.value:
            raise ValueError(f"evidence id {self.id} does not match kind {self.kind.value}")
        return self

    @property
    def is_complete(self) -> bool:
        """``True`` only for complete evidence."""
        return self.status is EvidenceStatus.COMPLETE


class Coverage(ArtifactModel):
    """Coverage percentages (0–100)."""

    lines: float | None = Field(default=None, ge=0, le=100)
    branches: float | None = Field(default=None, ge=0, le=100)
    diff_lines: float | None = Field(default=None, ge=0, le=100)


class Mutation(ArtifactModel):
    """Mutation testing result with explicit scope disclosure."""

    score: float | None = Field(default=None, ge=0, le=1)
    scope: list[str] = Field(default_factory=list)
    excluded: list[str] = Field(default_factory=list)


class TestEvidence(EvidenceBase):
    """``evidence/tests.json`` entry."""

    __test__ = False  # not a pytest test class despite the name

    kind: Literal[EvidenceKind.TESTS] = EvidenceKind.TESTS
    command: str = ""
    exit_code: int | None = None
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    coverage: Coverage = Field(default_factory=Coverage)
    mutation: Mutation | None = None

    @property
    def succeeded(self) -> bool:
        """Complete, exit code zero and no failures."""
        return self.is_complete and self.exit_code == 0 and self.failed == 0


class Finding(ArtifactModel):
    """A review finding."""

    id: FindingId
    severity: Severity = Severity.MEDIUM
    grounded: bool = Field(default=False, description="Traced to concrete code/evidence.")
    blocking: bool = False
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    title: str = ""
    detail: str = ""
    overturned: bool = Field(default=False, description="Rejected after human/agent triage.")

    @property
    def is_grounded_blocking(self) -> bool:
        """Blocks G3: grounded, blocking and not overturned."""
        return self.grounded and self.blocking and not self.overturned


class ReviewVerdict(StrEnum):
    """Outcome of a review round."""

    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    REJECTED = "rejected"


class ReviewEvidence(EvidenceBase):
    """``evidence/reviews.json`` entry."""

    kind: Literal[EvidenceKind.REVIEWS] = EvidenceKind.REVIEWS
    reviewer_model_family: str = ""
    implementer_model_family: str = ""
    findings: list[Finding] = Field(default_factory=list)
    verdict: ReviewVerdict = ReviewVerdict.CHANGES_REQUESTED
    round: int = Field(default=1, ge=1)
    scope: list[str] = Field(default_factory=list, description="Files/diff hunks reviewed.")

    @property
    def independent(self) -> bool:
        """Reviewer is a *known* model family different from the implementer's.

        Fails closed: when either family is unrecorded the review cannot be shown to be
        independent (ARCHITECTURE.md §3, G3), so this is ``False``.
        """
        reviewer = self.reviewer_model_family.strip()
        implementer = self.implementer_model_family.strip()
        return bool(reviewer) and bool(implementer) and reviewer != implementer

    def grounded_blocking_findings(self) -> list[Finding]:
        """Findings that block G3."""
        return [f for f in self.findings if f.is_grounded_blocking]


class ScanResult(ArtifactModel):
    """Result of one scanner (SAST/SCA/secrets)."""

    tool: str = ""
    ran: bool = False
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    report_uri: str | None = None


class PyritSummary(ArtifactModel):
    """Summary of a PyRIT campaign (§7)."""

    campaign_id: str
    asr: float = Field(ge=0, le=1)
    undetermined_rate: float = Field(default=0.0, ge=0, le=1)
    complete: bool = False
    baseline_delta: float | None = None
    trials: int = Field(default=0, ge=0)


class SafetySummary(ArtifactModel):
    """Summary of the RAMPART-style safety regression suite.

    ``trials`` counts the trials that produced a verdict across every category;
    ``trials_by_category`` splits them per harm category so G4 can enforce the policy's
    minimum per category. ``undetermined_rate`` is the share of completed trials with no
    verdict — undetermined never counts as a pass.
    """

    asr_by_category: dict[str, float] = Field(default_factory=dict)
    complete: bool = False
    threshold_breaches: list[str] = Field(default_factory=list)
    trials: int = Field(default=0, ge=0, description="Completed trials across categories.")
    trials_by_category: dict[str, int] = Field(default_factory=dict)
    undetermined_rate: float = Field(default=0.0, ge=0, le=1)
    undetermined_by_category: dict[str, float] = Field(default_factory=dict)

    def trials_for(self, category: str) -> int:
        """Completed trials for *category* (falls back to the total when not split)."""
        if self.trials_by_category:
            return self.trials_by_category.get(category, 0)
        return self.trials


class SecurityEvidence(EvidenceBase):
    """``evidence/security.json``."""

    kind: Literal[EvidenceKind.SECURITY] = EvidenceKind.SECURITY
    sast: ScanResult | None = None
    sca: ScanResult | None = None
    secrets: ScanResult | None = None
    sbom_present: bool = False
    provenance_present: bool = False
    critical_open: int = Field(default=0, ge=0)
    high_open: int = Field(default=0, ge=0)
    pyrit: PyritSummary | None = None
    safety_regression: SafetySummary | None = None
    manifest_drift: bool = False

    def scans(self) -> list[ScanResult]:
        """The scanner results that actually ran."""
        return [s for s in (self.sast, self.sca, self.secrets) if s is not None and s.ran]

    @property
    def scan_critical(self) -> int:
        """Critical findings summed over the scans that ran."""
        return sum(s.critical for s in self.scans())

    @property
    def scan_high(self) -> int:
        """High findings summed over the scans that ran."""
        return sum(s.high for s in self.scans())

    @model_validator(mode="after")
    def _open_counts_cover_scans(self) -> SecurityEvidence:
        """``critical_open``/``high_open`` can never be lower than what the scans report.

        The counters are a free field on the record; a hand-edited record that reports
        high findings per scan but ``high_open=0`` would otherwise slip through G4. The
        scan counts are already VEX-adjusted by the supply-chain parser, so raising the
        counters to the scan sums never re-introduces a suppressed finding.
        """
        if self.critical_open < self.scan_critical:
            object.__setattr__(self, "critical_open", self.scan_critical)
        if self.high_open < self.scan_high:
            object.__setattr__(self, "high_open", self.scan_high)
        return self


PERFORMANCE_TARGET_KEYS: tuple[str, ...] = ("p50_target_ms", "p95_target_ms", "throughput_min_rps")
"""``PerformanceEvidence.details`` keys carrying the SLO targets the gate compares against."""


class PerformanceEvidence(EvidenceBase):
    """``evidence/performance.json``.

    ``details`` carries the SLO targets under :data:`PERFORMANCE_TARGET_KEYS`
    (``p50_target_ms``, ``p95_target_ms``, ``throughput_min_rps``) next to any extra
    measurements; G5 recomputes ``slo_met`` from measurements and targets rather than
    trusting the flag.
    """

    kind: Literal[EvidenceKind.PERFORMANCE] = EvidenceKind.PERFORMANCE
    p50_ms: float | None = Field(default=None, ge=0)
    p95_ms: float | None = Field(default=None, ge=0)
    throughput: float | None = Field(default=None, ge=0, description="Requests per second.")
    slo_met: bool = False
    details: dict[str, float] = Field(default_factory=dict)

    @property
    def measured(self) -> bool:
        """At least one latency/throughput measurement is recorded."""
        return any(v is not None for v in (self.p50_ms, self.p95_ms, self.throughput))

    def targets(self) -> dict[str, float]:
        """SLO targets recorded in ``details`` (subset of :data:`PERFORMANCE_TARGET_KEYS`)."""
        return {k: self.details[k] for k in PERFORMANCE_TARGET_KEYS if k in self.details}

    def slo_problems(self) -> list[str]:
        """Why the SLO is not demonstrably met (empty when every recorded target holds).

        Fails closed: no measurement or no target is a problem, and a target without the
        matching measurement is a problem.
        """
        problems: list[str] = []
        if not self.measured:
            problems.append("no latency/throughput measurement recorded")
        targets = self.targets()
        if not targets:
            problems.append(
                "no SLO targets recorded (details: " + ", ".join(PERFORMANCE_TARGET_KEYS) + ")"
            )
            return problems
        checks: tuple[tuple[str, float | None, str, bool], ...] = (
            ("p50_target_ms", self.p50_ms, "p50 latency", True),
            ("p95_target_ms", self.p95_ms, "p95 latency", True),
            ("throughput_min_rps", self.throughput, "throughput", False),
        )
        for key, value, label, upper_bound in checks:
            if key not in targets:
                continue
            target = targets[key]
            if value is None:
                problems.append(f"{label} target {target:g} set but {label} not measured")
            elif upper_bound and value > target:
                problems.append(f"{label} {value:g} ms exceeds target {target:g} ms")
            elif not upper_bound and value < target:
                problems.append(f"{label} {value:g} rps below target {target:g} rps")
        return problems


class CostEvidence(EvidenceBase):
    """``evidence/cost.json`` — ledger extract for this change."""

    kind: Literal[EvidenceKind.COST] = EvidenceKind.COST
    total_cost_usd: float = Field(default=0.0, ge=0)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    cached_tokens: int = Field(default=0, ge=0)
    budget_usd: float | None = Field(default=None, ge=0)
    variance: float | None = Field(
        default=None,
        description="(total - budget) / budget; derived when budget is known and not given.",
    )
    escalations: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _derive_variance(self) -> CostEvidence:
        if self.variance is None and self.budget_usd:
            object.__setattr__(
                self, "variance", (self.total_cost_usd - self.budget_usd) / self.budget_usd
            )
        return self

    @property
    def over_budget(self) -> bool:
        """``True`` when a budget exists and was exceeded."""
        return self.budget_usd is not None and self.total_cost_usd > self.budget_usd


class AuditEvidence(EvidenceBase):
    """``evidence/audit.json`` — privileged tool call summary from the audit log."""

    kind: Literal[EvidenceKind.AUDIT] = EvidenceKind.AUDIT
    entries: int = Field(default=0, ge=0)
    integrity_ok: bool = False
    privileged_calls: int = Field(default=0, ge=0)
    denied_calls: int = Field(default=0, ge=0)
    approvals: int = Field(default=0, ge=0)


Evidence = (
    TestEvidence
    | ReviewEvidence
    | SecurityEvidence
    | PerformanceEvidence
    | CostEvidence
    | AuditEvidence
)
"""Union of all concrete evidence records."""


class EvidenceBundle(ArtifactModel):
    """All evidence of a change package, mirroring ``evidence/*.json``."""

    tests: list[TestEvidence] = Field(default_factory=list)
    reviews: list[ReviewEvidence] = Field(default_factory=list)
    security: SecurityEvidence | None = None
    performance: PerformanceEvidence | None = None
    cost: CostEvidence | None = None
    audit: AuditEvidence | None = None

    def all(self) -> list[Evidence]:
        """Flat list of every evidence record."""
        records: list[Evidence] = [*self.tests, *self.reviews]
        for single in (self.security, self.performance, self.cost, self.audit):
            if single is not None:
                records.append(single)
        return records

    def ids(self) -> list[str]:
        """Ids of every evidence record."""
        return [record.id for record in self.all()]


# --------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------


class GateId(StrEnum):
    """Progressive gates G0..G6 (§3)."""

    G0 = "G0"
    G1 = "G1"
    G2 = "G2"
    G3 = "G3"
    G4 = "G4"
    G5 = "G5"
    G6 = "G6"


class GateDepth(StrEnum):
    """How deep a gate is evaluated for a risk class; never changes its meaning."""

    SKIPPED = "skipped"
    LIGHT = "light"
    STANDARD = "standard"
    DEEP = "deep"

    @property
    def rank(self) -> int:
        """Ordering used by policy narrowing (skipped < light < standard < deep)."""
        return list(GateDepth).index(self)


class GateResult(ArtifactModel):
    """Outcome of evaluating one gate."""

    gate: GateId
    passed: bool
    depth: GateDepth = GateDepth.STANDARD
    reasons: list[str] = Field(default_factory=list)
    evidence_ids: list[EvidenceId] = Field(default_factory=list)


class Signature(ArtifactModel):
    """Signature over the evidence bundle."""

    signer: str
    algorithm: Literal["hmac-sha256", "ed25519"] = "hmac-sha256"
    value: str
    signed_at: datetime | None = None


class FinalVerdict(ArtifactModel):
    """``final-verdict.json``.

    ``fingerprint`` is the package content fingerprint the gates were evaluated against;
    the bundle builder refuses to certify a verdict whose fingerprint no longer matches
    the package (a stale verdict must be re-evaluated, never re-signed).
    """

    change_id: ChangeId
    gate_results: list[GateResult] = Field(default_factory=list)
    overall: bool = False
    signatures: list[Signature] = Field(default_factory=list)
    produced_at: datetime | None = None
    commit_sha: str = ""
    fingerprint: str = Field(default="", description="Package fingerprint when evaluated.")
    bundle_digest: str | None = None

    def result_for(self, gate: GateId) -> GateResult | None:
        """The result of *gate*, if evaluated."""
        for result in self.gate_results:
            if result.gate is gate:
                return result
        return None


# --------------------------------------------------------------------------------------
# Change package aggregate
# --------------------------------------------------------------------------------------


class ChangeState(StrEnum):
    """Workflow state derived purely from the artifacts (never stored separately).

    ``draft`` → ``specified`` → ``planned`` → ``implementing`` → ``verifying`` →
    ``reviewed`` → ``secured`` → ``released``.
    """

    DRAFT = "draft"
    SPECIFIED = "specified"
    PLANNED = "planned"
    IMPLEMENTING = "implementing"
    VERIFYING = "verifying"
    REVIEWED = "reviewed"
    SECURED = "secured"
    RELEASED = "released"

    @property
    def rank(self) -> int:
        """Ordinal position in the lifecycle."""
        return list(ChangeState).index(self)


class ScenarioFile(ArtifactModel):
    """Ownership record for an optional ``scenarios/<name>.md`` file.

    Scenarios listed here live in that file rather than in ``requirements.md``: the file
    is the source of truth for them on load and they are written back to it on save, so
    edits to either side round-trip losslessly.
    """

    requirement_id: RequirementId
    scenario_ids: list[ScenarioId] = Field(default_factory=list)


class ChangePackage(ArtifactModel):
    """In-memory aggregate of everything under ``changes/<change-id>/``.

    ``bodies`` keeps the prose body of each markdown file (keyed by path relative to the
    package root) so that a load/save round trip preserves human text byte-for-byte.
    ``root`` is set by :meth:`load` and excluded from serialisation.
    """

    intent: Intent
    requirements: list[Requirement] = Field(default_factory=list)
    assumptions: list[Assumption] = Field(default_factory=list)
    open_questions: list[OpenQuestion] = Field(default_factory=list)
    decisions: list[ArchitectureDecision] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    threat_model: ThreatModel | None = None
    plan: Plan | None = None
    tasks: list[Task] = Field(default_factory=list)
    evidence: EvidenceBundle = Field(default_factory=EvidenceBundle)
    final_verdict: FinalVerdict | None = None
    bodies: dict[str, str] = Field(default_factory=dict)
    scenario_files: dict[str, ScenarioFile] = Field(
        default_factory=dict,
        description="Scenario files (relative path -> owned scenarios); see ScenarioFile.",
    )
    root: Path | None = Field(default=None, exclude=True)
    base_fingerprint: str | None = Field(default=None, exclude=True)

    @property
    def change_id(self) -> str:
        """The ``CHG-…`` id of this package."""
        return self.intent.id

    def file_owned_scenario_ids(self) -> set[str]:
        """Ids of scenarios that live in ``scenarios/*.md`` rather than ``requirements.md``."""
        return {sid for ref in self.scenario_files.values() for sid in ref.scenario_ids}

    @model_validator(mode="after")
    def _unique_ids(self) -> ChangePackage:
        groups: list[tuple[str, list[Any]]] = [
            ("requirement", self.requirements),
            ("assumption", self.assumptions),
            ("open question", self.open_questions),
            ("decision", self.decisions),
            ("interface", self.interfaces),
            ("task", self.tasks),
        ]
        for label, items in groups:
            seen: set[str] = set()
            for item in items:
                item_id = str(item.id)
                if item_id in seen:
                    raise ValueError(f"duplicate {label} id {item_id}")
                seen.add(item_id)
        return self

    # -- lookups -----------------------------------------------------------------------

    def requirement(self, requirement_id: str) -> Requirement | None:
        """Requirement by id."""
        return next((r for r in self.requirements if r.id == requirement_id), None)

    def task(self, task_id: str) -> Task | None:
        """Task by id."""
        return next((t for t in self.tasks if t.id == task_id), None)

    def scenarios(self) -> list[Scenario]:
        """All scenarios across requirements."""
        return [s for r in self.requirements for s in r.scenarios]

    def all_ids(self) -> list[str]:
        """Every artifact id in the package (for ``ids.next_id``)."""
        collected: list[str] = [self.intent.id]
        for requirement in self.requirements:
            collected.append(requirement.id)
            collected.extend(s.id for s in requirement.scenarios)
        collected.extend(a.id for a in self.assumptions)
        collected.extend(q.id for q in self.open_questions)
        collected.extend(d.id for d in self.decisions)
        collected.extend(i.id for i in self.interfaces)
        if self.threat_model is not None:
            collected.extend(t.id for t in self.threat_model.threats)
        collected.extend(t.id for t in self.tasks)
        collected.extend(self.evidence.ids())
        for review in self.evidence.reviews:
            collected.extend(f.id for f in review.findings)
        return collected

    # -- state -------------------------------------------------------------------------

    def derive_state(self) -> ChangeState:
        """Derive the workflow state from the artifacts (highest satisfied state wins).

        * ``released`` — final verdict present with ``overall`` true.
        * ``secured`` — complete security evidence with no open critical vulnerabilities,
          no manifest drift and (if present) a complete PyRIT summary.
        * ``reviewed`` — a complete, approved review with no grounded blocking findings.
        * ``verifying`` — every task is done/skipped (implementation finished).
        * ``implementing`` — at least one task left ``pending``.
        * ``planned`` — plan with >= 1 wave and >= 1 task.
        * ``specified`` — >= 1 requirement and every requirement has >= 1 scenario.
        * ``draft`` — anything else.
        """
        if self.final_verdict is not None and self.final_verdict.overall:
            return ChangeState.RELEASED
        security = self.evidence.security
        if (
            security is not None
            and security.is_complete
            and security.critical_open == 0
            and not security.manifest_drift
            and (security.pyrit is None or security.pyrit.complete)
        ):
            return ChangeState.SECURED
        if any(
            r.is_complete
            and r.verdict is ReviewVerdict.APPROVED
            and not r.grounded_blocking_findings()
            for r in self.evidence.reviews
        ):
            return ChangeState.REVIEWED
        finished = {TaskStatus.DONE, TaskStatus.SKIPPED}
        if self.tasks and all(t.status in finished for t in self.tasks):
            return ChangeState.VERIFYING
        if any(t.status is not TaskStatus.PENDING for t in self.tasks):
            return ChangeState.IMPLEMENTING
        if self.plan is not None and self.plan.waves and self.tasks:
            return ChangeState.PLANNED
        if self.requirements and all(r.scenarios for r in self.requirements):
            return ChangeState.SPECIFIED
        return ChangeState.DRAFT

    # -- persistence (implemented in aisdlc.schema.package) ----------------------------

    @classmethod
    def load(cls, directory: str | Path) -> ChangePackage:
        """Load a package from its directory (see :func:`aisdlc.schema.package.load`)."""
        from aisdlc.schema import package

        return package.load(directory)

    def save(
        self,
        directory: str | Path | None = None,
        *,
        base_fingerprint: str | None = None,
    ) -> Path:
        """Write the package (see :func:`aisdlc.schema.package.save`)."""
        from aisdlc.schema import package

        return package.save(self, directory, base_fingerprint=base_fingerprint)
