"""Test coverage portfolio: layers, thresholds, risk-class requirements, evaluation, ratchets.

The portfolio has ten layers (``unit`` … ``performance``). A :class:`RiskProfile` says which
layers a change of a given :class:`~aisdlc.schema.models.RiskClass` must exercise;
:class:`PortfolioThresholds` carries the numeric floors; :func:`evaluate` turns measured
:class:`PortfolioEvidence` into a :class:`PortfolioReport` with a per-layer status, the list
of threshold breaches and the layers that are required but missing.

Fail-closed rules:

* an incomplete run of any layer is a breach (``fail_on_incomplete``);
* a required layer with no run is a breach;
* a required measurement that was not taken (``None``) is a breach.

Documented :class:`PortfolioException` records (reason, approver, expiry) may exempt a breach;
expired exceptions are ignored and reported.  :func:`ratchet` only ever raises floors.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    Coverage,
    EvidenceBundle,
    Mutation,
    RiskClass,
    TestEvidence,
    utcnow,
)

__all__ = [
    "DEFAULT_REQUIRED_LAYERS",
    "LAYERS",
    "METRICS",
    "PORTFOLIO_FILE",
    "Breach",
    "Layer",
    "LayerReport",
    "LayerRun",
    "LayerStatus",
    "PortfolioEvidence",
    "PortfolioException",
    "PortfolioInputs",
    "PortfolioModel",
    "PortfolioRecord",
    "PortfolioReport",
    "PortfolioThresholds",
    "RiskProfile",
    "classify_test_evidence",
    "evaluate",
    "portfolio_path",
    "ratchet",
    "ratchet_to_observed",
    "read_portfolio_record",
    "risk_profile_for",
    "write_portfolio_record",
]

PORTFOLIO_FILE = "portfolio.json"
"""``evidence/portfolio.json`` — persisted portfolio inputs + last report (bundle-covered)."""


class PortfolioModel(BaseModel):
    """Base for portfolio models (strict, JSON-serialisable)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Layer(StrEnum):
    """The ten coverage-portfolio layers."""

    UNIT = "unit"
    PROPERTY = "property"
    INTEGRATION = "integration"
    CONTRACT = "contract"
    E2E = "e2e"
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    AGENT_SAFETY = "agent_safety"
    PROMPT_EVALS = "prompt_evals"
    PERFORMANCE = "performance"


LAYERS: tuple[Layer, ...] = tuple(Layer)
"""All layers in canonical order."""


class LayerStatus(StrEnum):
    """Outcome of one layer in a portfolio evaluation."""

    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    MISSING = "missing"
    NOT_REQUIRED = "not_required"
    EXEMPTED = "exempted"


# Metric names used in breaches, thresholds and exceptions.
METRIC_LINES = "lines"
METRIC_DIFF_LINES = "diff_lines"
METRIC_BRANCHES = "branches"
METRIC_CRITICAL_MODULES = "critical_modules"
METRIC_MUTATION = "mutation_score"
METRIC_ACCEPTANCE = "acceptance_criteria_with_evidence"
METRIC_JOURNEYS = "critical_journeys_e2e"
METRIC_SAFETY_SCENARIOS = "agent_safety_scenarios_executed"
METRIC_LAYER_PRESENT = "layer_present"
METRIC_LAYER_COMPLETE = "layer_complete"
METRIC_LAYER_FAILURES = "layer_failures"

METRICS: tuple[str, ...] = (
    METRIC_LINES,
    METRIC_DIFF_LINES,
    METRIC_BRANCHES,
    METRIC_CRITICAL_MODULES,
    METRIC_MUTATION,
    METRIC_ACCEPTANCE,
    METRIC_JOURNEYS,
    METRIC_SAFETY_SCENARIOS,
    METRIC_LAYER_PRESENT,
    METRIC_LAYER_COMPLETE,
    METRIC_LAYER_FAILURES,
)
"""Every metric name a :class:`Breach` or :class:`PortfolioException` may reference."""

_RATCHET_FIELDS: tuple[str, ...] = (
    "lines",
    "lines_floor",
    "diff_lines",
    "branches",
    "critical_modules",
    "mutation_score",
    "acceptance_criteria_with_evidence",
    "critical_journeys_e2e",
    "agent_safety_scenarios_executed",
)


class PortfolioThresholds(PortfolioModel):
    """Numeric floors for the portfolio.

    Defaults follow the organisation policy: line coverage sits between the 75 % ratchet
    floor and the 80 % target (78 %), diff coverage 90 %, branches 70 %, critical modules
    90 %, mutation score 0.60 (ratcheted upwards as it improves), and 100 % for the three
    completeness metrics (acceptance criteria backed by evidence, critical journeys covered by
    e2e tests, required agent-safety scenarios executed).
    """

    lines: float = Field(default=78.0, ge=0, le=100, description="Enforced line coverage %.")
    lines_floor: float = Field(default=75.0, ge=0, le=100, description="Never-lowered floor.")
    diff_lines: float = Field(default=90.0, ge=0, le=100)
    branches: float = Field(default=70.0, ge=0, le=100)
    critical_modules: float = Field(default=90.0, ge=0, le=100)
    mutation_score: float = Field(default=0.60, ge=0, le=1)
    acceptance_criteria_with_evidence: float = Field(default=100.0, ge=0, le=100)
    critical_journeys_e2e: float = Field(default=100.0, ge=0, le=100)
    agent_safety_scenarios_executed: float = Field(default=100.0, ge=0, le=100)
    fail_on_incomplete: bool = Field(
        default=True, description="An incomplete run of any layer is a breach (fail closed)."
    )
    require_diff_coverage: bool = Field(
        default=True, description="Missing diff coverage is a breach when unit tests are required."
    )

    @classmethod
    def from_org_policy(cls, policy: Any) -> PortfolioThresholds:
        """Build thresholds from an :class:`aisdlc.policy.OrgPolicy` (or any object with
        ``security_baselines.coverage`` and ``security_baselines.mutation_score``).

        The enforced line threshold is placed 60 % of the way from the ratchet floor to the
        target so that the org defaults (75 / 80) yield 78.
        """
        baselines = policy.security_baselines
        cov = baselines.coverage
        floor = float(cov.lines_floor)
        target = float(cov.lines)
        lines = max(floor, min(target, round(floor + 0.6 * (target - floor), 2)))
        return cls(
            lines=lines,
            lines_floor=floor,
            diff_lines=float(cov.diff_lines),
            branches=float(cov.branches),
            critical_modules=float(cov.critical_modules),
            mutation_score=float(baselines.mutation_score),
        )


class PortfolioException(PortfolioModel):
    """A documented, approved, time-boxed exemption from one metric (optionally one layer).

    ``metric`` is one of :data:`METRICS`.  Layer-level exemptions use the
    ``layer_present`` / ``layer_complete`` / ``layer_failures`` metrics together with
    ``layer``.  Expired exceptions never apply.
    """

    metric: str
    layer: Layer | None = None
    reason: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    expires_at: datetime
    reference: str | None = Field(default=None, description="Ticket / ADR / risk register id.")

    @field_validator("metric")
    @classmethod
    def _known_metric(cls, value: str) -> str:
        if value not in METRICS:
            raise ValueError(f"unknown metric {value!r}; expected one of {METRICS}")
        return value

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return value

    def is_active(self, now: datetime | None = None) -> bool:
        """``True`` while ``now`` is before ``expires_at``."""
        moment = now or utcnow()
        return moment < self.expires_at

    def covers(self, metric: str, layer: Layer | None) -> bool:
        """``True`` when this exception applies to *metric* on *layer*."""
        if self.metric != metric:
            return False
        return self.layer is None or self.layer == layer


class LayerRun(PortfolioModel):
    """Observed execution of one portfolio layer."""

    layer: Layer
    executed: bool = True
    complete: bool = True
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    metrics: dict[str, float] = Field(
        default_factory=dict,
        description="Layer metrics in percent, e.g. acceptance_criteria_with_evidence.",
    )
    evidence_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        """Executed, complete and without failures."""
        return self.executed and self.complete and self.failed == 0


class PortfolioEvidence(PortfolioModel):
    """Everything :func:`evaluate` looks at."""

    runs: list[LayerRun] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    mutation: Mutation | None = None
    critical_module_coverage: dict[str, float] = Field(
        default_factory=dict, description="Line coverage % per critical module."
    )

    def run_for(self, layer: Layer) -> LayerRun | None:
        """The run recorded for *layer* (runs of the same layer are merged)."""
        found = [r for r in self.runs if r.layer == layer]
        if not found:
            return None
        if len(found) == 1:
            return found[0]
        return _merge_runs(found)

    @classmethod
    def from_bundle(
        cls,
        bundle: EvidenceBundle,
        *,
        extra_runs: Iterable[LayerRun] = (),
        layer_of: Callable[[TestEvidence], Layer] | None = None,
        critical_module_coverage: Mapping[str, float] | None = None,
    ) -> PortfolioEvidence:
        """Derive portfolio evidence from a change package's :class:`EvidenceBundle`.

        Test evidence is mapped to a layer by *layer_of* (default
        :func:`classify_test_evidence`); coverage and mutation come from the unit layer's
        evidence (falling back to any test evidence that measured them).  Security,
        safety-regression/PyRIT and performance evidence populate the ``security``,
        ``agent_safety`` and ``performance`` layers.
        """
        classify = layer_of or classify_test_evidence
        runs: list[LayerRun] = []
        coverage = Coverage()
        mutation: Mutation | None = None
        for ev in bundle.tests:
            layer = classify(ev)
            runs.append(
                LayerRun(
                    layer=layer,
                    executed=True,
                    complete=ev.is_complete,
                    passed=ev.passed,
                    failed=ev.failed
                    + (
                        1
                        if ev.is_complete and ev.exit_code not in (0, None) and ev.failed == 0
                        else 0
                    ),
                    skipped=ev.skipped,
                    evidence_ids=[ev.id],
                )
            )
            prefer = layer is Layer.UNIT
            coverage = _merge_coverage(coverage, ev.coverage, prefer=prefer)
            if ev.mutation is not None and (mutation is None or prefer):
                mutation = ev.mutation
        sec = bundle.security
        if sec is not None:
            runs.append(
                LayerRun(
                    layer=Layer.SECURITY,
                    executed=True,
                    complete=sec.is_complete,
                    failed=sec.critical_open + sec.high_open,
                    evidence_ids=[sec.id],
                )
            )
            safety_metrics: dict[str, float] = {}
            safety_complete = True
            safety_failed = 0
            saw_safety = False
            if sec.safety_regression is not None:
                saw_safety = True
                safety_complete &= sec.safety_regression.complete
                safety_failed += len(sec.safety_regression.threshold_breaches)
                if sec.safety_regression.complete:
                    safety_metrics[METRIC_SAFETY_SCENARIOS] = 100.0
            if sec.pyrit is not None:
                saw_safety = True
                safety_complete &= sec.pyrit.complete
            if saw_safety:
                runs.append(
                    LayerRun(
                        layer=Layer.AGENT_SAFETY,
                        executed=True,
                        complete=sec.is_complete and safety_complete,
                        failed=safety_failed,
                        metrics=safety_metrics,
                        evidence_ids=[sec.id],
                    )
                )
        perf = bundle.performance
        if perf is not None:
            runs.append(
                LayerRun(
                    layer=Layer.PERFORMANCE,
                    executed=True,
                    complete=perf.is_complete,
                    failed=0 if perf.slo_met else 1,
                    evidence_ids=[perf.id],
                )
            )
        runs.extend(extra_runs)
        return cls(
            runs=runs,
            coverage=coverage,
            mutation=mutation,
            critical_module_coverage=dict(critical_module_coverage or {}),
        )


_LAYER_KEYWORDS: tuple[tuple[str, Layer], ...] = (
    ("agent_safety", Layer.AGENT_SAFETY),
    ("agent-safety", Layer.AGENT_SAFETY),
    ("safety", Layer.AGENT_SAFETY),
    ("prompt_evals", Layer.PROMPT_EVALS),
    ("prompt-evals", Layer.PROMPT_EVALS),
    ("promptfoo", Layer.PROMPT_EVALS),
    ("architecture", Layer.ARCHITECTURE),
    ("import-linter", Layer.ARCHITECTURE),
    ("lint-imports", Layer.ARCHITECTURE),
    ("performance", Layer.PERFORMANCE),
    ("benchmark", Layer.PERFORMANCE),
    ("k6", Layer.PERFORMANCE),
    ("locust", Layer.PERFORMANCE),
    ("contract", Layer.CONTRACT),
    ("pact", Layer.CONTRACT),
    ("integration", Layer.INTEGRATION),
    ("e2e", Layer.E2E),
    ("playwright", Layer.E2E),
    ("cypress", Layer.E2E),
    ("property", Layer.PROPERTY),
    ("hypothesis", Layer.PROPERTY),
    ("security", Layer.SECURITY),
    ("unit", Layer.UNIT),
)


def classify_test_evidence(evidence: TestEvidence) -> Layer:
    """Guess the portfolio layer of a :class:`TestEvidence` record.

    ``produced_by`` may carry an explicit ``layer=<name>`` tag; otherwise the first layer
    keyword found in ``produced_by`` or ``command`` wins (``unit`` when nothing matches).
    """
    tag = evidence.produced_by.lower()
    for token in tag.replace(";", " ").replace(",", " ").split():
        if token.startswith("layer=") or token.startswith("layer:"):
            candidate = token[6:]
            try:
                return Layer(candidate)
            except ValueError:
                break
    haystack = f"{tag} {evidence.command.lower()}"
    for keyword, layer in _LAYER_KEYWORDS:
        if keyword in haystack:
            return layer
    return Layer.UNIT


class RiskProfile(PortfolioModel):
    """Which layers and completeness metrics a risk class demands."""

    risk_class: RiskClass
    required_layers: list[Layer] = Field(default_factory=list)
    mutation_required: bool = False
    acceptance_criteria_required: bool = False
    critical_journeys_required: bool = False
    agent_safety_required: bool = False

    def requires(self, layer: Layer) -> bool:
        """``True`` when *layer* must have a complete, passing run."""
        return layer in self.required_layers


DEFAULT_REQUIRED_LAYERS: dict[RiskClass, tuple[Layer, ...]] = {
    RiskClass.DOCS_ONLY: (),
    RiskClass.LOW: (Layer.UNIT, Layer.INTEGRATION),
    RiskClass.STANDARD: (
        Layer.UNIT,
        Layer.INTEGRATION,
        Layer.CONTRACT,
        Layer.E2E,
        Layer.ARCHITECTURE,
        Layer.SECURITY,
    ),
    RiskClass.HIGH: (
        Layer.UNIT,
        Layer.PROPERTY,
        Layer.INTEGRATION,
        Layer.CONTRACT,
        Layer.E2E,
        Layer.ARCHITECTURE,
        Layer.SECURITY,
        Layer.PERFORMANCE,
    ),
    RiskClass.CRITICAL: (
        Layer.UNIT,
        Layer.PROPERTY,
        Layer.INTEGRATION,
        Layer.CONTRACT,
        Layer.E2E,
        Layer.ARCHITECTURE,
        Layer.SECURITY,
        Layer.PERFORMANCE,
    ),
    RiskClass.AI_AGENT: LAYERS,
}
"""Layers required per risk class; ``ai_agent`` requires all ten."""


def risk_profile_for(risk_class: RiskClass | str) -> RiskProfile:
    """The default :class:`RiskProfile` for *risk_class*."""
    rc = RiskClass(risk_class)
    layers = DEFAULT_REQUIRED_LAYERS[rc]
    rank = list(RiskClass).index(rc)
    return RiskProfile(
        risk_class=rc,
        required_layers=list(layers),
        mutation_required=rc not in (RiskClass.DOCS_ONLY, RiskClass.LOW),
        acceptance_criteria_required=rc is not RiskClass.DOCS_ONLY,
        critical_journeys_required=rank >= list(RiskClass).index(RiskClass.HIGH),
        agent_safety_required=rc is RiskClass.AI_AGENT,
    )


class Breach(PortfolioModel):
    """A threshold or completeness violation."""

    metric: str
    layer: Layer | None = None
    threshold: float | None = None
    actual: float | None = None
    subject: str | None = Field(default=None, description="Module or scenario the breach is about.")
    message: str
    exempted: bool = False
    exception_reference: str | None = None

    @property
    def blocking(self) -> bool:
        """A breach blocks unless a documented, active exception covers it."""
        return not self.exempted


class LayerReport(PortfolioModel):
    """Per-layer outcome."""

    layer: Layer
    status: LayerStatus
    required: bool
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    reasons: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class PortfolioReport(PortfolioModel):
    """Result of :func:`evaluate`."""

    risk_class: RiskClass
    layers: list[LayerReport] = Field(default_factory=list)
    breaches: list[Breach] = Field(default_factory=list)
    missing_layers: list[Layer] = Field(default_factory=list)
    exceptions_applied: list[str] = Field(default_factory=list)
    exceptions_expired: list[str] = Field(default_factory=list)
    thresholds: PortfolioThresholds = Field(default_factory=PortfolioThresholds)
    evaluated_at: datetime = Field(default_factory=utcnow)

    @property
    def blocking_breaches(self) -> list[Breach]:
        """Breaches not covered by an active exception."""
        return [b for b in self.breaches if b.blocking]

    @property
    def passed(self) -> bool:
        """``True`` when nothing blocks."""
        return not self.blocking_breaches

    def layer(self, layer: Layer) -> LayerReport:
        """The report for *layer*."""
        for item in self.layers:
            if item.layer == layer:
                return item
        raise KeyError(layer)

    def summary_lines(self) -> list[str]:
        """Human-readable summary (one line per layer and breach)."""
        lines = [f"portfolio: {'PASS' if self.passed else 'FAIL'} (risk {self.risk_class.value})"]
        for item in self.layers:
            flag = "required" if item.required else "optional"
            detail = f" passed={item.passed} failed={item.failed} skipped={item.skipped}"
            lines.append(f"  {item.layer.value:<14} {item.status.value:<12} {flag}{detail}")
        for breach in self.breaches:
            mark = "exempted" if breach.exempted else "BREACH"
            lines.append(f"  {mark}: {breach.message}")
        return lines


def _merge_runs(runs: Sequence[LayerRun]) -> LayerRun:
    first = runs[0]
    metrics: dict[str, float] = {}
    for run in runs:
        for key, value in run.metrics.items():
            metrics[key] = min(metrics.get(key, value), value)
    return LayerRun(
        layer=first.layer,
        executed=any(r.executed for r in runs),
        complete=all(r.complete for r in runs if r.executed),
        passed=sum(r.passed for r in runs),
        failed=sum(r.failed for r in runs),
        skipped=sum(r.skipped for r in runs),
        metrics=metrics,
        evidence_ids=[e for r in runs for e in r.evidence_ids],
        notes=[n for r in runs for n in r.notes],
    )


def _merge_coverage(current: Coverage, new: Coverage, *, prefer: bool) -> Coverage:
    data = current.model_dump()
    for key, value in new.model_dump().items():
        if value is None:
            continue
        if data[key] is None or prefer:
            data[key] = value
    return Coverage(**data)


def _pct(value: float | None) -> str:
    return "not measured" if value is None else f"{value:.2f}"


def evaluate(
    evidence: PortfolioEvidence,
    thresholds: PortfolioThresholds | None = None,
    risk_profile: RiskProfile | RiskClass | str | None = None,
    *,
    exceptions: Iterable[PortfolioException] = (),
    now: datetime | None = None,
) -> PortfolioReport:
    """Evaluate *evidence* against *thresholds* for the given risk profile.

    *risk_profile* may be a :class:`RiskProfile`, a :class:`RiskClass` (or its value) or
    ``None`` (``standard``).  Returns a :class:`PortfolioReport`; ``report.passed`` is ``True``
    only when every breach is covered by an active documented exception.
    """
    thr = thresholds or PortfolioThresholds()
    profile = (
        risk_profile
        if isinstance(risk_profile, RiskProfile)
        else risk_profile_for(risk_profile or RiskClass.STANDARD)
    )
    moment = now or utcnow()
    breaches: list[Breach] = []
    layers: list[LayerReport] = []
    missing: list[Layer] = []

    for layer in LAYERS:
        required = profile.requires(layer)
        run = evidence.run_for(layer)
        if run is None or not run.executed:
            if required:
                missing.append(layer)
                breaches.append(
                    Breach(
                        metric=METRIC_LAYER_PRESENT,
                        layer=layer,
                        threshold=1,
                        actual=0,
                        message=f"required layer {layer.value} was not executed",
                    )
                )
                status = LayerStatus.MISSING
                reasons = ["no run recorded"]
            else:
                status = LayerStatus.NOT_REQUIRED
                reasons = []
            layers.append(
                LayerReport(layer=layer, status=status, required=required, reasons=reasons)
            )
            continue
        reasons = list(run.notes)
        if not run.complete:
            status = LayerStatus.INCOMPLETE
            reasons.append("run incomplete")
            if thr.fail_on_incomplete or required:
                breaches.append(
                    Breach(
                        metric=METRIC_LAYER_COMPLETE,
                        layer=layer,
                        threshold=1,
                        actual=0,
                        message=f"layer {layer.value} run is incomplete (fails closed)",
                    )
                )
        elif run.failed > 0:
            status = LayerStatus.FAILED
            reasons.append(f"{run.failed} failure(s)")
            breaches.append(
                Breach(
                    metric=METRIC_LAYER_FAILURES,
                    layer=layer,
                    threshold=0,
                    actual=run.failed,
                    message=f"layer {layer.value} has {run.failed} failing check(s)",
                )
            )
        else:
            status = LayerStatus.PASSED
        layers.append(
            LayerReport(
                layer=layer,
                status=status,
                required=required,
                passed=run.passed,
                failed=run.failed,
                skipped=run.skipped,
                reasons=reasons,
                evidence_ids=list(run.evidence_ids),
            )
        )

    unit_required = profile.requires(Layer.UNIT)
    cov = evidence.coverage
    _check_pct(breaches, METRIC_LINES, cov.lines, thr.lines, Layer.UNIT, required=unit_required)
    _check_pct(
        breaches,
        METRIC_BRANCHES,
        cov.branches,
        thr.branches,
        Layer.UNIT,
        required=unit_required,
    )
    _check_pct(
        breaches,
        METRIC_DIFF_LINES,
        cov.diff_lines,
        thr.diff_lines,
        Layer.UNIT,
        required=unit_required and thr.require_diff_coverage,
    )
    for module, value in sorted(evidence.critical_module_coverage.items()):
        if value < thr.critical_modules:
            breaches.append(
                Breach(
                    metric=METRIC_CRITICAL_MODULES,
                    layer=Layer.UNIT,
                    threshold=thr.critical_modules,
                    actual=value,
                    subject=module,
                    message=(
                        f"critical module {module} line coverage {value:.2f} "
                        f"< {thr.critical_modules:.2f}"
                    ),
                )
            )

    mutation = evidence.mutation
    score = mutation.score if mutation is not None else None
    if score is None:
        if profile.mutation_required:
            breaches.append(
                Breach(
                    metric=METRIC_MUTATION,
                    layer=Layer.UNIT,
                    threshold=thr.mutation_score,
                    actual=None,
                    message="mutation score not measured",
                )
            )
    elif score < thr.mutation_score:
        scope = ", ".join(mutation.scope) if mutation and mutation.scope else "undisclosed scope"
        breaches.append(
            Breach(
                metric=METRIC_MUTATION,
                layer=Layer.UNIT,
                threshold=thr.mutation_score,
                actual=score,
                message=f"mutation score {score:.2f} < {thr.mutation_score:.2f} ({scope})",
            )
        )

    _check_layer_metric(
        breaches,
        evidence,
        METRIC_ACCEPTANCE,
        thr.acceptance_criteria_with_evidence,
        (Layer.E2E, Layer.INTEGRATION, Layer.UNIT),
        required=profile.acceptance_criteria_required,
    )
    _check_layer_metric(
        breaches,
        evidence,
        METRIC_JOURNEYS,
        thr.critical_journeys_e2e,
        (Layer.E2E,),
        required=profile.critical_journeys_required,
    )
    _check_layer_metric(
        breaches,
        evidence,
        METRIC_SAFETY_SCENARIOS,
        thr.agent_safety_scenarios_executed,
        (Layer.AGENT_SAFETY,),
        required=profile.agent_safety_required,
    )

    applied: list[str] = []
    expired: list[str] = []
    active: list[PortfolioException] = []
    for exc in exceptions:
        label = exc.reference or f"{exc.metric}:{exc.layer.value if exc.layer else '*'}"
        if exc.is_active(moment):
            active.append(exc)
        else:
            expired.append(label)
    for breach in breaches:
        for exc in active:
            if exc.covers(breach.metric, breach.layer):
                breach.exempted = True
                breach.exception_reference = exc.reference or f"{exc.approved_by}: {exc.reason}"
                label = exc.reference or f"{exc.metric}:{exc.layer.value if exc.layer else '*'}"
                if label not in applied:
                    applied.append(label)
                break
    for item in layers:
        if item.status in (LayerStatus.MISSING, LayerStatus.INCOMPLETE, LayerStatus.FAILED):
            related = [
                b for b in breaches if b.layer == item.layer and b.metric.startswith("layer_")
            ]
            if related and all(b.exempted for b in related):
                item.status = LayerStatus.EXEMPTED

    return PortfolioReport(
        risk_class=profile.risk_class,
        layers=layers,
        breaches=breaches,
        missing_layers=missing,
        exceptions_applied=applied,
        exceptions_expired=expired,
        thresholds=thr,
        evaluated_at=moment,
    )


def _check_pct(
    breaches: list[Breach],
    metric: str,
    actual: float | None,
    threshold: float,
    layer: Layer,
    *,
    required: bool,
) -> None:
    if actual is None:
        if required:
            breaches.append(
                Breach(
                    metric=metric,
                    layer=layer,
                    threshold=threshold,
                    actual=None,
                    message=f"{metric} coverage not measured (required)",
                )
            )
        return
    if actual < threshold:
        breaches.append(
            Breach(
                metric=metric,
                layer=layer,
                threshold=threshold,
                actual=actual,
                message=f"{metric} coverage {_pct(actual)} < {threshold:.2f}",
            )
        )


def _check_layer_metric(
    breaches: list[Breach],
    evidence: PortfolioEvidence,
    metric: str,
    threshold: float,
    layers: Sequence[Layer],
    *,
    required: bool,
) -> None:
    value: float | None = None
    source: Layer | None = None
    for layer in layers:
        run = evidence.run_for(layer)
        if run is not None and metric in run.metrics:
            value = run.metrics[metric]
            source = layer
            break
    if value is None:
        if required:
            breaches.append(
                Breach(
                    metric=metric,
                    layer=layers[0],
                    threshold=threshold,
                    actual=None,
                    message=f"{metric} not measured (required)",
                )
            )
        return
    if value < threshold:
        breaches.append(
            Breach(
                metric=metric,
                layer=source,
                threshold=threshold,
                actual=value,
                message=f"{metric} {value:.2f} < {threshold:.2f}",
            )
        )


def ratchet(previous: PortfolioThresholds, current: PortfolioThresholds) -> PortfolioThresholds:
    """Merge two threshold sets so that no floor ever goes down.

    Every numeric floor becomes ``max(previous, current)``; the boolean switches are taken
    from *current* only when they are stricter (``True``).
    """
    data = current.model_dump()
    prev = previous.model_dump()
    for name in _RATCHET_FIELDS:
        data[name] = max(float(prev[name]), float(data[name]))
    data["lines"] = max(data["lines"], data["lines_floor"])
    data["fail_on_incomplete"] = bool(prev["fail_on_incomplete"] or data["fail_on_incomplete"])
    data["require_diff_coverage"] = bool(
        prev["require_diff_coverage"] or data["require_diff_coverage"]
    )
    return PortfolioThresholds(**data)


def ratchet_to_observed(
    previous: PortfolioThresholds,
    evidence: PortfolioEvidence,
    *,
    step: float = 0.5,
    mutation_step: float = 0.01,
) -> PortfolioThresholds:
    """Raise coverage/mutation floors towards what *evidence* actually achieved.

    Observed values are rounded **down** to the nearest *step* (percent) / *mutation_step*
    (score) and floors move only upwards.  Only complete unit-layer evidence ratchets; an
    incomplete run leaves the thresholds untouched.
    """
    unit = evidence.run_for(Layer.UNIT)
    if unit is None or not unit.complete:
        return previous.model_copy()
    data = previous.model_dump()

    def down(value: float, granularity: float) -> float:
        return math.floor(value / granularity) * granularity

    cov = evidence.coverage
    if cov.lines is not None:
        observed = down(cov.lines, step)
        data["lines_floor"] = max(data["lines_floor"], observed)
        data["lines"] = max(data["lines"], observed)
    if cov.branches is not None:
        data["branches"] = max(data["branches"], down(cov.branches, step))
    if cov.diff_lines is not None:
        data["diff_lines"] = max(data["diff_lines"], down(cov.diff_lines, step))
    if evidence.mutation is not None and evidence.mutation.score is not None:
        data["mutation_score"] = max(
            data["mutation_score"], min(1.0, down(evidence.mutation.score, mutation_step))
        )
    return PortfolioThresholds(**data)


# --------------------------------------------------------------------------------------
# Persisted portfolio record (``evidence/portfolio.json``)
# --------------------------------------------------------------------------------------


class PortfolioInputs(PortfolioModel):
    """Inputs that cannot be derived from the evidence bundle alone.

    Extra layer runs (property, contract, e2e … with their completeness metrics),
    documented exceptions and per-critical-module coverage. Persisted by
    ``aisdlc test portfolio`` and re-read by gate G2, which always re-evaluates — the
    stored report is informational, never trusted.
    """

    runs: list[LayerRun] = Field(default_factory=list)
    exceptions: list[PortfolioException] = Field(default_factory=list)
    critical_module_coverage: dict[str, float] = Field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        """``True`` when nothing was supplied."""
        return not (self.runs or self.exceptions or self.critical_module_coverage)


class PortfolioRecord(PortfolioModel):
    """What ``evidence/portfolio.json`` holds."""

    kind: Literal["portfolio"] = "portfolio"
    risk_class: RiskClass
    inputs: PortfolioInputs = Field(default_factory=PortfolioInputs)
    report: PortfolioReport
    evaluated_at: datetime = Field(default_factory=utcnow)


def portfolio_path(package_dir: str | Path) -> Path:
    """``<package>/evidence/portfolio.json``."""
    return Path(package_dir) / pkgio.EVIDENCE_DIR / PORTFOLIO_FILE


def read_portfolio_record(package_dir: str | Path) -> PortfolioRecord | None:
    """The persisted record, or ``None`` when absent. Raises ``ValueError`` when malformed."""
    path = portfolio_path(package_dir)
    if not path.is_file():
        return None
    try:
        return PortfolioRecord.model_validate(pkgio.read_json(path))
    except (ValidationError, pkgio.PackageError) as exc:
        raise ValueError(f"{path}: {exc}") from exc


def write_portfolio_record(package_dir: str | Path, record: PortfolioRecord) -> Path:
    """Write the record deterministically; returns the path."""
    path = portfolio_path(package_dir)
    pkgio.write_json(path, record.model_dump(mode="json"))
    return path
