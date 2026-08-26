"""LAYER 2 — planning and architecture governance.

* :mod:`aisdlc.planning.planner` — requirements -> tasks with verification; waves.
* :mod:`aisdlc.planning.plan_checker` — goal-backward plan validation (G1).
* :mod:`aisdlc.planning.adr` — MADR-style architecture decision records.
* :mod:`aisdlc.planning.threat_model` — threat model seeding and validation (G1).
* :mod:`aisdlc.planning.risk` — risk classification and the gate depth profile.
"""

from aisdlc.planning.adr import (
    AdrDocument,
    AdrError,
    list_adrs,
    new_adr,
    parse_adr,
    read_adr,
    render_adr,
    validate_adr,
    validate_adrs,
    write_adr,
)
from aisdlc.planning.plan_checker import PlanCheckIssue, PlanCheckReport, check_plan
from aisdlc.planning.planner import (
    DependencyCycleError,
    PlannerConfig,
    PlanningError,
    PlanResult,
    apply_plan,
    build_plan,
    compute_waves,
    derive_tasks,
    generate_plan,
    infer_dependencies,
    requirements_fingerprint,
)
from aisdlc.planning.risk import (
    GateDepthProfile,
    QualityCheck,
    RiskAssessment,
    RiskSignal,
    classify,
    gate_depth_profile,
)
from aisdlc.planning.threat_model import (
    ThreatModelReport,
    check_threat_model,
    init_threat_model,
    tool_tier,
    unresolved_high_risk,
    validate_threat_model,
)

__all__ = [
    "AdrDocument",
    "AdrError",
    "list_adrs",
    "new_adr",
    "parse_adr",
    "read_adr",
    "render_adr",
    "validate_adr",
    "validate_adrs",
    "write_adr",
    "PlanCheckIssue",
    "PlanCheckReport",
    "check_plan",
    "DependencyCycleError",
    "PlannerConfig",
    "PlanningError",
    "PlanResult",
    "apply_plan",
    "build_plan",
    "compute_waves",
    "derive_tasks",
    "generate_plan",
    "infer_dependencies",
    "requirements_fingerprint",
    "GateDepthProfile",
    "QualityCheck",
    "RiskAssessment",
    "RiskSignal",
    "classify",
    "gate_depth_profile",
    "ThreatModelReport",
    "check_threat_model",
    "init_threat_model",
    "tool_tier",
    "unresolved_high_risk",
    "validate_threat_model",
]
