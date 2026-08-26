"""LAYER 1 — intake and specification quality (Spec Kit / BMAD / HVE).

* :mod:`aisdlc.intake.kernel` — BMAD five-part kernel and G0 readiness.
* :mod:`aisdlc.intake.clarify` — ranked clarification questions and deterministic answers.
* :mod:`aisdlc.intake.checklist` — requirements-quality checklist.
* :mod:`aisdlc.intake.analyze` — cross-artifact consistency analysis.
* :mod:`aisdlc.intake.discovery` — coached plain-language discovery for non-developers.

The submodules are re-exported under their own names (``aisdlc.intake.analyze`` is the
module; call ``analyze.analyze(pkg)``), alongside the main classes and functions.
"""

from aisdlc.intake import analyze, checklist, clarify, discovery, kernel
from aisdlc.intake.analyze import (
    AnalysisFinding,
    AnalysisReport,
    DuplicatePair,
    QuantifierConflict,
    Quantity,
    TerminologyDrift,
    extract_quantities,
    find_conflicting_quantifiers,
    find_contradictions,
    find_duplicates,
    find_terminology_drift,
    similarity,
)
from aisdlc.intake.checklist import ChecklistItem, ChecklistReport, run_checklist
from aisdlc.intake.clarify import (
    AnswerError,
    AnswerResult,
    ClarificationQuestion,
    ClarificationSet,
    QuestionCategory,
    apply_answer,
    apply_answers,
    find_undefined_terms,
    generate_questions,
)
from aisdlc.intake.discovery import (
    DISCOVERY_SCRIPT,
    DiscoveryError,
    DiscoveryQuestion,
    DiscoveryResult,
    DiscoverySession,
    Persona,
    classify_risk,
    draft_requirement_text,
    load_answers,
)
from aisdlc.intake.kernel import (
    KERNEL_PROMPTS,
    KernelPart,
    ReadinessCriterion,
    ReadinessReport,
    UnstatedAssumption,
    build_kernel,
    find_unstated_assumptions,
    is_measurable,
    missing_parts,
    readiness,
    validate_kernel,
)

__all__ = [
    "analyze",
    "checklist",
    "clarify",
    "discovery",
    "kernel",
    "AnalysisFinding",
    "AnalysisReport",
    "DuplicatePair",
    "QuantifierConflict",
    "Quantity",
    "TerminologyDrift",
    "extract_quantities",
    "find_conflicting_quantifiers",
    "find_contradictions",
    "find_duplicates",
    "find_terminology_drift",
    "similarity",
    "ChecklistItem",
    "ChecklistReport",
    "run_checklist",
    "AnswerError",
    "AnswerResult",
    "ClarificationQuestion",
    "ClarificationSet",
    "QuestionCategory",
    "apply_answer",
    "apply_answers",
    "find_undefined_terms",
    "generate_questions",
    "DISCOVERY_SCRIPT",
    "DiscoveryError",
    "DiscoveryQuestion",
    "DiscoveryResult",
    "DiscoverySession",
    "Persona",
    "classify_risk",
    "draft_requirement_text",
    "load_answers",
    "KERNEL_PROMPTS",
    "KernelPart",
    "ReadinessCriterion",
    "ReadinessReport",
    "UnstatedAssumption",
    "build_kernel",
    "find_unstated_assumptions",
    "is_measurable",
    "missing_parts",
    "readiness",
    "validate_kernel",
]
