"""Test coverage portfolio, test-evidence capture and mutation evidence.

* :mod:`aisdlc.testing.portfolio` — the ten-layer coverage portfolio, thresholds, risk-class
  requirements, evaluation and ratchets.
* :mod:`aisdlc.testing.evidence` — run a test command and parse JUnit/coverage artifacts
  into :class:`aisdlc.schema.models.TestEvidence`.
* :mod:`aisdlc.testing.mutation` — mutation-score evidence with explicit scope disclosure.
"""

from __future__ import annotations

from aisdlc.testing.evidence import (
    CaptureResult,
    CoverageData,
    DiffCoverage,
    JunitCounts,
    capture,
    capture_test_evidence,
    diff_coverage,
    evidence_from_artifacts,
    parse_cobertura,
    parse_coverage_json,
    parse_junit,
    record_test_evidence,
)
from aisdlc.testing.mutation import (
    MutantResult,
    MutantStatus,
    MutationReport,
    attach_mutation,
    load_mutation_report,
    parse_mutation_json,
    ratchet_mutation_floor,
    run_builtin_mutation,
)
from aisdlc.testing.portfolio import (
    LAYERS,
    Breach,
    Layer,
    LayerReport,
    LayerRun,
    LayerStatus,
    PortfolioEvidence,
    PortfolioException,
    PortfolioReport,
    PortfolioThresholds,
    RiskProfile,
    evaluate,
    ratchet,
    ratchet_to_observed,
    risk_profile_for,
)

__all__ = [
    "LAYERS",
    "Breach",
    "CaptureResult",
    "CoverageData",
    "DiffCoverage",
    "JunitCounts",
    "Layer",
    "LayerReport",
    "LayerRun",
    "LayerStatus",
    "MutantResult",
    "MutantStatus",
    "MutationReport",
    "PortfolioEvidence",
    "PortfolioException",
    "PortfolioReport",
    "PortfolioThresholds",
    "RiskProfile",
    "attach_mutation",
    "capture",
    "capture_test_evidence",
    "diff_coverage",
    "evaluate",
    "evidence_from_artifacts",
    "load_mutation_report",
    "parse_cobertura",
    "parse_coverage_json",
    "parse_junit",
    "parse_mutation_json",
    "ratchet",
    "ratchet_mutation_floor",
    "ratchet_to_observed",
    "record_test_evidence",
    "risk_profile_for",
    "run_builtin_mutation",
]
