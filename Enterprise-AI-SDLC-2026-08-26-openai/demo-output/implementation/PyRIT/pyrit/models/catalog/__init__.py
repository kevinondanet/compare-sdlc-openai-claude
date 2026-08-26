# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
# ruff: noqa: F401

"""
Catalog sub-package - registry/wire-format types for scenarios, initializers,
and targets that the PyRIT REST API exposes to external clients.

These models describe canonical PyRIT entities (a registered scenario, a
registered initializer, a runtime target instance, a scenario run summary)
and are imported by both the backend (as response/request payloads) and the
CLI (and any future external REST client). REST framing types (pagination
envelopes, RFC 7807 problem details, GUI-only request bodies) stay in
``pyrit.backend.models``
"""

from typing import TYPE_CHECKING

from pyrit.common.lazy_imports import get_lazy_dir, resolve_lazy_export

if TYPE_CHECKING:
    from pyrit.models.catalog.initializer import RegisteredInitializer
    from pyrit.models.catalog.scenario import (
        AttackErrorSummary,
        AttackRetrySummary,
        RegisteredScenario,
        RunScenarioRequest,
        ScenarioRunSummary,
    )
    from pyrit.models.catalog.security_evidence import (
        SECURITY_EVIDENCE_BASELINE_SCHEMA,
        SECURITY_EVIDENCE_SCHEMA,
        SECURITY_EVIDENCE_TRIAL_PLAN_SCHEMA,
        EvidenceCachedTrial,
        EvidenceCompletenessStatus,
        EvidenceComponentIdentity,
        EvidenceCoverage,
        EvidenceGroupSummary,
        EvidenceLatencySummary,
        EvidenceMetricSummary,
        EvidenceMoney,
        EvidenceObservedTrial,
        EvidenceTrialIdentity,
        SecurityEvidence,
        SecurityEvidenceBaseline,
        SecurityEvidenceCompleteness,
        SecurityEvidenceConfiguration,
        SecurityEvidenceMetrics,
        SecurityEvidenceRun,
        SecurityEvidenceSubject,
        SecurityEvidenceTrialPlan,
        SecurityEvidenceUsage,
    )
    from pyrit.models.catalog.target import TargetInstance

_LAZY_EXPORTS: dict[str, str] = {
    "AttackErrorSummary": "pyrit.models.catalog.scenario",
    "AttackRetrySummary": "pyrit.models.catalog.scenario",
    "RegisteredInitializer": "pyrit.models.catalog.initializer",
    "RegisteredScenario": "pyrit.models.catalog.scenario",
    "RunScenarioRequest": "pyrit.models.catalog.scenario",
    "ScenarioRunSummary": "pyrit.models.catalog.scenario",
    "EvidenceCachedTrial": "pyrit.models.catalog.security_evidence",
    "EvidenceComponentIdentity": "pyrit.models.catalog.security_evidence",
    "EvidenceCompletenessStatus": "pyrit.models.catalog.security_evidence",
    "EvidenceCoverage": "pyrit.models.catalog.security_evidence",
    "EvidenceGroupSummary": "pyrit.models.catalog.security_evidence",
    "EvidenceLatencySummary": "pyrit.models.catalog.security_evidence",
    "EvidenceMetricSummary": "pyrit.models.catalog.security_evidence",
    "EvidenceMoney": "pyrit.models.catalog.security_evidence",
    "EvidenceObservedTrial": "pyrit.models.catalog.security_evidence",
    "EvidenceTrialIdentity": "pyrit.models.catalog.security_evidence",
    "SECURITY_EVIDENCE_BASELINE_SCHEMA": "pyrit.models.catalog.security_evidence",
    "SECURITY_EVIDENCE_SCHEMA": "pyrit.models.catalog.security_evidence",
    "SECURITY_EVIDENCE_TRIAL_PLAN_SCHEMA": "pyrit.models.catalog.security_evidence",
    "SecurityEvidence": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceBaseline": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceCompleteness": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceConfiguration": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceMetrics": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceRun": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceSubject": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceTrialPlan": "pyrit.models.catalog.security_evidence",
    "SecurityEvidenceUsage": "pyrit.models.catalog.security_evidence",
    "TargetInstance": "pyrit.models.catalog.target",
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> object:
    """
    Resolve a public catalog export on first access.

    Args:
        name (str): The requested public name.

    Returns:
        object: The resolved export.
    """
    return resolve_lazy_export(
        name=name,
        module_name=__name__,
        module_globals=globals(),
        exports=_LAZY_EXPORTS,
    )


def __dir__() -> list[str]:
    """Return package attributes, including unresolved exports."""
    return get_lazy_dir(module_globals=globals(), exports=_LAZY_EXPORTS)
