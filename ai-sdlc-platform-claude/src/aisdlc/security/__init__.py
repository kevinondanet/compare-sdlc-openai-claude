"""Security planes: CI/supply-chain evidence (plane 1) and AI/agent security testing (plane 3).

Submodules are imported lazily (PEP 562) so that a missing optional dependency (PyRIT) or a
sibling module that is not present yet never breaks ``import aisdlc.security``.

Plane 1 (CI / supply chain) modules:

* :mod:`aisdlc.security.ci_templates` – render/lint/pin the reusable GitHub workflows.
* :mod:`aisdlc.security.supply_chain` – SARIF/SBOM/provenance/secret-scan parsers ->
  ``evidence/security.json``.
* :mod:`aisdlc.security.manifest` – declared tool/data manifest vs observed audit behaviour.

Plane 3 (PyRIT-based) modules:

* :mod:`aisdlc.security.pyrit_campaign` – campaign specs, ASR/undetermined math, baselines.
* :mod:`aisdlc.security.safety_regression` – pytest-native ``@safety_case`` suites.
* :mod:`aisdlc.security.judges` – scorer calibration against human labels.
* :mod:`aisdlc.security.targets` – PyRIT targets wrapping the application under test.

Submodules themselves (``aisdlc.security.manifest`` …) are also resolved lazily by name.
"""

from __future__ import annotations

import importlib
from typing import Any

_SUBMODULES: tuple[str, ...] = (
    "ci_templates",
    "supply_chain",
    "manifest",
    "pyrit_campaign",
    "safety_regression",
    "judges",
    "targets",
)

_LAZY: dict[str, str] = {
    # ci_templates
    "CI_DIR": "aisdlc.security.ci_templates",
    "PINNED_ACTIONS": "aisdlc.security.ci_templates",
    "SUPPORTED_LANGUAGES": "aisdlc.security.ci_templates",
    "WORKFLOWS_DIR": "aisdlc.security.ci_templates",
    "PinIssue": "aisdlc.security.ci_templates",
    "RenderError": "aisdlc.security.ci_templates",
    "RenderOptions": "aisdlc.security.ci_templates",
    "WorkflowIssue": "aisdlc.security.ci_templates",
    "lint_workflow": "aisdlc.security.ci_templates",
    "list_workflows": "aisdlc.security.ci_templates",
    "load_workflow": "aisdlc.security.ci_templates",
    "pin": "aisdlc.security.ci_templates",
    "render": "aisdlc.security.ci_templates",
    "render_caller": "aisdlc.security.ci_templates",
    "render_to": "aisdlc.security.ci_templates",
    "verify_pins": "aisdlc.security.ci_templates",
    # supply_chain
    "CollectedInputs": "aisdlc.security.supply_chain",
    "ProvenanceInfo": "aisdlc.security.supply_chain",
    "SarifReport": "aisdlc.security.supply_chain",
    "SarifResult": "aisdlc.security.supply_chain",
    "SbomInfo": "aisdlc.security.supply_chain",
    "SeverityLevel": "aisdlc.security.supply_chain",
    "VexStatement": "aisdlc.security.supply_chain",
    "Vulnerability": "aisdlc.security.supply_chain",
    "apply_vex": "aisdlc.security.supply_chain",
    "build_security_evidence": "aisdlc.security.supply_chain",
    "collect_directory": "aisdlc.security.supply_chain",
    "detect_provenance": "aisdlc.security.supply_chain",
    "detect_sbom": "aisdlc.security.supply_chain",
    "parse_dependency_review": "aisdlc.security.supply_chain",
    "parse_gitleaks": "aisdlc.security.supply_chain",
    "parse_openvex": "aisdlc.security.supply_chain",
    "parse_sarif": "aisdlc.security.supply_chain",
    "scan_result_for": "aisdlc.security.supply_chain",
    "severity_from_score": "aisdlc.security.supply_chain",
    "update_security_evidence": "aisdlc.security.supply_chain",
    "write_security_evidence": "aisdlc.security.supply_chain",
    # manifest
    "DriftReport": "aisdlc.security.manifest",
    "ObservedBehaviour": "aisdlc.security.manifest",
    "ToolCallRecord": "aisdlc.security.manifest",
    "check_drift": "aisdlc.security.manifest",
    "compare": "aisdlc.security.manifest",
    "drift_for_package": "aisdlc.security.manifest",
    "host_of": "aisdlc.security.manifest",
    "load_audit_entries": "aisdlc.security.manifest",
    "load_declared_manifest": "aisdlc.security.manifest",
    "matches_declared": "aisdlc.security.manifest",
    "observe": "aisdlc.security.manifest",
    "observe_audit": "aisdlc.security.manifest",
    "record_from_audit_entry": "aisdlc.security.manifest",
    # pyrit_campaign
    "AttackSpec": "aisdlc.security.pyrit_campaign",
    "BaselineDelta": "aisdlc.security.pyrit_campaign",
    "BaselineNotFoundError": "aisdlc.security.pyrit_campaign",
    "BaselineStore": "aisdlc.security.pyrit_campaign",
    "CampaignError": "aisdlc.security.pyrit_campaign",
    "CampaignResult": "aisdlc.security.pyrit_campaign",
    "CampaignSpec": "aisdlc.security.pyrit_campaign",
    "Objective": "aisdlc.security.pyrit_campaign",
    "ObjectiveResult": "aisdlc.security.pyrit_campaign",
    "ScorerSpec": "aisdlc.security.pyrit_campaign",
    "SuccessCriteria": "aisdlc.security.pyrit_campaign",
    "UsageSummary": "aisdlc.security.pyrit_campaign",
    "compare_results": "aisdlc.security.pyrit_campaign",
    "load_campaign": "aisdlc.security.pyrit_campaign",
    "run_campaign": "aisdlc.security.pyrit_campaign",
    "run_campaign_async": "aisdlc.security.pyrit_campaign",
    # safety_regression
    "SafetyCase": "aisdlc.security.safety_regression",
    "SafetyReport": "aisdlc.security.safety_regression",
    "SafetyRun": "aisdlc.security.safety_regression",
    "TrialOutcome": "aisdlc.security.safety_regression",
    "run_safety_suite": "aisdlc.security.safety_regression",
    "safety_case": "aisdlc.security.safety_regression",
    # judges
    "CalibrationReport": "aisdlc.security.judges",
    "JudgeThresholds": "aisdlc.security.judges",
    "LabelledRow": "aisdlc.security.judges",
    "calibrate_scorer": "aisdlc.security.judges",
    "calibrate_scorer_async": "aisdlc.security.judges",
    "check_calibration": "aisdlc.security.judges",
    # targets (requires PyRIT)
    "AppUnderTestTarget": "aisdlc.security.targets",
    "CannedTarget": "aisdlc.security.targets",
    "EchoTarget": "aisdlc.security.targets",
    "HttpAppTarget": "aisdlc.security.targets",
    "ToolEventRecorder": "aisdlc.security.targets",
    "demo_vulnerable_app": "aisdlc.security.targets",
}

__all__ = sorted(set(_LAZY) | set(_SUBMODULES))


def __getattr__(name: str) -> Any:
    if name in _SUBMODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY) | set(_SUBMODULES))
