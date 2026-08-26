"""Plane 1 supply-chain evidence parsers → :class:`~aisdlc.schema.models.SecurityEvidence`.

Parsers (all offline, all tolerant of the common real-world shapes):

* :func:`parse_sarif` — CodeQL / Semgrep / gitleaks SARIF (severity from
  ``security-severity`` CVSS, else result level);
* :func:`parse_dependency_review` — ``actions/dependency-review-action`` output
  (``vulnerable-changes`` / dependency changes with ``vulnerabilities``);
* :func:`parse_gitleaks` — gitleaks JSON findings (every finding counts as ``high``);
* :func:`detect_sbom` — SPDX / CycloneDX presence and component count;
* :func:`detect_provenance` — in-toto / SLSA statements, DSSE envelopes, Sigstore bundles,
  GitHub attestation API responses;
* :func:`parse_openvex` / :func:`apply_vex` — OpenVEX statements that suppress
  ``not_affected`` / ``fixed`` vulnerabilities.

:func:`build_security_evidence` merges the parsed pieces with PyRIT / safety-regression
summaries supplied by the plane-3 modules (plain dicts or models) into one
:class:`SecurityEvidence`; :func:`collect_directory` finds the artifacts in a CI download
directory by name.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import __version__
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    EvidenceKind,
    EvidenceStatus,
    PyritSummary,
    SafetySummary,
    ScanResult,
    SecurityEvidence,
    utcnow,
)

__all__ = [
    "DEFAULT_EVIDENCE_ID",
    "PRODUCED_BY",
    "CollectedInputs",
    "ProvenanceInfo",
    "SarifReport",
    "SarifResult",
    "SbomInfo",
    "SeverityLevel",
    "VexStatement",
    "Vulnerability",
    "apply_vex",
    "build_security_evidence",
    "collect_directory",
    "detect_provenance",
    "detect_sbom",
    "load_json",
    "parse_dependency_review",
    "parse_gitleaks",
    "parse_openvex",
    "parse_sarif",
    "scan_result_for",
    "severity_from_score",
    "write_security_evidence",
    "update_security_evidence",
]

PRODUCED_BY = f"aisdlc.security.supply_chain/{__version__}"
DEFAULT_EVIDENCE_ID = "EVD-security-001"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SeverityLevel(StrEnum):
    """Severity buckets used for counting."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_ALIASES: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "error": SeverityLevel.HIGH,
    "moderate": SeverityLevel.MEDIUM,
    "medium": SeverityLevel.MEDIUM,
    "warning": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "note": SeverityLevel.LOW,
    "recommendation": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
    "none": SeverityLevel.INFO,
    "unknown": SeverityLevel.MEDIUM,
}


def severity_from_score(score: float) -> SeverityLevel:
    """CVSS v3 qualitative rating: ≥9 critical, ≥7 high, ≥4 medium, >0 low, else info."""
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score > 0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def _severity(value: Any, default: SeverityLevel = SeverityLevel.MEDIUM) -> SeverityLevel:
    if value is None:
        return default
    if isinstance(value, int | float) and not isinstance(value, bool):
        return severity_from_score(float(value))
    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    try:
        return severity_from_score(float(text))
    except ValueError:
        return default


def load_json(source: str | Path | bytes | Mapping[str, Any] | Sequence[Any]) -> Any:
    """Load JSON from a path, text, bytes or return an already-parsed object."""
    if isinstance(source, bytes):
        text = source.decode("utf-8", errors="replace")
    elif isinstance(source, Path):
        text = source.read_text(encoding="utf-8")
    elif isinstance(source, str):
        text = source if source.lstrip().startswith(("{", "[")) else Path(source).read_text("utf-8")
    else:
        return source
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


# --------------------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------------------


class SarifResult(_Model):
    """One SARIF result, reduced to what the gate needs."""

    rule_id: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    level: str = ""
    message: str = ""
    file: str | None = None
    line: int | None = Field(default=None, ge=0)
    suppressed: bool = False


class SarifReport(_Model):
    """Parsed SARIF log."""

    tool: str = ""
    version: str = ""
    results: list[SarifResult] = Field(default_factory=list)

    @property
    def active(self) -> list[SarifResult]:
        """Results that are not suppressed."""
        return [r for r in self.results if not r.suppressed]

    def scan_result(self, *, report_uri: str | None = None) -> ScanResult:
        """Count active results by severity."""
        counts = _count(r.severity for r in self.active)
        return ScanResult(tool=self.tool or "sarif", ran=True, report_uri=report_uri, **counts)


def _count(severities: Iterable[SeverityLevel]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev in severities:
        if sev is SeverityLevel.INFO:
            continue
        counts[sev.value] += 1
    return counts


def parse_sarif(source: str | Path | bytes | Mapping[str, Any]) -> SarifReport:
    """Parse a SARIF 2.1 log (all runs merged; the first run's tool names the report).

    Severity comes from the rule's ``properties.security-severity`` (CVSS score) when
    present, else ``properties.problem.severity``, else the result ``level``.
    """
    data = load_json(source)
    if not isinstance(data, Mapping) or "runs" not in data:
        raise ValueError("not a SARIF log (missing 'runs')")
    report = SarifReport()
    results: list[SarifResult] = []
    for run in data.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        if not report.tool:
            report = report.model_copy(
                update={
                    "tool": str(driver.get("name", "")),
                    "version": str(driver.get("semanticVersion", driver.get("version", ""))),
                }
            )
        rules: dict[str, Mapping[str, Any]] = {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, Mapping) and rule.get("id"):
                rules[str(rule["id"])] = rule
        for ext in run.get("tool", {}).get("extensions") or []:
            for rule in ext.get("rules") or []:
                if isinstance(rule, Mapping) and rule.get("id"):
                    rules.setdefault(str(rule["id"]), rule)
        for item in run.get("results") or []:
            if not isinstance(item, Mapping):
                continue
            rule_id = str(item.get("ruleId", ""))
            rule = rules.get(rule_id) or (item.get("rule") or {})
            props = rule.get("properties") or {}
            level = str(
                item.get("level") or (rule.get("defaultConfiguration") or {}).get("level", "")
            )
            if "security-severity" in props:
                severity = _severity(props["security-severity"])
            elif isinstance(props.get("problem"), Mapping) and "severity" in props["problem"]:
                severity = _severity(props["problem"]["severity"])
            elif "severity" in props:
                severity = _severity(props["severity"])
            else:
                severity = _severity(level or None)
            file: str | None = None
            line: int | None = None
            for loc in item.get("locations") or []:
                phys = (loc or {}).get("physicalLocation") or {}
                file = (phys.get("artifactLocation") or {}).get("uri") or file
                region = phys.get("region") or {}
                if isinstance(region.get("startLine"), int):
                    line = region["startLine"]
                if file:
                    break
            suppressed = bool(item.get("suppressions")) or str(item.get("kind", "")) in (
                "pass",
                "notApplicable",
                "informational",
            )
            results.append(
                SarifResult(
                    rule_id=rule_id,
                    severity=severity,
                    level=level,
                    message=str((item.get("message") or {}).get("text", ""))[:500],
                    file=file,
                    line=line,
                    suppressed=suppressed,
                )
            )
    return report.model_copy(update={"results": results})


# --------------------------------------------------------------------------------------
# Dependency review / vulnerabilities / VEX
# --------------------------------------------------------------------------------------


class Vulnerability(_Model):
    """A dependency vulnerability from SCA output."""

    id: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    package: str = ""
    version: str = ""
    ecosystem: str = ""
    source: str = "dependency-review"
    fixed_version: str | None = None
    suppressed_by: str | None = Field(default=None, description="VEX statement that suppressed it.")

    @property
    def open(self) -> bool:
        """Not suppressed by a VEX statement."""
        return self.suppressed_by is None


def parse_dependency_review(
    source: str | Path | bytes | Mapping[str, Any] | Sequence[Any],
) -> list[Vulnerability]:
    """Parse ``dependency-review-action`` output into :class:`Vulnerability` records.

    Accepts the ``vulnerable-changes`` output (a list of dependency changes, each with
    ``vulnerabilities``), a wrapper object (``changes``/``vulnerable_changes``/
    ``vulnerabilities``) or a bare list of vulnerability objects
    (``advisory_ghsa_id``/``id``, ``severity``, ``package``).
    """
    data = load_json(source)
    if isinstance(data, Mapping):
        for key in ("vulnerable_changes", "vulnerable-changes", "changes", "vulnerabilities"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            raise ValueError("dependency-review JSON has no changes/vulnerabilities list")
    if not isinstance(data, list):
        raise ValueError("dependency-review JSON must be a list or an object with a list")
    found: list[Vulnerability] = []
    for entry in data:
        if not isinstance(entry, Mapping):
            continue
        if isinstance(entry.get("vulnerabilities"), list):
            change_type = str(entry.get("change_type", "added"))
            if change_type == "removed":
                continue
            package = str(entry.get("name", entry.get("package", "")))
            version = str(entry.get("version", ""))
            ecosystem = str(entry.get("ecosystem", ""))
            for vuln in entry["vulnerabilities"]:
                if isinstance(vuln, Mapping):
                    found.append(_vuln(vuln, package=package, version=version, ecosystem=ecosystem))
        else:
            found.append(_vuln(entry))
    return found


def _vuln(
    item: Mapping[str, Any], *, package: str = "", version: str = "", ecosystem: str = ""
) -> Vulnerability:
    ident = item.get("advisory_ghsa_id") or item.get("ghsa_id") or item.get("id") or item.get("cve")
    if not ident:
        ident = item.get("advisory_url") or "unknown"
    pkg = item.get("package")
    pkg_name = pkg.get("name", "") if isinstance(pkg, Mapping) else pkg
    return Vulnerability(
        id=str(ident),
        severity=_severity(item.get("severity")),
        package=str(package or pkg_name or item.get("name", "")),
        version=str(version or item.get("version", "")),
        ecosystem=str(ecosystem or (pkg.get("ecosystem", "") if isinstance(pkg, Mapping) else "")),
        fixed_version=(
            str(item["first_patched_version"]) if item.get("first_patched_version") else None
        ),
    )


class VexStatement(_Model):
    """One OpenVEX statement."""

    vulnerability: str
    status: str
    products: list[str] = Field(default_factory=list)
    justification: str | None = None
    statement_id: str | None = None


_VEX_SUPPRESSING = frozenset({"not_affected", "fixed"})


def parse_openvex(source: str | Path | bytes | Mapping[str, Any]) -> list[VexStatement]:
    """Parse an OpenVEX document into :class:`VexStatement` records."""
    data = load_json(source)
    if not isinstance(data, Mapping) or not isinstance(data.get("statements"), list):
        raise ValueError("not an OpenVEX document (missing 'statements')")
    statements: list[VexStatement] = []
    for index, item in enumerate(data["statements"]):
        if not isinstance(item, Mapping):
            continue
        vuln = item.get("vulnerability")
        name = vuln.get("name") or vuln.get("@id") if isinstance(vuln, Mapping) else vuln
        if not name:
            raise ValueError(f"statement {index} has no vulnerability name")
        products: list[str] = []
        for product in item.get("products") or []:
            if isinstance(product, Mapping):
                products.append(
                    str(product.get("@id") or product.get("identifiers", {}).get("purl", ""))
                )
            else:
                products.append(str(product))
        statements.append(
            VexStatement(
                vulnerability=str(name),
                status=str(item.get("status", "under_investigation")),
                products=[p for p in products if p],
                justification=item.get("justification"),
                statement_id=str(item["@id"]) if item.get("@id") else f"statement-{index}",
            )
        )
    return statements


def apply_vex(
    vulns: Iterable[Vulnerability], statements: Iterable[VexStatement]
) -> list[Vulnerability]:
    """Suppress vulnerabilities covered by ``not_affected``/``fixed`` VEX statements.

    A statement without products applies to every package; otherwise the vulnerable
    package name (or ``pkg:<ecosystem>/<name>`` purl prefix) must appear in ``products``.
    """
    suppressors = [s for s in statements if s.status in _VEX_SUPPRESSING]
    result: list[Vulnerability] = []
    for vuln in vulns:
        match: VexStatement | None = None
        for stmt in suppressors:
            if stmt.vulnerability.lower() != vuln.id.lower():
                continue
            if not stmt.products or any(_product_matches(p, vuln) for p in stmt.products):
                match = stmt
                break
        if match is not None:
            result.append(
                vuln.model_copy(update={"suppressed_by": match.statement_id or match.status})
            )
        else:
            result.append(vuln)
    return result


def _product_matches(product: str, vuln: Vulnerability) -> bool:
    text = product.lower()
    name = vuln.package.lower()
    if not name:
        return False
    if text == name:
        return True
    if text.startswith("pkg:"):
        body = text[4:]
        if "/" in body:
            _eco, rest = body.split("/", 1)
            rest = rest.split("@", 1)[0].split("?", 1)[0]
            return rest == name or rest.endswith("/" + name)
    return False


def scan_result_for(
    vulns: Iterable[Vulnerability],
    *,
    tool: str = "dependency-review",
    ran: bool = True,
    report_uri: str | None = None,
) -> ScanResult:
    """Count open (non-suppressed) vulnerabilities by severity."""
    counts = _count(v.severity for v in vulns if v.open)
    return ScanResult(tool=tool, ran=ran, report_uri=report_uri, **counts)


# --------------------------------------------------------------------------------------
# gitleaks
# --------------------------------------------------------------------------------------


def parse_gitleaks(
    source: str | Path | bytes | Mapping[str, Any] | Sequence[Any], *, report_uri: str | None = None
) -> ScanResult:
    """Parse gitleaks JSON output (a list of findings, or SARIF) into a :class:`ScanResult`.

    Every leaked secret counts as ``high`` (gitleaks assigns no severity).
    """
    data = load_json(source)
    if isinstance(data, Mapping) and "runs" in data:
        report = parse_sarif(data)
        active = report.active
        return ScanResult(
            tool=report.tool or "gitleaks",
            ran=True,
            high=len(active),
            report_uri=report_uri,
        )
    if isinstance(data, Mapping):
        findings = data.get("findings", data.get("results"))
        if not isinstance(findings, list):
            raise ValueError("gitleaks JSON must be a list of findings")
        data = findings
    if not isinstance(data, list):
        raise ValueError("gitleaks JSON must be a list of findings")
    count = sum(1 for item in data if isinstance(item, Mapping))
    return ScanResult(tool="gitleaks", ran=True, high=count, report_uri=report_uri)


# --------------------------------------------------------------------------------------
# SBOM / provenance presence
# --------------------------------------------------------------------------------------


class SbomInfo(_Model):
    """Presence and shape of a software bill of materials."""

    present: bool = False
    format: str | None = Field(default=None, description="``spdx`` or ``cyclonedx``.")
    spec_version: str | None = None
    components: int = Field(default=0, ge=0)
    path: str | None = None
    problem: str | None = None


def detect_sbom(source: str | Path | bytes | Mapping[str, Any] | None) -> SbomInfo:
    """Detect an SPDX (``spdxVersion``) or CycloneDX (``bomFormat``) SBOM document."""
    if source is None:
        return SbomInfo(problem="no SBOM supplied")
    path = str(source) if isinstance(source, Path) else None
    try:
        data = load_json(source)
    except (OSError, ValueError) as exc:
        return SbomInfo(path=path, problem=str(exc))
    if not isinstance(data, Mapping):
        return SbomInfo(path=path, problem="SBOM must be a JSON object")
    if "spdxVersion" in data:
        packages = data.get("packages") or []
        return SbomInfo(
            present=True,
            format="spdx",
            spec_version=str(data["spdxVersion"]),
            components=len(packages) if isinstance(packages, list) else 0,
            path=path,
        )
    if str(data.get("bomFormat", "")).lower() == "cyclonedx":
        components = data.get("components") or []
        return SbomInfo(
            present=True,
            format="cyclonedx",
            spec_version=str(data.get("specVersion", "")) or None,
            components=len(components) if isinstance(components, list) else 0,
            path=path,
        )
    return SbomInfo(path=path, problem="unrecognised SBOM format (expected SPDX or CycloneDX)")


class ProvenanceInfo(_Model):
    """Presence of build provenance / attestations."""

    present: bool = False
    format: str | None = Field(
        default=None, description="in-toto | dsse | sigstore-bundle | github-attestations"
    )
    predicate_type: str | None = None
    builder_id: str | None = None
    subjects: list[str] = Field(default_factory=list)
    path: str | None = None
    problem: str | None = None


def _statement_info(statement: Mapping[str, Any], fmt: str, path: str | None) -> ProvenanceInfo:
    predicate_type = str(statement.get("predicateType", ""))
    predicate = statement.get("predicate") or {}
    builder: str | None = None
    if isinstance(predicate, Mapping):
        run_details = predicate.get("runDetails") or {}
        builder_obj = run_details.get("builder") if isinstance(run_details, Mapping) else None
        if isinstance(builder_obj, Mapping) and builder_obj.get("id"):
            builder = str(builder_obj["id"])
        elif isinstance(predicate.get("builder"), Mapping) and predicate["builder"].get("id"):
            builder = str(predicate["builder"]["id"])
    subjects: list[str] = []
    for subject in statement.get("subject") or []:
        if isinstance(subject, Mapping):
            name = str(subject.get("name", ""))
            digest = subject.get("digest") or {}
            sha = digest.get("sha256") if isinstance(digest, Mapping) else None
            subjects.append(f"{name}@sha256:{sha}" if sha else name)
    is_provenance = "provenance" in predicate_type.lower() or (
        not predicate_type and "in-toto.io" in str(statement.get("_type", ""))
    )
    if not is_provenance:
        return ProvenanceInfo(
            path=path, problem=f"statement predicate {predicate_type!r} is not provenance"
        )
    return ProvenanceInfo(
        present=True,
        format=fmt,
        predicate_type=predicate_type or None,
        builder_id=builder,
        subjects=subjects,
        path=path,
    )


def _decode_envelope(envelope: Mapping[str, Any], fmt: str, path: str | None) -> ProvenanceInfo:
    payload_type = str(envelope.get("payloadType", ""))
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        return ProvenanceInfo(path=path, problem="DSSE envelope has no payload")
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4))
        statement = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        return ProvenanceInfo(path=path, problem=f"cannot decode DSSE payload: {exc}")
    if "in-toto" not in payload_type and not isinstance(statement, Mapping):
        return ProvenanceInfo(path=path, problem=f"unexpected payloadType {payload_type!r}")
    return _statement_info(statement, fmt, path)


def detect_provenance(
    source: str | Path | bytes | Mapping[str, Any] | Sequence[Any] | None,
) -> ProvenanceInfo:
    """Detect SLSA/in-toto provenance in any of the usual containers.

    Handles a bare in-toto statement, a DSSE envelope, a Sigstore bundle
    (``dsseEnvelope``), a GitHub attestations API response (``attestations[].bundle``) and
    JSON-lines files (``*.intoto.jsonl``, first line).
    """
    if source is None:
        return ProvenanceInfo(problem="no provenance supplied")
    path = str(source) if isinstance(source, Path) else None
    try:
        if isinstance(source, Path) and source.suffix == ".jsonl":
            first = source.read_text(encoding="utf-8").strip().splitlines()
            data: Any = json.loads(first[0]) if first else {}
        else:
            data = load_json(source)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return ProvenanceInfo(path=path, problem=str(exc))
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, Mapping):
        return ProvenanceInfo(path=path, problem="provenance must be a JSON object")
    if isinstance(data.get("attestations"), list) and data["attestations"]:
        first_att = data["attestations"][0]
        bundle = first_att.get("bundle") if isinstance(first_att, Mapping) else None
        if isinstance(bundle, Mapping) and isinstance(bundle.get("dsseEnvelope"), Mapping):
            return _decode_envelope(bundle["dsseEnvelope"], "github-attestations", path)
        return ProvenanceInfo(path=path, problem="attestation has no dsseEnvelope")
    if isinstance(data.get("dsseEnvelope"), Mapping):
        return _decode_envelope(data["dsseEnvelope"], "sigstore-bundle", path)
    if "payloadType" in data and "payload" in data:
        return _decode_envelope(data, "dsse", path)
    if "predicateType" in data or "_type" in data:
        return _statement_info(data, "in-toto", path)
    return ProvenanceInfo(path=path, problem="unrecognised provenance format")


# --------------------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------------------


def _pyrit(value: PyritSummary | Mapping[str, Any] | None) -> PyritSummary | None:
    if value is None or isinstance(value, PyritSummary):
        return value
    return PyritSummary.model_validate(dict(value))


def _safety(value: SafetySummary | Mapping[str, Any] | None) -> SafetySummary | None:
    if value is None or isinstance(value, SafetySummary):
        return value
    return SafetySummary.model_validate(dict(value))


def build_security_evidence(
    *,
    sast: ScanResult | SarifReport | None = None,
    sca: ScanResult | Sequence[Vulnerability] | None = None,
    secrets: ScanResult | None = None,
    sbom: SbomInfo | bool | None = None,
    provenance: ProvenanceInfo | bool | None = None,
    vex: Sequence[VexStatement] = (),
    pyrit: PyritSummary | Mapping[str, Any] | None = None,
    safety: SafetySummary | Mapping[str, Any] | None = None,
    manifest_drift: bool = False,
    commit_sha: str = "",
    environment: str = "ci",
    evidence_id: str = DEFAULT_EVIDENCE_ID,
    produced_by: str = PRODUCED_BY,
    report_uri: str | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    required_scans: Iterable[str] = ("sast", "sca", "secrets"),
) -> SecurityEvidence:
    """Merge parsed supply-chain inputs and plane-3 summaries into :class:`SecurityEvidence`.

    ``critical_open``/``high_open`` sum the three scans (after VEX suppression for SCA).
    The record is ``complete`` only when every scan named in *required_scans* ran and any
    PyRIT / safety summary supplied is itself complete — anything less fails G4 closed.
    """
    sast_result = sast.scan_result() if isinstance(sast, SarifReport) else sast
    if isinstance(sca, ScanResult) or sca is None:
        sca_result = sca
    else:
        sca_result = scan_result_for(apply_vex(sca, vex) if vex else sca)
    sbom_present = sbom.present if isinstance(sbom, SbomInfo) else bool(sbom)
    prov_present = (
        provenance.present if isinstance(provenance, ProvenanceInfo) else bool(provenance)
    )
    scans: dict[str, ScanResult | None] = {
        "sast": sast_result,
        "sca": sca_result,
        "secrets": secrets,
    }
    critical = sum(s.critical for s in scans.values() if s is not None and s.ran)
    high = sum(s.high for s in scans.values() if s is not None and s.ran)
    pyrit_summary = _pyrit(pyrit)
    safety_summary = _safety(safety)
    complete = all((scan := scans.get(name)) is not None and scan.ran for name in required_scans)
    if pyrit_summary is not None and not pyrit_summary.complete:
        complete = False
    if safety_summary is not None and not safety_summary.complete:
        complete = False
    now = utcnow()
    return SecurityEvidence(
        id=evidence_id,
        kind=EvidenceKind.SECURITY,
        commit_sha=commit_sha,
        environment=environment,
        produced_by=produced_by,
        started_at=started_at or now,
        finished_at=finished_at or now,
        report_uri=report_uri,
        status=EvidenceStatus.COMPLETE if complete else EvidenceStatus.INCOMPLETE,
        sast=sast_result,
        sca=sca_result,
        secrets=secrets,
        sbom_present=sbom_present,
        provenance_present=prov_present,
        critical_open=critical,
        high_open=high,
        pyrit=pyrit_summary,
        safety_regression=safety_summary,
        manifest_drift=manifest_drift,
    )


class CollectedInputs(_Model):
    """What :func:`collect_directory` found (paths are relative to the directory)."""

    sarif: list[str] = Field(default_factory=list)
    dependency_review: str | None = None
    gitleaks: str | None = None
    sbom: str | None = None
    provenance: str | None = None
    vex: str | None = None
    pyrit: str | None = None
    safety: str | None = None
    notes: list[str] = Field(default_factory=list)


_SARIF_SUFFIXES = (".sarif", ".sarif.json")
_SBOM_HINTS = ("sbom", ".spdx", ".cdx", "cyclonedx", "bom.json")
_PROVENANCE_HINTS = ("provenance", "attestation", ".intoto", "slsa")
_VEX_HINTS = ("vex",)


def collect_directory(
    directory: str | Path,
    *,
    commit_sha: str = "",
    environment: str = "ci",
    evidence_id: str = DEFAULT_EVIDENCE_ID,
    manifest_drift: bool = False,
    report_uri: str | None = None,
) -> tuple[SecurityEvidence, CollectedInputs]:
    """Find CI artifacts under *directory* by name and build :class:`SecurityEvidence`.

    Recognised files: ``*.sarif`` (CodeQL/Semgrep; a gitleaks SARIF is routed to the secrets
    scan), ``dependency-review*.json``, ``gitleaks*.json``, SBOMs (``*sbom*``, ``*.spdx.json``,
    ``*.cdx.json``), provenance (``*provenance*``, ``*attestation*``, ``*.intoto.jsonl``),
    OpenVEX (``*vex*.json``), ``pyrit*.json`` and ``safety*.json`` summaries.
    """
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"{root} is not a directory")
    found = CollectedInputs()
    sast_reports: list[SarifReport] = []
    secrets: ScanResult | None = None
    sca: list[Vulnerability] | None = None
    sbom: SbomInfo | None = None
    provenance: ProvenanceInfo | None = None
    vex: list[VexStatement] = []
    pyrit: Any = None
    safety: Any = None
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        name = path.name.lower()
        rel = str(path.relative_to(root))
        try:
            if name.endswith(_SARIF_SUFFIXES):
                report = parse_sarif(path)
                if "gitleaks" in report.tool.lower() or "gitleaks" in name:
                    secrets = parse_gitleaks(path, report_uri=rel)
                    found.gitleaks = rel
                else:
                    sast_reports.append(report)
                    found.sarif.append(rel)
            elif name.startswith("dependency-review") and name.endswith(".json"):
                sca = parse_dependency_review(path)
                found.dependency_review = rel
            elif name.startswith("gitleaks") and name.endswith(".json"):
                secrets = parse_gitleaks(path, report_uri=rel)
                found.gitleaks = rel
            elif name.endswith(".json") and any(h in name for h in _VEX_HINTS):
                vex = parse_openvex(path)
                found.vex = rel
            elif any(h in name for h in _SBOM_HINTS) and name.endswith(".json"):
                candidate = detect_sbom(path)
                if candidate.present:
                    sbom = candidate
                    found.sbom = rel
                else:
                    found.notes.append(f"{rel}: {candidate.problem}")
            elif any(h in name for h in _PROVENANCE_HINTS):
                candidate_p = detect_provenance(path)
                if candidate_p.present:
                    provenance = candidate_p
                    found.provenance = rel
                else:
                    found.notes.append(f"{rel}: {candidate_p.problem}")
            elif name.startswith("pyrit") and name.endswith(".json"):
                pyrit = _summary_dict(load_json(path), "pyrit")
                found.pyrit = rel
            elif name.startswith("safety") and name.endswith(".json"):
                safety = _summary_dict(load_json(path), "safety_regression")
                found.safety = rel
        except (OSError, ValueError) as exc:
            found.notes.append(f"{rel}: {exc}")
    sast: ScanResult | None = None
    if sast_reports:
        merged = SarifReport(
            tool=", ".join(sorted({r.tool for r in sast_reports if r.tool})) or "sarif",
            results=[r for rep in sast_reports for r in rep.results],
        )
        sast = merged.scan_result(report_uri=";".join(found.sarif))
    evidence = build_security_evidence(
        sast=sast,
        sca=sca,
        secrets=secrets,
        sbom=sbom,
        provenance=provenance,
        vex=vex,
        pyrit=pyrit,
        safety=safety,
        manifest_drift=manifest_drift,
        commit_sha=commit_sha,
        environment=environment,
        evidence_id=evidence_id,
        report_uri=report_uri,
    )
    return evidence, found


def _summary_dict(data: Any, key: str) -> Mapping[str, Any] | None:
    """Accept a bare summary or a wrapper holding it under *key*."""
    if not isinstance(data, Mapping):
        raise ValueError(f"{key} summary must be a JSON object")
    inner = data.get(key)
    if isinstance(inner, Mapping):
        return inner
    return data


def write_security_evidence(package_dir: str | Path, evidence: SecurityEvidence) -> Path:
    """Write *evidence* to ``<package>/evidence/security.json`` via the schema package API."""
    return pkgio.write_evidence(package_dir, EvidenceKind.SECURITY, evidence)


def update_security_evidence(
    package_dir: str | Path,
    *,
    pyrit: PyritSummary | Mapping[str, Any] | None = None,
    safety: SafetySummary | Mapping[str, Any] | None = None,
    manifest_drift: bool | None = None,
    commit_sha: str | None = None,
    environment: str | None = None,
    produced_by: str = PRODUCED_BY,
    report_uri: str | None = None,
    evidence_id: str = DEFAULT_EVIDENCE_ID,
) -> SecurityEvidence:
    """Merge plane-3 summaries into the package's ``evidence/security.json``.

    The PyRIT campaign and safety-regression runners call this so that their results land
    in the canonical :class:`SecurityEvidence` record instead of a side file. Every
    supply-chain field of an existing record (scans, SBOM, provenance, vulnerability
    counts) is kept and only the supplied parts are replaced; ``None`` arguments leave the
    existing value alone. When no record exists a new one is created holding just the
    supplied summaries — its scans stay ``None`` so G4 still fails closed on missing
    SAST/SCA/secrets evidence. Status is ``complete`` only when every present summary is
    complete and the pre-existing record (if any) was complete.
    """
    existing = pkgio.read_evidence(package_dir, EvidenceKind.SECURITY)
    base = existing[0] if existing and isinstance(existing[0], SecurityEvidence) else None
    pyrit_summary = _pyrit(pyrit) if pyrit is not None else (base.pyrit if base else None)
    safety_summary = (
        _safety(safety) if safety is not None else (base.safety_regression if base else None)
    )
    drift = (
        manifest_drift if manifest_drift is not None else (base.manifest_drift if base else False)
    )
    complete = (
        (base is None or base.is_complete)
        and (pyrit_summary is None or pyrit_summary.complete)
        and (safety_summary is None or safety_summary.complete)
    )
    now = utcnow()
    update: dict[str, Any] = {
        "pyrit": pyrit_summary,
        "safety_regression": safety_summary,
        "manifest_drift": drift,
        "finished_at": now,
        "status": EvidenceStatus.COMPLETE if complete else EvidenceStatus.INCOMPLETE,
    }
    if commit_sha is not None and (commit_sha or base is None):
        update["commit_sha"] = commit_sha
    if environment is not None:
        update["environment"] = environment
    if report_uri is not None:
        update["report_uri"] = report_uri
    if base is None:
        record = SecurityEvidence(
            id=evidence_id,
            kind=EvidenceKind.SECURITY,
            produced_by=produced_by,
            started_at=now,
            **update,
        )
    else:
        producers = [p for p in base.produced_by.split(" + ") if p]
        if produced_by not in producers:
            producers.append(produced_by)
        update["produced_by"] = " + ".join(producers)
        record = base.model_copy(update=update)
    write_security_evidence(package_dir, record)
    return record
