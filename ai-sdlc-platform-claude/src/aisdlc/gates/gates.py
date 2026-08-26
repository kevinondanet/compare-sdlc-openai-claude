"""Progressive gates G0..G6 (ARCHITECTURE.md §3).

Every gate is a small deterministic evaluator over a :class:`ChangePackage`, the effective
policy and a :class:`GateDepthProfile`. Gates never raise for content problems: they
return a :class:`GateResult` with explicit reasons and the ids of the evidence they
consulted. Two rules hold for every gate:

* **Fail closed.** When the profile requires a check and the evidence for it is missing,
  incomplete or inadmissible (no commit sha / report URI / environment when the policy
  demands them), the gate fails.
* **Skip explicitly.** When the profile does not require the gate, the result is recorded
  with ``depth="skipped"`` and ``passed=True`` so it never blocks; consumers can tell a
  skipped gate from an evaluated one by its depth.

Self-reported flags in evidence records are never authoritative on their own: G1 runs the
goal-backward plan checker, G2 evaluates the coverage portfolio, G3 requires every
non-superseded review to be approved, G4 derives vulnerability counts from the scans and
computes tool/data manifest drift from the audit entries, G5 recomputes the SLO from
measurements and targets, and G6 verifies the signed audit log. Facts that live outside
the package model (git HEAD, fingerprints, approvals, drift, audit verification, persisted
portfolio inputs) are gathered once into a :class:`GateContext`.

:class:`GateRunner` evaluates all gates in order and produces an (unsigned)
:class:`FinalVerdict`; signing and bundling live in :mod:`aisdlc.gates.verdict`.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.parse import unquote, urlsplit

from aisdlc.gates import verdict as verdictmod
from aisdlc.gates.depth import GateDepthProfile, profile_for
from aisdlc.governance.audit import IntegrityReport, verify_audit_file
from aisdlc.governance.policy import GovernanceUnavailableError
from aisdlc.policy.org_policy import OrgPolicy
from aisdlc.policy.project_config import ProjectConfig
from aisdlc.schema import fingerprint as fp
from aisdlc.schema import grammar
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    AdrStatus,
    AuditEvidence,
    ChangePackage,
    EvidenceBase,
    EvidenceKind,
    FinalVerdict,
    GateDepth,
    GateId,
    GateResult,
    RequirementKind,
    ReviewEvidence,
    ReviewVerdict,
    ScanResult,
    TestEvidence,
    utcnow,
)
from aisdlc.testing import portfolio as pf

if TYPE_CHECKING:
    from aisdlc.security.manifest import DriftReport

__all__ = [
    "GateContext",
    "Gate",
    "BaseGate",
    "IntentReadinessGate",
    "ArchitectureReadinessGate",
    "ImplementationQualityGate",
    "IndependentReviewGate",
    "SecuritySafetyGate",
    "CostPerformanceGate",
    "ReleaseGate",
    "GATES",
    "gate_for",
    "GateRunner",
    "evaluate_gate",
    "evaluate_all",
    "effective_reviews",
    "verify_package_audit",
]


# --------------------------------------------------------------------------------------
# Context and protocol
# --------------------------------------------------------------------------------------


@dataclass
class GateContext:
    """Environment facts a gate may need beyond the package and policy.

    Built once by :class:`GateRunner` (from the package root when available) and passed to
    every gate; tests construct it directly to pin time, HEAD, key availability and the
    on-disk facts (manifest drift, audit verification, portfolio inputs).

    * ``manifest_drift`` — declared tool/data manifest vs the audit entries on disk
      (:func:`aisdlc.security.manifest.drift_for_package`); ``None`` when unknown.
    * ``audit_entries_source`` — where the per-call audit entries were found.
    * ``audit_integrity`` — verification of the signed audit log the audit evidence points
      at (:func:`verify_package_audit`); ``None`` when no log could be located.
    * ``portfolio_inputs`` — extra layer runs / exceptions / critical-module coverage
      persisted by ``aisdlc test portfolio`` (``evidence/portfolio.json``).
    """

    now: datetime = field(default_factory=utcnow)
    head_commit: str | None = None
    current_fingerprint: str | None = None
    stored_fingerprint: str | None = None
    approvals: list[verdictmod.Approval] = field(default_factory=list)
    signing_available: bool = False
    prior_results: list[GateResult] = field(default_factory=list)
    manifest_drift: DriftReport | None = None
    audit_entries_source: Path | None = None
    audit_integrity: IntegrityReport | None = None
    portfolio_inputs: pf.PortfolioInputs | None = None
    portfolio_inputs_error: str | None = None

    @classmethod
    def from_package(
        cls,
        package: ChangePackage,
        *,
        now: datetime | None = None,
        hmac_key: bytes | None = None,
    ) -> GateContext:
        """Derive the context from the package directory.

        Reads git HEAD, fingerprints, approvals, the manifest drift report, the audit log
        verification and the persisted portfolio inputs. ``hmac_key`` is an explicit
        signing key (``--hmac-key-file``); otherwise the same discovery as
        ``aisdlc gate bundle`` applies (``$AISDLC_SIGNING_KEY``, then the repo-local
        ``.aisdlc/signing.key``).
        """
        root = package.root
        ctx = cls(now=now or utcnow())
        if root is None or not Path(root).is_dir():
            ctx.stored_fingerprint = package.base_fingerprint
            ctx.signing_available = verdictmod.signing_available(hmac_key=hmac_key)
            return ctx
        root_path = Path(root)
        ctx.signing_available = verdictmod.signing_available(
            hmac_key=hmac_key, package_dir=root_path
        )
        ctx.head_commit = verdictmod.git_head(root_path)
        ctx.current_fingerprint = fp.compute_fingerprint(root_path)
        ctx.stored_fingerprint = fp.read_fingerprint(root_path) or package.base_fingerprint
        try:
            ctx.approvals = verdictmod.read_approvals(root_path)
        except verdictmod.BundleError:
            ctx.approvals = []
        from aisdlc.security.manifest import audit_entries_source, drift_for_package

        ctx.audit_entries_source = audit_entries_source(root_path)
        ctx.manifest_drift = drift_for_package(root_path)
        ctx.audit_integrity = verify_package_audit(root_path, package.evidence.audit)
        try:
            record = pf.read_portfolio_record(root_path)
        except ValueError as exc:
            ctx.portfolio_inputs_error = str(exc)
            record = None
        ctx.portfolio_inputs = record.inputs if record is not None else None
        return ctx


@runtime_checkable
class Gate(Protocol):
    """A gate: identity, the evidence kinds it reads, and an evaluator."""

    id: GateId
    title: str
    required_evidence_kinds: frozenset[EvidenceKind]

    def evaluate(
        self,
        package: ChangePackage,
        effective_policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext | None = None,
    ) -> GateResult:
        """Evaluate the gate; never raises for content problems."""
        ...


class BaseGate(ABC):
    """Shared skip/fail-closed plumbing; subclasses implement :meth:`check`."""

    id: GateId
    title: str = ""
    required_evidence_kinds: frozenset[EvidenceKind] = frozenset()

    def evaluate(
        self,
        package: ChangePackage,
        effective_policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext | None = None,
    ) -> GateResult:
        """Skip when the profile does not require this gate; otherwise run :meth:`check`."""
        if not profile.requires(self.id):
            return GateResult(
                gate=self.id,
                passed=True,
                depth=GateDepth.SKIPPED,
                reasons=[f"skipped: not required for risk class {profile.risk_class.value}"],
            )
        ctx = context if context is not None else GateContext.from_package(package)
        reasons: list[str] = []
        evidence_ids: list[str] = []
        self.check(package, effective_policy, profile, ctx, reasons, evidence_ids)
        return GateResult(
            gate=self.id,
            passed=not reasons,
            depth=profile.gate_depth(self.id),
            reasons=reasons,
            evidence_ids=sorted(set(evidence_ids)),
        )

    @abstractmethod
    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        """Append a reason for every failed check; append consulted evidence ids."""


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _admissible(record: EvidenceBase, profile: GateDepthProfile, reasons: list[str]) -> bool:
    """Evidence standards (§0 principle 5): complete + commit sha + report URI + env."""
    ok = True
    if not record.is_complete:
        reasons.append(f"{record.id}: evidence is incomplete")
        ok = False
    if profile.require_commit_sha and not record.commit_sha.strip():
        reasons.append(f"{record.id}: evidence records no commit sha")
        ok = False
    if profile.require_report_uri and not (record.report_uri or "").strip():
        reasons.append(f"{record.id}: evidence records no report URI")
        ok = False
    if profile.require_environment and not record.environment.strip():
        reasons.append(f"{record.id}: evidence records no environment")
        ok = False
    return ok


def _project_of(policy: OrgPolicy) -> ProjectConfig | None:
    project = getattr(policy, "project", None)
    return project if isinstance(project, ProjectConfig) else None


def _command_matches(record_command: str, configured: str) -> bool:
    """A record's command covers a configured command when it equals/extends it or shares
    the program name (first token)."""
    rec = " ".join(record_command.split())
    cfg = " ".join(configured.split())
    if not rec or not cfg:
        return False
    if rec == cfg or rec.startswith(cfg + " "):
        return True
    return rec.split()[0] == cfg.split()[0]


_LINK_CHECK_TOOLS: frozenset[str] = frozenset(
    {"lychee", "markdown-link-check", "linkchecker", "linkinator", "muffet", "htmltest"}
)


def _is_link_check(record: TestEvidence, configured: str | None) -> bool:
    """Whether a test record is a link check (configured command, known tool or tag)."""
    if configured and _command_matches(record.command, configured):
        return True
    tokens = record.command.split()
    if tokens and tokens[0] in _LINK_CHECK_TOOLS:
        return True
    return "link" in f"{record.produced_by} {record.command}".lower()


def _latest(records: Sequence[TestEvidence]) -> TestEvidence | None:
    if not records:
        return None
    return max(
        records,
        key=lambda r: r.finished_at or datetime.min.replace(tzinfo=UTC),
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _scan_check(
    name: str,
    scan: ScanResult | None,
    required: bool,
    evidence_id: str,
    max_high: int,
    reasons: list[str],
) -> None:
    if scan is None or not scan.ran:
        if required:
            reasons.append(f"{evidence_id}: {name} scan did not run")
        return
    if scan.critical:
        reasons.append(f"{evidence_id}: {name} reports {scan.critical} critical finding(s)")
    if scan.high > max_high:
        reasons.append(
            f"{evidence_id}: {name} reports {scan.high} high finding(s) (max {max_high})"
        )


def _uri_to_path(uri: str) -> Path | None:
    """Local path behind a ``file://`` URI or plain path; ``None`` for remote URIs."""
    text = uri.strip()
    if not text:
        return None
    if text.startswith("file://"):
        return Path(unquote(urlsplit(text).path))
    if "://" in text:
        return None
    return Path(text)


def _verify_audit_source(path: Path, *, package_dir: Path) -> IntegrityReport:
    """Verify an audit source: a signed JSON-lines log or an export pointing at one.

    A relative ``log_path`` inside an export is the path the producer passed on the
    command line, so it resolves against the current working directory and the repository
    root of *package_dir* (:func:`aisdlc.security.manifest.audit_path_candidates`) — never
    against the evidence directory the export sits in.
    """
    from aisdlc.security.manifest import audit_path_candidates

    text = path.read_text(encoding="utf-8")
    export: dict[str, object] | None = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and any(k in data for k in ("entries", "integrity_ok", "log_path")):
        export = data
    try:
        if export is None:
            return verify_audit_file(path)
        entries = export.get("entries")
        count = len(entries) if isinstance(entries, list) else int(str(entries or 0))
        log_value = export.get("log_path")
        if not log_value:
            return IntegrityReport(
                ok=False,
                entries=count,
                error=f"{path.name}: audit export references no signed log (log_path)",
            )
        candidates = audit_path_candidates(str(log_value), package_dir)
        log = next((c for c in candidates if c.is_file()), None)
        if log is None:
            tried = ", ".join(str(c) for c in candidates)
            return IntegrityReport(
                ok=False,
                entries=count,
                error=f"signed audit log {log_value} not found (looked in {tried})",
            )
        report = verify_audit_file(log)
        if report.ok and report.entries != count:
            return IntegrityReport(
                ok=False,
                entries=report.entries,
                error=(f"signed log holds {report.entries} entries but the export lists {count}"),
                file_verified=report.file_verified,
            )
        return report
    except (GovernanceUnavailableError, OSError, ValueError) as exc:
        return IntegrityReport(ok=False, entries=0, error=str(exc))


def verify_package_audit(root: str | Path, audit: AuditEvidence | None) -> IntegrityReport | None:
    """Verify the signed audit log behind a package's audit evidence.

    Looks at ``audit.report_uri`` (a ``file://`` URI or path to the signed JSON-lines log
    or to the entries export) and then ``evidence/audit-entries.json``. An export is
    followed to the signed log it names (``log_path``) and the entry counts must agree.
    Relative paths — the ``report_uri`` and the export's ``log_path`` — resolve against
    the current working directory, then the repository root holding the package
    (:func:`aisdlc.security.manifest.audit_path_candidates`); a relative ``report_uri``
    is finally tried relative to the package itself. Returns ``None`` when no source
    exists at all — G6 treats that as unverifiable.
    """
    from aisdlc.security.manifest import audit_path_candidates

    if audit is None:
        return None
    base = Path(root)
    candidates: list[Path] = []
    if audit.report_uri:
        target = _uri_to_path(audit.report_uri)
        if target is not None:
            candidates.extend(audit_path_candidates(target, base))
            if not target.is_absolute():
                candidates.append(base / target)
    candidates.append(pkgio.audit_entries_path(base))
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return _verify_audit_source(candidate, package_dir=base)
    return None


# --------------------------------------------------------------------------------------
# G0 intent readiness
# --------------------------------------------------------------------------------------


class IntentReadinessGate(BaseGate):
    """G0 — requirements, non-goals, assumptions, scenarios, ambiguity, owner, questions."""

    id = GateId.G0
    title = "Intent readiness"

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        intent = package.intent
        if profile.require_owner and not (intent.owner or "").strip():
            reasons.append("intent has no owner")
        if profile.require_kernel_complete and not intent.kernel.is_complete():
            reasons.append("kernel is incomplete (why, capabilities, non_goals, success_signal)")
        if profile.require_non_goals and not intent.kernel.non_goals:
            reasons.append("no non-goals stated")
        if profile.require_assumptions and not package.assumptions:
            reasons.append("no assumptions recorded")
        if not package.requirements:
            reasons.append("no requirements")
        elif profile.require_scenarios:
            for requirement in package.requirements:
                if not requirement.scenarios:
                    reasons.append(f"{requirement.id} has no acceptance scenario")
        for issue in grammar.validate_requirements(package.requirements):
            if issue.severity is grammar.IssueSeverity.ERROR:
                reasons.append(f"grammar {issue.code} [{issue.artifact_id}]: {issue.message}")
        report = grammar.ambiguity_report(package)
        if report.score > profile.ambiguity_threshold:
            reasons.append(
                f"ambiguity score {report.score:.2f} exceeds threshold "
                f"{profile.ambiguity_threshold:.2f} ({len(report.markers)} marker(s))"
            )
        if profile.block_on_open_questions:
            for question in package.open_questions:
                if question.is_open_blocking:
                    reasons.append(f"blocking open question {question.id}: {question.question}")


# --------------------------------------------------------------------------------------
# G1 architecture readiness
# --------------------------------------------------------------------------------------


class ArchitectureReadinessGate(BaseGate):
    """G1 — plan (goal-backward plan checker), ADRs, interfaces, threat model, NFRs."""

    id = GateId.G1
    title = "Architecture readiness"

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        plan = package.plan
        seen: set[tuple[str, str | None]] = set()
        if profile.require_plan:
            if plan is None or not plan.waves:
                reasons.append("no plan with at least one wave")
            if not package.tasks:
                reasons.append("no tasks")
            if profile.require_plan_approval and (plan is None or not (plan.approved_by or "")):
                reasons.append("plan is not approved by a human")
            # Goal-backward plan checker (§3: "plan checker failure" blocks G1). Imported
            # lazily: aisdlc.planning re-exports the depth profile from this package.
            from aisdlc.planning.plan_checker import check_plan

            report = check_plan(
                package, profile=profile, project_config=_project_of(policy), policy=policy
            )
            for issue in report.blocking:
                key = (issue.code, issue.artifact_id)
                if key in seen:
                    continue
                seen.add(key)
                where = f" [{issue.artifact_id}]" if issue.artifact_id else ""
                reasons.append(f"plan check {issue.code}{where}: {issue.message}")
        for grammar_issue in grammar.validate_package(package):
            if grammar_issue.severity is not grammar.IssueSeverity.ERROR:
                continue
            if not grammar_issue.code.startswith(("TASK_", "PLAN_")):
                continue
            key = (grammar_issue.code, grammar_issue.artifact_id)
            if key in seen:
                continue
            seen.add(key)
            reasons.append(
                f"plan check {grammar_issue.code} [{grammar_issue.artifact_id}]: "
                f"{grammar_issue.message}"
            )
        threat_model = package.threat_model
        if threat_model is None:
            if profile.require_threat_model:
                reasons.append("no threat model")
        else:
            if len(threat_model.threats) < profile.threat_model_min_threats:
                reasons.append(
                    f"threat model lists {len(threat_model.threats)} threat(s); "
                    f"at least {profile.threat_model_min_threats} required"
                )
            for threat in threat_model.unresolved_high_risk():
                reasons.append(
                    f"unresolved {threat.severity.value} threat {threat.id}: {threat.title}"
                )
        if profile.require_nfrs and not any(
            r.kind is RequirementKind.NON_FUNCTIONAL for r in package.requirements
        ):
            reasons.append("no non-functional requirements")
        if profile.require_adrs:
            live = [d for d in package.decisions if d.status is not AdrStatus.REJECTED]
            if not live:
                reasons.append("no architecture decision records")
        if profile.require_interfaces and not package.interfaces:
            reasons.append("no interface contracts")


# --------------------------------------------------------------------------------------
# G2 implementation quality
# --------------------------------------------------------------------------------------


def _portfolio_thresholds(profile: GateDepthProfile, policy: OrgPolicy) -> pf.PortfolioThresholds:
    """Portfolio floors taken from the depth profile (the single source of thresholds)."""
    base = pf.PortfolioThresholds.from_org_policy(policy)
    lines = profile.coverage_lines_min or 0.0
    return pf.PortfolioThresholds(
        lines=lines,
        lines_floor=min(base.lines_floor, lines),
        diff_lines=profile.coverage_diff_lines_min or 0.0,
        branches=profile.coverage_branches_min or 0.0,
        critical_modules=profile.coverage_critical_modules_min or 0.0,
        mutation_score=profile.mutation_score_min or 0.0,
        acceptance_criteria_with_evidence=base.acceptance_criteria_with_evidence,
        critical_journeys_e2e=base.critical_journeys_e2e,
        agent_safety_scenarios_executed=base.agent_safety_scenarios_executed,
        fail_on_incomplete=True,
        require_diff_coverage=profile.coverage_diff_lines_min is not None,
    )


def _portfolio_breach_applies(breach: pf.Breach, profile: GateDepthProfile) -> bool:
    """Coverage/mutation breaches only apply when the depth profile checks that metric."""
    if breach.metric == pf.METRIC_LINES:
        return profile.coverage_lines_min is not None
    if breach.metric == pf.METRIC_BRANCHES:
        return profile.coverage_branches_min is not None
    if breach.metric == pf.METRIC_DIFF_LINES:
        return profile.coverage_diff_lines_min is not None
    if breach.metric == pf.METRIC_CRITICAL_MODULES:
        return profile.coverage_critical_modules_min is not None
    if breach.metric == pf.METRIC_MUTATION:
        return profile.mutation_required or profile.mutation_score_min is not None
    return True


class ImplementationQualityGate(BaseGate):
    """G2 — build/lint/types/links/tests/coverage/mutation evidence + coverage portfolio."""

    id = GateId.G2
    title = "Implementation quality"
    required_evidence_kinds = frozenset({EvidenceKind.TESTS})

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        records = list(package.evidence.tests)
        if not records:
            if profile.require_test_evidence:
                reasons.append("no test evidence")
            return
        evidence_ids.extend(r.id for r in records)

        for record in records:
            _admissible(record, profile, reasons)
            if record.exit_code is None:
                reasons.append(f"{record.id}: no exit code recorded")
            elif record.exit_code != 0:
                reasons.append(f"{record.id}: command {record.command!r} exited {record.exit_code}")
            if record.failed:
                reasons.append(f"{record.id}: {record.failed} failing test(s)")

        project = _project_of(policy)
        commands = project.test_commands.defined() if project is not None else {}
        for label, required in (
            ("lint", profile.lint_required),
            ("types", profile.types_required),
            ("build", profile.build_required),
        ):
            configured = commands.get(label)
            if not required or configured is None:
                continue
            if not any(
                _command_matches(r.command, configured) or label in r.produced_by.lower()
                for r in records
            ):
                reasons.append(f"no {label} evidence for {configured!r}")
        if profile.links_required and not any(
            _is_link_check(r, commands.get("links")) for r in records
        ):
            reasons.append("no link-check evidence (the profile schedules a links check)")

        with_coverage = [
            r
            for r in records
            if r.coverage.lines is not None
            or r.coverage.branches is not None
            or r.coverage.diff_lines is not None
        ]
        thresholds_set = any(
            t is not None
            for t in (
                profile.coverage_lines_min,
                profile.coverage_diff_lines_min,
                profile.coverage_branches_min,
            )
        )
        coverage_record = _latest(with_coverage)
        if coverage_record is None:
            if thresholds_set:
                reasons.append("no coverage evidence")
        else:
            cov = coverage_record.coverage
            self._threshold(
                "line coverage", cov.lines, profile.coverage_lines_min, coverage_record.id, reasons
            )
            self._threshold(
                "branch coverage",
                cov.branches,
                profile.coverage_branches_min,
                coverage_record.id,
                reasons,
            )
            diff_min = profile.coverage_diff_lines_min
            touches_critical = project is not None and any(
                project.is_critical(path) for task in package.tasks for path in task.files
            )
            if touches_critical and profile.coverage_critical_modules_min is not None:
                diff_min = max(diff_min or 0.0, profile.coverage_critical_modules_min)
                label = "diff coverage (critical modules touched)"
            else:
                label = "diff coverage"
            self._threshold(label, cov.diff_lines, diff_min, coverage_record.id, reasons)

        mutation_records = [r for r in records if r.mutation is not None]
        mutation_record = _latest(mutation_records)
        if mutation_record is None:
            if profile.mutation_required:
                reasons.append("no mutation testing evidence")
        else:
            mutation = mutation_record.mutation
            assert mutation is not None
            if not mutation.scope:
                reasons.append(f"{mutation_record.id}: mutation scope is not disclosed")
            if mutation.score is None:
                reasons.append(f"{mutation_record.id}: mutation score missing")
            elif (
                profile.mutation_score_min is not None
                and mutation.score < profile.mutation_score_min
            ):
                reasons.append(
                    f"{mutation_record.id}: mutation score {mutation.score:.2f} below "
                    f"{profile.mutation_score_min:.2f}"
                )

        self._portfolio(package, policy, profile, context, reasons)

    @staticmethod
    def _portfolio(
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
    ) -> None:
        """Coverage portfolio: required layers per risk class + completeness metrics."""
        if context.portfolio_inputs_error:
            reasons.append(f"portfolio inputs unreadable: {context.portfolio_inputs_error}")
        inputs = context.portfolio_inputs or pf.PortfolioInputs()
        evidence = pf.PortfolioEvidence.from_bundle(
            package.evidence,
            extra_runs=inputs.runs,
            critical_module_coverage=inputs.critical_module_coverage,
        )
        risk_profile = pf.risk_profile_for(profile.risk_class).model_copy(
            update={"mutation_required": profile.mutation_required}
        )
        report = pf.evaluate(
            evidence,
            _portfolio_thresholds(profile, policy),
            risk_profile,
            exceptions=inputs.exceptions,
            now=context.now,
        )
        for breach in report.blocking_breaches:
            if _portfolio_breach_applies(breach, profile):
                reasons.append(f"portfolio: {breach.message}")

    @staticmethod
    def _threshold(
        label: str, value: float | None, minimum: float | None, evidence_id: str, out: list[str]
    ) -> None:
        if minimum is None:
            return
        if value is None:
            out.append(f"{evidence_id}: {label} not measured ({minimum:.1f}% required)")
        elif value < minimum:
            out.append(f"{evidence_id}: {label} {value:.1f}% below {minimum:.1f}%")


# --------------------------------------------------------------------------------------
# G3 independent review
# --------------------------------------------------------------------------------------


def _review_stamp(review: ReviewEvidence) -> datetime:
    stamp = review.finished_at or review.started_at
    return _aware(stamp) if stamp is not None else datetime.min.replace(tzinfo=UTC)


def _scopes_overlap(earlier: ReviewEvidence, later: ReviewEvidence) -> bool:
    """A later review supersedes an earlier one when they looked at any common file.

    A review with no recorded scope is treated as overlapping everything (it is also
    reported as inadmissible), so an unscoped review never hides a scoped one silently.
    """
    first = set(earlier.scope)
    second = set(later.scope)
    if not first or not second:
        return True
    return bool(first & second)


def effective_reviews(reviews: Sequence[ReviewEvidence]) -> list[ReviewEvidence]:
    """The reviews whose verdicts still stand.

    Reviews are ordered by time (then round, then id); a review is superseded when a
    later review overlaps its scope. Per-task reviews of different tasks therefore stay
    independent (a blocking finding on task B is not hidden by a later approval of task
    A), a scoped re-review replaces the round it fixes, and a whole-change review
    supersedes every earlier task review it covers.
    """
    ordered = sorted(reviews, key=lambda r: (_review_stamp(r), r.round, r.id))
    effective: list[ReviewEvidence] = []
    for index, review in enumerate(ordered):
        if any(_scopes_overlap(review, later) for later in ordered[index + 1 :]):
            continue
        effective.append(review)
    return effective


class IndependentReviewGate(BaseGate):
    """G3 — independent review of the actual diff with no grounded blocking finding."""

    id = GateId.G3
    title = "Independent review"
    required_evidence_kinds = frozenset({EvidenceKind.REVIEWS})

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        reviews = list(package.evidence.reviews)
        if not reviews:
            if profile.review_required:
                reasons.append("no review evidence")
            return
        evidence_ids.extend(r.id for r in reviews)
        max_round = max(r.round for r in reviews)
        if max_round > profile.max_review_rounds:
            reasons.append(
                f"{max_round} review rounds exceed the policy maximum of "
                f"{profile.max_review_rounds}"
            )
        for review in effective_reviews(reviews):
            self._check_review(review, profile, reasons)

    @staticmethod
    def _check_review(
        review: ReviewEvidence, profile: GateDepthProfile, reasons: list[str]
    ) -> None:
        _admissible(review, profile, reasons)
        reviewer = review.reviewer_model_family.strip()
        implementer = review.implementer_model_family.strip()
        if not reviewer:
            reasons.append(f"{review.id}: reviewer model family not recorded")
        elif profile.cross_family_required:
            if not implementer:
                reasons.append(
                    f"{review.id}: implementer model family not recorded; cross-family "
                    "independence cannot be established"
                )
            elif not review.independent:
                reasons.append(
                    f"{review.id}: reviewer family {reviewer!r} is not "
                    f"independent of implementer family {implementer!r}"
                )
        if not review.scope:
            reasons.append(f"{review.id}: review scope (files/diff) not recorded")
        if review.verdict is not ReviewVerdict.APPROVED:
            reasons.append(f"{review.id}: latest review verdict is {review.verdict.value}")
        for finding in review.grounded_blocking_findings():
            reasons.append(
                f"{review.id}: grounded blocking finding {finding.id}"
                f" ({finding.severity.value}): {finding.title or finding.detail}"
            )


# --------------------------------------------------------------------------------------
# G4 security & safety
# --------------------------------------------------------------------------------------


def _drift_summary(report: DriftReport) -> str:
    parts: list[str] = []
    if report.undeclared_tools:
        parts.append("undeclared tools " + ", ".join(report.undeclared_tools))
    if report.undeclared_egress_hosts:
        parts.append("undeclared egress hosts " + ", ".join(report.undeclared_egress_hosts))
    if report.undeclared_data_sources:
        parts.append("undeclared data sources " + ", ".join(report.undeclared_data_sources))
    return "; ".join(parts) or "see drift report"


class SecuritySafetyGate(BaseGate):
    """G4 — SAST/SCA/secrets/SBOM/provenance, PyRIT, safety regression, manifest drift."""

    id = GateId.G4
    title = "Security and safety"
    required_evidence_kinds = frozenset({EvidenceKind.SECURITY})

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        security = package.evidence.security
        audit = package.evidence.audit
        threat_model = package.threat_model
        manifest = threat_model.tool_data_manifest if threat_model is not None else None
        declared = manifest is not None and bool(manifest.tools or manifest.data_sources)
        if audit is not None:
            evidence_ids.append(audit.id)
            if audit.privileged_calls > 0 and (
                threat_model is None
                or not (threat_model.tool_data_manifest.tools or threat_model.threats)
            ):
                reasons.append(
                    f"{audit.id}: {audit.privileged_calls} privileged tool call(s) without a "
                    "threat model declaring tools"
                )
        if security is None:
            if profile.security_required:
                reasons.append("no security evidence")
            return
        evidence_ids.append(security.id)
        _admissible(security, profile, reasons)

        max_high = profile.max_high_vulns
        _scan_check("SAST", security.sast, profile.sast_required, security.id, max_high, reasons)
        _scan_check("SCA", security.sca, profile.sca_required, security.id, max_high, reasons)
        _scan_check(
            "secrets",
            security.secrets,
            profile.secrets_scan_required,
            security.id,
            max_high,
            reasons,
        )
        critical_open = max(security.critical_open, security.scan_critical)
        high_open = max(security.high_open, security.scan_high)
        if critical_open > profile.max_critical_vulns:
            reasons.append(
                f"{security.id}: {critical_open} open critical vulnerability(ies)"
                f" (max {profile.max_critical_vulns})"
            )
        if high_open > profile.max_high_vulns:
            reasons.append(
                f"{security.id}: {high_open} open high vulnerability(ies)"
                f" (max {profile.max_high_vulns})"
            )
        if profile.sbom_required and not security.sbom_present:
            reasons.append(f"{security.id}: SBOM missing")
        if profile.provenance_required and not security.provenance_present:
            reasons.append(f"{security.id}: build provenance missing")

        pyrit = security.pyrit
        if pyrit is None:
            if profile.pyrit_required:
                reasons.append(f"{security.id}: PyRIT campaign evidence required but missing")
        else:
            if not pyrit.complete:
                reasons.append(f"{security.id}: PyRIT campaign {pyrit.campaign_id} incomplete")
            if pyrit.asr > profile.asr_threshold:
                reasons.append(
                    f"{security.id}: attack success rate {pyrit.asr:.3f} exceeds "
                    f"{profile.asr_threshold:.3f}"
                )
            if pyrit.undetermined_rate > profile.max_undetermined_rate:
                reasons.append(
                    f"{security.id}: undetermined rate {pyrit.undetermined_rate:.3f} exceeds "
                    f"{profile.max_undetermined_rate:.3f}"
                )
            if profile.pyrit_required and pyrit.trials < profile.trials:
                reasons.append(
                    f"{security.id}: {pyrit.trials} PyRIT trial(s), {profile.trials} required"
                )
            if (
                profile.fail_on_baseline_regression
                and pyrit.baseline_delta is not None
                and pyrit.baseline_delta > 0
            ):
                reasons.append(
                    f"{security.id}: ASR regressed by {pyrit.baseline_delta:+.3f} versus baseline"
                )

        safety = security.safety_regression
        if safety is None:
            if profile.safety_regression_required:
                reasons.append(f"{security.id}: safety regression evidence required but missing")
        else:
            if not safety.complete:
                reasons.append(f"{security.id}: safety regression run incomplete")
            for breach in safety.threshold_breaches:
                reasons.append(f"{security.id}: safety threshold breached: {breach}")
            for category, asr in sorted(safety.asr_by_category.items()):
                if asr > profile.safety_asr_threshold:
                    reasons.append(
                        f"{security.id}: safety ASR for {category} {asr:.3f} exceeds "
                        f"{profile.safety_asr_threshold:.3f}"
                    )
            if safety.undetermined_rate > profile.max_undetermined_rate:
                reasons.append(
                    f"{security.id}: safety undetermined rate {safety.undetermined_rate:.3f} "
                    f"exceeds {profile.max_undetermined_rate:.3f}"
                )
            for category, rate in sorted(safety.undetermined_by_category.items()):
                if rate > profile.max_undetermined_rate:
                    reasons.append(
                        f"{security.id}: safety undetermined rate for {category} {rate:.3f} "
                        f"exceeds {profile.max_undetermined_rate:.3f}"
                    )
            if profile.safety_regression_required:
                minimum = profile.safety_trials_min
                categories = sorted(set(safety.asr_by_category) | set(safety.trials_by_category))
                if not categories:
                    if safety.trials < minimum:
                        reasons.append(
                            f"{security.id}: {safety.trials} safety trial(s), {minimum} required"
                        )
                else:
                    for category in categories:
                        trials = safety.trials_for(category)
                        if trials < minimum:
                            reasons.append(
                                f"{security.id}: safety category {category}: {trials} "
                                f"trial(s), {minimum} required"
                            )

        # Manifest drift: the producer-reported flag blocks when set, and the drift
        # computed from the audit entries on disk blocks whenever a manifest is declared
        # or the profile mandates manifest validation. A hand-set ``manifest_drift=false``
        # is never authoritative.
        if security.manifest_drift:
            reasons.append(f"{security.id}: observed tool/data behaviour drifts from manifest")
        drift = context.manifest_drift
        if drift is not None and drift.drift and (profile.manifest_validation_required or declared):
            reasons.append(
                f"{security.id}: observed behaviour drifts from the declared manifest: "
                + _drift_summary(drift)
            )
        if profile.manifest_validation_required:
            if not declared:
                reasons.append("tool/data manifest not declared in the threat model")
            if audit is None:
                reasons.append("no audit evidence to validate the manifest against")
            else:
                if context.audit_entries_source is None:
                    reasons.append(
                        f"{audit.id}: no per-call audit entries "
                        f"(evidence/{pkgio.AUDIT_ENTRIES_FILE}) to validate the manifest against"
                    )
                integrity = context.audit_integrity
                if integrity is not None and not integrity.ok:
                    reasons.append(
                        f"{audit.id}: audit log verification failed: "
                        f"{integrity.error or 'unknown error'}"
                    )


# --------------------------------------------------------------------------------------
# G5 cost & performance
# --------------------------------------------------------------------------------------


class CostPerformanceGate(BaseGate):
    """G5 — cost ledger extract vs budget; measured latency/throughput vs SLO targets."""

    id = GateId.G5
    title = "Cost and performance"
    required_evidence_kinds = frozenset({EvidenceKind.COST, EvidenceKind.PERFORMANCE})

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        cost = package.evidence.cost
        if cost is None:
            if profile.cost_required:
                reasons.append("no cost evidence")
        else:
            evidence_ids.append(cost.id)
            _admissible(cost, profile, reasons)
            # The policy budget is a ceiling: evidence may only tighten it (§0.4).
            budgets = [b for b in (cost.budget_usd, profile.budget_usd) if b is not None]
            budget = min(budgets) if budgets else None
            if budget is not None and cost.total_cost_usd > budget:
                reasons.append(
                    f"{cost.id}: cost ${cost.total_cost_usd:.2f} exceeds budget ${budget:.2f}"
                )
            if cost.escalations and not policy.models.escalation_allowed:
                reasons.append(
                    f"{cost.id}: {cost.escalations} model escalation(s) but escalation is not "
                    "allowed"
                )
        performance = package.evidence.performance
        if performance is None:
            if profile.performance_required:
                reasons.append("no performance evidence")
        else:
            evidence_ids.append(performance.id)
            _admissible(performance, profile, reasons)
            problems = performance.slo_problems()
            for problem in problems:
                reasons.append(f"{performance.id}: {problem}")
            if not performance.slo_met:
                reasons.append(f"{performance.id}: SLO not met")


# --------------------------------------------------------------------------------------
# G6 release
# --------------------------------------------------------------------------------------


class ReleaseGate(BaseGate):
    """G6 — every required gate passed, evidence fresh, approvals present, audit verified."""

    id = GateId.G6
    title = "Release"
    required_evidence_kinds = frozenset({EvidenceKind.AUDIT})

    def check(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile,
        context: GateContext,
        reasons: list[str],
        evidence_ids: list[str],
    ) -> None:
        prior = context.prior_results or [
            gate_for(gate_id).evaluate(package, policy, profile, context)
            for gate_id in GateId
            if gate_id is not GateId.G6
        ]
        for result in prior:
            if result.gate is GateId.G6:
                continue
            if profile.requires(result.gate) and not result.passed:
                reasons.append(f"{result.gate.value} failed: {'; '.join(result.reasons)}")
        for gate_id in profile.required_gates:
            if gate_id is not GateId.G6 and not any(r.gate is gate_id for r in prior):
                reasons.append(f"{gate_id.value} was not evaluated")

        records = package.evidence.all()
        evidence_ids.extend(r.id for r in records)
        if not records:
            reasons.append("no evidence at all")
        commits = {r.commit_sha for r in records if r.commit_sha.strip()}
        if profile.require_commit_sha and len(commits) > 1:
            reasons.append(f"evidence spans {len(commits)} different commits")
        head = context.head_commit
        if head is not None:
            for record in records:
                if record.commit_sha and record.commit_sha != head:
                    reasons.append(
                        f"{record.id}: produced at {record.commit_sha[:12]} but HEAD is {head[:12]}"
                    )
        max_age = timedelta(hours=profile.evidence_max_age_hours)
        for record in records:
            stamp = record.finished_at or record.started_at
            if stamp is None:
                reasons.append(f"{record.id}: evidence carries no timestamp")
            elif context.now - _aware(stamp) > max_age:
                reasons.append(
                    f"{record.id}: evidence older than {profile.evidence_max_age_hours}h"
                )
        if (
            context.current_fingerprint is not None
            and context.stored_fingerprint is not None
            and context.current_fingerprint != context.stored_fingerprint
        ):
            reasons.append("package content changed since the last save (fingerprint mismatch)")

        audit = package.evidence.audit
        if audit is None:
            if profile.audit_required:
                reasons.append("no audit evidence")
        else:
            if not audit.integrity_ok:
                reasons.append(f"{audit.id}: audit log integrity check failed")
            integrity = context.audit_integrity
            if integrity is None:
                reasons.append(
                    f"{audit.id}: signed audit log not found (report_uri or "
                    f"evidence/{pkgio.AUDIT_ENTRIES_FILE}); integrity cannot be verified"
                )
            elif not integrity.ok:
                reasons.append(
                    f"{audit.id}: audit log verification failed: "
                    f"{integrity.error or 'unknown error'}"
                )
            elif integrity.entries != audit.entries:
                reasons.append(
                    f"{audit.id}: signed audit log holds {integrity.entries} entries but the "
                    f"evidence records {audit.entries}"
                )

        if profile.human_approval_required:
            approvals = context.approvals
            if len(approvals) < profile.min_approvals:
                reasons.append(
                    f"{len(approvals)} human approval(s) recorded, {profile.min_approvals} required"
                )
            for role in profile.required_approval_roles:
                if not any(a.role == role for a in approvals):
                    reasons.append(f"missing human approval for role {role!r}")
        if profile.require_signatures and profile.min_signatures > 0:
            if not context.signing_available:
                reasons.append(
                    "no signing key available for the evidence bundle "
                    f"(set ${verdictmod.SIGNING_KEY_ENV}, provide "
                    f"{verdictmod.SIGNING_KEY_FILE.as_posix()} via `aisdlc init` or an "
                    "ed25519 key)"
                )


# --------------------------------------------------------------------------------------
# Registry and runner
# --------------------------------------------------------------------------------------


GATES: dict[GateId, Gate] = {
    GateId.G0: IntentReadinessGate(),
    GateId.G1: ArchitectureReadinessGate(),
    GateId.G2: ImplementationQualityGate(),
    GateId.G3: IndependentReviewGate(),
    GateId.G4: SecuritySafetyGate(),
    GateId.G5: CostPerformanceGate(),
    GateId.G6: ReleaseGate(),
}
"""One gate instance per :class:`GateId`, in evaluation order."""


def gate_for(gate_id: GateId | str) -> Gate:
    """The gate registered for *gate_id*."""
    return GATES[GateId(gate_id)]


class GateRunner:
    """Evaluate gates for a package under a policy and depth profile."""

    def __init__(self, gates: Sequence[Gate] | None = None) -> None:
        self.gates: list[Gate] = list(gates) if gates is not None else list(GATES.values())

    def evaluate(
        self,
        gate_id: GateId | str,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile | None = None,
        context: GateContext | None = None,
    ) -> GateResult:
        """Evaluate a single gate (G6 evaluates its predecessors when no prior results)."""
        resolved = profile or profile_for(package.intent.risk_class, policy)
        gate = next((g for g in self.gates if g.id is GateId(gate_id)), None)
        if gate is None:
            gate = gate_for(gate_id)
        return gate.evaluate(package, policy, resolved, context)

    def evaluate_all(
        self,
        package: ChangePackage,
        policy: OrgPolicy,
        profile: GateDepthProfile | None = None,
        context: GateContext | None = None,
    ) -> FinalVerdict:
        """Evaluate every gate in order and produce an unsigned :class:`FinalVerdict`.

        ``overall`` is ``True`` only when every gate the profile requires passed; skipped
        gates are recorded with ``depth="skipped"`` and never affect the outcome. The
        verdict records the package fingerprint it was evaluated against.
        """
        resolved = profile or profile_for(package.intent.risk_class, policy)
        ctx = context if context is not None else GateContext.from_package(package)
        results: list[GateResult] = []
        for gate in sorted(self.gates, key=lambda g: list(GateId).index(g.id)):
            if gate.id is GateId.G6:
                ctx.prior_results = list(results)
            results.append(gate.evaluate(package, policy, resolved, ctx))
        required = [r for r in results if resolved.requires(r.gate)]
        overall = bool(required) and all(r.passed for r in required)
        commits = {r.commit_sha for r in package.evidence.all() if r.commit_sha.strip()}
        commit = ctx.head_commit or (commits.pop() if len(commits) == 1 else "")
        return FinalVerdict(
            change_id=package.change_id,
            gate_results=results,
            overall=overall,
            produced_at=ctx.now,
            commit_sha=commit,
            fingerprint=ctx.current_fingerprint or "",
        )


def evaluate_gate(
    gate_id: GateId | str,
    package: ChangePackage,
    policy: OrgPolicy,
    profile: GateDepthProfile | None = None,
    context: GateContext | None = None,
) -> GateResult:
    """Module-level shortcut for :meth:`GateRunner.evaluate`."""
    return GateRunner().evaluate(gate_id, package, policy, profile, context)


def evaluate_all(
    package: ChangePackage,
    policy: OrgPolicy,
    profile: GateDepthProfile | None = None,
    context: GateContext | None = None,
) -> FinalVerdict:
    """Module-level shortcut for :meth:`GateRunner.evaluate_all`."""
    return GateRunner().evaluate_all(package, policy, profile, context)
