"""Independent review of the actual diff (ARCHITECTURE.md §3 G3, §6).

:class:`IndependentReviewer` hands a reviewer-role brief containing the worktree diff to
a runner, then *grounds* every returned finding against that diff: a finding is grounded
only when it cites a file in the diff and a line inside one of that file's changed hunks.
Ungrounded findings are kept for the record but marked ``grounded=False`` and can never
block. Scoped re-review passes only the changed files' hunks; the whole-branch final
review passes the full base..HEAD diff.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import ids
from aisdlc.control_plane.routing import RoutingDecision
from aisdlc.orchestration.brief import AgentBrief, OutputContract, enforce_size, estimate_tokens
from aisdlc.orchestration.roles import AgentRole, default_tool_tier
from aisdlc.orchestration.runner import AgentResult, AgentRunner, RunStatus
from aisdlc.orchestration.worktree import DiffSummary
from aisdlc.schema.models import (
    EvidenceStatus,
    Finding,
    ReviewEvidence,
    ReviewVerdict,
    Severity,
    Task,
)

__all__ = [
    "ReviewError",
    "FindingDraft",
    "ReviewResult",
    "parse_findings",
    "changed_line_ranges",
    "ground_findings",
    "build_review_brief",
    "IndependentReviewer",
    "WHOLE_CHANGE_TASK_ID",
]

#: Synthetic task id used for whole-change reviews.
WHOLE_CHANGE_TASK_ID = "TASK-000"

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")
#: At most this share of the brief budget goes to the patch.
_MAX_PATCH_SHARE = 0.6
#: The patch is never clipped below this many characters (the diff is the review's subject).
_MIN_PATCH_CHARS = 400
#: Tokens reserved for the diff fence and section heading.
_PATCH_OVERHEAD_TOKENS = 16


class ReviewError(RuntimeError):
    """The review could not be performed."""


class FindingDraft(BaseModel):
    """A finding as reported by the reviewer, before grounding."""

    model_config = ConfigDict(extra="forbid")

    file: str | None = None
    line: int | None = None
    severity: Severity = Severity.MEDIUM
    blocking: bool = False
    title: str = ""
    detail: str = ""


class ReviewResult(BaseModel):
    """Evidence plus the raw runner result for one review."""

    model_config = ConfigDict(extra="forbid")

    evidence: ReviewEvidence
    result: AgentResult
    brief_hash: str = ""
    scope: list[str] = Field(default_factory=list)

    @property
    def blocking(self) -> list[Finding]:
        """Grounded blocking findings."""
        return self.evidence.grounded_blocking_findings()

    @property
    def approved(self) -> bool:
        """Complete and approved with nothing blocking."""
        return (
            self.evidence.is_complete
            and self.evidence.verdict is ReviewVerdict.APPROVED
            and not self.blocking
        )


def _severity(value: Any) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.MEDIUM


def _line(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 1 else None


def parse_findings(raw: Iterable[Any]) -> list[FindingDraft]:
    """Parse reviewer output (list of dicts) tolerantly into drafts."""
    drafts: list[FindingDraft] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        file_value = item.get("file") or item.get("path")
        drafts.append(
            FindingDraft(
                file=str(file_value).strip() if file_value else None,
                line=_line(item.get("line")),
                severity=_severity(item.get("severity", "medium")),
                blocking=bool(item.get("blocking", False)),
                title=str(item.get("title") or item.get("summary") or "")[:200],
                detail=str(item.get("detail") or item.get("description") or "")[:2000],
            )
        )
    return drafts


def changed_line_ranges(patch: str) -> dict[str, list[tuple[int, int]]]:
    """New-file line ranges per path from a unified diff (``+++ b/<path>`` / ``@@`` hunks)."""
    ranges: dict[str, list[tuple[int, int]]] = {}
    current: str | None = None
    for line in patch.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current = None
                continue
            current = target[2:] if target.startswith(("a/", "b/")) else target
            ranges.setdefault(current, [])
            continue
        if current is None:
            continue
        match = _HUNK_RE.match(line)
        if match:
            start = int(match.group("start"))
            count = int(match.group("count")) if match.group("count") is not None else 1
            if count > 0:
                ranges[current].append((start, start + count - 1))
    return ranges


def _normalise_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    for prefix in ("./", "a/", "b/"):
        if path.startswith(prefix):
            path = path[len(prefix) :]
    return path


def ground_findings(
    drafts: Sequence[FindingDraft], diff: DiffSummary, *, existing_ids: Iterable[str] = ()
) -> list[Finding]:
    """Turn drafts into :class:`Finding` records grounded against ``diff``.

    A finding is grounded when its file is in the diff and its line falls inside a
    changed hunk of that file. Ungrounded findings are never blocking.
    """
    ranges = changed_line_ranges(diff.patch)
    files = {_normalise_path(p) for p in diff.file_paths}
    taken = list(existing_ids)
    findings: list[Finding] = []
    for draft in drafts:
        grounded = False
        file_path = _normalise_path(draft.file) if draft.file else None
        if file_path and file_path in files and draft.line is not None:
            grounded = any(lo <= draft.line <= hi for lo, hi in ranges.get(file_path, []))
        fid = ids.next_id("FND", taken)
        taken.append(fid)
        findings.append(
            Finding(
                id=fid,
                severity=draft.severity,
                grounded=grounded,
                blocking=bool(draft.blocking and grounded),
                file=file_path,
                line=draft.line,
                title=draft.title or (f"{draft.severity.value} finding"),
                detail=draft.detail
                + ("" if grounded else " [ungrounded: not traced to a changed line]"),
            )
        )
    return findings


def _clip_patch(patch: str, max_chars: int) -> tuple[str, bool]:
    """Clip ``patch`` to ``max_chars`` (never below :data:`_MIN_PATCH_CHARS`)."""
    budget_chars = max(_MIN_PATCH_CHARS, max_chars)
    if len(patch) <= budget_chars:
        return patch, False
    return patch[:budget_chars].rstrip() + "\n[diff truncated]\n", True


def _patch_budget_chars(brief: AgentBrief) -> int:
    """Characters available for the patch once the rest of ``brief`` is rendered."""
    remaining = (brief.max_tokens - brief.estimated_tokens - _PATCH_OVERHEAD_TOKENS) * 4
    share = int(brief.max_tokens * _MAX_PATCH_SHARE) * 4
    return min(share, remaining)


def build_review_brief(
    brief: AgentBrief,
    diff: DiffSummary,
    *,
    routing: RoutingDecision | None,
    round: int = 1,
    scope: Sequence[str] | None = None,
    previous_findings: Sequence[Finding] = (),
    max_tokens: int | None = None,
) -> AgentBrief:
    """Reviewer brief: the implementer brief's task/requirements plus the actual diff.

    The diff is the subject of the review, so it is never dropped by size enforcement:
    the rest of the brief is sized first and the patch is clipped (with a
    ``[diff truncated]`` marker and a warning) to whatever budget remains.
    """
    budget = max_tokens or brief.max_tokens
    header = [
        f"Diff under review: {diff.base[:12]}..{diff.head[:12]} "
        f"({len(diff.files)} file(s), +{diff.additions}/-{diff.deletions})",
    ]
    if scope:
        header.append("Scoped re-review of: " + ", ".join(scope))
    files = "\n".join(f"- {f.status} {f.path} (+{f.additions}/-{f.deletions})" for f in diff.files)
    context: list[str] = ["\n".join(header) + ("\n" + files if files else "\n(no changes)")]
    if previous_findings:
        context.append(
            "Findings from the previous round (verify they are addressed):\n"
            + "\n".join(
                f"- {f.id} {f.severity.value} {f.file or '?'}:{f.line or '?'} {f.title}"
                for f in previous_findings
            )
        )
    constraints = [
        "Review only the diff shown; do not implement changes.",
        "Every blocking finding must cite a file and line number that appears in the diff;"
        " findings that do not are recorded as ungrounded and cannot block.",
        "Prefer precision over volume: report defects, security issues, unmet requirements"
        " and missing verification, not style preferences.",
        *[c for c in brief.constraints if c.startswith(("Constraint:", "Non-goal"))],
    ]
    review = AgentBrief(
        change_id=brief.change_id,
        change_title=brief.change_title,
        role=AgentRole.REVIEWER,
        task=brief.task,
        requirements=[r.model_copy(deep=True) for r in brief.requirements],
        interfaces=list(brief.interfaces),
        decisions=list(brief.decisions),
        context=context,
        verification=brief.verification,
        constraints=constraints,
        allowed_tool_tier=default_tool_tier(AgentRole.REVIEWER),
        routing=routing,
        worktree=brief.worktree,
        output_contract=OutputContract(),
        round=round,
        max_tokens=budget,
    )
    review = enforce_size(review)
    patch, clipped = _clip_patch(diff.patch, _patch_budget_chars(review))
    review.context.append("```diff\n" + patch + "\n```")
    if clipped:
        review.warnings.append("diff truncated to fit the brief budget")
    if review.estimated_tokens > review.max_tokens and not any(
        "still exceeds" in w for w in review.warnings
    ):
        review.warnings.append(
            f"brief still exceeds its budget ({review.estimated_tokens} > {review.max_tokens} "
            "tokens) with the minimum diff excerpt"
        )
    return review


class IndependentReviewer:
    """Runs reviewer-role agents against real diffs and produces ``ReviewEvidence``.

    Args:
        runner: Runner used for the reviewer role.
        environment: Evidence environment label.
        require_independent: Fail closed (incomplete evidence) when the reviewer family
            equals the implementer family.
    """

    def __init__(
        self,
        runner: AgentRunner,
        *,
        environment: str = "local",
        require_independent: bool = True,
    ) -> None:
        self.runner = runner
        self.environment = environment
        self.require_independent = require_independent

    def review(
        self,
        brief: AgentBrief,
        diff: DiffSummary,
        *,
        routing: RoutingDecision | None,
        implementer_family: str,
        evidence_id: str,
        round: int = 1,
        scope: Sequence[str] | None = None,
        previous_findings: Sequence[Finding] = (),
        existing_finding_ids: Iterable[str] = (),
        report_uri: str | None = None,
    ) -> ReviewResult:
        """Review ``diff`` for the task in ``brief`` and return grounded evidence."""
        review_brief = build_review_brief(
            brief,
            diff,
            routing=routing,
            round=round,
            scope=scope,
            previous_findings=previous_findings,
        )
        started = datetime.now(UTC)
        result = self.runner.run(review_brief)
        finished = datetime.now(UTC)
        drafts = parse_findings(result.findings)
        findings = ground_findings(drafts, diff, existing_ids=existing_finding_ids)
        reviewer_family = (
            result.usage.family
            or (routing.family if routing is not None else "")
            or result.usage.model
        )
        blocking = [f for f in findings if f.is_grounded_blocking]
        verdict = ReviewVerdict.APPROVED
        if blocking:
            verdict = (
                ReviewVerdict.REJECTED
                if str(result.verdict or "").lower() == "rejected"
                else ReviewVerdict.CHANGES_REQUESTED
            )
        status = EvidenceStatus.COMPLETE
        notes: list[str] = []
        if result.status is not RunStatus.SUCCESS:
            status = EvidenceStatus.INCOMPLETE
            verdict = ReviewVerdict.CHANGES_REQUESTED
            notes.append(f"reviewer run {result.status.value}: {result.summary}")
        if (
            self.require_independent
            and reviewer_family
            and implementer_family
            and reviewer_family == implementer_family
        ):
            status = EvidenceStatus.INCOMPLETE
            notes.append("reviewer and implementer share a model family; not independent")
        evidence = ReviewEvidence(
            id=evidence_id,
            reviewer_model_family=reviewer_family,
            implementer_model_family=implementer_family,
            findings=findings,
            verdict=verdict,
            round=round,
            scope=list(scope) if scope else diff.file_paths,
            commit_sha=diff.head,
            environment=self.environment,
            produced_by=f"{result.runner or self.runner.name}:{result.usage.model or brief.model}"
            + (f" ({'; '.join(notes)})" if notes else ""),
            started_at=started,
            finished_at=finished,
            report_uri=report_uri,
            status=status,
        )
        return ReviewResult(
            evidence=evidence,
            result=result,
            brief_hash=review_brief.content_hash(),
            scope=list(scope) if scope else [],
        )


def whole_change_task(change_id: str, title: str, task_ids: Sequence[str]) -> Task:
    """Synthetic task describing a whole-change review."""
    return Task(
        id=WHOLE_CHANGE_TASK_ID,
        title=f"Whole-change review of {change_id}: {title}",
        description=(
            "Review the complete branch diff for the change as a whole: cross-task"
            " consistency, requirement coverage and integration defects. Tasks: "
            + (", ".join(task_ids) if task_ids else "none")
        ),
    )


def patch_tokens(diff: DiffSummary) -> int:
    """Token estimate of a diff patch."""
    return estimate_tokens(diff.patch)
