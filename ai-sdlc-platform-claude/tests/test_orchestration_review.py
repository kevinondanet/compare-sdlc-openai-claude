"""Independent review grounding, review briefs, and durable handoffs."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.control_plane.routing import RoutingDecision, RoutingTier
from aisdlc.orchestration.brief import AgentBrief
from aisdlc.orchestration.handoff import (
    Handoff,
    HandoffStatus,
    HandoffStep,
    HandoffStore,
    handoff_name,
    inputs_hash,
    load_handoffs,
    summarize_handoffs,
)
from aisdlc.orchestration.review import (
    WHOLE_CHANGE_TASK_ID,
    FindingDraft,
    IndependentReviewer,
    build_review_brief,
    changed_line_ranges,
    ground_findings,
    parse_findings,
    whole_change_task,
)
from aisdlc.orchestration.roles import AgentRole
from aisdlc.orchestration.runner import DryRunRunner, ScriptedOutcome
from aisdlc.orchestration.worktree import DiffSummary, FileChange
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ReviewVerdict, Severity, Task

PATCH = """diff --git a/src/a.py b/src/a.py
index 1..2 100644
--- a/src/a.py
+++ b/src/a.py
@@ -1,3 +1,4 @@
 import os
+import sys
 x = 1
+y = 2
@@ -10,2 +11,3 @@ def f():
     pass
+    return 1
diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+hello
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""


def _diff() -> DiffSummary:
    return DiffSummary(
        base="a" * 40,
        head="b" * 40,
        files=[
            FileChange(path="src/a.py", status="M", additions=3),
            FileChange(path="new.txt", status="A", additions=1),
            FileChange(path="gone.txt", status="D", deletions=1),
        ],
        patch=PATCH,
    )


def _routing(family: str = "gpt", model: str = "gpt-5") -> RoutingDecision:
    return RoutingDecision(
        model=model,
        provider="openai",
        family=family,
        tier=RoutingTier.independent_review,
        reason="r",
        estimated_cost_per_1k=0.001,
        estimated_task_cost_usd=0.01,
    )


def test_changed_line_ranges_parses_hunks() -> None:
    ranges = changed_line_ranges(PATCH)
    assert ranges["src/a.py"] == [(1, 4), (11, 13)]
    assert ranges["new.txt"] == [(1, 1)]
    assert "gone.txt" not in ranges  # deleted file has no new lines


def test_parse_and_ground_findings() -> None:
    drafts = parse_findings(
        [
            {"file": "src/a.py", "line": 2, "severity": "high", "blocking": True, "title": "A"},
            {"path": "b/new.txt", "line": "1", "blocking": True, "summary": "B"},
            {"file": "src/a.py", "line": 7, "blocking": True, "title": "outside hunk"},
            {"file": "other.py", "line": 1, "blocking": True, "title": "not in diff"},
            {"line": 1, "blocking": True, "title": "no file"},
            {"file": "src/a.py", "severity": "bogus", "title": "no line"},
            "not a dict",
        ]
    )
    assert len(drafts) == 6
    assert drafts[0] == FindingDraft(
        file="src/a.py", line=2, severity=Severity.HIGH, blocking=True, title="A"
    )
    assert drafts[5].severity is Severity.MEDIUM and drafts[5].line is None
    findings = ground_findings(drafts, _diff(), existing_ids=["FND-004"])
    assert [f.id for f in findings] == [f"FND-{i:03d}" for i in range(5, 11)]
    assert [f.grounded for f in findings] == [True, True, False, False, False, False]
    assert [f.blocking for f in findings] == [True, True, False, False, False, False]
    assert findings[1].file == "new.txt"
    assert all("ungrounded" in f.detail for f in findings if not f.grounded)
    assert findings[5].title == "no line"


def test_build_review_brief_includes_diff_and_scope() -> None:
    base = AgentBrief(
        change_id="CHG-demo",
        task=Task(id="TASK-001", title="t"),
        constraints=["Only modify files inside the worktree", "Constraint: be careful"],
        worktree="/wt",
        max_tokens=5000,
    )
    review = build_review_brief(base, _diff(), routing=_routing(), round=2, scope=["src/a.py"])
    assert review.role is AgentRole.REVIEWER and review.round == 2
    assert review.allowed_tool_tier == 2 and review.worktree == "/wt"
    text = review.render_markdown()
    assert "Scoped re-review of: src/a.py" in text and "```diff" in text
    assert "+import sys" in text and "Constraint: be careful" in text
    assert "Only modify files" not in text
    assert "must cite a file and line" in text
    big = _diff().model_copy(update={"patch": PATCH + "+x\n" * 2000})
    clipped = build_review_brief(base, big, routing=None, max_tokens=500)
    assert any("diff truncated" in w for w in clipped.warnings)
    assert "[diff truncated]" in clipped.render_markdown()


def test_independent_reviewer_produces_grounded_evidence() -> None:
    runner = DryRunRunner(
        script={
            "reviewer:TASK-001": [
                ScriptedOutcome(
                    findings=[
                        {"file": "src/a.py", "line": 2, "blocking": True, "title": "real"},
                        {"file": "nope.py", "line": 2, "blocking": True, "title": "fake"},
                    ],
                    verdict="rejected",
                )
            ]
        }
    )
    reviewer = IndependentReviewer(runner, environment="ci")
    brief = AgentBrief(change_id="CHG-demo", task=Task(id="TASK-001", title="t"))
    result = reviewer.review(
        brief,
        _diff(),
        routing=_routing(),
        implementer_family="claude",
        evidence_id="EVD-reviews-003",
        round=1,
        existing_finding_ids=["FND-001"],
    )
    ev = result.evidence
    assert ev.id == "EVD-reviews-003" and ev.round == 1 and ev.environment == "ci"
    assert ev.reviewer_model_family == "gpt" and ev.implementer_model_family == "claude"
    assert ev.independent and ev.is_complete and ev.commit_sha == "b" * 40
    assert ev.verdict is ReviewVerdict.REJECTED
    assert [f.id for f in ev.findings] == ["FND-002", "FND-003"]
    assert [f.is_grounded_blocking for f in ev.findings] == [True, False]
    assert result.blocking == [ev.findings[0]] and not result.approved
    assert ev.scope == ["src/a.py", "new.txt", "gone.txt"]
    assert result.brief_hash and ev.produced_by.startswith("dry-run:")

    # approved when nothing blocks
    clean = IndependentReviewer(DryRunRunner()).review(
        brief,
        _diff(),
        routing=_routing(),
        implementer_family="claude",
        evidence_id="EVD-reviews-004",
    )
    assert clean.approved and clean.evidence.verdict is ReviewVerdict.APPROVED


def test_reviewer_same_family_or_failed_run_is_incomplete() -> None:
    brief = AgentBrief(change_id="CHG-demo", task=Task(id="TASK-001", title="t"))
    same = IndependentReviewer(DryRunRunner()).review(
        brief,
        _diff(),
        routing=_routing(family="claude", model="claude-opus-5"),
        implementer_family="claude",
        evidence_id="EVD-reviews-001",
    )
    assert not same.evidence.is_complete and not same.evidence.independent and not same.approved
    assert "not independent" in same.evidence.produced_by
    lenient = IndependentReviewer(DryRunRunner(), require_independent=False).review(
        brief,
        _diff(),
        routing=_routing(family="claude", model="claude-opus-5"),
        implementer_family="claude",
        evidence_id="EVD-reviews-001",
    )
    assert lenient.evidence.is_complete
    failed = IndependentReviewer(DryRunRunner(script={"reviewer:*": ["failed"]})).review(
        brief,
        _diff(),
        routing=_routing(),
        implementer_family="claude",
        evidence_id="EVD-reviews-002",
    )
    assert not failed.evidence.is_complete
    assert failed.evidence.verdict is ReviewVerdict.CHANGES_REQUESTED and not failed.approved


def test_whole_change_task() -> None:
    task = whole_change_task("CHG-demo", "Demo", ["TASK-001"])
    assert task.id == WHOLE_CHANGE_TASK_ID and "TASK-001" in task.description


# --------------------------------------------------------------------------------------
# handoffs
# --------------------------------------------------------------------------------------


def test_handoff_store_sequence_and_queries(tmp_path: Path) -> None:
    store = HandoffStore(tmp_path)
    assert store.next_seq == 1 and store.load() == [] and store.summary() == "no handoffs"
    h1 = store.write(HandoffStep.RUN_START, inputs=inputs_hash("a", 1))
    h2 = store.write(
        HandoffStep.IMPLEMENT,
        task_id="TASK-001",
        status="failed",
        outputs={"summary": "x"},
        usage={"input_tokens": 1},
        wave=0,
        round=1,
        notes="boom",
    )
    h3 = store.write(HandoffStep.TASK_DONE, task_id="TASK-001")
    store.write(HandoffStep.TASK_FAILED, task_id="TASK-002", status=HandoffStatus.BLOCKED)
    store.write(HandoffStep.PLAN_APPROVAL, status=HandoffStatus.APPROVED)
    assert (h1.seq, h2.seq, h3.seq) == (1, 2, 3)
    assert h1.name == "0001-run_start" == handoff_name(1, "run_start")
    assert (tmp_path / "handoffs" / "0002-implement.json").is_file()
    loaded = store.load()
    assert [h.step for h in loaded][:3] == [
        HandoffStep.RUN_START,
        HandoffStep.IMPLEMENT,
        HandoffStep.TASK_DONE,
    ]
    assert loaded[1].status is HandoffStatus.FAILED and loaded[1].outputs == {"summary": "x"}
    assert store.completed_tasks() == {"TASK-001"} and store.failed_tasks() == {"TASK-002"}
    assert store.latest(HandoffStep.IMPLEMENT, "TASK-001") == loaded[1]
    assert store.latest(HandoffStep.REVIEW) is None
    assert store.plan_approved() is not None
    assert [h.task_id for h in store.for_task("TASK-001")] == ["TASK-001", "TASK-001"]
    line = h2.line()
    assert (
        line.startswith("0002 implement") and "TASK-001" in line and "r1" in line and "boom" in line
    )
    summary = summarize_handoffs(loaded)
    assert summary.count("\n") == 4

    # a second store over the same directory continues the sequence
    again = HandoffStore(tmp_path)
    assert again.next_seq == 6
    # junk files are ignored
    (tmp_path / "handoffs" / "notes.json").write_text("{}")
    (tmp_path / "handoffs" / "0099-implement.json").write_text("not json")
    assert len(load_handoffs(tmp_path)) == 5
    with pytest.raises(pkgio.PackageError):
        pkgio.write_handoff(tmp_path, "../escape", {})


def test_handoff_model_is_strict() -> None:
    with pytest.raises(ValueError):
        Handoff(seq=1, step=HandoffStep.REVIEW, unexpected=1)  # type: ignore[call-arg]
    assert inputs_hash({"b": 1, "a": 2}) == inputs_hash({"a": 2, "b": 1})


def test_build_review_brief_never_drops_the_diff() -> None:
    """Even when the rest of the brief already exceeds the budget, a diff excerpt stays."""
    base = AgentBrief(
        change_id="CHG-demo",
        task=Task(id="TASK-001", title="t", description="d" * 4000),
        decisions=["ADR-0001 " + "x" * 1500],
        interfaces=["IFC-001 " + "y" * 1500],
        max_tokens=5000,
    )
    review = build_review_brief(base, _diff(), routing=None, max_tokens=120)
    text = review.render_markdown()
    assert "```diff" in text and "+import sys" in text  # minimum excerpt kept
    assert review.decisions == [] and review.interfaces == []  # low-priority sections dropped
    assert any("still exceeds" in w for w in review.warnings)
    # deterministic
    again = build_review_brief(base, _diff(), routing=None, max_tokens=120)
    assert again.render_markdown() == text
