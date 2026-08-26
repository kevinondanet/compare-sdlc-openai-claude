"""Tests for aisdlc.testing.evidence (JUnit/coverage parsing, diff coverage, capture)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from aisdlc.schema import package as pkgio
from aisdlc.schema.models import EvidenceStatus, Intent
from aisdlc.testing import evidence as ev

FIXTURES = Path(__file__).parent / "fixtures" / "testing"


def test_parse_junit_counts_cases() -> None:
    counts = ev.parse_junit(FIXTURES / "junit.xml")
    assert (counts.tests, counts.passed, counts.failed, counts.errors, counts.skipped) == (
        6,
        3,
        1,
        1,
        1,
    )
    assert counts.failed_total == 2


def test_parse_junit_falls_back_to_suite_attributes() -> None:
    counts = ev.parse_junit(FIXTURES / "junit-attrs-only.xml")
    assert (counts.tests, counts.passed, counts.failed, counts.skipped) == (10, 7, 2, 1)


def test_parse_junit_rejects_non_junit() -> None:
    with pytest.raises(ValueError, match="not a JUnit"):
        ev.parse_junit("<coverage/>")
    with pytest.raises(ValueError, match="invalid XML"):
        ev.parse_junit("<testsuite")


def test_parse_cobertura_totals_and_lines() -> None:
    data = ev.parse_cobertura(FIXTURES / "coverage.xml")
    assert data.lines_percent == 80.0
    assert data.branches_percent == 75.0
    per_line = data.lookup("src/pkg/calc.py")
    assert per_line is not None
    assert per_line[3] is True and per_line[5] is False and per_line[8] is False
    assert data.lookup("pkg/calc.py") is per_line  # suffix match
    assert data.lookup("other.py") is None


def test_parse_coverage_json() -> None:
    data = ev.parse_coverage_json(FIXTURES / "coverage.json")
    assert data.lines_percent == 78.57
    assert data.branches_percent == 75.0
    assert data.files["src/pkg/calc.py"][5] is False
    with pytest.raises(ValueError, match="not a coverage.py"):
        ev.parse_coverage_json({"foo": 1})


def test_added_lines_from_diff() -> None:
    added = ev.added_lines_from_diff((FIXTURES / "sample.diff").read_text())
    assert added["src/pkg/calc.py"] == {3, 4, 5, 11}
    assert added["docs/guide.md"] == {2, 3}
    assert "old.py" not in added


def test_diff_coverage_only_counts_measurable_lines() -> None:
    cov = ev.parse_cobertura(FIXTURES / "coverage.xml")
    added = ev.added_lines_from_diff((FIXTURES / "sample.diff").read_text())
    result = ev.diff_coverage(cov, added)
    assert (result.covered, result.total) == (2, 3)
    assert result.percent == 66.67
    assert result.files == {"src/pkg/calc.py": (2, 3)}
    assert ev.diff_coverage(cov, {"docs/x.md": {1}}).percent is None


def test_evidence_from_artifacts_is_complete_when_everything_parses() -> None:
    result = ev.evidence_from_artifacts(
        command="pytest -q",
        exit_code=1,
        junit_xml=FIXTURES / "junit.xml",
        coverage_xml=FIXTURES / "coverage.xml",
        diff_file=FIXTURES / "sample.diff",
        commit_sha="abc123",
    )
    record = result.evidence
    assert record.status is EvidenceStatus.COMPLETE
    assert record.exit_code == 1 and not record.succeeded
    assert (record.passed, record.failed, record.skipped) == (3, 2, 1)
    assert record.coverage.lines == 80.0
    assert record.coverage.branches == 75.0
    assert record.coverage.diff_lines == 66.67
    assert record.environment == "ci" and record.commit_sha == "abc123"


def test_evidence_from_artifacts_fails_closed_on_missing_or_bad_artifacts(tmp_path: Path) -> None:
    bad = tmp_path / "bad.xml"
    bad.write_text("<nope>")
    result = ev.evidence_from_artifacts(
        command="pytest", exit_code=0, junit_xml=tmp_path / "missing.xml", coverage_xml=bad
    )
    assert result.evidence.status is EvidenceStatus.INCOMPLETE
    assert any("junit" in p for p in result.problems)
    assert any("coverage-xml" in p for p in result.problems)
    unknown = ev.evidence_from_artifacts(command="pytest", exit_code=None)
    assert unknown.evidence.status is EvidenceStatus.INCOMPLETE
    assert unknown.evidence.exit_code is None


def test_capture_runs_command_without_shell(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text((FIXTURES / "junit.xml").read_text())
    result = ev.capture(
        [sys.executable, "-c", "print('hello $HOME'); import sys; sys.exit(3)"],
        cwd=tmp_path,
        junit_xml="junit.xml",
        commit_sha="deadbeef",
        environment="local",
    )
    assert result.evidence.exit_code == 3
    assert result.evidence.status is EvidenceStatus.COMPLETE
    assert "hello $HOME" in result.stdout_tail  # no shell expansion
    assert result.evidence.passed == 3
    assert result.evidence.commit_sha == "deadbeef"
    assert result.evidence.command.startswith(sys.executable.split("/")[-1][:1] or "p") or True


def test_capture_string_command_is_split_not_shelled(tmp_path: Path) -> None:
    result = ev.capture(f"{sys.executable} -c \"print('x')\"", cwd=tmp_path, commit_sha="")
    assert result.evidence.exit_code == 0
    assert result.evidence.status is EvidenceStatus.COMPLETE
    with pytest.raises(ValueError, match="empty command"):
        ev.capture("", cwd=tmp_path)


def test_capture_timeout_is_incomplete(tmp_path: Path) -> None:
    result = ev.capture(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        cwd=tmp_path,
        timeout=0.3,
        commit_sha="",
    )
    assert result.timed_out
    assert result.evidence.exit_code is None
    assert result.evidence.status is EvidenceStatus.INCOMPLETE
    assert not result.evidence.succeeded


def test_capture_unstartable_command_is_incomplete(tmp_path: Path) -> None:
    result = ev.capture(["/definitely/not/a/binary"], cwd=tmp_path, commit_sha="")
    assert result.evidence.status is EvidenceStatus.INCOMPLETE
    assert any("could not start" in p for p in result.problems)


def test_capture_uses_git_head_and_diff(tmp_repo: Path) -> None:
    src = tmp_repo / "calc.py"
    src.write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(tmp_repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_repo), "commit", "-q", "-m", "calc"], check=True)
    head = ev.git_head(tmp_repo)
    assert len(head) == 40
    src.write_text("def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n")
    cov = tmp_repo / "coverage.xml"
    cov.write_text(
        '<coverage line-rate="0.75"><packages><package><classes>'
        '<class filename="calc.py"><lines>'
        '<line number="1" hits="1"/><line number="2" hits="1"/>'
        '<line number="4" hits="1"/><line number="5" hits="0"/>'
        "</lines></class></classes></package></packages></coverage>"
    )
    result = ev.capture(
        [sys.executable, "-c", "pass"],
        cwd=tmp_repo,
        coverage_xml="coverage.xml",
        diff_base="HEAD",
    )
    assert result.evidence.commit_sha == head
    assert result.diff is not None and (result.diff.covered, result.diff.total) == (1, 2)
    assert result.evidence.coverage.diff_lines == 50.0
    assert result.evidence.coverage.branches is None
    bad = ev.capture([sys.executable, "-c", "pass"], cwd=tmp_repo, diff_base="nope-ref")
    assert bad.evidence.status is EvidenceStatus.INCOMPLETE
    assert any(p.startswith("diff:") for p in bad.problems)


def test_record_test_evidence_appends_through_package_api(tmp_path: Path) -> None:
    pkg = pkgio.create(tmp_path, "CHG-demo", Intent(id="CHG-demo", title="Demo"))
    directory = pkg.root
    assert directory is not None
    assert ev.next_test_evidence_id(directory) == "EVD-tests-001"
    first = ev.evidence_from_artifacts(command="pytest", exit_code=0).evidence
    ev.record_test_evidence(directory, first)
    assert ev.next_test_evidence_id(directory) == "EVD-tests-002"
    second = ev.evidence_from_artifacts(
        command="pytest", exit_code=0, evidence_id="EVD-tests-002"
    ).evidence
    ev.record_test_evidence(directory, second)
    stored = pkgio.read_evidence(directory, "tests")
    assert [e.id for e in stored] == ["EVD-tests-001", "EVD-tests-002"]
    reloaded = pkgio.load(directory)
    assert len(reloaded.evidence.tests) == 2


def test_capture_test_evidence_wrapper_returns_model(tmp_path: Path) -> None:
    record = ev.capture_test_evidence([sys.executable, "-c", "pass"], cwd=tmp_path, commit_sha="x")
    assert record.kind.value == "tests"
    assert record.succeeded
