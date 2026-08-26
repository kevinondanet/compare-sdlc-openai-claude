"""Tests for the RAMPART-style pytest-native safety regression API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisdlc.security.safety_regression import (
    CaseResult,
    SafetyCase,
    SafetyReport,
    SafetyRun,
    TrialOutcome,
    TrialRecord,
    coerce_outcome,
    collect_cases,
    merge_reports,
    run_safety_suite,
    safety_case,
    set_active_run,
    write_report,
)


@pytest.fixture
def run() -> SafetyRun:
    fresh = SafetyRun()
    previous = set_active_run(fresh)
    yield fresh
    set_active_run(previous)


class TestOutcomeCoercion:
    def test_bool_and_enum_and_strings(self) -> None:
        assert coerce_outcome(True) is TrialOutcome.SUCCESS
        assert coerce_outcome(False) is TrialOutcome.FAILURE
        assert coerce_outcome(None) is TrialOutcome.UNDETERMINED
        assert coerce_outcome("safe") is TrialOutcome.FAILURE
        assert coerce_outcome("unsafe") is TrialOutcome.SUCCESS
        assert coerce_outcome(TrialOutcome.UNDETERMINED) is TrialOutcome.UNDETERMINED
        with pytest.raises(TypeError):
            coerce_outcome(3)


class TestDecorator:
    def test_passing_case_records_into_run(self, run: SafetyRun) -> None:
        @safety_case("prompt-injection", trials=4)
        def case(trial: int) -> bool:
            return False

        assert isinstance(case.safety_case, SafetyCase)
        case()  # behaves like a pytest test: no assertion error
        report = run.report()
        assert report.total_trials == 4 and report.completed_trials == 4
        assert report.complete and report.passed
        assert report.asr_by_category == {"prompt-injection": 0.0}

    def test_failing_case_raises_with_asr(self, run: SafetyRun) -> None:
        @safety_case("tool-misuse", trials=4, pass_threshold=0.25)
        def case(trial: int) -> bool:
            return trial % 2 == 0  # 2/4 attacks succeed

        with pytest.raises(AssertionError, match=r"asr 0.500 exceeds pass_threshold 0.250"):
            case()
        report = run.report()
        assert report.asr_by_category["tool-misuse"] == 0.5
        assert report.threshold_breaches and not report.passed

    def test_threshold_allows_some_successes(self, run: SafetyRun) -> None:
        @safety_case("x", trials=4, pass_threshold=0.5)
        def case(trial: int) -> bool:
            return trial == 0

        case()
        assert run.report().passed

    def test_exception_makes_case_incomplete(self, run: SafetyRun) -> None:
        @safety_case("secret-disclosure", trials=3)
        def case(trial: int) -> bool:
            if trial == 1:
                raise RuntimeError("agent crashed")
            return False

        with pytest.raises(AssertionError, match="incomplete: 2/3 trials"):
            case()
        report = run.report()
        assert report.complete is False
        assert report.completed_trials == 2 and report.total_trials == 3
        with pytest.raises(AssertionError, match="safety run incomplete"):
            report.assert_passed()

    def test_undetermined_counts_as_completed_not_success(self, run: SafetyRun) -> None:
        @safety_case("c", trials=2)
        def case(trial: int) -> bool | None:
            return None

        # Complete (every trial answered) but never a pass: no verdict is not "safe".
        with pytest.raises(AssertionError, match="undetermined_rate 1.000 exceeds"):
            case()
        rep = run.report()
        assert rep.complete and rep.asr == 0.0 and rep.undetermined_rate == 1.0
        assert not rep.passed and any("undetermined_rate" in b for b in rep.threshold_breaches)
        assert rep.to_evidence()["threshold_breaches"]  # G4 sees the breach

    def test_undetermined_tolerated_within_case_threshold(self, run: SafetyRun) -> None:
        @safety_case("c", trials=4, max_undetermined_rate=0.5)
        def case(trial: int) -> bool | None:
            return None if trial % 2 else False

        case()
        rep = run.report()
        assert rep.complete and rep.undetermined_rate == 0.5 and rep.threshold_breaches == []

    def test_empty_suite_fails_closed(self) -> None:
        report = run_safety_suite([])
        assert report.total_trials == 0 and report.complete is False and not report.passed
        assert any("empty suite" in b for b in report.threshold_breaches)
        with pytest.raises(AssertionError, match="empty suite"):
            report.assert_passed()
        assert SafetyRun().report().complete is False

    def test_zero_arg_and_async_functions(self, run: SafetyRun) -> None:
        @safety_case("c", trials=2)
        def no_args() -> bool:
            return False

        @safety_case("c", trials=2)
        async def coro(trial: int) -> bool:
            return False

        no_args()
        coro()
        assert run.report().completed_trials == 4

    def test_invalid_parameters(self) -> None:
        with pytest.raises(ValueError):
            safety_case("c", trials=0)(lambda: False)
        with pytest.raises(ValueError):
            safety_case("c", pass_threshold=2.0)(lambda: False)
        with pytest.raises(ValueError):
            safety_case("")(lambda: False)

    def test_method_binding(self, run: SafetyRun) -> None:
        class Suite:
            @safety_case("c", trials=1)
            def test_it(self) -> bool:
                return False

        Suite().test_it()
        assert run.report().completed_trials == 1


class TestRunAndReport:
    def test_scheduled_but_unrun_case_fails_closed(self) -> None:
        suite = SafetyRun()

        @safety_case("a", trials=2, run=suite)
        def ran() -> bool:
            return False

        @safety_case("b", trials=3, run=suite)
        def never_ran() -> bool:
            return False

        ran()
        report = suite.report()
        assert report.complete is False
        assert report.missing_cases == [never_ran.safety_case.case_id]
        assert report.total_trials == 5 and report.completed_trials == 2
        with pytest.raises(AssertionError, match="cases never executed"):
            report.assert_passed()

    def test_run_safety_suite_and_collect(self) -> None:
        @safety_case("a", trials=2)
        def c1() -> bool:
            return False

        @safety_case("b", trials=2)
        def c2(trial: int) -> bool:
            return True

        class Holder:
            pass

        holder = Holder()
        holder.c1 = c1  # type: ignore[attr-defined]
        holder.c2 = c2  # type: ignore[attr-defined]
        assert {c.case_id for c in collect_cases(holder)} == {
            c1.safety_case.case_id,
            c2.safety_case.case_id,
        }
        report = run_safety_suite([c1, c2])
        assert report.complete and not report.passed
        assert report.asr_by_category == {"a": 0.0, "b": 1.0}
        assert len(report.threshold_breaches) == 1 and "b" in report.threshold_breaches[0]

    def test_merge_shards_missing_fails_closed(self) -> None:
        @safety_case("a", trials=2)
        def c1() -> bool:
            return False

        @safety_case("b", trials=2)
        def c2() -> bool:
            return False

        shard1 = run_safety_suite([c1])
        merged = merge_reports([shard1], scheduled=[c1, c2])
        assert merged.complete is False and merged.missing_cases == [c2.safety_case.case_id]
        shard2 = run_safety_suite([c2])
        merged_ok = merge_reports([shard1, shard2], scheduled=[c1, c2])
        assert merged_ok.complete and merged_ok.passed
        assert merged_ok.total_trials == 4
        assert merged_ok.scheduled_cases == sorted([c1.safety_case.case_id, c2.safety_case.case_id])
        # A manifest of case ids (e.g. from the collector's report) works as `scheduled`;
        # a dropped shard is still detected.
        manifest = merged_ok.scheduled_cases
        by_ids = merge_reports([shard1], scheduled=manifest)
        assert by_ids.complete is False and by_ids.missing_cases == [c2.safety_case.case_id]
        # Merging without a manifest cannot prove completeness and is refused.
        with pytest.raises(TypeError):
            merge_reports([shard1])  # type: ignore[call-arg]
        with pytest.raises(ValueError, match="scheduled cases"):
            merge_reports([shard1], scheduled=[])

    def test_evidence_shape_and_report_file(self, tmp_path: Path) -> None:
        @safety_case("prompt-injection", trials=2)
        def c1() -> bool:
            return False

        report = run_safety_suite([c1])
        ev = report.to_evidence()
        assert {"asr_by_category", "complete", "threshold_breaches"} <= set(ev)
        models = pytest.importorskip("aisdlc.schema.models")
        assert models.SafetySummary.model_validate(ev).complete is True
        path = write_report(report, tmp_path / "out" / "safety.json")
        payload = json.loads(path.read_text())
        assert payload["passed"] is True and payload["per_case"][0]["asr"] == 0.0

    def test_case_result_properties(self) -> None:
        cr = CaseResult(
            case_id="x",
            category="c",
            scheduled_trials=4,
            pass_threshold=0.0,
            trials=[
                TrialRecord(trial=0, outcome=TrialOutcome.SUCCESS),
                TrialRecord(trial=1, outcome=TrialOutcome.FAILURE),
                TrialRecord(trial=2, outcome=TrialOutcome.UNDETERMINED),
                TrialRecord(trial=3, outcome=TrialOutcome.ERROR, error="boom"),
            ],
        )
        assert cr.asr == 0.5 and cr.completed_trials == 3 and not cr.complete and cr.breached
        rep = SafetyReport(total_trials=4, completed_trials=3, complete=False, per_case=[cr])
        assert rep.undetermined_rate == pytest.approx(1 / 3)


# --- module-level suite used by the CLI test (names avoid pytest's test_ prefix) ----------


def _safe_trial(trial: int) -> bool:
    return False


demo_suite = [
    safety_case("prompt-injection", trials=2, case_id="demo-pi")(_safe_trial),
    safety_case("tool-misuse", trials=2, case_id="demo-tm")(_safe_trial),
]


class TestCli:
    def test_safety_run_cli(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from aisdlc.cli.main import app

        out = tmp_path / "safety.json"
        evidence = tmp_path / "evidence.json"
        res = CliRunner().invoke(
            app,
            [
                "security",
                "safety",
                "run",
                "tests.test_security_safety_regression:demo_suite",
                "--out",
                str(out),
                "--evidence",
                str(evidence),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "2 cases" in res.output and "complete=True" in res.output
        assert json.loads(evidence.read_text())["complete"] is True
        assert json.loads(out.read_text())["passed"] is True
        missing = CliRunner().invoke(app, ["security", "safety", "run", "tests.conftest"])
        assert missing.exit_code == 2


class TestPytestCollection:
    def test_decorated_functions_collect_and_run_under_pytest(self, tmp_path: Path) -> None:
        """A real pytest process must collect @safety_case tests (no 'trial' fixture lookup)."""
        import subprocess
        import sys

        (tmp_path / "test_agent_safety.py").write_text(
            "from aisdlc.security.safety_regression import safety_case\n"
            "\n"
            "@safety_case('prompt-injection', trials=3)\n"
            "def test_safe(trial: int) -> bool:\n"
            "    return False\n"
            "\n"
            "@safety_case('tool-misuse', trials=2)\n"
            "def test_unsafe() -> bool:\n"
            "    return True\n"
            "\n"
            "class TestSuite:\n"
            "    @safety_case('secret-disclosure', trials=2)\n"
            "    def test_method(self, trial: int) -> bool:\n"
            "        return trial == 99\n"
        )
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(tmp_path),
        )
        assert "2 passed" in proc.stdout and "1 failed" in proc.stdout, proc.stdout + proc.stderr
        assert "fixture 'trial' not found" not in proc.stdout
        assert "asr 1.000 exceeds pass_threshold 0.000" in proc.stdout
