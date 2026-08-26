"""Tests for the ``aisdlc test`` CLI (run-evidence, portfolio, mutation)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    Coverage,
    EvidenceKind,
    EvidenceStatus,
    Intent,
    Mutation,
    RiskClass,
    TestEvidence,
)
from aisdlc.testing import portfolio as pf

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures" / "testing"
PASSING_JUNIT = (
    '<testsuite name="ok" tests="2"><testcase name="a"/><testcase name="b"/></testsuite>'
)


def _package(root: Path, name: str = "CHG-cli", risk: RiskClass = RiskClass.STANDARD) -> Path:
    pkg = pkgio.create(root, name, Intent(id=name, title=name, risk_class=risk))
    assert pkg.root is not None
    return pkg.root


def test_run_evidence_parse_only_records_into_package(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path)
    junit = tmp_path / "junit.xml"
    junit.write_text(PASSING_JUNIT)
    out = tmp_path / "tests.json"
    result = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "--parse-only",
            "--exit-code",
            "0",
            "--command",
            "pytest -q",
            "--junit",
            str(junit),
            "--coverage-xml",
            str(FIXTURES / "coverage.xml"),
            "--diff-file",
            str(FIXTURES / "sample.diff"),
            "--package",
            str(pkg_dir),
            "--commit-sha",
            "abc",
            "--out",
            str(out),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["id"] == "EVD-tests-001" and payload["status"] == "complete"
    assert payload["passed"] == 2 and payload["coverage"]["diff_lines"] == 66.67
    assert json.loads(out.read_text())["id"] == "EVD-tests-001"
    stored = pkgio.read_evidence(pkg_dir, "tests")
    assert len(stored) == 1 and stored[0].commit_sha == "abc"
    again = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "--parse-only",
            "--exit-code",
            "0",
            "-c",
            "pytest",
            "--junit",
            str(junit),
            "-p",
            str(pkg_dir),
        ],
    )
    assert again.exit_code == 0, again.output
    assert [e.id for e in pkgio.read_evidence(pkg_dir, "tests")] == [
        "EVD-tests-001",
        "EVD-tests-002",
    ]


def test_run_evidence_fails_on_failed_tests_and_missing_artifacts(tmp_path: Path) -> None:
    failing = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "--parse-only",
            "--exit-code",
            "1",
            "-c",
            "pytest",
            "--junit",
            str(FIXTURES / "junit.xml"),
        ],
    )
    assert failing.exit_code == 1
    assert "failed=2" in failing.output
    missing = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "--parse-only",
            "--exit-code",
            "0",
            "-c",
            "x",
            "--junit",
            "nope.xml",
        ],
    )
    assert missing.exit_code == 1 and "problem: junit" in missing.output
    usage = runner.invoke(app, ["test", "run-evidence"])
    assert usage.exit_code == 2 and "--command is required" in usage.output
    not_pkg = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "-c",
            "x",
            "--parse-only",
            "--exit-code",
            "0",
            "-p",
            str(tmp_path),
        ],
    )
    assert not_pkg.exit_code == 2 and "not a change package" in not_pkg.output


def test_run_evidence_runs_a_real_command(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "-c",
            f"{sys.executable} -c \"print('ran')\"",
            "--cwd",
            str(tmp_path),
            "--commit-sha",
            "",
            "--environment",
            "ci",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "status=complete exit=0" in result.output
    timeout = runner.invoke(
        app,
        [
            "test",
            "run-evidence",
            "-c",
            f'{sys.executable} -c "import time; time.sleep(5)"',
            "--cwd",
            str(tmp_path),
            "--timeout",
            "0.3",
            "--commit-sha",
            "",
        ],
    )
    assert timeout.exit_code == 1 and "timed out" in timeout.output


def test_portfolio_command(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path)
    pkgio.append_evidence(
        pkg_dir,
        TestEvidence(
            id="EVD-tests-001",
            command="pytest -q",
            exit_code=0,
            passed=10,
            status=EvidenceStatus.COMPLETE,
            coverage=Coverage(lines=90, branches=80, diff_lines=95),
            mutation=Mutation(score=0.8, scope=["src"]),
        ),
    )
    standard = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--json"])
    assert standard.exit_code == 1
    report = json.loads(standard.output)
    assert "integration" in report["missing_layers"]
    docs = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--risk-class", "docs_only"])
    assert docs.exit_code == 0, docs.output
    assert "portfolio: PASS" in docs.output
    layers = tmp_path / "layers.json"
    layers.write_text(
        json.dumps(
            [
                {
                    "layer": "integration",
                    "passed": 3,
                    "metrics": {"acceptance_criteria_with_evidence": 100},
                },
            ]
        )
    )
    low = runner.invoke(
        app, ["test", "portfolio", str(pkg_dir), "-r", "low", "--layers", str(layers)]
    )
    assert low.exit_code == 0, low.output
    bad_rc = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "-r", "bogus"])
    assert bad_rc.exit_code == 2
    bad_org = runner.invoke(
        app, ["test", "portfolio", str(pkg_dir), "--org", str(tmp_path / "x.yaml")]
    )
    assert bad_org.exit_code == 2


def test_portfolio_with_exceptions_and_critical_coverage(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path, risk=RiskClass.LOW)
    pkgio.append_evidence(
        pkg_dir,
        TestEvidence(
            id="EVD-tests-001",
            command="pytest -q",
            exit_code=0,
            passed=1,
            status=EvidenceStatus.COMPLETE,
            coverage=Coverage(lines=90, branches=80, diff_lines=95),
        ),
    )
    pkgio.append_evidence(
        pkg_dir,
        TestEvidence(
            id="EVD-tests-002",
            command="pytest -m integration",
            exit_code=0,
            passed=1,
            status=EvidenceStatus.COMPLETE,
        ),
    )
    critical = tmp_path / "critical.json"
    critical.write_text(json.dumps({"src/auth": 50.0}))
    layers = tmp_path / "layers.json"
    layers.write_text(
        json.dumps([{"layer": "unit", "metrics": {"acceptance_criteria_with_evidence": 100}}])
    )
    breach = runner.invoke(
        app,
        [
            "test",
            "portfolio",
            str(pkg_dir),
            "--critical-coverage",
            str(critical),
            "--layers",
            str(layers),
        ],
    )
    assert breach.exit_code == 1 and "critical module src/auth" in breach.output
    exceptions = tmp_path / "exceptions.json"
    exceptions.write_text(
        json.dumps(
            [
                {
                    "metric": "critical_modules",
                    "reason": "auth rewrite in progress",
                    "approved_by": "ciso",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                    "reference": "RISK-1",
                }
            ]
        )
    )
    ok = runner.invoke(
        app,
        [
            "test",
            "portfolio",
            str(pkg_dir),
            "--critical-coverage",
            str(critical),
            "--layers",
            str(layers),
            "--exceptions",
            str(exceptions),
        ],
    )
    assert ok.exit_code == 0, ok.output
    assert "exempted" in ok.output


def test_mutation_command_from_report_attaches_to_package(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path)
    pkgio.append_evidence(
        pkg_dir,
        TestEvidence(
            id="EVD-tests-001", command="pytest", exit_code=0, status=EvidenceStatus.COMPLETE
        ),
    )
    out = tmp_path / "mutation.json"
    result = runner.invoke(
        app,
        [
            "test",
            "mutation",
            "--report",
            str(FIXTURES / "mutmut.json"),
            "--package",
            str(pkg_dir),
            "--floor",
            "0.6",
            "--out",
            str(out),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["attached_to"] == "EVD-tests-001"
    assert payload["ratcheted_floor"] == 0.76
    stored = pkgio.read_evidence(pkg_dir, "tests")
    assert isinstance(stored[0], TestEvidence)
    assert stored[0].mutation is not None and stored[0].mutation.scope == ["src/pkg"]
    assert json.loads(out.read_text())["killed"] == 12
    incomplete = runner.invoke(
        app, ["test", "mutation", "--report", str(FIXTURES / "cosmic-ray.json"), "--scope", "src"]
    )
    assert incomplete.exit_code == 1 and "complete=False" in incomplete.output
    usage = runner.invoke(app, ["test", "mutation"])
    assert usage.exit_code == 2
    empty_pkg = _package(tmp_path, "CHG-empty")
    no_tests = runner.invoke(
        app, ["test", "mutation", "--report", str(FIXTURES / "mutmut.json"), "-p", str(empty_pkg)]
    )
    assert no_tests.exit_code == 2 and "no test evidence" in no_tests.output


def test_mutation_command_builtin(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (src / "__pycache__").mkdir()
    check = "import sys; sys.path.insert(0, 'src'); import calc; assert calc.add(1, 2) == 3"
    result = runner.invoke(
        app,
        [
            "test",
            "mutation",
            "src",
            "--builtin",
            "--command",
            f'{sys.executable} -c "{check}"',
            "--cwd",
            str(tmp_path),
            "--timeout",
            "60",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "score=1.00" in result.output and "killed=1" in result.output
    no_files = runner.invoke(
        app, ["test", "mutation", "--builtin", "--command", "true", "--cwd", str(tmp_path)]
    )
    assert no_files.exit_code == 2
    no_cmd = runner.invoke(app, ["test", "mutation", "src", "--builtin", "--cwd", str(tmp_path)])
    assert no_cmd.exit_code == 2


def test_portfolio_persists_inputs_for_gate_g2(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path, risk=RiskClass.LOW)
    pkgio.append_evidence(
        pkg_dir,
        TestEvidence(
            id="EVD-tests-001",
            command="pytest -q",
            exit_code=0,
            passed=1,
            status=EvidenceStatus.COMPLETE,
            coverage=Coverage(lines=90, branches=80, diff_lines=95),
        ),
    )
    layers = tmp_path / "layers.json"
    layers.write_text(
        json.dumps(
            [
                {
                    "layer": "integration",
                    "passed": 3,
                    "metrics": {"acceptance_criteria_with_evidence": 100},
                }
            ]
        )
    )
    first = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--layers", str(layers)])
    assert first.exit_code == 0, first.output
    assert "wrote" in first.output
    record = pf.read_portfolio_record(pkg_dir)
    assert record is not None and record.risk_class is RiskClass.LOW
    assert record.inputs.runs[0].metrics["acceptance_criteria_with_evidence"] == 100
    assert record.report.passed
    # persisted inputs are reused when the option is omitted
    again = runner.invoke(app, ["test", "portfolio", str(pkg_dir)])
    assert again.exit_code == 0, again.output
    # --reset-inputs drops them: the completeness metric is no longer measured
    reset = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--reset-inputs"])
    assert reset.exit_code == 1
    assert "acceptance_criteria_with_evidence not measured" in reset.output
    stored = pf.read_portfolio_record(pkg_dir)
    assert stored is not None and stored.inputs.is_empty
    # --no-write leaves the file alone
    no_write = runner.invoke(
        app, ["test", "portfolio", str(pkg_dir), "--layers", str(layers), "--no-write"]
    )
    assert no_write.exit_code == 0 and "wrote" not in no_write.output
    unchanged = pf.read_portfolio_record(pkg_dir)
    assert unchanged is not None and unchanged.inputs.is_empty
    pf.portfolio_path(pkg_dir).write_text("{broken")
    broken = runner.invoke(app, ["test", "portfolio", str(pkg_dir)])
    assert broken.exit_code == 2 and "portfolio.json" in broken.output


def test_perf_evidence_command(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path, risk=RiskClass.HIGH)
    summary = tmp_path / "k6.json"
    summary.write_text(
        json.dumps(
            {
                "metrics": {
                    "http_req_duration": {"values": {"med": 80.0, "p(95)": 180.0}},
                    "http_reqs": {"values": {"rate": 40.0}},
                }
            }
        )
    )
    ok = runner.invoke(
        app,
        [
            "test",
            "perf-evidence",
            str(summary),
            "--package",
            str(pkg_dir),
            "--p95-max-ms",
            "200",
            "--min-throughput",
            "30",
            "--commit-sha",
            "abc",
        ],
    )
    assert ok.exit_code == 0, ok.output
    assert "slo_met=True" in ok.output
    stored = pkgio.read_evidence(pkg_dir, EvidenceKind.PERFORMANCE)
    assert len(stored) == 1
    record = stored[0]
    assert record.is_complete and record.commit_sha == "abc"
    assert record.report_uri == str(summary.resolve())
    payload = json.loads(pkgio.evidence_path(pkg_dir, EvidenceKind.PERFORMANCE).read_text())
    entry = payload[0] if isinstance(payload, list) else payload
    assert entry["details"]["p95_target_ms"] == 200.0 and entry["p95_ms"] == 180.0

    unmet = runner.invoke(
        app, ["test", "perf-evidence", str(summary), "--p95-max-ms", "100", "--json"]
    )
    assert unmet.exit_code == 1
    data = json.loads(unmet.output)
    assert data["slo_met"] is False and data["status"] == "complete"

    no_target = runner.invoke(
        app, ["test", "perf-evidence", str(summary), "-o", str(tmp_path / "o.json")]
    )
    assert no_target.exit_code == 1 and "no SLO targets" in no_target.output
    assert (tmp_path / "o.json").is_file()

    bad_format = runner.invoke(app, ["test", "perf-evidence", str(summary), "--format", "nope"])
    assert bad_format.exit_code == 2
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{oops")
    unparsable = runner.invoke(app, ["test", "perf-evidence", str(bad_file)])
    assert unparsable.exit_code == 2 and "cannot parse" in unparsable.output


def test_run_evidence_parse_only_does_not_need_a_command(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(PASSING_JUNIT)
    parse = ["test", "run-evidence", "--parse-only", "--exit-code", "0"]
    result = runner.invoke(app, [*parse, "--junit", str(junit), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["command"] == "<parsed-from-artifacts>"
    assert payload["status"] == "complete" and payload["passed"] == 2

    ci_command = "pytest -q --junitxml=junit.xml"
    named = runner.invoke(app, [*parse, "--junit", str(junit), "--command", ci_command, "--json"])
    assert named.exit_code == 0, named.output
    assert json.loads(named.output)["command"] == ci_command

    coverage_only = runner.invoke(
        app, [*parse, "--coverage-xml", str(FIXTURES / "coverage.xml"), "--json"]
    )
    assert coverage_only.exit_code in (0, 1), coverage_only.output
    assert "<parsed-from-artifacts>" in coverage_only.output

    no_artifacts = runner.invoke(app, parse)
    assert no_artifacts.exit_code == 2, no_artifacts.output
    assert "--parse-only needs at least one artifact" in no_artifacts.output
    assert "--junit" in no_artifacts.output and "--coverage-json" in no_artifacts.output

    usage = runner.invoke(app, ["test", "run-evidence"])
    assert usage.exit_code == 2 and "--command is required" in usage.output
    usage_junit = runner.invoke(app, ["test", "run-evidence", "--junit", str(junit)])
    assert usage_junit.exit_code == 2 and "--command is required" in usage_junit.output


def test_portfolio_input_files_report_path_and_exit_2(tmp_path: Path) -> None:
    pkg_dir = _package(tmp_path)
    layers = tmp_path / "layers.json"
    layers.write_text('[{"layer": "nope"}]')
    result = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--layers", str(layers)])
    assert result.exit_code == 2, result.output
    assert result.output.startswith(f"error: {layers}: item 0: layer: Input should be")
    assert "Traceback" not in result.output and "validation error" not in result.output

    not_list = tmp_path / "exceptions.json"
    not_list.write_text('{"a": 1}')
    listed = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--exceptions", str(not_list)])
    assert listed.exit_code == 2 and f"error: {not_list}: expected a JSON list" in listed.output

    critical = tmp_path / "critical.json"
    critical.write_text('{"module": "high"}')
    bad = runner.invoke(
        app, ["test", "portfolio", str(pkg_dir), "--critical-coverage", str(critical)]
    )
    assert bad.exit_code == 2, bad.output
    assert bad.output.startswith(f"error: {critical}: critical_module_coverage.module")

    broken = tmp_path / "broken.json"
    broken.write_text("[")
    unreadable = runner.invoke(app, ["test", "portfolio", str(pkg_dir), "--layers", str(broken)])
    assert unreadable.exit_code == 2 and f"error: {broken}: cannot read layers" in unreadable.output
