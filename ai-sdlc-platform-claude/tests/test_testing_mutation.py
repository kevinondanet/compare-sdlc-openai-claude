"""Tests for aisdlc.testing.mutation (tool JSON parsing, built-in runner, ratchet)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aisdlc.schema.models import TestEvidence
from aisdlc.testing import mutation as mut

FIXTURES = Path(__file__).parent / "fixtures" / "testing"


def test_parse_mutmut_counts() -> None:
    report = mut.load_mutation_report(FIXTURES / "mutmut.json")
    assert report.tool == "mutmut"
    assert (report.killed, report.survived, report.timeout) == (12, 4, 1)
    assert report.tested == 17 and report.total == 20
    assert report.score == pytest.approx(13 / 17, abs=1e-4)
    assert report.complete
    assert report.scope == ["src/pkg"] and report.excluded == ["src/pkg/cli.py"]
    model = report.to_model()
    assert model.score == report.score and model.scope == ["src/pkg"]


def test_parse_cosmic_ray_work_items_incomplete() -> None:
    report = mut.load_mutation_report(
        FIXTURES / "cosmic-ray.json", scope=["src/pkg/calc.py"], tool="cosmic-ray"
    )
    assert report.tool == "cosmic-ray"
    assert (
        report.killed,
        report.survived,
        report.timeout,
        report.incompetent,
        report.untested,
    ) == (
        1,
        1,
        1,
        1,
        1,
    )
    assert not report.complete
    assert report.score == pytest.approx(2 / 3, abs=1e-4)
    assert report.to_model().score is None  # incomplete never reports a score
    assert report.mutants[0].line == 4 and report.mutants[0].file == "src/pkg/calc.py"


def test_parse_mutants_list_and_summary_wrapper() -> None:
    data = {
        "summary": {"killed": 3, "survived": 1},
        "scope": ["a.py"],
        "excluded": ["b.py"],
        "tool": "custom",
    }
    report = mut.parse_mutation_json(data)
    assert report.score == 0.75 and report.scope == ["a.py"] and report.excluded == ["b.py"]
    listed = mut.parse_mutation_json(
        {"mutants": [{"id": 1, "status": "killed"}, {"id": 2, "status": "survived"}]}
    )
    assert listed.score == 0.5 and len(listed.mutants) == 2


def test_parse_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="no mutant counts"):
        mut.parse_mutation_json({"foo": 1})
    with pytest.raises(ValueError, match="unknown mutant status"):
        mut.parse_mutation_json([{"status": "weird"}])
    with pytest.raises(ValueError, match="non-negative"):
        mut.parse_mutation_json({"killed": -1})


def test_ratchet_only_moves_up() -> None:
    report = mut.parse_mutation_json({"killed": 7, "survived": 3})
    assert mut.ratchet_mutation_floor(0.6, report) == 0.7
    assert mut.ratchet_mutation_floor(0.9, report) == 0.9
    incomplete = mut.parse_mutation_json({"killed": 9, "survived": 0, "untested": 1})
    assert mut.ratchet_mutation_floor(0.6, incomplete) == 0.6
    sampled = report.model_copy(update={"sampled": True})
    assert mut.ratchet_mutation_floor(0.6, sampled) == 0.6


def test_attach_mutation_to_test_evidence() -> None:
    evidence = TestEvidence(id="EVD-tests-001", command="pytest", exit_code=0, status="complete")
    report = mut.parse_mutation_json({"killed": 2, "survived": 2, "scope": ["src"]})
    attached = mut.attach_mutation(evidence, report)
    assert attached.mutation is not None and attached.mutation.score == 0.5
    assert evidence.mutation is None  # original untouched


CALC = '''"""Tiny module for the built-in mutation runner."""


def add(a, b):
    return a + b


def is_positive(x):
    return x > 0
'''

CHECK = (
    "import calc; assert calc.add(1, 2) == 3; "
    "assert calc.is_positive(1); assert not calc.is_positive(-1)"
)


def test_find_mutation_sites() -> None:
    sites_file = Path(__file__).parent / "fixtures" / "testing" / "_calc_sites.py"
    sites_file.write_text(CALC)
    try:
        sites = mut.find_mutation_sites(sites_file)
    finally:
        sites_file.unlink()
    operators = sorted(s.operator for s in sites)
    assert operators == ["binop", "compare", "constant"]
    assert all(s.line > 0 for s in sites)


def test_builtin_runner_scores_and_restores_files(tmp_path: Path) -> None:
    calc = tmp_path / "calc.py"
    calc.write_text(CALC)
    original = calc.read_bytes()
    report = mut.run_builtin_mutation(
        [calc], [sys.executable, "-c", CHECK], cwd=tmp_path, timeout=60
    )
    assert calc.read_bytes() == original
    assert report.tool == "aisdlc-builtin"
    assert report.complete and not report.sampled
    assert (report.killed, report.survived, report.timeout) == (2, 1, 0)
    assert report.score == pytest.approx(2 / 3, abs=1e-4)
    survivors = [m for m in report.mutants if m.status is mut.MutantStatus.SURVIVED]
    assert survivors and survivors[0].operator == "compare"
    assert report.scope == [str(calc)]


def test_builtin_runner_samples_when_bounded(tmp_path: Path) -> None:
    calc = tmp_path / "calc.py"
    calc.write_text(CALC)
    report = mut.run_builtin_mutation(
        [calc], [sys.executable, "-c", CHECK], cwd=tmp_path, max_mutants=1, timeout=60
    )
    assert report.sampled and report.tested == 1
    assert any("sampled 1 of 3" in n for n in report.notes)
    assert mut.ratchet_mutation_floor(0.5, report) == 0.5  # sampled runs never ratchet


def test_builtin_runner_fails_closed_on_red_baseline(tmp_path: Path) -> None:
    calc = tmp_path / "calc.py"
    calc.write_text(CALC)
    report = mut.run_builtin_mutation(
        [calc], [sys.executable, "-c", "raise SystemExit(1)"], cwd=tmp_path, timeout=60
    )
    assert not report.complete and report.untested == 3
    assert any("baseline run failed" in n for n in report.notes)
    assert report.to_model().score is None


def test_builtin_runner_timeout_baseline(tmp_path: Path) -> None:
    calc = tmp_path / "calc.py"
    calc.write_text(CALC)
    report = mut.run_builtin_mutation(
        [calc], [sys.executable, "-c", "import time; time.sleep(5)"], cwd=tmp_path, timeout=0.3
    )
    assert not report.complete
    assert any("timed out" in n for n in report.notes)


def test_builtin_runner_without_sites_or_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.py"
    empty.write_text("x = 'text'\n")
    report = mut.run_builtin_mutation([empty, tmp_path / "missing.py"], "true", cwd=tmp_path)
    assert not report.complete
    assert any("not a file" in n for n in report.notes)
    assert any("no mutation sites" in n for n in report.notes)
    with pytest.raises(ValueError, match="empty verification command"):
        mut.run_builtin_mutation([empty], "", cwd=tmp_path)


def test_report_round_trips_as_json() -> None:
    report = mut.parse_mutation_json({"killed": 1, "survived": 1})
    data = json.loads(report.model_dump_json())
    assert mut.MutationReport.model_validate(data) == report
