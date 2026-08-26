"""Tests for aisdlc.testing.performance: parsers, SLO derivation, evidence record."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisdlc.schema import package as pkgio
from aisdlc.schema.models import EvidenceKind, Intent, PerformanceEvidence, RiskClass
from aisdlc.testing import performance as perf

K6 = {
    "metrics": {
        "http_req_duration": {
            "values": {
                "avg": 90.5,
                "min": 10.0,
                "med": 80.0,
                "max": 400.0,
                "p(90)": 150.0,
                "p(95)": 180.0,
            },
        },
        "http_reqs": {"values": {"count": 1200, "rate": 40.0}},
    }
}

LOCUST_COLUMNS = [
    "Type",
    "Name",
    "Request Count",
    "Failure Count",
    "Median Response Time",
    "Average Response Time",
    "Min Response Time",
    "Max Response Time",
    "Average Content Size",
    "Requests/s",
    "Failures/s",
    "50%",
    "66%",
    "75%",
    "80%",
    "90%",
    "95%",
    "98%",
    "99%",
    "99.9%",
    "99.99%",
    "100%",
]
LOCUST = (
    ",".join(LOCUST_COLUMNS)
    + "\n"
    + "\n".join(
        [
            "GET,/login,100,0,50,55,10,200,512,10.5,0,50,60,70,75,90,120,150,180,200,200,200",
            ",Aggregated,100,0,50,55,10,200,512,10.5,0,50,60,70,75,90,120,150,180,200,200,200",
        ]
    )
    + "\n"
)

BENCH = {
    "benchmarks": [
        {
            "name": "test_fast",
            "stats": {"median": 0.001, "mean": 0.0012, "ops": 900.0, "min": 0.0009, "max": 0.002},
        },
        {
            "name": "test_slow",
            "stats": {
                "median": 0.05,
                "mean": 0.051,
                "ops": 19.5,
                "min": 0.04,
                "max": 0.07,
                "q95": 0.06,
            },
        },
    ]
}


def test_parse_k6_summary() -> None:
    m = perf.parse_k6_summary(K6)
    assert m.p50_ms == 80.0 and m.p95_ms == 180.0 and m.throughput == 40.0
    assert m.source_format == "k6" and m.extra["p90_ms"] == 150.0 and m.extra["max_ms"] == 400.0
    with pytest.raises(ValueError, match="metrics"):
        perf.parse_k6_summary({"nope": 1})
    empty = perf.parse_k6_summary({"metrics": {"http_req_duration": {"values": {}}}})
    assert not empty.measured and empty.notes


def test_parse_locust_stats() -> None:
    m = perf.parse_locust_stats(LOCUST)
    assert m.p50_ms == 50.0 and m.p95_ms == 120.0 and m.throughput == 10.5
    assert m.extra["max_ms"] == 200.0 and m.extra["failures"] == 0.0 and not m.notes
    no_aggregate = "\n".join(LOCUST.splitlines()[:2]) + "\n"
    assert perf.parse_locust_stats(no_aggregate).notes
    with pytest.raises(ValueError, match="no rows"):
        perf.parse_locust_stats("Type,Name\n")


def test_parse_pytest_benchmark_reports_slowest() -> None:
    m = perf.parse_pytest_benchmark(BENCH)
    assert m.p50_ms == 50.0 and m.p95_ms == 60.0 and m.throughput == 19.5
    assert "test_slow" in m.notes[0]
    without_p95 = perf.parse_pytest_benchmark({"benchmarks": [BENCH["benchmarks"][0]]})
    assert without_p95.p95_ms is None and any("no p95" in n for n in without_p95.notes)
    with pytest.raises(ValueError, match="benchmarks"):
        perf.parse_pytest_benchmark({})


def test_parse_plain_json_and_detection(tmp_path: Path) -> None:
    m = perf.parse_plain_json({"p50_ms": 5, "p95_ms": "9.5", "throughput_rps": 100, "max": 12})
    assert m.p50_ms == 5.0 and m.p95_ms == 9.5 and m.throughput == 100.0 and m.extra == {"max": 12}
    with pytest.raises(ValueError, match="none of"):
        perf.parse_plain_json({"x": 1})

    k6 = tmp_path / "summary.json"
    k6.write_text(json.dumps(K6))
    locust = tmp_path / "run_stats.csv"
    locust.write_text(LOCUST)
    bench = tmp_path / "bench.json"
    bench.write_text(json.dumps(BENCH))
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"p95_ms": 10}))
    assert perf.parse_measurement(k6).source_format == "k6"
    assert perf.parse_measurement(locust).source_format == "locust"
    assert perf.parse_measurement(bench).source_format == "pytest-benchmark"
    assert perf.parse_measurement(plain).source_format == "json"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        perf.parse_measurement(bad)
    with pytest.raises(ValueError, match="JSON object"):
        listy = tmp_path / "list.json"
        listy.write_text("[1, 2]")
        perf.parse_measurement(listy, "json")


def test_build_performance_evidence_derives_slo(tmp_path: Path) -> None:
    measurement = perf.parse_k6_summary(K6)
    met = perf.build_performance_evidence(
        measurement,
        perf.PerformanceTargets(p95_max_ms=200.0, throughput_min_rps=30.0),
        commit_sha="abc",
        report_uri="file:///reports/k6.json",
    )
    assert met.is_complete and met.slo_met and met.slo_problems() == []
    assert met.details["p95_target_ms"] == 200.0 and met.details["throughput_min_rps"] == 30.0
    assert met.details["max_ms"] == 400.0 and "(k6)" in met.produced_by

    unmet = perf.build_performance_evidence(measurement, perf.PerformanceTargets(p95_max_ms=100.0))
    assert unmet.is_complete and not unmet.slo_met
    assert unmet.slo_problems() == ["p95 latency 180 ms exceeds target 100 ms"]

    no_targets = perf.build_performance_evidence(measurement, perf.PerformanceTargets())
    assert not no_targets.is_complete and not no_targets.slo_met
    assert any("no SLO targets" in p for p in no_targets.slo_problems())

    unmeasured = perf.build_performance_evidence(
        perf.PerformanceMeasurement(), perf.PerformanceTargets(p50_max_ms=1.0)
    )
    assert not unmeasured.is_complete and not unmeasured.slo_met

    # the gate re-derives: a record claiming slo_met without targets is still a problem
    forged = PerformanceEvidence(id="EVD-performance-001", p95_ms=1.0, slo_met=True)
    assert forged.slo_problems() and forged.targets() == {}

    pkg = pkgio.create(
        tmp_path, "CHG-perf", Intent(id="CHG-perf", title="p", risk_class=RiskClass.HIGH)
    )
    assert pkg.root is not None
    path = perf.record_performance_evidence(pkg.root, met)
    assert path == pkgio.evidence_path(pkg.root, EvidenceKind.PERFORMANCE)
    stored = pkgio.read_evidence(pkg.root, EvidenceKind.PERFORMANCE)
    assert len(stored) == 1 and isinstance(stored[0], PerformanceEvidence) and stored[0].slo_met
