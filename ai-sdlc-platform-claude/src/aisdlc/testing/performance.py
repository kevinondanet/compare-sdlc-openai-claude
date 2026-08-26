"""Performance evidence producer: load/latency tool output -> ``evidence/performance.json``.

Gate G5 blocks on an *unmet SLO* (ARCHITECTURE.md §3). Nothing can be unmet without a
measurement and a target, so this module turns the summary output of common load tools
into a :class:`~aisdlc.schema.models.PerformanceEvidence` record that carries both:

* measurements — ``p50_ms``, ``p95_ms``, ``throughput`` (requests per second);
* targets — stored in ``details`` under ``p50_target_ms``, ``p95_target_ms`` and
  ``throughput_min_rps`` (:data:`~aisdlc.schema.models.PERFORMANCE_TARGET_KEYS`).

``slo_met`` is *derived* from the two (never hand-set) and the gate re-derives it from
the same fields, so a record that says ``slo_met: true`` without a target or a
measurement still fails closed.

Supported inputs (:func:`parse_measurement`, format auto-detected):

* **k6** ``--summary-export`` JSON (``metrics.http_req_duration.values``: ``med``,
  ``p(95)``; ``metrics.http_reqs.values.rate``);
* **locust** ``--csv`` stats file (the ``Aggregated`` row: ``50%``, ``95%``,
  ``Requests/s``);
* **pytest-benchmark** JSON (``benchmarks[].stats``: ``median``/``mean`` in seconds,
  ``ops``); the slowest benchmark's median is reported and p95 is left unmeasured unless
  the stats carry a ``q95``/``p95`` value;
* a **plain JSON** object with ``p50_ms`` / ``p95_ms`` / ``throughput`` (or
  ``throughput_rps``) keys — the escape hatch for any other tool.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import __version__
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    EvidenceKind,
    EvidenceStatus,
    PerformanceEvidence,
    utcnow,
)

__all__ = [
    "DEFAULT_EVIDENCE_ID",
    "PRODUCED_BY",
    "InputFormat",
    "PerformanceMeasurement",
    "PerformanceTargets",
    "build_performance_evidence",
    "detect_format",
    "parse_k6_summary",
    "parse_locust_stats",
    "parse_measurement",
    "parse_plain_json",
    "parse_pytest_benchmark",
    "record_performance_evidence",
]

DEFAULT_EVIDENCE_ID = "EVD-performance-001"
PRODUCED_BY = f"aisdlc.testing.performance {__version__}"

InputFormat = Literal["auto", "k6", "locust", "pytest-benchmark", "json"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PerformanceTargets(_Model):
    """SLO targets; ``None`` means "no target for this dimension"."""

    p50_max_ms: float | None = Field(default=None, ge=0)
    p95_max_ms: float | None = Field(default=None, ge=0)
    throughput_min_rps: float | None = Field(default=None, ge=0)

    @property
    def is_empty(self) -> bool:
        """No target at all (the gate treats this as an unmet SLO)."""
        return (
            self.p50_max_ms is None
            and self.p95_max_ms is None
            and (self.throughput_min_rps is None)
        )

    def as_details(self) -> dict[str, float]:
        """The ``PerformanceEvidence.details`` entries for these targets."""
        out: dict[str, float] = {}
        if self.p50_max_ms is not None:
            out["p50_target_ms"] = self.p50_max_ms
        if self.p95_max_ms is not None:
            out["p95_target_ms"] = self.p95_max_ms
        if self.throughput_min_rps is not None:
            out["throughput_min_rps"] = self.throughput_min_rps
        return out


class PerformanceMeasurement(_Model):
    """What a load/latency tool measured."""

    p50_ms: float | None = Field(default=None, ge=0)
    p95_ms: float | None = Field(default=None, ge=0)
    throughput: float | None = Field(default=None, ge=0, description="Requests per second.")
    source_format: str = ""
    extra: dict[str, float] = Field(
        default_factory=dict, description="Other numeric facts worth keeping (max, mean …)."
    )
    notes: list[str] = Field(default_factory=list)

    @property
    def measured(self) -> bool:
        """At least one of p50/p95/throughput is present."""
        return any(v is not None for v in (self.p50_ms, self.p95_ms, self.throughput))


# --------------------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------------------


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def parse_k6_summary(data: Mapping[str, Any]) -> PerformanceMeasurement:
    """Parse a k6 ``--summary-export`` document."""
    metrics = data.get("metrics")
    if not isinstance(metrics, Mapping):
        raise ValueError("k6 summary has no 'metrics' object")
    duration = metrics.get("http_req_duration")
    values: Mapping[str, Any] = {}
    if isinstance(duration, Mapping):
        inner = duration.get("values")
        values = inner if isinstance(inner, Mapping) else duration
    p50 = _num(values.get("med")) if values else None
    if p50 is None and values:
        p50 = _num(values.get("p(50)"))
    p95 = _num(values.get("p(95)")) if values else None
    reqs = metrics.get("http_reqs")
    rate: float | None = None
    if isinstance(reqs, Mapping):
        inner_reqs = reqs.get("values")
        source = inner_reqs if isinstance(inner_reqs, Mapping) else reqs
        rate = _num(source.get("rate"))
    extra: dict[str, float] = {}
    for key in ("avg", "min", "max", "p(90)", "p(99)"):
        val = _num(values.get(key)) if values else None
        if val is not None:
            extra[key.replace("(", "").replace(")", "") + "_ms"] = val
    notes: list[str] = []
    if p50 is None and p95 is None:
        notes.append("k6 summary carries no http_req_duration percentiles")
    return PerformanceMeasurement(
        p50_ms=p50, p95_ms=p95, throughput=rate, source_format="k6", extra=extra, notes=notes
    )


def parse_locust_stats(text: str) -> PerformanceMeasurement:
    """Parse a locust ``--csv`` ``*_stats.csv`` file (uses the ``Aggregated`` row)."""
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        raise ValueError("locust stats CSV has no rows")
    aggregated = next((r for r in rows if (r.get("Name") or "").strip() == "Aggregated"), None)
    row = aggregated if aggregated is not None else rows[-1]
    p50 = _num(row.get("50%")) or _num(row.get("Median Response Time"))
    p95 = _num(row.get("95%"))
    rate = _num(row.get("Requests/s"))
    extra: dict[str, float] = {}
    for column, key in (
        ("Average Response Time", "avg_ms"),
        ("Max Response Time", "max_ms"),
        ("99%", "p99_ms"),
        ("Failure Count", "failures"),
    ):
        val = _num(row.get(column))
        if val is not None:
            extra[key] = val
    notes = [] if aggregated is not None else ["no 'Aggregated' row; used the last row"]
    return PerformanceMeasurement(
        p50_ms=p50, p95_ms=p95, throughput=rate, source_format="locust", extra=extra, notes=notes
    )


def parse_pytest_benchmark(data: Mapping[str, Any]) -> PerformanceMeasurement:
    """Parse pytest-benchmark JSON; reports the slowest benchmark (seconds -> ms)."""
    benchmarks = data.get("benchmarks")
    if not isinstance(benchmarks, list) or not benchmarks:
        raise ValueError("pytest-benchmark JSON has no 'benchmarks'")
    slowest: Mapping[str, Any] | None = None
    slowest_median = -1.0
    for bench in benchmarks:
        if not isinstance(bench, Mapping):
            continue
        stats = bench.get("stats")
        if not isinstance(stats, Mapping):
            continue
        median = _num(stats.get("median"))
        if median is None:
            median = _num(stats.get("mean"))
        if median is not None and median > slowest_median:
            slowest_median = median
            slowest = bench
    if slowest is None:
        raise ValueError("pytest-benchmark JSON has no benchmark with stats")
    stats = slowest["stats"]
    p50 = slowest_median * 1000.0
    p95_raw = _num(stats.get("q95")) or _num(stats.get("p95"))
    p95 = p95_raw * 1000.0 if p95_raw is not None else None
    ops = _num(stats.get("ops"))
    extra: dict[str, float] = {}
    for key in ("min", "max", "mean", "stddev"):
        val = _num(stats.get(key))
        if val is not None:
            extra[f"{key}_ms"] = val * 1000.0
    notes = [f"slowest benchmark: {slowest.get('name', '?')}"]
    if p95 is None:
        notes.append("pytest-benchmark reports no p95; only p50 is measured")
    return PerformanceMeasurement(
        p50_ms=p50,
        p95_ms=p95,
        throughput=ops,
        source_format="pytest-benchmark",
        extra=extra,
        notes=notes,
    )


def parse_plain_json(data: Mapping[str, Any]) -> PerformanceMeasurement:
    """Parse ``{"p50_ms": .., "p95_ms": .., "throughput": ..}`` (aliases accepted)."""
    p50 = _num(data.get("p50_ms"))
    if p50 is None:
        p50 = _num(data.get("p50"))
    p95 = _num(data.get("p95_ms"))
    if p95 is None:
        p95 = _num(data.get("p95"))
    rate = _num(data.get("throughput"))
    if rate is None:
        rate = _num(data.get("throughput_rps"))
    if rate is None:
        rate = _num(data.get("rps"))
    extra = {
        k: v
        for k, v in ((key, _num(val)) for key, val in data.items())
        if v is not None
        and k not in {"p50_ms", "p95_ms", "throughput", "p50", "p95"}
        and k not in {"throughput_rps", "rps"}
    }
    if p50 is None and p95 is None and rate is None:
        raise ValueError("JSON carries none of p50_ms / p95_ms / throughput")
    return PerformanceMeasurement(
        p50_ms=p50, p95_ms=p95, throughput=rate, source_format="json", extra=extra
    )


def detect_format(path: Path, text: str) -> InputFormat:
    """Guess the input format from the file suffix and content."""
    if path.suffix.lower() == ".csv":
        return "locust"
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        lines = text.splitlines()
        return "locust" if lines and "," in lines[0] else "json"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "json"
    if isinstance(data, Mapping):
        if "benchmarks" in data and isinstance(data.get("benchmarks"), list):
            return "pytest-benchmark"
        metrics = data.get("metrics")
        if isinstance(metrics, Mapping) and "http_req_duration" in metrics:
            return "k6"
    return "json"


def parse_measurement(path: str | Path, fmt: InputFormat = "auto") -> PerformanceMeasurement:
    """Read *path* and parse it as *fmt* (auto-detected by default)."""
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    resolved: InputFormat = detect_format(source, text) if fmt == "auto" else fmt
    if resolved == "locust":
        return parse_locust_stats(text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source}: not valid JSON ({exc})") from exc
    if not isinstance(data, Mapping):
        raise ValueError(f"{source}: expected a JSON object")
    if resolved == "k6":
        return parse_k6_summary(data)
    if resolved == "pytest-benchmark":
        return parse_pytest_benchmark(data)
    return parse_plain_json(data)


# --------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------


def build_performance_evidence(
    measurement: PerformanceMeasurement,
    targets: PerformanceTargets,
    *,
    evidence_id: str = DEFAULT_EVIDENCE_ID,
    commit_sha: str = "",
    environment: str = "ci",
    report_uri: str | None = None,
    produced_by: str = PRODUCED_BY,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> PerformanceEvidence:
    """Combine a measurement and targets into a :class:`PerformanceEvidence` record.

    ``slo_met`` is derived: every recorded target must hold against its measurement and
    at least one target must exist. The record is ``incomplete`` when nothing was measured
    or no target is recorded, so it fails G5 closed.
    """
    details: dict[str, float] = dict(measurement.extra)
    details.update(targets.as_details())
    now = utcnow()
    record = PerformanceEvidence(
        id=evidence_id,
        kind=EvidenceKind.PERFORMANCE,
        commit_sha=commit_sha,
        environment=environment,
        produced_by=produced_by
        + (f" ({measurement.source_format})" if measurement.source_format else ""),
        started_at=started_at or now,
        finished_at=finished_at or now,
        report_uri=report_uri,
        status=EvidenceStatus.INCOMPLETE,
        p50_ms=measurement.p50_ms,
        p95_ms=measurement.p95_ms,
        throughput=measurement.throughput,
        slo_met=False,
        details=details,
    )
    problems = record.slo_problems()
    complete = measurement.measured and not targets.is_empty
    return record.model_copy(
        update={
            "slo_met": not problems,
            "status": EvidenceStatus.COMPLETE if complete else EvidenceStatus.INCOMPLETE,
        }
    )


def record_performance_evidence(package_dir: str | Path, record: PerformanceEvidence) -> Path:
    """Write *record* as the package's single ``evidence/performance.json`` entry."""
    return pkgio.write_evidence(package_dir, EvidenceKind.PERFORMANCE, record)
