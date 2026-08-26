"""BenchmarkService: observed quality/security/test-gen/review-precision/cost results.

Results are stored in SQLite and aggregated per model so that routing and KPI computation
rank models by **observed** score and cost rather than reputation.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

BENCHMARK_ID_RE = re.compile(r"^BM-[a-z0-9]+(?:-[a-z0-9]+)*-[A-Za-z0-9.]+$")


class BenchmarkCategory(StrEnum):
    """Benchmark categories consumed by routing and KPIs."""

    quality = "quality"
    security = "security"
    test_generation = "test_generation"
    review_precision = "review_precision"
    cost_performance = "cost_performance"


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class BenchmarkResult(BaseModel):
    """One observed benchmark measurement for a model version."""

    model_config = ConfigDict(extra="forbid")

    benchmark_id: str = Field(description="BM-<slug>-<version>")
    category: BenchmarkCategory
    model: str = Field(min_length=1)
    version: str = ""
    metric: str = Field(min_length=1, description="e.g. pass_rate, precision, asr_detected")
    value: float
    higher_is_better: bool = True
    cost_usd: float = Field(default=0.0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0)
    ts: datetime = Field(default_factory=_utcnow)
    sample_size: int = Field(default=1, ge=1)
    notes: str = ""

    @field_validator("benchmark_id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not BENCHMARK_ID_RE.match(value):
            raise ValueError(f"benchmark_id must match BM-<slug>-<version>, got {value!r}")
        return value

    @field_validator("ts")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)


class ModelScore(BaseModel):
    """Aggregated benchmark standing for one model in one category."""

    model_config = ConfigDict(extra="forbid")

    model: str
    category: BenchmarkCategory
    score: float = Field(description="Sample-weighted mean of normalised values (higher=better)")
    total_samples: int
    results: int
    mean_cost_usd: float
    mean_latency_ms: float
    score_per_dollar: float | None = Field(
        default=None, description="score / mean_cost_usd when cost is known"
    )
    benchmark_ids: list[str] = Field(default_factory=list)


def _iso(dt: datetime) -> str:
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


class BenchmarkService:
    """SQLite-backed store of :class:`BenchmarkResult` records."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS benchmark_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                benchmark_id TEXT NOT NULL,
                category TEXT NOT NULL,
                model TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                higher_is_better INTEGER NOT NULL DEFAULT 1,
                cost_usd REAL NOT NULL DEFAULT 0,
                latency_ms REAL NOT NULL DEFAULT 0,
                ts TEXT NOT NULL,
                sample_size INTEGER NOT NULL DEFAULT 1,
                notes TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_bm_cat_model ON benchmark_results(category, model)"
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def __enter__(self) -> BenchmarkService:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ write
    def store(self, result: BenchmarkResult) -> int:
        """Persist one result and return its row id."""
        cur = self._conn.execute(
            """
            INSERT INTO benchmark_results
              (benchmark_id, category, model, version, metric, value, higher_is_better,
               cost_usd, latency_ms, ts, sample_size, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                result.benchmark_id,
                result.category.value,
                result.model,
                result.version,
                result.metric,
                result.value,
                1 if result.higher_is_better else 0,
                result.cost_usd,
                result.latency_ms,
                _iso(result.ts),
                result.sample_size,
                result.notes,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def store_many(self, results: Iterable[BenchmarkResult]) -> int:
        """Persist many results; returns the count stored."""
        n = 0
        for r in results:
            self.store(r)
            n += 1
        return n

    # ------------------------------------------------------------------ read
    def query(
        self,
        *,
        category: BenchmarkCategory | str | None = None,
        model: str | None = None,
        benchmark_id: str | None = None,
        metric: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> list[BenchmarkResult]:
        """Return results matching all provided filters, newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if category is not None:
            cat = category.value if isinstance(category, BenchmarkCategory) else str(category)
            clauses.append("category = ?")
            params.append(cat)
        if model is not None:
            clauses.append("model = ?")
            params.append(model)
        if benchmark_id is not None:
            clauses.append("benchmark_id = ?")
            params.append(benchmark_id)
        if metric is not None:
            clauses.append("metric = ?")
            params.append(metric)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("ts <= ?")
            params.append(_iso(until))
        sql = "SELECT * FROM benchmark_results"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC, id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_result(r) for r in rows]

    @staticmethod
    def _row_to_result(row: sqlite3.Row) -> BenchmarkResult:
        return BenchmarkResult(
            benchmark_id=row["benchmark_id"],
            category=BenchmarkCategory(row["category"]),
            model=row["model"],
            version=row["version"],
            metric=row["metric"],
            value=row["value"],
            higher_is_better=bool(row["higher_is_better"]),
            cost_usd=row["cost_usd"],
            latency_ms=row["latency_ms"],
            ts=datetime.fromisoformat(row["ts"]),
            sample_size=row["sample_size"],
            notes=row["notes"],
        )

    def scores(
        self,
        category: BenchmarkCategory | str,
        *,
        min_samples: int = 1,
        models: Iterable[str] | None = None,
        since: datetime | None = None,
    ) -> dict[str, ModelScore]:
        """Aggregate per-model scores for ``category``.

        Values are sample-weighted; ``higher_is_better=False`` results are folded as
        ``1 - value`` so all scores read higher-is-better. Only models with at least
        ``min_samples`` total samples are returned.
        """
        wanted = set(models) if models is not None else None
        results = self.query(category=category, since=since)
        acc: dict[str, dict[str, Any]] = {}
        for r in results:
            if wanted is not None and r.model not in wanted:
                continue
            a = acc.setdefault(
                r.model,
                {"wsum": 0.0, "n": 0, "count": 0, "cost": 0.0, "lat": 0.0, "ids": set()},
            )
            v = r.value if r.higher_is_better else 1.0 - r.value
            a["wsum"] += v * r.sample_size
            a["n"] += r.sample_size
            a["count"] += 1
            a["cost"] += r.cost_usd
            a["lat"] += r.latency_ms
            a["ids"].add(r.benchmark_id)
        out: dict[str, ModelScore] = {}
        cat = category if isinstance(category, BenchmarkCategory) else BenchmarkCategory(category)
        for model, a in acc.items():
            if a["n"] < min_samples:
                continue
            score = a["wsum"] / a["n"]
            mean_cost = a["cost"] / a["count"]
            mean_lat = a["lat"] / a["count"]
            out[model] = ModelScore(
                model=model,
                category=cat,
                score=score,
                total_samples=a["n"],
                results=a["count"],
                mean_cost_usd=mean_cost,
                mean_latency_ms=mean_lat,
                score_per_dollar=(score / mean_cost) if mean_cost > 0 else None,
                benchmark_ids=sorted(a["ids"]),
            )
        return out

    def best_for(
        self,
        category: BenchmarkCategory | str,
        *,
        min_samples: int = 1,
        models: Iterable[str] | None = None,
        by: str = "score",
    ) -> ModelScore | None:
        """Return the best model for ``category`` ranked by ``score`` or ``score_per_dollar``."""
        if by not in {"score", "score_per_dollar"}:
            raise ValueError("by must be 'score' or 'score_per_dollar'")
        table = self.scores(category, min_samples=min_samples, models=models)
        if not table:
            return None

        def key(ms: ModelScore) -> tuple[float, float]:
            if by == "score_per_dollar":
                return (ms.score_per_dollar if ms.score_per_dollar is not None else -1.0, ms.score)
            return (ms.score, ms.score_per_dollar or 0.0)

        return max(table.values(), key=key)

    def count(self) -> int:
        """Total stored results."""
        row = self._conn.execute("SELECT COUNT(*) AS c FROM benchmark_results").fetchone()
        return int(row["c"])
