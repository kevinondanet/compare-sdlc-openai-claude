"""UsageLedger: SQLite-backed record of every metered model and tool call.

Every :class:`UsageEvent` is attributed to team / application / user / repository /
change / task / role / harness / provider / model / prompt version. The ledger answers
filtered queries, grouped summaries (tokens, cost, calls, latency percentiles) and produces
the ``evidence/cost.json`` extract for a change. It also owns the duplicate-run register
keyed by ``(source_hash, eval_config_hash)``.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

FILTERABLE_FIELDS: tuple[str, ...] = (
    "event_id",
    "team",
    "application",
    "user",
    "repository",
    "change_id",
    "task_id",
    "agent_role",
    "harness",
    "provider",
    "model",
    "prompt_version",
    "source",
    "environment",
    "routing_tier",
    "session_id",
    "cache_hit",
    "escalated",
    "success",
)

GROUPABLE_FIELDS: tuple[str, ...] = (
    "team",
    "application",
    "user",
    "repository",
    "change_id",
    "task_id",
    "agent_role",
    "harness",
    "provider",
    "model",
    "prompt_version",
    "source",
    "environment",
    "routing_tier",
    "session_id",
)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _iso(dt: datetime) -> str:
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class UsageEvent(BaseModel):
    """One metered call (model completion or privileged tool call)."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    ts: datetime = Field(default_factory=_utcnow)
    team: str = ""
    application: str = ""
    user: str = ""
    repository: str = ""
    change_id: str = ""
    task_id: str = ""
    agent_role: str = ""
    harness: str = ""
    provider: str = ""
    model: str = ""
    prompt_version: str = ""
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cached_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    reasoning_tokens: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0)
    cache_hit: bool = False
    source: str = Field(default="platform", description="platform|pyrit|claude_code|agt_audit|otel")
    environment: str = ""
    routing_tier: str = ""
    session_id: str = ""
    escalated: bool = False
    turn: int | None = Field(default=None, ge=0)
    review_round: int | None = Field(default=None, ge=0)
    success: bool | None = None
    source_hash: str = ""
    eval_config_hash: str = ""

    @field_validator("ts")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    @property
    def total_tokens(self) -> int:
        """All billed tokens for the call."""
        return (
            self.input_tokens
            + self.output_tokens
            + self.cached_tokens
            + self.cache_write_tokens
            + self.reasoning_tokens
        )


class UsageSummary(BaseModel):
    """Aggregate totals for one group of events."""

    model_config = ConfigDict(extra="forbid")

    group: dict[str, str] = Field(default_factory=dict)
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    cache_hit_rate: float = 0.0
    first_ts: datetime | None = None
    last_ts: datetime | None = None


class DuplicateCheck(BaseModel):
    """Result of a duplicate-run lookup."""

    model_config = ConfigDict(extra="forbid")

    duplicate: bool
    source_hash: str
    eval_config_hash: str
    prior_run_id: str | None = None
    prior_ts: datetime | None = None
    prior_change_id: str | None = None


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile (``pct`` in [0, 100]); 0.0 for empty input."""
    if not values:
        return 0.0
    if not 0 <= pct <= 100:
        raise ValueError("pct must be within [0, 100]")
    ordered = sorted(values)
    if pct == 0:
        return float(ordered[0])
    rank = max(1, int(round(pct / 100.0 * len(ordered) + 0.4999999)))
    return float(ordered[min(rank, len(ordered)) - 1])


_COLUMNS: tuple[str, ...] = (
    "event_id",
    "ts",
    "team",
    "application",
    "user",
    "repository",
    "change_id",
    "task_id",
    "agent_role",
    "harness",
    "provider",
    "model",
    "prompt_version",
    "input_tokens",
    "output_tokens",
    "cached_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "tool_calls",
    "latency_ms",
    "cost_usd",
    "cache_hit",
    "source",
    "environment",
    "routing_tier",
    "session_id",
    "escalated",
    "turn",
    "review_round",
    "success",
    "source_hash",
    "eval_config_hash",
)


class UsageLedger:
    """SQLite usage ledger (stdlib ``sqlite3``; ``':memory:'`` for tests)."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS usage_events (
                event_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                team TEXT NOT NULL DEFAULT '',
                application TEXT NOT NULL DEFAULT '',
                user TEXT NOT NULL DEFAULT '',
                repository TEXT NOT NULL DEFAULT '',
                change_id TEXT NOT NULL DEFAULT '',
                task_id TEXT NOT NULL DEFAULT '',
                agent_role TEXT NOT NULL DEFAULT '',
                harness TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT '',
                prompt_version TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cached_tokens INTEGER NOT NULL DEFAULT 0,
                cache_write_tokens INTEGER NOT NULL DEFAULT 0,
                reasoning_tokens INTEGER NOT NULL DEFAULT 0,
                tool_calls INTEGER NOT NULL DEFAULT 0,
                latency_ms REAL NOT NULL DEFAULT 0,
                cost_usd REAL NOT NULL DEFAULT 0,
                cache_hit INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'platform',
                environment TEXT NOT NULL DEFAULT '',
                routing_tier TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL DEFAULT '',
                escalated INTEGER NOT NULL DEFAULT 0,
                turn INTEGER,
                review_round INTEGER,
                success INTEGER,
                source_hash TEXT NOT NULL DEFAULT '',
                eval_config_hash TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS ix_usage_ts ON usage_events(ts);
            CREATE INDEX IF NOT EXISTS ix_usage_change ON usage_events(change_id);
            CREATE INDEX IF NOT EXISTS ix_usage_model ON usage_events(model);
            CREATE TABLE IF NOT EXISTS run_register (
                run_id TEXT PRIMARY KEY,
                source_hash TEXT NOT NULL,
                eval_config_hash TEXT NOT NULL,
                change_id TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT '',
                ts TEXT NOT NULL,
                UNIQUE(source_hash, eval_config_hash)
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the connection."""
        self._conn.close()

    def __enter__(self) -> UsageLedger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ write
    def record(self, event: UsageEvent) -> str:
        """Insert one event; returns its ``event_id``. Re-recording the same id is a no-op."""
        values = [self._to_sql(name, getattr(event, name)) for name in _COLUMNS]
        placeholders = ",".join("?" for _ in _COLUMNS)
        self._conn.execute(
            f"INSERT OR IGNORE INTO usage_events ({','.join(_COLUMNS)}) VALUES ({placeholders})",
            values,
        )
        self._conn.commit()
        return event.event_id

    def record_many(self, events: Iterable[UsageEvent]) -> int:
        """Insert many events; returns the number offered."""
        n = 0
        for ev in events:
            self.record(ev)
            n += 1
        return n

    @staticmethod
    def _to_sql(name: str, value: Any) -> Any:
        if name == "ts":
            return _iso(value)
        if isinstance(value, bool):
            return 1 if value else 0
        return value

    # ------------------------------------------------------------------ read
    @staticmethod
    def _where(
        filters: dict[str, Any] | None,
        since: datetime | None,
        until: datetime | None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in (filters or {}).items():
            if key not in FILTERABLE_FIELDS:
                raise ValueError(f"unsupported filter field: {key!r}")
            if isinstance(value, (list, tuple, set, frozenset)):
                items = [1 if v is True else 0 if v is False else v for v in value]
                if not items:
                    clauses.append("0")
                    continue
                clauses.append(f"{key} IN ({','.join('?' for _ in items)})")
                params.extend(items)
            else:
                clauses.append(f"{key} = ?")
                params.append(1 if value is True else 0 if value is False else value)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("ts <= ?")
            params.append(_iso(until))
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> UsageEvent:
        data: dict[str, Any] = {k: row[k] for k in _COLUMNS}
        data["ts"] = _parse_ts(data["ts"])
        for b in ("cache_hit", "escalated"):
            data[b] = bool(data[b])
        data["success"] = None if data["success"] is None else bool(data["success"])
        return UsageEvent.model_validate(data)

    def query(
        self,
        filters: dict[str, Any] | None = None,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> list[UsageEvent]:
        """Return events matching ``filters`` (field -> value or list of values)."""
        where, params = self._where(filters, since, until)
        order = "DESC" if newest_first else "ASC"
        sql = f"SELECT * FROM usage_events{where} ORDER BY ts {order}, rowid {order}"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count(self, filters: dict[str, Any] | None = None) -> int:
        """Number of events matching ``filters``."""
        where, params = self._where(filters, None, None)
        row = self._conn.execute(
            f"SELECT COUNT(*) AS c FROM usage_events{where}", params
        ).fetchone()
        return int(row["c"])

    def total_cost(
        self,
        filters: dict[str, Any] | None = None,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> float:
        """Sum of ``cost_usd`` over matching events."""
        where, params = self._where(filters, since, until)
        row = self._conn.execute(
            f"SELECT COALESCE(SUM(cost_usd), 0) AS c FROM usage_events{where}", params
        ).fetchone()
        return float(row["c"])

    def summarize(
        self,
        group_by: Sequence[str] = (),
        *,
        filters: dict[str, Any] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[UsageSummary]:
        """Aggregate matching events; one :class:`UsageSummary` per distinct group.

        With an empty ``group_by`` a single overall summary is returned (even when there
        are no events).
        """
        for g in group_by:
            if g not in GROUPABLE_FIELDS:
                raise ValueError(f"unsupported group_by field: {g!r}")
        events = self.query(filters, since=since, until=until)
        buckets: dict[tuple[str, ...], list[UsageEvent]] = {}
        for ev in events:
            key = tuple(str(getattr(ev, g)) for g in group_by)
            buckets.setdefault(key, []).append(ev)
        if not group_by and not buckets:
            buckets[()] = []
        out: list[UsageSummary] = []
        for key in sorted(buckets):
            evs = buckets[key]
            out.append(self._summarize_events(evs, dict(zip(group_by, key, strict=True))))
        return out

    def totals(
        self,
        filters: dict[str, Any] | None = None,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> UsageSummary:
        """Overall totals for matching events."""
        return self.summarize((), filters=filters, since=since, until=until)[0]

    @staticmethod
    def _summarize_events(events: list[UsageEvent], group: dict[str, str]) -> UsageSummary:
        latencies = [ev.latency_ms for ev in events]
        calls = len(events)
        hits = sum(1 for ev in events if ev.cache_hit)
        return UsageSummary(
            group=group,
            calls=calls,
            input_tokens=sum(ev.input_tokens for ev in events),
            output_tokens=sum(ev.output_tokens for ev in events),
            cached_tokens=sum(ev.cached_tokens for ev in events),
            cache_write_tokens=sum(ev.cache_write_tokens for ev in events),
            reasoning_tokens=sum(ev.reasoning_tokens for ev in events),
            total_tokens=sum(ev.total_tokens for ev in events),
            tool_calls=sum(ev.tool_calls for ev in events),
            cost_usd=round(sum(ev.cost_usd for ev in events), 10),
            latency_p50_ms=percentile(latencies, 50),
            latency_p95_ms=percentile(latencies, 95),
            cache_hit_rate=(hits / calls) if calls else 0.0,
            first_ts=min((ev.ts for ev in events), default=None),
            last_ts=max((ev.ts for ev in events), default=None),
        )

    # ------------------------------------------------------------------ evidence
    def export_change(self, change_id: str, *, evidence_id: str = "EVD-cost-001") -> dict[str, Any]:
        """Produce a ``CostEvidence``-shaped dict for ``evidence/cost.json``.

        ``status`` is ``complete`` when at least one event exists for the change and every
        event carries a model or tool attribution; otherwise ``incomplete`` (fails closed).
        """
        events = self.query({"change_id": change_id})
        totals = self._summarize_events(events, {})
        attributed = all(ev.model or ev.tool_calls for ev in events)
        by_model = self.summarize(("provider", "model"), filters={"change_id": change_id})
        by_role = self.summarize(("agent_role",), filters={"change_id": change_id})
        by_task = self.summarize(("task_id",), filters={"change_id": change_id})
        return {
            "id": evidence_id,
            "kind": "cost",
            "change_id": change_id,
            "status": "complete" if events and attributed else "incomplete",
            "produced_by": "aisdlc.control_plane.ledger",
            "started_at": _iso(totals.first_ts) if totals.first_ts else None,
            "finished_at": _iso(totals.last_ts) if totals.last_ts else None,
            "events": len(events),
            "totals": totals.model_dump(mode="json", exclude={"group"}),
            "by_model": [s.model_dump(mode="json") for s in by_model],
            "by_role": [s.model_dump(mode="json") for s in by_role],
            "by_task": [s.model_dump(mode="json") for s in by_task],
            "escalations": sum(1 for ev in events if ev.escalated),
            "ledger": self.path,
        }

    def cost_evidence(
        self,
        change_id: str,
        *,
        budget_usd: float | None = None,
        commit_sha: str = "",
        environment: str = "local",
        produced_by: str = "aisdlc.control_plane.ledger",
        evidence_id: str = "EVD-cost-001",
    ) -> Any:
        """Canonical :class:`~aisdlc.schema.models.CostEvidence` for ``evidence/cost.json``.

        Built from :meth:`export_change`; ``report_uri`` points at the ledger file so the
        full extract can be re-derived. Status is ``incomplete`` (fails G5 closed) when the
        change has no attributed usage at all.
        """
        from aisdlc.schema.models import CostEvidence, EvidenceStatus

        export = self.export_change(change_id, evidence_id=evidence_id)
        totals = export.get("totals", {}) if isinstance(export.get("totals"), dict) else {}

        def ts(value: Any) -> datetime | None:
            if not value:
                return None
            try:
                return datetime.fromisoformat(str(value))
            except ValueError:
                return None

        return CostEvidence(
            id=evidence_id,
            total_cost_usd=float(totals.get("cost_usd", 0.0) or 0.0),
            tokens_in=int(totals.get("input_tokens", 0) or 0),
            tokens_out=int(totals.get("output_tokens", 0) or 0),
            cached_tokens=int(totals.get("cached_tokens", 0) or 0),
            budget_usd=budget_usd,
            escalations=int(export.get("escalations", 0) or 0),
            commit_sha=commit_sha,
            environment=environment,
            produced_by=produced_by,
            started_at=ts(export.get("started_at")),
            finished_at=ts(export.get("finished_at")),
            report_uri=str(export.get("ledger") or "") or None,
            status=EvidenceStatus.COMPLETE
            if export.get("status") == "complete"
            else EvidenceStatus.INCOMPLETE,
        )

    # ------------------------------------------------------------------ duplicate runs
    def check_duplicate(self, source_hash: str, eval_config_hash: str) -> DuplicateCheck:
        """Look up whether a run with this ``(source_hash, eval_config_hash)`` already ran."""
        row = self._conn.execute(
            "SELECT run_id, ts, change_id FROM run_register"
            " WHERE source_hash=? AND eval_config_hash=?",
            (source_hash, eval_config_hash),
        ).fetchone()
        if row is None:
            return DuplicateCheck(
                duplicate=False, source_hash=source_hash, eval_config_hash=eval_config_hash
            )
        return DuplicateCheck(
            duplicate=True,
            source_hash=source_hash,
            eval_config_hash=eval_config_hash,
            prior_run_id=row["run_id"],
            prior_ts=_parse_ts(row["ts"]),
            prior_change_id=row["change_id"] or None,
        )

    def register_run(
        self,
        source_hash: str,
        eval_config_hash: str,
        *,
        change_id: str = "",
        kind: str = "",
        run_id: str | None = None,
    ) -> str:
        """Register a run so later identical runs are reported as duplicates.

        Returns the run id (existing id if the pair was already registered).
        """
        existing = self.check_duplicate(source_hash, eval_config_hash)
        if existing.duplicate and existing.prior_run_id:
            return existing.prior_run_id
        rid = run_id or uuid.uuid4().hex
        self._conn.execute(
            "INSERT INTO run_register (run_id, source_hash, eval_config_hash, change_id, kind, ts)"
            " VALUES (?,?,?,?,?,?)",
            (rid, source_hash, eval_config_hash, change_id, kind, _iso(_utcnow())),
        )
        self._conn.commit()
        return rid

    def suppress_duplicate(
        self,
        source_hash: str,
        eval_config_hash: str,
        *,
        change_id: str = "",
        kind: str = "",
    ) -> DuplicateCheck:
        """Atomically check-and-register: returns ``duplicate=True`` if the run already ran.

        On first sight the pair is registered and ``duplicate=False`` is returned, so callers
        can write ``if ledger.suppress_duplicate(...).duplicate: skip()``.
        """
        check = self.check_duplicate(source_hash, eval_config_hash)
        if check.duplicate:
            return check
        rid = self.register_run(source_hash, eval_config_hash, change_id=change_id, kind=kind)
        return DuplicateCheck(
            duplicate=False,
            source_hash=source_hash,
            eval_config_hash=eval_config_hash,
            prior_run_id=rid,
        )

    def forget_run(self, source_hash: str, eval_config_hash: str) -> bool:
        """Remove a run registration; returns True if one existed."""
        cur = self._conn.execute(
            "DELETE FROM run_register WHERE source_hash=? AND eval_config_hash=?",
            (source_hash, eval_config_hash),
        )
        self._conn.commit()
        return cur.rowcount > 0
