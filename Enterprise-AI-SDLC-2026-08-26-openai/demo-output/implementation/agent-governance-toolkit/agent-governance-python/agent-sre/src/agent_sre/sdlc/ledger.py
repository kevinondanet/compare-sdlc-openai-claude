# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Idempotent SQLite ledger for release evaluations."""

from __future__ import annotations

import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Generator

from agent_sre.sdlc.canonical import canonical_json_bytes
from agent_sre.sdlc.evaluator import parse_release_verdict

if TYPE_CHECKING:
    from agent_sre.sdlc.models import ReleaseVerdict


class EvaluationConflictError(RuntimeError):
    """Raised when one evidence digest is reused with a different policy."""


class EvaluationLedgerIntegrityError(RuntimeError):
    """Raised when a stored verdict fails schema or digest verification."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS release_evaluations (
    evaluation_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_digest TEXT NOT NULL,
    policy_digest   TEXT NOT NULL,
    verdict_digest  TEXT NOT NULL UNIQUE,
    evaluated_at    TEXT NOT NULL,
    verdict_json    TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_release_evidence
    ON release_evaluations(evidence_digest, evaluation_id);
CREATE INDEX IF NOT EXISTS idx_release_policy
    ON release_evaluations(policy_digest, evaluated_at);
"""


def _validated_db_path(value: str | Path) -> str:
    raw = str(value)
    if raw == ":memory:":
        return raw
    if "\x00" in raw or len(raw) > 4096:
        raise ValueError("invalid evaluation ledger path")
    if "://" in raw:
        raise ValueError("evaluation ledger must use a local filesystem path")
    resolved = Path(raw).expanduser().resolve()
    roots = (Path.cwd().resolve(), Path.home().resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(
        root.parent != root and (resolved == root or resolved.is_relative_to(root))
        for root in roots
    ):
        raise ValueError("evaluation ledger path is outside the current directory, home, or temp")
    if not resolved.parent.exists():
        raise ValueError("evaluation ledger parent directory does not exist")
    return str(resolved)


class SQLiteEvaluationLedger:
    """Durable, process-safe verdict store keyed by immutable evidence digest."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = _validated_db_path(db_path)
        self._memory = self._path == ":memory:"
        self._memory_connection: sqlite3.Connection | None = None
        self._memory_lock = threading.RLock()
        if self._memory:
            self._memory_connection = self._new_connection(self._path)
            self._memory_connection.executescript(_SCHEMA)
        else:
            with self._connect() as connection:
                connection.executescript(_SCHEMA)

    @staticmethod
    def _new_connection(path: str) -> sqlite3.Connection:
        connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        if path != ":memory:":
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        if self._memory:
            assert self._memory_connection is not None
            with self._memory_lock:
                try:
                    yield self._memory_connection
                    self._memory_connection.commit()
                except Exception:
                    self._memory_connection.rollback()
                    raise
            return
        connection = self._new_connection(self._path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get(self, evidence_digest: str) -> ReleaseVerdict | None:
        """Return and authenticate a stored verdict."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT policy_digest, verdict_digest, verdict_json "
                "FROM release_evaluations WHERE evidence_digest=? "
                "ORDER BY evaluation_id DESC LIMIT 1",
                (evidence_digest,),
            ).fetchone()
        if row is None:
            return None
        try:
            verdict = parse_release_verdict(row["verdict_json"])
        except (ValueError, TypeError) as exc:
            raise EvaluationLedgerIntegrityError("stored release verdict is invalid") from exc
        if verdict.evidence_digest != evidence_digest:
            raise EvaluationLedgerIntegrityError("stored verdict has the wrong evidence digest")
        if verdict.policy_digest != row["policy_digest"]:
            raise EvaluationLedgerIntegrityError(
                "stored verdict policy digest disagrees with its ledger index"
            )
        if verdict.verdict_digest != row["verdict_digest"]:
            raise EvaluationLedgerIntegrityError(
                "stored verdict digest disagrees with its ledger index"
            )
        return verdict

    def record(self, verdict: ReleaseVerdict) -> ReleaseVerdict:
        """Append a changed decision or return the equivalent latest evaluation."""

        encoded = canonical_json_bytes(verdict).decode("utf-8")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT policy_digest, verdict_json FROM release_evaluations "
                "WHERE evidence_digest=? ORDER BY evaluation_id DESC LIMIT 1",
                (verdict.evidence_digest,),
            ).fetchone()
            if row is not None:
                if row["policy_digest"] != verdict.policy_digest:
                    raise EvaluationConflictError(
                        "evidence digest has already been evaluated under a different policy"
                    )
                try:
                    existing = parse_release_verdict(row["verdict_json"])
                except (ValueError, TypeError) as exc:
                    raise EvaluationLedgerIntegrityError(
                        "stored release verdict is invalid"
                    ) from exc
                if existing.policy_digest != row["policy_digest"]:
                    raise EvaluationLedgerIntegrityError(
                        "stored verdict policy digest disagrees with its ledger index"
                    )
                # Evidence and policy are immutable. If the outcome and reason set
                # are unchanged, only the wall-clock evaluation instant differs, so
                # preserve the earlier canonical decision instead of writing noise.
                if (
                    existing.status is verdict.status
                    and existing.reason_codes == verdict.reason_codes
                ):
                    return existing
            connection.execute(
                "INSERT INTO release_evaluations "
                "(evidence_digest, policy_digest, verdict_digest, evaluated_at, verdict_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    verdict.evidence_digest,
                    verdict.policy_digest,
                    verdict.verdict_digest,
                    verdict.evaluated_at.isoformat(),
                    encoded,
                ),
            )
        return verdict

    def count(self) -> int:
        """Return the number of uniquely evaluated evidence documents."""

        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM release_evaluations").fetchone()
        assert row is not None
        return int(row["count"])

    def close(self) -> None:
        """Close the persistent in-memory connection, if any."""

        with self._memory_lock:
            if self._memory_connection is not None:
                self._memory_connection.close()
                self._memory_connection = None

    def __enter__(self) -> SQLiteEvaluationLedger:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
