# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Durable append-only AI usage ledger with budget reservations.

SQLite stores decimal amounts as canonical strings.  Every writer uses
``BEGIN IMMEDIATE`` and database uniqueness constraints, so idempotency holds across
threads and processes rather than only inside one Python object.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
from collections.abc import Iterable, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Literal

_SQLITE_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")

if TYPE_CHECKING:
    from agent_sre.sdlc.model_registry import (
        ModelIdentity,
        ModelPrice,
        PriceCatalog,
        TokenUsage,
    )


class LedgerError(RuntimeError):
    """Base error for durable ledger operations."""


class PathSafetyError(LedgerError):
    """Raised when a SQLite path is unsafe or outside its configured root."""


class IdempotencyConflictError(LedgerError):
    """Raised when an idempotency key is reused with a different payload."""


class BudgetConflictError(LedgerError):
    """Raised for conflicting or overlapping immutable budget definitions."""


class BudgetExceededError(LedgerError):
    """Raised when a reservation would exceed one or more applicable budgets."""

    def __init__(self, budget_ids: Iterable[str]) -> None:
        self.budget_ids = tuple(sorted(set(budget_ids)))
        super().__init__(f"reservation would exceed budgets: {', '.join(self.budget_ids)}")


class UnknownBudgetCostError(LedgerError):
    """Raised when an applicable budget contains usage whose cost is unknown."""


class ReservationNotFoundError(LedgerError):
    """Raised when reconciliation references an unknown reservation."""


def _nonempty(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LedgerError(f"{field_name} must be a non-empty string")
    return value.strip()


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LedgerError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _time_text(value: datetime) -> str:
    return _utc(value, field_name="datetime").isoformat(timespec="microseconds")


def _decimal(value: Decimal | str | int, *, field_name: str, nonnegative: bool = True) -> Decimal:
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise LedgerError(f"{field_name} must be a decimal") from exc
    if not parsed.is_finite() or (nonnegative and parsed < 0):
        qualifier = "finite and non-negative" if nonnegative else "finite"
        raise LedgerError(f"{field_name} must be {qualifier}")
    return parsed


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    return format(value.normalize(), "f")


def _payload_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def usage_event_set_digest(event_ids: Iterable[str]) -> str:
    """Hash the exact sorted set of usage event IDs without exposing those IDs."""

    normalized = tuple(sorted(_nonempty(event_id, field_name="event_id") for event_id in event_ids))
    if len(normalized) != len(set(normalized)):
        raise LedgerError("event_ids must be unique")
    return _payload_hash(
        {
            "event_ids": normalized,
            "schema": "agt.usage-ledger/event-set/v1",
        }
    )


@dataclass(frozen=True, slots=True)
class UsageAttribution:
    """Required organizational and change attribution for each usage event."""

    organization_id: str
    team_id: str
    application_id: str
    user_id: str
    environment: str
    repository: str
    change_id: str
    task_id: str

    def __post_init__(self) -> None:
        for name in (
            "organization_id",
            "team_id",
            "application_id",
            "user_id",
            "environment",
            "repository",
            "change_id",
            "task_id",
        ):
            object.__setattr__(self, name, _nonempty(getattr(self, name), field_name=name))

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in _ATTRIBUTION_COLUMNS}


@dataclass(frozen=True, slots=True)
class PromptIdentity:
    """Immutable prompt name, version, and content digest attribution."""

    prompt_id: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        for name in ("prompt_id", "version", "digest"):
            object.__setattr__(self, name, _nonempty(getattr(self, name), field_name=name))


UsageOutcome = Literal["accepted", "rejected", "failed", "unknown"]


@dataclass(frozen=True, slots=True)
class UsageEvent:
    """Immutable usage facts supplied to the ledger for pricing and persistence."""

    event_id: str
    occurred_at: datetime
    attribution: UsageAttribution
    model: ModelIdentity
    prompt: PromptIdentity
    usage: TokenUsage
    latency_ms: int = 0
    tool_calls: int = 0
    turns: int = 1
    outcome: UsageOutcome = "unknown"
    metadata: Mapping[str, str] | tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        from agent_sre.sdlc.model_registry import ModelIdentity, TokenUsage

        object.__setattr__(self, "event_id", _nonempty(self.event_id, field_name="event_id"))
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at, field_name="occurred_at"))
        if not isinstance(self.attribution, UsageAttribution):
            raise LedgerError("attribution must be a UsageAttribution")
        if not isinstance(self.model, ModelIdentity):
            raise LedgerError("model must be a ModelIdentity")
        if not isinstance(self.prompt, PromptIdentity):
            raise LedgerError("prompt must be a PromptIdentity")
        if not isinstance(self.usage, TokenUsage):
            raise LedgerError("usage must be a TokenUsage")
        for name in ("latency_ms", "tool_calls", "turns"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LedgerError(f"{name} must be a non-negative integer")
        if self.outcome not in {"accepted", "rejected", "failed", "unknown"}:
            raise LedgerError("outcome must be accepted, rejected, failed, or unknown")
        raw_items = self.metadata.items() if isinstance(self.metadata, Mapping) else self.metadata
        normalized: list[tuple[str, str]] = []
        for key, value in raw_items:
            normalized.append((_nonempty(key, field_name="metadata key"), str(value)))
        if len({key for key, _ in normalized}) != len(normalized):
            raise LedgerError("metadata keys must be unique")
        object.__setattr__(self, "metadata", tuple(sorted(normalized)))

    @property
    def metadata_dict(self) -> dict[str, str]:
        return dict(self.metadata)

    def canonical_payload(
        self, *, cost: Decimal | None, price: ModelPrice | None
    ) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "occurred_at": _time_text(self.occurred_at),
            "attribution": self.attribution.to_dict(),
            "model": {
                "provider": self.model.provider,
                "provider_family": self.model.provider_family,
                "model": self.model.model,
                "version": self.model.version,
                "deployment": self.model.deployment,
            },
            "prompt": {
                "prompt_id": self.prompt.prompt_id,
                "version": self.prompt.version,
                "digest": self.prompt.digest,
            },
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "cached_input_tokens": self.usage.cached_input_tokens,
                "reasoning_tokens": self.usage.reasoning_tokens,
            },
            "latency_ms": self.latency_ms,
            "tool_calls": self.tool_calls,
            "turns": self.turns,
            "outcome": self.outcome,
            "metadata": self.metadata_dict,
            "cost_usd": _decimal_text(cost) if cost is not None else None,
            "price_effective_from": _time_text(price.effective_from) if price else None,
        }


class BudgetScope(str, Enum):
    ORGANIZATION = "organization"
    TEAM = "team"
    APPLICATION = "application"
    USER = "user"
    ENVIRONMENT = "environment"
    REPOSITORY = "repository"
    CHANGE = "change"
    TASK = "task"


_ATTRIBUTION_COLUMNS: tuple[str, ...] = (
    "organization_id",
    "team_id",
    "application_id",
    "user_id",
    "environment",
    "repository",
    "change_id",
    "task_id",
)

_SCOPE_COLUMN: dict[BudgetScope, str] = {
    BudgetScope.ORGANIZATION: "organization_id",
    BudgetScope.TEAM: "team_id",
    BudgetScope.APPLICATION: "application_id",
    BudgetScope.USER: "user_id",
    BudgetScope.ENVIRONMENT: "environment",
    BudgetScope.REPOSITORY: "repository",
    BudgetScope.CHANGE: "change_id",
    BudgetScope.TASK: "task_id",
}


@dataclass(frozen=True, slots=True)
class BudgetDefinition:
    """Immutable budget for one explicit scope and time window."""

    budget_id: str
    scope: BudgetScope
    scope_value: str
    period_start: datetime
    period_end: datetime
    limit_usd: Decimal

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget_id", _nonempty(self.budget_id, field_name="budget_id"))
        if not isinstance(self.scope, BudgetScope):
            raise LedgerError("scope must be a BudgetScope")
        object.__setattr__(
            self, "scope_value", _nonempty(self.scope_value, field_name="scope_value")
        )
        object.__setattr__(self, "period_start", _utc(self.period_start, field_name="period_start"))
        object.__setattr__(self, "period_end", _utc(self.period_end, field_name="period_end"))
        if self.period_end <= self.period_start:
            raise LedgerError("period_end must be after period_start")
        object.__setattr__(self, "limit_usd", _decimal(self.limit_usd, field_name="limit_usd"))

    @property
    def payload_hash(self) -> str:
        return _payload_hash(
            {
                "budget_id": self.budget_id,
                "scope": self.scope.value,
                "scope_value": self.scope_value,
                "period_start": _time_text(self.period_start),
                "period_end": _time_text(self.period_end),
                "limit_usd": _decimal_text(self.limit_usd),
            }
        )


@dataclass(frozen=True, slots=True)
class ReservationRequest:
    """A pre-execution cost reservation checked against every matching budget."""

    reservation_id: str
    attribution: UsageAttribution
    amount_usd: Decimal
    reserved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "reservation_id", _nonempty(self.reservation_id, field_name="reservation_id")
        )
        if not isinstance(self.attribution, UsageAttribution):
            raise LedgerError("attribution must be a UsageAttribution")
        object.__setattr__(self, "amount_usd", _decimal(self.amount_usd, field_name="amount_usd"))
        object.__setattr__(self, "reserved_at", _utc(self.reserved_at, field_name="reserved_at"))
        object.__setattr__(self, "expires_at", _utc(self.expires_at, field_name="expires_at"))
        if self.expires_at <= self.reserved_at:
            raise LedgerError("expires_at must be after reserved_at")

    @property
    def payload_hash(self) -> str:
        return _payload_hash(
            {
                "reservation_id": self.reservation_id,
                "attribution": self.attribution.to_dict(),
                "amount_usd": _decimal_text(self.amount_usd),
                "reserved_at": _time_text(self.reserved_at),
                "expires_at": _time_text(self.expires_at),
            }
        )


@dataclass(frozen=True, slots=True)
class StoredUsage:
    row_id: int
    event_id: str
    payload_hash: str
    cost_usd: Decimal | None
    price_effective_from: datetime | None


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    reservation_id: str
    usage: StoredUsage
    reserved_usd: Decimal
    actual_usd: Decimal
    variance_usd: Decimal
    breached_budget_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UsageRollup:
    group: tuple[tuple[str, str], ...]
    event_count: int
    distinct_tasks: int
    accepted_tasks: int
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    reasoning_tokens: int
    tool_calls: int
    turns: int
    known_cost_usd: Decimal
    unpriced_events: int
    average_latency_ms: Decimal | None
    p95_latency_ms: int | None
    cache_hit_rate: Decimal | None
    cost_per_task_usd: Decimal | None
    cost_per_accepted_task_usd: Decimal | None
    event_set_digest: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_events (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    application_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    repository TEXT NOT NULL,
    change_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_family TEXT NOT NULL,
    model TEXT NOT NULL,
    model_version TEXT NOT NULL,
    deployment TEXT NOT NULL,
    prompt_id TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    prompt_digest TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL,
    reasoning_tokens INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    tool_calls INTEGER NOT NULL,
    turns INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    cost_usd TEXT,
    price_effective_from TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_definitions (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    budget_id TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    scope TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    limit_usd TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_reservations (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    application_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    repository TEXT NOT NULL,
    change_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    amount_usd TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_reconciliations (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    reconciliation_id TEXT NOT NULL UNIQUE,
    reservation_id TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    usage_event_id TEXT NOT NULL,
    actual_cost_usd TEXT NOT NULL,
    variance_usd TEXT NOT NULL,
    reconciled_at TEXT NOT NULL,
    breached_budget_ids_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY(reservation_id) REFERENCES budget_reservations(reservation_id),
    FOREIGN KEY(usage_event_id) REFERENCES usage_events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_usage_time ON usage_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_usage_org ON usage_events(organization_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_usage_team ON usage_events(team_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_usage_app ON usage_events(application_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_reservation_time ON budget_reservations(reserved_at, expires_at);

CREATE TRIGGER IF NOT EXISTS usage_events_no_update
BEFORE UPDATE ON usage_events BEGIN SELECT RAISE(ABORT, 'usage_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS usage_events_no_delete
BEFORE DELETE ON usage_events BEGIN SELECT RAISE(ABORT, 'usage_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS budget_definitions_no_update
BEFORE UPDATE ON budget_definitions BEGIN SELECT RAISE(ABORT, 'budget_definitions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS budget_definitions_no_delete
BEFORE DELETE ON budget_definitions BEGIN SELECT RAISE(ABORT, 'budget_definitions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS budget_reservations_no_update
BEFORE UPDATE ON budget_reservations BEGIN SELECT RAISE(ABORT, 'budget_reservations is append-only'); END;
CREATE TRIGGER IF NOT EXISTS budget_reservations_no_delete
BEFORE DELETE ON budget_reservations BEGIN SELECT RAISE(ABORT, 'budget_reservations is append-only'); END;
CREATE TRIGGER IF NOT EXISTS budget_reconciliations_no_update
BEFORE UPDATE ON budget_reconciliations BEGIN SELECT RAISE(ABORT, 'budget_reconciliations is append-only'); END;
CREATE TRIGGER IF NOT EXISTS budget_reconciliations_no_delete
BEFORE DELETE ON budget_reconciliations BEGIN SELECT RAISE(ABORT, 'budget_reconciliations is append-only'); END;
"""


class UsageLedger:
    """SQLite-backed append-only usage and budget ledger."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        allowed_root: str | os.PathLike[str] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise LedgerError("timeout_seconds must be finite and positive")
        self._root, self._path = self._safe_database_path(
            database_path,
            allowed_root=allowed_root,
        )
        root_stat = self._root.stat(follow_symlinks=False)
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._parent_identities = self._capture_parent_identities(self._root, self._path)
        database_identity = self._assert_database_file_types(
            self._path,
            require_database=True,
        )
        assert database_identity is not None
        self._database_identity = database_identity
        self._timeout_seconds = float(timeout_seconds)
        self._initialize()
        self._assert_current_path_safety()

    @staticmethod
    def _relative_to_canonical_root(candidate: Path, root: Path) -> Path:
        for ancestor in (candidate, *candidate.parents):
            try:
                if ancestor.resolve(strict=False) == root:
                    return candidate.relative_to(ancestor)
            except (OSError, RuntimeError, ValueError) as exc:
                raise PathSafetyError("database_path cannot be safely resolved") from exc
        raise PathSafetyError("database_path escapes allowed_root")

    @staticmethod
    def _assert_path_component_types(root: Path, relative: Path) -> None:
        cursor = root
        for index, part in enumerate(relative.parts):
            cursor /= part
            try:
                mode = cursor.lstat().st_mode
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise PathSafetyError("database_path cannot be safely inspected") from exc
            if stat.S_ISLNK(mode):
                raise PathSafetyError("database_path must not traverse a symbolic link")
            is_database = index == len(relative.parts) - 1
            if is_database and not stat.S_ISREG(mode):
                raise PathSafetyError("database_path must identify a regular file")
            if not is_database and not stat.S_ISDIR(mode):
                raise PathSafetyError("database_path parent must be a directory")

    @staticmethod
    def _database_paths(database: Path) -> tuple[Path, ...]:
        return (database, *(Path(f"{database}{suffix}") for suffix in _SQLITE_COMPANION_SUFFIXES))

    @staticmethod
    def _assert_database_file_types(
        database: Path,
        *,
        require_database: bool,
    ) -> tuple[int, int] | None:
        database_identity: tuple[int, int] | None = None
        for path in UsageLedger._database_paths(database):
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                if path == database and require_database:
                    raise PathSafetyError(
                        "database file changed after ledger construction"
                    ) from None
                continue
            except OSError as exc:
                raise PathSafetyError("database files cannot be safely inspected") from exc
            if not stat.S_ISREG(path_stat.st_mode):
                raise PathSafetyError("database files must be regular files, not links")
            if path == database:
                database_identity = (path_stat.st_dev, path_stat.st_ino)
        return database_identity

    @staticmethod
    def _create_database_file(database: Path) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(database, flags, 0o600)
        except FileExistsError:
            return
        except OSError as exc:
            raise PathSafetyError("database file cannot be safely created") from exc
        os.close(descriptor)

    @staticmethod
    def _capture_parent_identities(
        root: Path,
        database: Path,
    ) -> tuple[tuple[Path, tuple[int, int]], ...]:
        try:
            relative_parent = database.parent.relative_to(root)
        except ValueError as exc:  # pragma: no cover - safe path construction establishes this
            raise PathSafetyError("database_path escapes allowed_root") from exc
        identities: list[tuple[Path, tuple[int, int]]] = []
        cursor = root
        for part in relative_parent.parts:
            cursor /= part
            try:
                directory_stat = cursor.lstat()
            except OSError as exc:
                raise PathSafetyError("database parent cannot be safely inspected") from exc
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise PathSafetyError("database_path parent must be a directory")
            identities.append((cursor, (directory_stat.st_dev, directory_stat.st_ino)))
        return tuple(identities)

    @staticmethod
    def _safe_database_path(
        database_path: str | os.PathLike[str],
        *,
        allowed_root: str | os.PathLike[str] | None,
    ) -> tuple[Path, Path]:
        raw = os.fspath(database_path)
        if not raw or "\x00" in raw or raw == ":memory:" or raw.startswith("file:"):
            raise PathSafetyError("database_path must be a filesystem path, not a SQLite URI")
        supplied = Path(raw).expanduser()
        if allowed_root is None:
            candidate = Path(os.path.abspath(supplied))
            root_candidate = candidate.parent
            while not root_candidate.exists() and root_candidate != root_candidate.parent:
                root_candidate = root_candidate.parent
        else:
            raw_root = os.fspath(allowed_root)
            if not raw_root or "\x00" in raw_root:
                raise PathSafetyError("allowed_root must be a filesystem directory")
            root_candidate = Path(os.path.abspath(Path(raw_root).expanduser()))
            candidate = supplied if supplied.is_absolute() else root_candidate / supplied
            candidate = Path(os.path.abspath(candidate))
        if root_candidate.is_symlink():
            raise PathSafetyError("allowed_root must not be a symbolic link")
        try:
            root = root_candidate.resolve(strict=True)
        except OSError as exc:
            raise PathSafetyError("allowed_root must already exist") from exc
        if not root.is_dir():
            raise PathSafetyError("allowed_root must be a directory")
        relative = UsageLedger._relative_to_canonical_root(candidate, root)
        if not relative.parts:
            raise PathSafetyError("database_path must identify a regular file")
        database = root.joinpath(*relative.parts)
        UsageLedger._assert_path_component_types(root, relative)
        try:
            database.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PathSafetyError("database parent cannot be safely created") from exc
        UsageLedger._assert_path_component_types(root, relative)
        UsageLedger._assert_database_file_types(database, require_database=False)
        UsageLedger._create_database_file(database)
        UsageLedger._assert_database_file_types(database, require_database=True)
        return root, database

    def _assert_current_path_safety(self) -> tuple[int, int]:
        if self._root.is_symlink() or not self._root.is_dir():
            raise PathSafetyError("allowed_root changed after ledger construction")
        try:
            root_stat = self._root.stat(follow_symlinks=False)
        except OSError as exc:
            raise PathSafetyError("allowed_root changed after ledger construction") from exc
        if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
            raise PathSafetyError("allowed_root changed after ledger construction")
        try:
            relative = self._path.relative_to(self._root)
        except ValueError as exc:  # pragma: no cover - constructor establishes this invariant
            raise PathSafetyError("database_path escapes allowed_root") from exc
        self._assert_path_component_types(self._root, relative)
        for directory, expected_identity in self._parent_identities:
            try:
                directory_stat = directory.lstat()
            except OSError as exc:
                raise PathSafetyError("database parent changed after ledger construction") from exc
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or (directory_stat.st_dev, directory_stat.st_ino) != expected_identity
            ):
                raise PathSafetyError("database parent changed after ledger construction")
        identity = self._assert_database_file_types(self._path, require_database=True)
        assert identity is not None
        if identity != self._database_identity:
            raise PathSafetyError("database file changed after ledger construction")
        return identity

    def _connect(self) -> sqlite3.Connection:
        identity_before = self._assert_current_path_safety()
        connection = sqlite3.connect(
            str(self._path),
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        try:
            identity_after = self._assert_current_path_safety()
            if identity_after != identity_before:
                raise PathSafetyError("database file changed while opening the ledger")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
        except BaseException:
            connection.close()
            raise
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(_SCHEMA)
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(budget_reconciliations)"
                ).fetchall()
            }
            if "breached_budget_ids_json" not in columns:
                connection.execute(
                    "ALTER TABLE budget_reconciliations "
                    "ADD COLUMN breached_budget_ids_json TEXT NOT NULL DEFAULT '[]'"
                )
        finally:
            connection.close()
        with suppress(OSError):
            self._path.chmod(0o600)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _stored_usage(row: sqlite3.Row) -> StoredUsage:
        price_at = (
            datetime.fromisoformat(row["price_effective_from"])
            if row["price_effective_from"]
            else None
        )
        return StoredUsage(
            row_id=int(row["row_id"]),
            event_id=str(row["event_id"]),
            payload_hash=str(row["payload_hash"]),
            cost_usd=Decimal(row["cost_usd"]) if row["cost_usd"] is not None else None,
            price_effective_from=price_at,
        )

    def append_usage(
        self,
        event: UsageEvent,
        *,
        prices: PriceCatalog,
        require_cost: bool = True,
    ) -> StoredUsage:
        """Price and append one event idempotently."""

        cost, price = prices.calculate(
            event.model,
            usage=event.usage,
            at=event.occurred_at,
            required=require_cost,
        )
        with self._transaction() as connection:
            return self._append_usage_in_transaction(
                connection, event=event, cost=cost, price=price
            )

    def _append_usage_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        event: UsageEvent,
        cost: Decimal | None,
        price: ModelPrice | None,
    ) -> StoredUsage:
        payload_hash = _payload_hash(event.canonical_payload(cost=cost, price=price))
        existing = connection.execute(
            "SELECT row_id, event_id, payload_hash, cost_usd, price_effective_from "
            "FROM usage_events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        if existing is not None:
            if existing["payload_hash"] != payload_hash:
                raise IdempotencyConflictError(
                    f"event id {event.event_id!r} was reused with different facts"
                )
            return self._stored_usage(existing)

        attrs = event.attribution.to_dict()
        cursor = connection.execute(
            """
            INSERT INTO usage_events (
                event_id, payload_hash, occurred_at,
                organization_id, team_id, application_id, user_id, environment,
                repository, change_id, task_id,
                provider, provider_family, model, model_version, deployment,
                prompt_id, prompt_version, prompt_digest,
                input_tokens, output_tokens, cached_input_tokens, reasoning_tokens,
                latency_ms, tool_calls, turns, outcome, metadata_json,
                cost_usd, price_effective_from, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                payload_hash,
                _time_text(event.occurred_at),
                *(attrs[name] for name in _ATTRIBUTION_COLUMNS),
                event.model.provider,
                event.model.provider_family,
                event.model.model,
                event.model.version,
                event.model.deployment,
                event.prompt.prompt_id,
                event.prompt.version,
                event.prompt.digest,
                event.usage.input_tokens,
                event.usage.output_tokens,
                event.usage.cached_input_tokens,
                event.usage.reasoning_tokens,
                event.latency_ms,
                event.tool_calls,
                event.turns,
                event.outcome,
                json.dumps(event.metadata_dict, sort_keys=True, separators=(",", ":")),
                _decimal_text(cost) if cost is not None else None,
                _time_text(price.effective_from) if price else None,
                _time_text(datetime.now(UTC)),
            ),
        )
        row_id = cursor.lastrowid
        if row_id is None:
            raise LedgerError("SQLite did not return a row id for appended usage")
        return StoredUsage(
            row_id=int(row_id),
            event_id=event.event_id,
            payload_hash=payload_hash,
            cost_usd=cost,
            price_effective_from=price.effective_from if price else None,
        )

    def add_budget(self, budget: BudgetDefinition) -> BudgetDefinition:
        """Append one non-overlapping budget definition idempotently."""

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT payload_hash FROM budget_definitions WHERE budget_id = ?",
                (budget.budget_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != budget.payload_hash:
                    raise BudgetConflictError(
                        f"budget id {budget.budget_id!r} was reused with different facts"
                    )
                return budget
            overlap = connection.execute(
                """
                SELECT budget_id FROM budget_definitions
                WHERE scope = ? AND scope_value = ? AND period_start < ? AND ? < period_end
                LIMIT 1
                """,
                (
                    budget.scope.value,
                    budget.scope_value,
                    _time_text(budget.period_end),
                    _time_text(budget.period_start),
                ),
            ).fetchone()
            if overlap is not None:
                raise BudgetConflictError(
                    f"budget overlaps {overlap['budget_id']!r} for the same scope"
                )
            connection.execute(
                """
                INSERT INTO budget_definitions (
                    budget_id, payload_hash, scope, scope_value, period_start,
                    period_end, limit_usd, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    budget.budget_id,
                    budget.payload_hash,
                    budget.scope.value,
                    budget.scope_value,
                    _time_text(budget.period_start),
                    _time_text(budget.period_end),
                    _decimal_text(budget.limit_usd),
                    _time_text(datetime.now(UTC)),
                ),
            )
        return budget

    @staticmethod
    def _matching_budgets(
        connection: sqlite3.Connection,
        *,
        attribution: UsageAttribution,
        at: datetime,
    ) -> list[sqlite3.Row]:
        rows = connection.execute(
            """
            SELECT budget_id, scope, scope_value, period_start, period_end, limit_usd
            FROM budget_definitions WHERE period_start <= ? AND ? < period_end
            """,
            (_time_text(at), _time_text(at)),
        ).fetchall()
        attrs = attribution.to_dict()
        return [
            row
            for row in rows
            if attrs[_SCOPE_COLUMN[BudgetScope(row["scope"])]] == row["scope_value"]
        ]

    @staticmethod
    def _actual_spend(connection: sqlite3.Connection, *, budget: sqlite3.Row) -> Decimal:
        column = _SCOPE_COLUMN[BudgetScope(budget["scope"])]
        rows = connection.execute(
            f"SELECT cost_usd FROM usage_events WHERE {column} = ? "
            "AND occurred_at >= ? AND occurred_at < ?",
            (budget["scope_value"], budget["period_start"], budget["period_end"]),
        ).fetchall()
        if any(row["cost_usd"] is None for row in rows):
            raise UnknownBudgetCostError(
                f"budget {budget['budget_id']!r} contains usage with unknown cost"
            )
        return sum((Decimal(row["cost_usd"]) for row in rows), Decimal("0"))

    @staticmethod
    def _outstanding_reservations(
        connection: sqlite3.Connection,
        *,
        budget: sqlite3.Row,
        as_of: datetime,
        exclude_reservation_id: str | None = None,
    ) -> Decimal:
        column = _SCOPE_COLUMN[BudgetScope(budget["scope"])]
        exclusion = " AND r.reservation_id <> ?" if exclude_reservation_id is not None else ""
        parameters: list[str] = [
            str(budget["scope_value"]),
            str(budget["period_start"]),
            str(budget["period_end"]),
            _time_text(as_of),
        ]
        if exclude_reservation_id is not None:
            parameters.append(exclude_reservation_id)
        rows = connection.execute(
            f"""
            SELECT r.amount_usd FROM budget_reservations r
            WHERE r.{column} = ?
              AND r.reserved_at >= ? AND r.reserved_at < ?
              AND r.expires_at > ?
              AND NOT EXISTS (
                  SELECT 1 FROM budget_reconciliations x
                  WHERE x.reservation_id = r.reservation_id
              )
              {exclusion}
            """,
            parameters,
        ).fetchall()
        return sum((Decimal(row["amount_usd"]) for row in rows), Decimal("0"))

    @staticmethod
    def _stored_breached_budget_ids(row: sqlite3.Row) -> tuple[str, ...]:
        encoded = row["breached_budget_ids_json"]
        if not isinstance(encoded, str):
            raise LedgerError("stored reconciliation breached-budget facts are invalid")
        try:
            value = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise LedgerError("stored reconciliation breached-budget facts are invalid") from exc
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) or not item for item in value)
            or value != sorted(set(value))
            or encoded != json.dumps(value, separators=(",", ":"), ensure_ascii=True)
        ):
            raise LedgerError("stored reconciliation breached-budget facts are not canonical")
        return tuple(value)

    def reserve(self, request: ReservationRequest) -> ReservationRequest:
        """Atomically reserve forecast cost against every applicable budget."""

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT payload_hash FROM budget_reservations WHERE reservation_id = ?",
                (request.reservation_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != request.payload_hash:
                    raise IdempotencyConflictError(
                        f"reservation id {request.reservation_id!r} was reused with different facts"
                    )
                return request

            exceeded: list[str] = []
            for budget in self._matching_budgets(
                connection,
                attribution=request.attribution,
                at=request.reserved_at,
            ):
                projected = (
                    self._actual_spend(connection, budget=budget)
                    + self._outstanding_reservations(
                        connection,
                        budget=budget,
                        as_of=request.reserved_at,
                    )
                    + request.amount_usd
                )
                if projected > Decimal(budget["limit_usd"]):
                    exceeded.append(str(budget["budget_id"]))
            if exceeded:
                raise BudgetExceededError(exceeded)

            attrs = request.attribution.to_dict()
            connection.execute(
                """
                INSERT INTO budget_reservations (
                    reservation_id, payload_hash,
                    organization_id, team_id, application_id, user_id, environment,
                    repository, change_id, task_id,
                    amount_usd, reserved_at, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.reservation_id,
                    request.payload_hash,
                    *(attrs[name] for name in _ATTRIBUTION_COLUMNS),
                    _decimal_text(request.amount_usd),
                    _time_text(request.reserved_at),
                    _time_text(request.expires_at),
                    _time_text(datetime.now(UTC)),
                ),
            )
        return request

    def reconcile(
        self,
        reservation_id: str,
        event: UsageEvent,
        *,
        prices: PriceCatalog,
        reconciliation_id: str | None = None,
        reconciled_at: datetime | None = None,
    ) -> ReconciliationResult:
        """Consume a reservation and atomically append its actual priced usage.

        Actual spend is never dropped merely because it exceeds a forecast.  Any budgets
        breached by actual cost are returned and will block subsequent reservations.
        """

        reservation_key = _nonempty(reservation_id, field_name="reservation_id")
        reconciliation_key = _nonempty(
            reconciliation_id or f"reconcile:{reservation_key}",
            field_name="reconciliation_id",
        )
        reconciled = _utc(reconciled_at or event.occurred_at, field_name="reconciled_at")
        if reconciled < event.occurred_at:
            raise LedgerError("reconciled_at must not precede the usage event")
        cost, price = prices.calculate(
            event.model,
            usage=event.usage,
            at=event.occurred_at,
            required=True,
        )
        assert cost is not None

        with self._transaction() as connection:
            reservation = connection.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id = ?",
                (reservation_key,),
            ).fetchone()
            if reservation is None:
                raise ReservationNotFoundError(f"unknown reservation {reservation_key!r}")
            reserved_at = datetime.fromisoformat(reservation["reserved_at"])
            expires_at = datetime.fromisoformat(reservation["expires_at"])
            if not reserved_at <= event.occurred_at < expires_at:
                raise LedgerError("usage event must occur within the reservation window")
            for column in _ATTRIBUTION_COLUMNS:
                if reservation[column] != getattr(event.attribution, column):
                    raise IdempotencyConflictError(
                        f"usage attribution {column} does not match reservation"
                    )

            stored = self._append_usage_in_transaction(
                connection,
                event=event,
                cost=cost,
                price=price,
            )
            reserved = Decimal(reservation["amount_usd"])
            variance = cost - reserved
            reconciliation_hash = _payload_hash(
                {
                    "reconciliation_id": reconciliation_key,
                    "reservation_id": reservation_key,
                    "usage_event_id": event.event_id,
                    "usage_payload_hash": stored.payload_hash,
                    "actual_cost_usd": _decimal_text(cost),
                    "variance_usd": _decimal_text(variance),
                    "reconciled_at": _time_text(reconciled),
                }
            )
            prior = connection.execute(
                "SELECT * FROM budget_reconciliations WHERE reservation_id = ? OR reconciliation_id = ?",
                (reservation_key, reconciliation_key),
            ).fetchone()
            if prior is not None:
                if prior["payload_hash"] != reconciliation_hash:
                    raise IdempotencyConflictError(
                        f"reservation {reservation_key!r} was reconciled with different facts"
                    )
                breached = self._stored_breached_budget_ids(prior)
            else:
                computed_breaches: list[str] = []
                for budget in self._matching_budgets(
                    connection,
                    attribution=event.attribution,
                    at=event.occurred_at,
                ):
                    committed = self._actual_spend(connection, budget=budget)
                    outstanding = self._outstanding_reservations(
                        connection,
                        budget=budget,
                        as_of=reconciled,
                        exclude_reservation_id=reservation_key,
                    )
                    if committed + outstanding > Decimal(budget["limit_usd"]):
                        computed_breaches.append(str(budget["budget_id"]))
                breached = tuple(sorted(set(computed_breaches)))
                breached_json = json.dumps(breached, separators=(",", ":"), ensure_ascii=True)
                connection.execute(
                    """
                    INSERT INTO budget_reconciliations (
                        reconciliation_id, reservation_id, payload_hash, usage_event_id,
                        actual_cost_usd, variance_usd, reconciled_at,
                        breached_budget_ids_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reconciliation_key,
                        reservation_key,
                        reconciliation_hash,
                        event.event_id,
                        _decimal_text(cost),
                        _decimal_text(variance),
                        _time_text(reconciled),
                        breached_json,
                        _time_text(datetime.now(UTC)),
                    ),
                )

        return ReconciliationResult(
            reservation_id=reservation_key,
            usage=stored,
            reserved_usd=reserved,
            actual_usd=cost,
            variance_usd=variance,
            breached_budget_ids=breached,
        )

    def rollup(
        self,
        *,
        start: datetime,
        end: datetime,
        group_by: tuple[str, ...] = (),
        filters: Mapping[str, str] | None = None,
    ) -> tuple[UsageRollup, ...]:
        """Return exact usage and cost KPIs for an interval."""

        start_utc = _utc(start, field_name="start")
        end_utc = _utc(end, field_name="end")
        if end_utc <= start_utc:
            raise LedgerError("end must be after start")
        allowed_grouping = set(_ATTRIBUTION_COLUMNS) | {
            "provider",
            "provider_family",
            "model",
            "model_version",
            "deployment",
            "prompt_id",
            "prompt_version",
            "outcome",
        }
        if any(column not in allowed_grouping for column in group_by):
            raise LedgerError("group_by contains an unsupported column")
        supplied_filters = dict(filters or {})
        if any(column not in allowed_grouping for column in supplied_filters):
            raise LedgerError("filters contains an unsupported column")

        where = ["occurred_at >= ?", "occurred_at < ?"]
        parameters: list[str] = [_time_text(start_utc), _time_text(end_utc)]
        for column, value in sorted(supplied_filters.items()):
            where.append(f"{column} = ?")
            parameters.append(value)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM usage_events WHERE " + " AND ".join(where),
                parameters,
            ).fetchall()
        finally:
            connection.close()

        grouped: dict[tuple[str, ...], list[sqlite3.Row]] = {}
        for row in rows:
            key = tuple(str(row[column]) for column in group_by)
            grouped.setdefault(key, []).append(row)

        rollups: list[UsageRollup] = []
        for key, members in grouped.items():
            event_ids = tuple(str(row["event_id"]) for row in members)
            tasks = {str(row["task_id"]) for row in members}
            accepted = {str(row["task_id"]) for row in members if row["outcome"] == "accepted"}
            known_cost = sum(
                (Decimal(row["cost_usd"]) for row in members if row["cost_usd"] is not None),
                Decimal("0"),
            )
            unpriced = sum(1 for row in members if row["cost_usd"] is None)
            latencies = sorted(int(row["latency_ms"]) for row in members)
            input_tokens = sum(int(row["input_tokens"]) for row in members)
            cached_tokens = sum(int(row["cached_input_tokens"]) for row in members)
            cache_denominator = input_tokens + cached_tokens
            cost_per_task = None if unpriced or not tasks else known_cost / Decimal(len(tasks))
            cost_per_accepted = (
                None if unpriced or not accepted else known_cost / Decimal(len(accepted))
            )
            rollups.append(
                UsageRollup(
                    group=tuple(zip(group_by, key, strict=True)),
                    event_count=len(members),
                    distinct_tasks=len(tasks),
                    accepted_tasks=len(accepted),
                    input_tokens=input_tokens,
                    output_tokens=sum(int(row["output_tokens"]) for row in members),
                    cached_input_tokens=cached_tokens,
                    reasoning_tokens=sum(int(row["reasoning_tokens"]) for row in members),
                    tool_calls=sum(int(row["tool_calls"]) for row in members),
                    turns=sum(int(row["turns"]) for row in members),
                    known_cost_usd=known_cost,
                    unpriced_events=unpriced,
                    average_latency_ms=(
                        Decimal(sum(latencies)) / Decimal(len(latencies)) if latencies else None
                    ),
                    p95_latency_ms=(
                        latencies[max(0, math.ceil(Decimal("0.95") * len(latencies)) - 1)]
                        if latencies
                        else None
                    ),
                    cache_hit_rate=(
                        Decimal(cached_tokens) / Decimal(cache_denominator)
                        if cache_denominator
                        else None
                    ),
                    cost_per_task_usd=cost_per_task,
                    cost_per_accepted_task_usd=cost_per_accepted,
                    event_set_digest=usage_event_set_digest(event_ids),
                )
            )
        return tuple(sorted(rollups, key=lambda item: item.group))


__all__ = [
    "BudgetConflictError",
    "BudgetDefinition",
    "BudgetExceededError",
    "BudgetScope",
    "IdempotencyConflictError",
    "LedgerError",
    "PathSafetyError",
    "PromptIdentity",
    "ReconciliationResult",
    "ReservationNotFoundError",
    "ReservationRequest",
    "StoredUsage",
    "UnknownBudgetCostError",
    "UsageAttribution",
    "UsageEvent",
    "UsageLedger",
    "UsageRollup",
    "usage_event_set_digest",
]
