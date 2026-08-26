"""In-memory ticket service: create, read, list, update, delete — with priorities.

``CHG-add-ticket-priority`` adds the ``priority`` field: a closed set of values with an
explicit rank (ADR-0001), a default of ``normal`` and a ``sort="priority"`` listing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

PRIORITIES: tuple[str, ...] = ("low", "normal", "high", "urgent")
"""Allowed priorities, lowest first."""

DEFAULT_PRIORITY = "normal"
STATUSES: tuple[str, ...] = ("open", "in_progress", "closed")

_RANK = {name: index for index, name in enumerate(PRIORITIES)}
_SORTS = ("created", "priority")
Rows = list[dict[str, Any]]


def validate_priority(value: object) -> str:
    """Normalise *value* to one of :data:`PRIORITIES`.

    Raises ``TypeError`` for non-strings and ``ValueError`` for unknown values.
    """
    if not isinstance(value, str):
        raise TypeError(f"priority must be a string, got {type(value).__name__}")
    text = value.strip().lower()
    if text not in _RANK:
        raise ValueError(f"priority must be one of {', '.join(PRIORITIES)}; got {value!r}")
    return text


def validate_status(value: object) -> str:
    """Normalise *value* to one of :data:`STATUSES` or raise ``ValueError``."""
    if not isinstance(value, str) or value.strip().lower() not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}; got {value!r}")
    return value.strip().lower()


@dataclass(frozen=True)
class Ticket:
    """A support ticket."""

    id: int
    title: str
    status: str
    priority: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict form used by the CLI store and the JSON contract."""
        return asdict(self)


Tickets = list[Ticket]


class TicketService:
    """CRUD over an in-memory table of :class:`Ticket` records."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._tickets: dict[int, Ticket] = {}
        self._next_id = 1

    # ------------------------------------------------------------------ create/read
    def create(self, title: str, *, priority: str = DEFAULT_PRIORITY) -> Ticket:
        """Create a ticket; *priority* defaults to ``normal`` and is validated."""
        if not title.strip():
            raise ValueError("title must not be empty")
        ticket = Ticket(
            id=self._next_id,
            title=title.strip(),
            status="open",
            priority=validate_priority(priority),
            created_at=self._clock().isoformat(),
        )
        self._tickets[ticket.id] = ticket
        self._next_id += 1
        return ticket

    def get(self, ticket_id: int) -> Ticket:
        """Return one ticket or raise ``KeyError``."""
        try:
            return self._tickets[ticket_id]
        except KeyError:
            raise KeyError(f"no ticket with id {ticket_id}") from None

    def list(self, *, status: str | None = None, sort: str = "created") -> Tickets:
        """List tickets, optionally filtered by status and sorted by ``created`` or ``priority``.

        Priority order is urgent, high, normal, low; creation order is kept within a
        priority (the sort is stable).
        """
        if sort not in _SORTS:
            raise ValueError(f"sort must be one of {', '.join(_SORTS)}; got {sort!r}")
        wanted = validate_status(status) if status is not None else None
        rows = [t for t in self._tickets.values() if wanted is None or t.status == wanted]
        rows.sort(key=lambda t: t.id)
        if sort == "priority":
            rows.sort(key=lambda t: -_RANK[t.priority])
        return rows

    # ------------------------------------------------------------------ update/delete
    def update(
        self,
        ticket_id: int,
        *,
        title: str | None = None,
        status: str | None = None,
        priority: str | None = None,
    ) -> Ticket:
        """Update the given fields of a ticket and return the new record."""
        current = self.get(ticket_id)
        changes: dict[str, Any] = {}
        if title is not None:
            if not title.strip():
                raise ValueError("title must not be empty")
            changes["title"] = title.strip()
        if status is not None:
            changes["status"] = validate_status(status)
        if priority is not None:
            changes["priority"] = validate_priority(priority)
        updated = Ticket(**{**current.to_dict(), **changes})
        self._tickets[ticket_id] = updated
        return updated

    def delete(self, ticket_id: int) -> None:
        """Delete a ticket or raise ``KeyError``."""
        self.get(ticket_id)
        del self._tickets[ticket_id]

    # ------------------------------------------------------------------ persistence
    def to_rows(self) -> Rows:
        """Snapshot every ticket as a dict (creation order)."""
        return [t.to_dict() for t in self.list()]

    @classmethod
    def from_rows(cls, rows: Rows) -> TicketService:
        """Rebuild a service from :meth:`to_rows` output (validating every row)."""
        service = cls()
        for row in rows:
            ticket = Ticket(
                id=int(row["id"]),
                title=str(row["title"]),
                status=validate_status(row.get("status", "open")),
                priority=validate_priority(row.get("priority", DEFAULT_PRIORITY)),
                created_at=str(row["created_at"]),
            )
            service._tickets[ticket.id] = ticket
            service._next_id = max(service._next_id, ticket.id + 1)
        return service
