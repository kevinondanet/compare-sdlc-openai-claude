"""Tiny in-memory tickets service (pilot 1: an internal CRUD application)."""

from tickets.service import (
    DEFAULT_PRIORITY,
    PRIORITIES,
    STATUSES,
    Ticket,
    TicketService,
    validate_priority,
)

__all__ = [
    "DEFAULT_PRIORITY",
    "PRIORITIES",
    "STATUSES",
    "Ticket",
    "TicketService",
    "validate_priority",
]
