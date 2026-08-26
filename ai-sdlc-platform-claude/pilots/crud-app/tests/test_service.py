"""Unit tests for the ticket service (behaviour that exists before and after the change)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from tickets.service import TicketService


def fixed_clock() -> datetime:
    return datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class ServiceCrudTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = TicketService(clock=fixed_clock)

    def test_create_assigns_sequential_ids_and_open_status(self) -> None:
        first = self.service.create("Printer on fire")
        second = self.service.create("VPN down")
        self.assertEqual((first.id, second.id), (1, 2))
        self.assertEqual(first.status, "open")
        self.assertEqual(first.created_at, "2026-01-02T03:04:05+00:00")

    def test_create_rejects_empty_title(self) -> None:
        with self.assertRaises(ValueError):
            self.service.create("   ")

    def test_get_unknown_id_raises_key_error(self) -> None:
        with self.assertRaises(KeyError):
            self.service.get(42)

    def test_list_filters_by_status_and_validates_it(self) -> None:
        self.service.create("a")
        self.service.create("b")
        self.service.update(2, status="closed")
        self.assertEqual([t.id for t in self.service.list(status="open")], [1])
        self.assertEqual([t.id for t in self.service.list(status="closed")], [2])
        with self.assertRaises(ValueError):
            self.service.list(status="bogus")
        with self.assertRaises(ValueError):
            self.service.list(sort="bogus")

    def test_update_changes_title_and_status(self) -> None:
        ticket = self.service.create("typo")
        updated = self.service.update(ticket.id, title="Typo in banner", status="in_progress")
        self.assertEqual((updated.title, updated.status), ("Typo in banner", "in_progress"))
        with self.assertRaises(ValueError):
            self.service.update(ticket.id, title=" ")
        with self.assertRaises(ValueError):
            self.service.update(ticket.id, status="done")

    def test_delete_removes_ticket(self) -> None:
        ticket = self.service.create("temp")
        self.service.delete(ticket.id)
        self.assertEqual(self.service.list(), [])
        with self.assertRaises(KeyError):
            self.service.delete(ticket.id)

    def test_rows_round_trip(self) -> None:
        self.service.create("a")
        self.service.create("b")
        rebuilt = TicketService.from_rows(self.service.to_rows())
        self.assertEqual(rebuilt.to_rows(), self.service.to_rows())
        self.assertEqual(rebuilt.create("c").id, 3)


if __name__ == "__main__":
    unittest.main()
