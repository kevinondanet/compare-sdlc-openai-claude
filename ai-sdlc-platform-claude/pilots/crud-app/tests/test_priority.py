"""Unit tests for CHG-add-ticket-priority; docstrings name the scenarios they verify."""

from __future__ import annotations

import io
import json
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from tickets.cli import main
from tickets.service import DEFAULT_PRIORITY, PRIORITIES, TicketService, validate_priority


class PriorityFieldTest(unittest.TestCase):
    """REQ-001 / REQ-002: the priority field, its validation and its default."""

    def setUp(self) -> None:
        self.service = TicketService()

    def test_valid_priority_is_stored(self) -> None:
        """SCN-001-01: a valid priority is stored on the ticket."""
        ticket = self.service.create("Disk full", priority="high")
        self.assertEqual(ticket.priority, "high")
        self.assertEqual(self.service.get(ticket.id).priority, "high")
        self.assertEqual(self.service.update(ticket.id, priority=" Urgent ").priority, "urgent")

    def test_invalid_priority_is_rejected(self) -> None:
        """SCN-001-02: any value outside low/normal/high/urgent is rejected."""
        for bad in ("critical", "", "P1"):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                validate_priority(bad)
        for wrong_type in (3, None):
            with self.subTest(value=wrong_type), self.assertRaises(TypeError):
                validate_priority(wrong_type)
        with self.assertRaises(ValueError):
            self.service.create("x", priority="critical")
        ticket = self.service.create("y")
        with self.assertRaises(ValueError):
            self.service.update(ticket.id, priority="blocker")
        self.assertEqual(self.service.get(ticket.id).priority, DEFAULT_PRIORITY)

    def test_priority_defaults_to_normal(self) -> None:
        """SCN-002-01: a ticket created without a priority gets 'normal'."""
        self.assertEqual(self.service.create("No priority given").priority, "normal")
        self.assertEqual(PRIORITIES, ("low", "normal", "high", "urgent"))

    def test_rows_without_priority_load_as_normal(self) -> None:
        """SCN-002-01: legacy rows (stored before the change) load with priority 'normal'."""
        legacy = [{"id": 7, "title": "old", "status": "open", "created_at": "2025-01-01"}]
        service = TicketService.from_rows(legacy)
        self.assertEqual(service.get(7).priority, "normal")
        with self.assertRaises(ValueError):
            TicketService.from_rows([{**legacy[0], "priority": "sev1"}])


class PrioritySortTest(unittest.TestCase):
    """REQ-003 / REQ-005: listing sorted by priority."""

    def test_sort_by_priority_orders_urgent_first(self) -> None:
        """SCN-003-01: urgent, high, normal, low."""
        service = TicketService()
        service.create("low", priority="low")
        service.create("urgent", priority="urgent")
        service.create("normal")
        service.create("high", priority="high")
        titles = [t.title for t in service.list(sort="priority")]
        self.assertEqual(titles, ["urgent", "high", "normal", "low"])

    def test_creation_order_kept_within_priority(self) -> None:
        """SCN-003-02: tickets of equal priority keep creation order; filters still apply."""
        service = TicketService()
        first = service.create("first high", priority="high")
        service.create("filler", priority="low")
        second = service.create("second high", priority="high")
        service.update(first.id, status="closed")
        ordered = [t.id for t in service.list(sort="priority")]
        self.assertEqual(ordered, [first.id, second.id, 2])
        self.assertEqual([t.id for t in service.list(status="open", sort="priority")], [3, 2])
        self.assertEqual([t.id for t in service.list()], [1, 2, 3])

    def test_sorting_ten_thousand_tickets_is_fast(self) -> None:
        """SCN-005-01: 10,000 tickets sort by priority within 200 ms."""
        service = TicketService()
        for index in range(10_000):
            service.create(f"t{index}", priority=PRIORITIES[index % len(PRIORITIES)])
        started = time.perf_counter()
        rows = service.list(sort="priority")
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.assertEqual(len(rows), 10_000)
        self.assertEqual(rows[0].priority, "urgent")
        self.assertLess(elapsed_ms, 200.0)


class PriorityCliTest(unittest.TestCase):
    """REQ-004: the ``--priority`` flag of the tickets CLI."""

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--store", str(self.store), *args])
        return code, out.getvalue(), err.getvalue()

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Path(self._tmp.name) / "tickets.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_priority_flag_reaches_the_service(self) -> None:
        """SCN-004-01: --priority is stored and 'list --sort priority' orders by it."""
        code, out, _ = self.run_cli("create", "Pager storm", "--priority", "urgent")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["priority"], "urgent")
        self.run_cli("create", "Coffee machine", "--priority", "low")
        self.run_cli("create", "Badge reader")
        code, out, _ = self.run_cli("list", "--sort", "priority")
        self.assertEqual(code, 0)
        self.assertEqual(
            [row["title"] for row in json.loads(out)],
            ["Pager storm", "Badge reader", "Coffee machine"],
        )
        code, out, _ = self.run_cli("update", "3", "--priority", "high")
        self.assertEqual((code, json.loads(out)["priority"]), (0, "high"))

    def test_invalid_priority_exits_two(self) -> None:
        """SCN-004-02: an invalid --priority value exits 2 and stores nothing."""
        code, _, err = self.run_cli("create", "Broken", "--priority", "sev1")
        self.assertEqual(code, 2)
        self.assertIn("priority must be one of", err)
        self.assertFalse(self.store.exists())


if __name__ == "__main__":
    unittest.main()
