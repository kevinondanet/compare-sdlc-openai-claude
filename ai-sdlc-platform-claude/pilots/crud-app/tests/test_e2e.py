"""End-to-end tests: the ``tickets`` program run as a real subprocess against a store file."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


def tickets(store: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tickets", "--store", str(store), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class TicketsCliJourneyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Path(self._tmp.name) / "tickets.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_support_agent_journey(self) -> None:
        """SCN-001-01, SCN-002-01, SCN-003-01, SCN-004-01: create, triage, list, close."""
        created = tickets(self.store, "create", "Laptop will not boot", "--priority", "high")
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(json.loads(created.stdout)["priority"], "high")
        self.assertEqual(
            json.loads(tickets(self.store, "create", "Mouse").stdout)["priority"], "normal"
        )
        listed = tickets(self.store, "list", "--sort", "priority")
        self.assertEqual(
            [r["title"] for r in json.loads(listed.stdout)], ["Laptop will not boot", "Mouse"]
        )
        closed = tickets(self.store, "update", "1", "--status", "closed")
        self.assertEqual(json.loads(closed.stdout)["status"], "closed")
        remaining = tickets(self.store, "list", "--status", "open")
        self.assertEqual([r["id"] for r in json.loads(remaining.stdout)], [2])

    def test_invalid_priority_is_refused_end_to_end(self) -> None:
        """SCN-004-02, SCN-001-02: the program exits 2 and the store is not created."""
        result = tickets(self.store, "create", "Bad", "--priority", "sev1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("priority must be one of", result.stderr)
        self.assertFalse(self.store.exists())


if __name__ == "__main__":
    unittest.main()
