"""End-to-end tests: the ``tickets`` program run as a real subprocess (before priorities)."""

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
        created = tickets(self.store, "create", "Laptop will not boot")
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(json.loads(created.stdout)["id"], 1)
        tickets(self.store, "create", "Mouse")
        listed = tickets(self.store, "list")
        self.assertEqual(
            [r["title"] for r in json.loads(listed.stdout)], ["Laptop will not boot", "Mouse"]
        )
        closed = tickets(self.store, "update", "1", "--status", "closed")
        self.assertEqual(json.loads(closed.stdout)["status"], "closed")
        remaining = tickets(self.store, "list", "--status", "open")
        self.assertEqual([r["id"] for r in json.loads(remaining.stdout)], [2])

    def test_unknown_ticket_is_reported_end_to_end(self) -> None:
        result = tickets(self.store, "get", "9")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no ticket with id 9", result.stderr)


if __name__ == "__main__":
    unittest.main()
