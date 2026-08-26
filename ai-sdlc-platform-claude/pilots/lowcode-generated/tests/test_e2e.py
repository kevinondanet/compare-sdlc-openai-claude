"""End-to-end: the generated lunch-order program as a subprocess with a JSON store."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


def lunch(
    store: Path, *args: str, now: str = "2026-08-27T09:00:00"
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "lowcode.generated.lunch_order",
            "--store",
            str(store),
            "--now",
            now,
            *args,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class LunchOrderJourneyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Path(self._tmp.name) / "orders.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_friday_lunch_journey(self) -> None:
        """SCN-001-01, SCN-002-01, SCN-003-01: two people order, the manager exports."""
        first = lunch(
            self.store, "submit", "--dish", "veggie pizza", "--quantity", "1", "--team", "ops"
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["id"], 1)
        second = lunch(
            self.store,
            "submit",
            "--dish",
            "salad bowl",
            "--quantity",
            "2",
            "--team",
            "sales",
            "--notes",
            "no onions",
        )
        self.assertEqual(json.loads(second.stdout)["notes"], "no onions")
        listed = lunch(self.store, "list")
        self.assertEqual([r["team"] for r in json.loads(listed.stdout)], ["ops", "sales"])
        exported = lunch(self.store, "export")
        self.assertEqual(
            exported.stdout.splitlines()[0], "id,submitted_at,dish,quantity,team,notes"
        )
        self.assertEqual(len(exported.stdout.splitlines()), 3)

    def test_order_after_cutoff_is_refused(self) -> None:
        """SCN-004-01: after Friday 10:00 the program exits 2 and stores nothing."""
        late = lunch(
            self.store,
            "submit",
            "--dish",
            "salad bowl",
            "--quantity",
            "1",
            "--team",
            "ops",
            now="2026-08-28T10:30:00",
        )
        self.assertEqual(late.returncode, 2)
        self.assertIn("closed", late.stderr)
        self.assertFalse(self.store.exists())


if __name__ == "__main__":
    unittest.main()
