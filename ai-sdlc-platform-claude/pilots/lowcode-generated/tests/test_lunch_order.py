"""Unit tests for the generated lunch-order application (CHG-lunch-order-form).

Docstrings name the acceptance scenarios of the change package they verify.
"""

from __future__ import annotations

import io
import json
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from lowcode.app import FormApp, SubmissionsClosed
from lowcode.generated import lunch_order
from lowcode.schema import ValidationError

THURSDAY = datetime(2026, 8, 27, 9, 0)
FRIDAY_LATE = datetime(2026, 8, 28, 10, 30)
ORDER = {"dish": "salad bowl", "quantity": "2", "team": "ops", "notes": ""}


class SubmitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = FormApp(lunch_order.SPEC)

    def test_team_member_submits_an_order(self) -> None:
        """SCN-001-01: a team member submits a lunch order in the form."""
        row = self.app.submit(ORDER, now=THURSDAY)
        self.assertEqual(row["id"], 1)
        self.assertEqual((row["dish"], row["quantity"], row["team"]), ("salad bowl", 2, "ops"))
        self.assertEqual(row["submitted_at"], "2026-08-27T09:00:00")

    def test_invalid_values_are_explained(self) -> None:
        """SCN-001-01: an invalid submission is refused with a message per field."""
        with self.assertRaises(ValidationError) as ctx:
            self.app.submit({"dish": "sushi", "quantity": "9", "team": ""}, now=THURSDAY)
        self.assertEqual(set(ctx.exception.errors), {"dish", "quantity", "team"})
        self.assertEqual(self.app.rows(), [])

    def test_office_manager_sees_all_orders(self) -> None:
        """SCN-002-01: every submitted order appears in the table, in order."""
        self.app.submit(ORDER, now=THURSDAY)
        self.app.submit({**ORDER, "dish": "veggie pizza", "team": "sales"}, now=THURSDAY)
        rows = self.app.rows()
        self.assertEqual([r["id"] for r in rows], [1, 2])
        self.assertEqual([r["dish"] for r in rows], ["salad bowl", "veggie pizza"])
        self.assertEqual(set(rows[0]), {"id", "submitted_at", "dish", "quantity", "team", "notes"})

    def test_export_as_csv(self) -> None:
        """SCN-003-01: the table exports as CSV with a header row and safe cells."""
        self.app.submit({**ORDER, "notes": "=HYPERLINK(evil)"}, now=THURSDAY)
        text = self.app.export_csv()
        lines = text.splitlines()
        self.assertEqual(lines[0], "id,submitted_at,dish,quantity,team,notes")
        self.assertEqual(lines[1], "1,2026-08-27T09:00:00,salad bowl,2,ops,'=HYPERLINK(evil)")

    def test_orders_after_cutoff_are_refused(self) -> None:
        """SCN-004-01: an order after Friday 10:00 is refused and nothing is stored."""
        with self.assertRaises(SubmissionsClosed):
            self.app.submit(ORDER, now=FRIDAY_LATE)
        self.assertEqual(self.app.rows(), [])
        self.assertEqual(self.app.submit(ORDER, now=datetime(2026, 8, 28, 9, 59))["id"], 1)
        self.assertEqual(self.app.submit(ORDER, now=datetime(2026, 8, 29, 12, 0))["id"], 2)

    def test_five_hundred_orders_render_within_one_second(self) -> None:
        """SCN-005-01: listing and exporting 500 orders takes under one second."""
        for index in range(500):
            self.app.submit({**ORDER, "team": f"team-{index % 7}"}, now=THURSDAY)
        started = time.perf_counter()
        rows = self.app.rows()
        text = self.app.export_csv()
        elapsed = time.perf_counter() - started
        self.assertEqual(len(rows), 500)
        self.assertEqual(len(text.splitlines()), 501)
        self.assertLess(elapsed, 1.0)


class GeneratedModuleTest(unittest.TestCase):
    def test_module_functions_share_one_table(self) -> None:
        """SCN-001-01, SCN-002-01, SCN-003-01: module-level submit/rows/export_csv."""
        before = len(lunch_order.rows())
        row = lunch_order.submit(ORDER, now=THURSDAY)
        self.assertEqual(row["id"], before + 1)
        self.assertEqual(len(lunch_order.rows()), before + 1)
        self.assertIn("salad bowl", lunch_order.export_csv())
        self.assertEqual(lunch_order.SPEC.slug, "lunch_order")
        self.assertEqual(lunch_order.APP.spec, lunch_order.SPEC)


class CommandLineTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Path(self._tmp.name) / "orders.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def cli(self, *args: str, now: datetime = THURSDAY) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = lunch_order.main(["--store", str(self.store), "--now", now.isoformat(), *args])
        return code, out.getvalue(), err.getvalue()

    def test_submit_list_export(self) -> None:
        """SCN-001-01, SCN-002-01, SCN-003-01 through the command line."""
        code, out, _ = self.cli(
            "submit", "--dish", "chicken curry", "--quantity", "1", "--team", "ops"
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["dish"], "chicken curry")
        code, out, _ = self.cli("list")
        self.assertEqual([r["id"] for r in json.loads(out)], [1])
        code, out, _ = self.cli("export")
        self.assertTrue(out.startswith("id,submitted_at,dish"))

    def test_cli_refuses_invalid_and_closed(self) -> None:
        """SCN-004-01: closed submissions and invalid values exit 2."""
        code, _, err = self.cli(
            "submit", "--dish", "salad bowl", "--quantity", "2", "--team", "ops", now=FRIDAY_LATE
        )
        self.assertEqual(code, 2)
        self.assertIn("closed", err)
        code, _, err = self.cli("submit", "--dish", "sushi", "--quantity", "2", "--team", "ops")
        self.assertEqual(code, 2)
        self.assertIn("dish: must be one of", err)
        self.assertFalse(self.store.exists())


if __name__ == "__main__":
    unittest.main()
