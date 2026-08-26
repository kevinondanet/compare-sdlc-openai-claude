"""Contract tests: what the office manager's tools may rely on from the generated app."""

from __future__ import annotations

import csv
import io
import unittest
from datetime import datetime

from lowcode.app import FormApp
from lowcode.generated import lunch_order

COLUMNS = ("id", "submitted_at", "dish", "quantity", "team", "notes")


class LunchOrderContractTest(unittest.TestCase):
    def test_public_surface(self) -> None:
        for name in ("SPEC", "APP", "submit", "rows", "export_csv", "main"):
            self.assertTrue(hasattr(lunch_order, name), name)
        self.assertEqual(lunch_order.SPEC.columns, COLUMNS[2:])
        self.assertEqual(lunch_order.SPEC.cutoff.describe(), "Friday 10:00")

    def test_csv_export_header_and_row_shape(self) -> None:
        app = FormApp(lunch_order.SPEC)
        app.submit({"dish": "falafel wrap", "quantity": 3, "team": "hr"}, now=datetime(2026, 8, 27))
        reader = csv.DictReader(io.StringIO(app.export_csv()))
        self.assertEqual(tuple(reader.fieldnames or ()), COLUMNS)
        rows = list(reader)
        self.assertEqual(rows[0]["dish"], "falafel wrap")
        self.assertEqual(rows[0]["quantity"], "3")

    def test_choices_are_the_caterer_menu(self) -> None:
        self.assertEqual(
            lunch_order.SPEC.field("dish").choices,
            ("falafel wrap", "chicken curry", "veggie pizza", "salad bowl"),
        )
        quantity = lunch_order.SPEC.field("quantity")
        self.assertEqual((quantity.minimum, quantity.maximum), (1, 5))


if __name__ == "__main__":
    unittest.main()
