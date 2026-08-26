"""Unit tests for the low-code engine (schema, table, app) — independent of any form."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, time
from pathlib import Path
from tempfile import TemporaryDirectory

from lowcode.app import FormApp, SubmissionsClosed
from lowcode.schema import Cutoff, Field, FormSpec, ValidationError
from lowcode.table import Table, csv_safe

SPEC = FormSpec.from_dict(
    {
        "slug": "demo",
        "title": "Demo form",
        "cutoff": {"weekday": "monday", "time": "12:00"},
        "fields": [
            {"name": "colour", "type": "choice", "choices": ["red", "blue"]},
            {"name": "count", "type": "number", "minimum": 1, "maximum": 3},
            {"name": "label", "type": "text", "max_length": 5},
            {"name": "remark", "type": "text", "required": False},
        ],
    }
)


class FieldTest(unittest.TestCase):
    def test_text_choice_and_number_cleaning(self) -> None:
        self.assertEqual(SPEC.field("label").clean("  hi "), "hi")
        self.assertEqual(SPEC.field("colour").clean("red"), "red")
        self.assertEqual(SPEC.field("count").clean("2"), 2)
        self.assertEqual(SPEC.field("count").clean("2.5"), 2.5)
        self.assertIsNone(SPEC.field("remark").clean(""))

    def test_rejections(self) -> None:
        cases = {
            "colour": ["green"],
            "count": ["x", "0", "9"],
            "label": ["toolong"],
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                    SPEC.field(name).clean(value)
        with self.assertRaises(ValueError):
            SPEC.field("count").clean(None)

    def test_invalid_definitions(self) -> None:
        with self.assertRaises(ValueError):
            Field(name="bad name")
        with self.assertRaises(ValueError):
            Field(name="x", type="date")
        with self.assertRaises(ValueError):
            Field(name="x", type="choice")
        with self.assertRaises(ValueError):
            Cutoff("someday", time(1, 0))
        with self.assertRaises(ValueError):
            FormSpec(slug="1x", title="t", fields=(Field(name="a"),))
        with self.assertRaises(ValueError):
            FormSpec(slug="x", title="t", fields=(Field(name="a"), Field(name="a")))
        with self.assertRaises(ValueError):
            FormSpec(slug="x", title="t", fields=())


class FormSpecTest(unittest.TestCase):
    def test_validate_collects_every_error(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            SPEC.validate({"colour": "green", "count": "7", "extra": 1})
        self.assertEqual(set(ctx.exception.errors), {"colour", "count", "label", "extra"})
        self.assertIn("extra: is not a field of this form", str(ctx.exception))

    def test_validate_returns_cleaned_row(self) -> None:
        row = SPEC.validate({"colour": "blue", "count": "1", "label": "ok"})
        self.assertEqual(row, {"colour": "blue", "count": 1, "label": "ok", "remark": None})
        self.assertEqual(SPEC.columns, ("colour", "count", "label", "remark"))
        with self.assertRaises(KeyError):
            SPEC.field("nope")

    def test_cutoff_window(self) -> None:
        cutoff = SPEC.cutoff
        assert cutoff is not None
        self.assertTrue(cutoff.is_open(datetime(2026, 8, 24, 11, 59)))  # Monday before
        self.assertFalse(cutoff.is_open(datetime(2026, 8, 24, 12, 0)))  # Monday at cut-off
        self.assertTrue(cutoff.is_open(datetime(2026, 8, 25, 12, 0)))  # Tuesday
        self.assertEqual(cutoff.describe(), "Monday 12:00")

    def test_load_from_file(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "form.json"
            path.write_text(json.dumps(SPEC.source), encoding="utf-8")
            loaded = FormSpec.load(path)
        self.assertEqual(loaded, SPEC)
        self.assertIsNone(FormSpec.from_dict({"slug": "s", "fields": [{"name": "a"}]}).cutoff)


class TableTest(unittest.TestCase):
    def test_add_rows_and_export(self) -> None:
        table = Table(("a", "b"))
        stamp = datetime(2026, 1, 1, 8, 30)
        first = table.add({"a": "x", "b": 1}, submitted_at=stamp)
        table.add({"a": "=SUM(A1)", "b": None}, submitted_at=stamp)
        self.assertEqual(first, {"id": 1, "submitted_at": "2026-01-01T08:30:00", "a": "x", "b": 1})
        self.assertEqual(len(table), 2)
        self.assertEqual([r["id"] for r in table.rows()], [1, 2])
        csv_text = table.export_csv()
        self.assertEqual(csv_text.splitlines()[0], "id,submitted_at,a,b")
        self.assertIn("'=SUM(A1)", csv_text)

    def test_csv_safe_prefixes(self) -> None:
        for dangerous in ("=1+1", "+1", "-1", "@cmd", "\tx"):
            self.assertTrue(csv_safe(dangerous).startswith("'"))
        self.assertEqual(csv_safe("plain"), "plain")
        self.assertEqual(csv_safe(3), 3)

    def test_rows_restore(self) -> None:
        table = Table(("a",), [{"id": 1, "submitted_at": "t", "a": "x"}])
        self.assertEqual(table.add({"a": "y"}, submitted_at=datetime(2026, 1, 1))["id"], 2)


class FormAppTest(unittest.TestCase):
    def test_submit_respects_cutoff_and_validation(self) -> None:
        app = FormApp(SPEC, clock=lambda: datetime(2026, 8, 24, 13, 0))
        with self.assertRaises(SubmissionsClosed):
            app.submit({"colour": "red", "count": 1, "label": "a"})
        self.assertFalse(app.is_open())
        row = app.submit({"colour": "red", "count": 1, "label": "a"}, now=datetime(2026, 8, 25))
        self.assertEqual(row["id"], 1)
        with self.assertRaises(ValidationError):
            app.submit({"colour": "red"}, now=datetime(2026, 8, 25))
        self.assertEqual(len(app.rows()), 1)
        self.assertTrue(app.export_csv().startswith("id,submitted_at,colour"))

    def test_app_without_cutoff_is_always_open(self) -> None:
        spec = FormSpec.from_dict({"slug": "open", "fields": [{"name": "a"}]})
        self.assertTrue(FormApp(spec).is_open())


if __name__ == "__main__":
    unittest.main()
