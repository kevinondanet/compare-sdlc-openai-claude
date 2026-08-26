"""Integration tests: form file -> generator -> importable module -> working application."""

from __future__ import annotations

import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from lowcode import generator

FORM = {
    "slug": "poll",
    "title": "Quick poll",
    "fields": [
        {"name": "answer", "type": "choice", "choices": ["yes", "no"]},
        {"name": "why", "type": "text", "required": False},
    ],
}


class GeneratorIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.form = self.root / "poll.json"
        self.form.write_text(json.dumps(FORM), encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _load(self, path: Path):  # noqa: ANN202 - dynamic module
        spec = importlib.util.spec_from_file_location("generated_poll", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_generated_module_runs_the_form(self) -> None:
        target = generator.generate(self.form, self.root / "out")
        self.assertEqual(target.name, "poll.py")
        module = self._load(target)
        row = module.submit({"answer": "yes"}, now=datetime(2026, 1, 5, 9))
        self.assertEqual((row["id"], row["answer"], row["why"]), (1, "yes", None))
        self.assertEqual(module.rows(), [row])
        self.assertTrue(module.export_csv().startswith("id,submitted_at,answer,why"))
        with self.assertRaises(ValueError):
            module.submit({"answer": "maybe"})

    def test_regeneration_is_idempotent(self) -> None:
        first = generator.generate(self.form, self.root / "out")
        stamp = first.stat().st_mtime_ns
        second = generator.generate(self.form, self.root / "out")
        self.assertEqual(first, second)
        self.assertEqual(second.stat().st_mtime_ns, stamp)  # unchanged file left alone

    def test_generator_cli_prints_the_target(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = generator.main([str(self.form), "--out-dir", str(self.root / "cli")])
        self.assertEqual(code, 0)
        self.assertTrue(out.getvalue().strip().endswith("poll.py"))


if __name__ == "__main__":
    unittest.main()
