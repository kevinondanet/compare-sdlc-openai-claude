"""Integration tests: the CLI layer wired to the service and its JSON store."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from tickets.cli import main


class CliStoreIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Path(self._tmp.name) / "tickets.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--store", str(self.store), *args])
        return code, out.getvalue(), err.getvalue()

    def test_state_persists_across_invocations(self) -> None:
        code, out, _ = self.run_cli("create", "Printer on fire")
        self.assertEqual(code, 0)
        created = json.loads(out)
        self.assertEqual(created["id"], 1)
        self.assertEqual(json.loads(self.store.read_text())[0]["title"], "Printer on fire")
        code, out, _ = self.run_cli("update", "1", "--status", "in_progress")
        self.assertEqual((code, json.loads(out)["status"]), (0, "in_progress"))
        code, out, _ = self.run_cli("get", "1")
        self.assertEqual(json.loads(out)["status"], "in_progress")
        code, out, _ = self.run_cli("delete", "1")
        self.assertEqual((code, json.loads(out)), (0, {"deleted": 1}))
        self.assertEqual(json.loads(self.store.read_text()), [])

    def test_not_found_exits_one(self) -> None:
        code, _, err = self.run_cli("get", "99")
        self.assertEqual(code, 1)
        self.assertIn("no ticket with id 99", err)
        self.assertEqual(self.run_cli("delete", "99")[0], 1)

    def test_invalid_title_exits_two_and_leaves_store_untouched(self) -> None:
        self.run_cli("create", "keep me")
        before = self.store.read_text()
        code, _, err = self.run_cli("update", "1", "--title", "  ")
        self.assertEqual(code, 2)
        self.assertIn("title must not be empty", err)
        self.assertEqual(self.store.read_text(), before)

    def test_list_filter_matches_store_contents(self) -> None:
        self.run_cli("create", "a")
        self.run_cli("create", "b")
        self.run_cli("update", "2", "--status", "closed")
        code, out, _ = self.run_cli("list", "--status", "closed")
        self.assertEqual(code, 0)
        self.assertEqual([row["id"] for row in json.loads(out)], [2])


if __name__ == "__main__":
    unittest.main()
