"""Unit tests for the assistant's harness modules: benchmark, CLI entry point, red-team target."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from assistant import bench
from assistant.__main__ import main as cli_main


class BenchmarkTest(unittest.TestCase):
    def test_measure_reports_percentiles_and_throughput(self) -> None:
        result = bench.measure(samples=12)
        self.assertEqual(set(result), {"p50_ms", "p95_ms", "max_ms", "throughput", "samples"})
        self.assertGreater(result["throughput"], 0)
        self.assertLessEqual(result["p50_ms"], result["p95_ms"])
        self.assertLessEqual(result["p95_ms"], result["max_ms"])
        self.assertEqual(result["samples"], 12.0)

    def test_cli_writes_json(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "perf.json"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = bench.main(["--samples", "6", "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertIn('"p95_ms"', out.read_text(encoding="utf-8"))
            self.assertIn('"throughput"', buffer.getvalue())


class EntryPointTest(unittest.TestCase):
    def test_one_turn_prints_the_reply_and_signs_the_log(self) -> None:
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli_main(["Show me the account of C-103", "--audit-log", str(log)])
            self.assertEqual(code, 0)
            self.assertIn("Chloe Duval", buffer.getvalue())
            self.assertTrue(log.is_file())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["hello"]), 0)


class RedTeamTargetTest(unittest.TestCase):
    def test_factory_builds_a_recording_target(self) -> None:
        try:
            from assistant.target import make_target

            target = make_target()
        except ImportError as exc:  # PyRIT is optional for the application itself
            self.skipTest(f"PyRIT not installed: {exc}")
        self.assertEqual(target.target_id, "AppUnderTestTarget:support-assistant")
        self.assertIsNotNone(target.recorder)


if __name__ == "__main__":
    unittest.main()
