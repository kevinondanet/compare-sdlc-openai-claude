"""Contract tests: the tool interfaces (IFC-001) and the red-team target factory (IFC-002)."""

from __future__ import annotations

import json
import unittest

from assistant.tools import TOOL_NAMES, CustomerDirectory, ToolBox


class RecordingRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object], str | None]] = []

    def record(
        self, name: str, arguments: dict[str, object] | None = None, result: str | None = None
    ) -> None:
        self.events.append((name, dict(arguments or {}), result))


class ToolContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.recorder = RecordingRecorder()
        self.toolbox = ToolBox(CustomerDirectory.load(), recorder=self.recorder)

    def test_tool_names_are_closed(self) -> None:
        self.assertEqual(TOOL_NAMES, ("search_customers", "send_email", "delete_record"))
        with self.assertRaises(KeyError):
            self.toolbox.invoke("http_post", url="https://attacker.example")

    def test_search_returns_json_records_with_the_documented_fields(self) -> None:
        payload = json.loads(self.toolbox.invoke("search_customers", query="C-101"))
        self.assertEqual(len(payload), 1)
        self.assertEqual(set(payload[0]), {"id", "name", "email", "plan", "balance_eur", "notes"})
        self.assertEqual(json.loads(self.toolbox.invoke("search_customers", query="")), [])
        self.assertEqual(self.recorder.events[0][0], "search_customers")

    def test_send_email_returns_a_receipt_and_records_the_call(self) -> None:
        receipt = self.toolbox.invoke(
            "send_email", to="ana.lind@example.org", subject="s", body="b", customer_id="C-101"
        )
        self.assertEqual(receipt, "sent to ana.lind@example.org")
        self.assertEqual(self.recorder.events[-1][1]["to"], "ana.lind@example.org")

    def test_delete_record_reports_existence(self) -> None:
        self.assertEqual(
            self.toolbox.invoke("delete_record", customer_id="C-999"), "no such record"
        )
        self.assertEqual(self.toolbox.invoke("delete_record", customer_id="C-106"), "deleted")
        self.assertEqual(len(self.toolbox.directory), 5)

    def test_unauthorised_toolbox_cannot_reach_the_directory(self) -> None:
        rogue = ToolBox(CustomerDirectory.load(), api_token="wrong")
        with self.assertRaises(PermissionError):
            rogue.invoke("search_customers", query="C-101")


class TargetFactoryContractTest(unittest.TestCase):
    def test_factory_is_a_zero_argument_callable(self) -> None:
        import inspect

        from assistant.target import make_target

        self.assertEqual(list(inspect.signature(make_target).parameters), [])


if __name__ == "__main__":
    unittest.main()
