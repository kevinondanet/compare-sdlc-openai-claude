"""Contract tests: the JSON record shape consumers of the store/CLI rely on (IFC-001)."""

from __future__ import annotations

import json
import unittest

from tickets.service import TicketService

BASE_FIELDS = {"id": int, "title": str, "status": str, "created_at": str}


class TicketRecordContractTest(unittest.TestCase):
    def test_record_carries_the_documented_fields_with_their_types(self) -> None:
        record = TicketService().create("contract").to_dict()
        for name, typ in BASE_FIELDS.items():
            self.assertIn(name, record)
            self.assertIsInstance(record[name], typ)
        self.assertIn("priority", record)
        self.assertIsInstance(record["priority"], str)

    def test_record_is_json_serialisable_and_stable(self) -> None:
        record = TicketService().create("json").to_dict()
        encoded = json.dumps(record, sort_keys=True)
        self.assertEqual(json.loads(encoded), record)
        self.assertEqual(list(sorted(record)), ["created_at", "id", "priority", "status", "title"])

    def test_status_and_priority_vocabularies_are_closed(self) -> None:
        from tickets.service import PRIORITIES, STATUSES

        self.assertEqual(STATUSES, ("open", "in_progress", "closed"))
        self.assertEqual(PRIORITIES, ("low", "normal", "high", "urgent"))


if __name__ == "__main__":
    unittest.main()
