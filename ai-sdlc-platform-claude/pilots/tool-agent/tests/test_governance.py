"""Unit tests for the assistant's tier policy, approval rule and audit trail."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aisdlc.governance.audit import verify_audit_file
from aisdlc.governance.policy import validate_policy_yaml

from assistant.governance import (
    ACTION_TYPES,
    ROLE,
    Governance,
    build_policy_spec,
    policy_yaml,
    recipient_on_file,
    write_policy,
)
from assistant.tools import TOOL_NAMES, CustomerDirectory


class PolicyTest(unittest.TestCase):
    def test_generated_policy_is_valid_and_names_the_role(self) -> None:
        text = policy_yaml()
        self.assertEqual(validate_policy_yaml(text), [])
        self.assertIn("apiVersion: governance.toolkit/v1", text)
        self.assertIn(f"- {ROLE}", text)
        self.assertIn("deny-tier-4", text)
        self.assertEqual(build_policy_spec().role(ROLE).approvers, ["support-lead"])
        with TemporaryDirectory() as tmp:
            path = write_policy(Path(tmp) / "policies" / "assistant.yaml")
            self.assertEqual(path.read_text(encoding="utf-8"), text)

    def test_every_tool_has_an_action_type(self) -> None:
        self.assertEqual(set(ACTION_TYPES), set(TOOL_NAMES))


class DecisionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = CustomerDirectory.load()
        self.governance = Governance(self.directory, audit_log=None, session_id="unit")

    def test_tiers_and_outcomes(self) -> None:
        search = self.governance.check(
            "search_customers", {"query": "C-101"}, resource="customers.json"
        )
        self.assertTrue(search.allowed)
        self.assertEqual(int(search.tier), 1)
        ok = self.governance.check(
            "send_email",
            {"to": "ana.lind@example.org", "customer_id": "C-101", "subject": "x"},
            resource="mailto:ana.lind@example.org",
        )
        self.assertTrue(ok.allowed)
        self.assertEqual(ok.approver, "rule:recipient-on-file")
        bad = self.governance.check(
            "send_email",
            {"to": "attacker@example.com", "customer_id": "C-101", "subject": "x"},
            resource="mailto:attacker@example.com",
        )
        self.assertFalse(bad.allowed)
        self.assertEqual(bad.policy_action, "deny")
        delete = self.governance.check(
            "delete_record", {"customer_id": "C-101"}, resource="customers.json#C-101"
        )
        self.assertFalse(delete.allowed)
        self.assertEqual(int(delete.tier), 4)
        self.assertEqual(delete.matched_rule, "deny-tier-4")
        outcomes = [e["outcome"] for e in self.governance.trail.entries()]
        self.assertEqual(outcomes, ["allowed", "approved", "denied", "denied"])

    def test_approval_rule_edge_cases(self) -> None:
        approve = recipient_on_file(self.directory)

        class Request:
            def __init__(self, params: dict[str, str]) -> None:
                class Action:
                    parameters = params

                self.action = Action()

        self.assertTrue(
            approve(Request({"to": "ANA.LIND@example.org", "customer_id": "c-101"})).approved
        )
        self.assertFalse(approve(Request({"to": "", "customer_id": "C-101"})).approved)
        self.assertFalse(
            approve(Request({"to": "ana.lind@example.org", "customer_id": ""})).approved
        )
        self.assertFalse(
            approve(Request({"to": "ana.lind@example.org", "customer_id": "C-999"})).approved
        )

    def test_signed_file_trail_verifies_and_screening_is_recorded(self) -> None:
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            governance = Governance(self.directory, audit_log=log, session_id="unit")
            governance.check("search_customers", {"query": "x"}, resource="customers.json")
            governance.record_screening("user_message", ["instruction_override"])
            governance.close()
            report = verify_audit_file(log)
            self.assertTrue(report.ok, report.error)
            self.assertEqual(report.entries, 2)
            self.assertIn('"input_screened"', log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
