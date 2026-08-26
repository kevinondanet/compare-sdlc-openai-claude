"""Architecture tests: the governance boundary is the only path to the tools and to AGT."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "assistant"


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class BoundaryTest(unittest.TestCase):
    def test_only_governance_talks_to_the_policy_engine(self) -> None:
        enforcement = {
            "aisdlc.governance.enforce",
            "aisdlc.governance.audit",
            "aisdlc.governance.policy",
            "aisdlc.governance.tiers",
        }
        for path in PACKAGE.glob("*.py"):
            names = imports_of(path)
            if path.name == "governance.py":
                self.assertTrue(names & enforcement)
            else:
                self.assertFalse(names & enforcement, f"{path.name} bypasses assistant.governance")

    def test_agent_uses_the_governance_layer(self) -> None:
        names = imports_of(PACKAGE / "agent.py")
        self.assertIn("assistant.governance", names)
        self.assertFalse({n for n in names if n.startswith("aisdlc.security")})

    def test_tools_know_nothing_about_the_platform(self) -> None:
        names = imports_of(PACKAGE / "tools.py")
        self.assertFalse({n for n in names if n.startswith("aisdlc")})

    def test_red_team_hooks_stay_in_their_modules(self) -> None:
        for path in PACKAGE.glob("*.py"):
            names = {n for n in imports_of(path) if n.startswith("aisdlc.security")}
            if path.name in {"target.py", "safety_cases.py"}:
                self.assertTrue(names, path.name)
            else:
                self.assertFalse(names, path.name)


if __name__ == "__main__":
    unittest.main()
