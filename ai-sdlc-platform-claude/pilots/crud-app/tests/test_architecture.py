"""Architecture tests: dependency direction inside the ``tickets`` package."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "tickets"


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class DependencyDirectionTest(unittest.TestCase):
    def test_service_does_not_depend_on_the_cli_or_third_parties(self) -> None:
        names = imports_of(PACKAGE / "service.py")
        self.assertFalse({n for n in names if n.startswith("tickets.cli")})
        allowed_prefixes = ("collections", "dataclasses", "datetime", "typing", "__future__")
        for name in names:
            self.assertTrue(name.startswith(allowed_prefixes), name)

    def test_cli_is_the_only_module_that_touches_the_filesystem(self) -> None:
        self.assertNotIn("pathlib", imports_of(PACKAGE / "service.py"))
        self.assertIn("pathlib", imports_of(PACKAGE / "cli.py"))

    def test_package_init_exports_the_public_surface_only(self) -> None:
        import tickets

        self.assertEqual(
            set(tickets.__all__),
            {
                "DEFAULT_PRIORITY",
                "PRIORITIES",
                "STATUSES",
                "Ticket",
                "TicketService",
                "validate_priority",
            },
        )


if __name__ == "__main__":
    unittest.main()
