"""Architecture tests: the engine never depends on generated code; generated code is fresh."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from lowcode import generator
from lowcode.schema import FormSpec

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "lowcode"
FORMS = ROOT / "forms"


def imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class LayeringTest(unittest.TestCase):
    def test_engine_modules_never_import_generated_code(self) -> None:
        for path in ENGINE.glob("*.py"):
            names = imports_of(path)
            self.assertFalse({n for n in names if n.startswith("lowcode.generated")}, path.name)

    def test_generated_modules_only_use_the_public_runtime(self) -> None:
        allowed = {"lowcode.app", "lowcode.schema"}
        for path in (ENGINE / "generated").glob("*.py"):
            if path.name == "__init__.py":
                continue
            local = {n for n in imports_of(path) if n.startswith("lowcode")}
            self.assertTrue(local <= allowed, f"{path.name}: {local - allowed}")

    def test_checked_in_generated_code_matches_its_form(self) -> None:
        for form in FORMS.glob("*.json"):
            spec = FormSpec.load(form)
            generated = ENGINE / "generated" / f"{spec.slug}.py"
            self.assertTrue(generated.is_file(), generated)
            expected = generator.render(spec, source=form.relative_to(ROOT).as_posix())
            self.assertEqual(generated.read_text(encoding="utf-8"), expected, generated.name)


if __name__ == "__main__":
    unittest.main()
