"""Every code citation in ``docs/plan-traceability.md`` points at something real.

Citations take the form ```path/to/file.py``` or ```path/to/file.py::symbol``` (repository
paths under ``src/``, ``tests/``, ``templates/`` or ``pilots/``) and bare test modules such
as ```test_grammar.py::test_valid_requirement_text``` (resolved under ``tests/``). A cited
symbol must be defined in the cited file as a function or class.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TRACEABILITY = REPO / "docs" / "plan-traceability.md"

_CITED_PATH_RE = re.compile(r"`((?:src|tests|templates|pilots)/[^`\s]+)`")
_BARE_TEST_RE = re.compile(r"`(test_[a-z0-9_]+\.py(?:::[A-Za-z_][\w.]*)?)`")


def _cited() -> list[str]:
    text = TRACEABILITY.read_text(encoding="utf-8")
    cited = {m.group(1) for m in _CITED_PATH_RE.finditer(text)}
    cited.update(f"tests/{m.group(1)}" for m in _BARE_TEST_RE.finditer(text))
    return sorted(cited)


@pytest.mark.parametrize("citation", _cited())
def test_traceability_citation_exists(citation: str) -> None:
    """The cited path exists and the cited symbol is defined in it."""
    if "{" in citation or "*" in citation:
        pytest.skip("brace/glob citation")
    path_part, _, symbol = citation.partition("::")
    target = REPO / path_part
    assert target.exists(), f"{citation}: {path_part} does not exist"
    if not symbol:
        return
    assert target.is_file(), f"{citation}: symbol cited on a directory"
    name = symbol.split(".")[0].split("(")[0]
    source = target.read_text(encoding="utf-8")
    pattern = re.compile(rf"^\s*(?:async\s+)?(?:def|class)\s+{re.escape(name)}\b", re.MULTILINE)
    assert pattern.search(source), f"{citation}: {name} is not defined in {path_part}"
