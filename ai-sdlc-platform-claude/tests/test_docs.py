"""Documentation regression tests.

The README and ``docs/`` document the real CLI: every relative link must resolve, every
``aisdlc <group> <command>`` invocation must exist in the typer application, and the
architecture decision records must be present and well formed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer
from typer.core import TyperCommand, TyperGroup
from typer.main import get_command

from aisdlc.cli.main import app

REPO = Path(__file__).resolve().parents[1]
DOC_FILES = [REPO / "README.md", *sorted((REPO / "docs").rglob("*.md"))]

_LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")
_TOKEN = r"[a-z][a-z-]*"
# An invocation is ``aisdlc`` (not part of a path or module name) followed on the same
# line by up to three lowercase tokens; anything else is an argument or prose.
_INVOCATION = re.compile(
    rf"(?<![/.\w-])aisdlc[ \t]+({_TOKEN})(?:[ \t]+({_TOKEN}))?(?:[ \t]+({_TOKEN}))?"
)
# Commands the docs mention explicitly as *not* existing.
_DOCUMENTED_AS_ABSENT = frozenset({"serve"})


def _doc_ids() -> list[str]:
    return [str(p.relative_to(REPO)) for p in DOC_FILES]


@pytest.mark.parametrize("doc", DOC_FILES, ids=_doc_ids())
def test_relative_links_resolve(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8")
    broken = [
        target
        for target in _LINK.findall(text)
        if not target.startswith(("http://", "https://", "mailto:"))
        and not (doc.parent / target).exists()
    ]
    assert broken == [], f"{doc.relative_to(REPO)}: broken links {broken}"


#: Typer registers every command as one of its own click subclasses (typer 0.27 vendors
#: click, so the public ``click`` types do not apply to this tree).
CommandNode = TyperCommand | TyperGroup


def _subcommands(node: CommandNode) -> dict[str, CommandNode] | None:
    """Return the subcommands of a group, ``None`` for a leaf command."""
    if not isinstance(node, TyperGroup):
        return None
    ctx = typer.Context(node)
    found: dict[str, CommandNode] = {}
    for name in node.list_commands(ctx):
        child = node.get_command(ctx, name)
        if isinstance(child, TyperCommand | TyperGroup):
            found[name] = child
    return found


def _root() -> TyperGroup:
    root = get_command(app)
    assert isinstance(root, TyperGroup), type(root)
    return root


def _resolve(root: CommandNode, tokens: tuple[str, ...]) -> str | None:
    """Return an error message when *tokens* do not name an existing command path."""
    node: CommandNode = root
    for depth, token in enumerate(tokens):
        children = _subcommands(node)
        if children is None:
            return None  # remaining tokens are arguments to a leaf command
        child = children.get(token)
        if child is None:
            if depth == 0 or token in _DOCUMENTED_AS_ABSENT:
                # ``aisdlc`` followed by prose (e.g. "aisdlc init scaffolds") is only
                # checked at the group level; documented-absent commands are allowed.
                return None if token in _DOCUMENTED_AS_ABSENT else f"unknown group {token!r}"
            return f"{' '.join(tokens[:depth])!r} has no subcommand {token!r}"
        node = child
    return None


@pytest.mark.parametrize("doc", DOC_FILES, ids=_doc_ids())
def test_documented_commands_exist(doc: Path) -> None:
    root = _root()
    assert _subcommands(root), "aisdlc root exposes no subcommands"
    text = doc.read_text(encoding="utf-8")
    problems: list[str] = []
    for match in _INVOCATION.finditer(text):
        tokens = tuple(t for t in match.groups() if t)
        error = _resolve(root, tokens)
        if error is not None:
            problems.append(f"'aisdlc {' '.join(tokens)}': {error}")
    assert problems == [], f"{doc.relative_to(REPO)}:\n  " + "\n  ".join(sorted(set(problems)))


def test_adrs_present_and_well_formed() -> None:
    adr_dir = REPO / "docs" / "adr"
    files = sorted(adr_dir.glob("ADR-*.md"))
    numbers = [f.name[:8] for f in files]
    assert numbers == [f"ADR-{n:04d}" for n in range(1, len(files) + 1)], numbers
    assert len(files) >= 5
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert text.startswith(f"# {path.name[:8]}:"), path.name
        assert re.search(r"^- Status: (proposed|accepted|superseded|deprecated)$", text, re.M), (
            path.name
        )
        for heading in ("## Context", "## Decision", "## Consequences"):
            assert heading in text, f"{path.name} lacks {heading!r}"


def test_plan_traceability_covers_every_cli_group() -> None:
    groups = _subcommands(_root()) or {}
    assert groups, "aisdlc root exposes no subcommands"
    text = (REPO / "docs" / "plan-traceability.md").read_text(encoding="utf-8")
    missing = [
        name for name in groups if f"aisdlc {name}" not in text and f"cmd_{name}" not in text
    ]
    assert missing == [], f"CLI groups not traced: {missing}"
