"""ADR creation, MADR rendering, round trip and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.planning import adr
from aisdlc.schema import package as pkgio
from aisdlc.schema.grammar import IssueSeverity
from aisdlc.schema.models import AdrStatus, ArchitectureDecision, Intent, Kernel


def test_new_adr_ids_and_fields() -> None:
    first = adr.new_adr("Use TOTP", existing_ids=[], requirement_ids=["REQ-001"])
    assert first.id == "ADR-0001"
    assert first.decision.status is AdrStatus.PROPOSED
    assert first.decision.date is not None
    second = adr.new_adr("Next", existing_ids=[first.id, "REQ-001"], consequences=["a", " "])
    assert second.id == "ADR-0002"
    assert second.decision.consequences == ["a"]
    with pytest.raises(adr.AdrError):
        adr.new_adr("   ", existing_ids=[])
    with pytest.raises(adr.AdrError):
        adr.new_adr("bad supersedes", existing_ids=[], supersedes="nope")
    with pytest.raises(ValueError):
        adr.new_adr("bad req", existing_ids=[], requirement_ids=["TASK-001"])


def test_render_parse_round_trip_preserves_requirements_and_body() -> None:
    doc = adr.new_adr(
        "Use TOTP",
        existing_ids=[],
        status=AdrStatus.ACCEPTED,
        context="Users need a second factor.",
        decision="Use TOTP apps.",
        consequences=["No SMS costs"],
        alternatives=["SMS", "Push"],
        requirement_ids=["REQ-001", "REQ-002"],
        deciders=["kev"],
    )
    text = adr.render_adr(doc)
    assert text.startswith("---\nid: ADR-0001\n")
    assert "## Related requirements\n\n- REQ-001\n- REQ-002\n" in text
    assert "- SMS" in text and "Status: accepted" in text
    back = adr.parse_adr(text)
    assert back.decision == doc.decision
    assert back.requirement_ids == ["REQ-001", "REQ-002"]
    assert back.body == doc.body
    # editing the ids re-renders only the related section
    edited = back.model_copy(update={"requirement_ids": ["REQ-003"]})
    again = adr.parse_adr(adr.render_adr(edited))
    assert again.requirement_ids == ["REQ-003"]
    assert "Use TOTP apps." in again.body and again.body.count(adr.RELATED_SECTION) == 1


def test_with_related_section_insert_replace_remove() -> None:
    body = "# T\n\n## Decision\n\nd\n\n## Related requirements\n\n- REQ-001\n\n## Notes\n\nn\n"
    replaced = adr.with_related_section(body, ["REQ-002"])
    assert "- REQ-002" in replaced and "- REQ-001" not in replaced and "## Notes\n\nn\n" in replaced
    removed = adr.with_related_section(body, [])
    assert adr.RELATED_SECTION not in removed and "## Notes" in removed
    appended = adr.with_related_section("# T\n", ["REQ-009"])
    assert appended.endswith("## Related requirements\n\n- REQ-009\n")
    assert adr.with_related_section("# T\n", []) == "# T\n"
    assert adr.related_requirement_ids("no section") == []


def test_write_read_list_and_package_load(tmp_path: Path) -> None:
    intent = Intent(id="CHG-demo", title="Demo", owner="kev", kernel=Kernel(why="w"))
    pkg = pkgio.create(tmp_path, "CHG-demo", intent)
    root = pkg.root
    assert root is not None
    doc = adr.new_adr("Use TOTP", existing_ids=[], requirement_ids=["REQ-001"])
    path = adr.write_adr(root, doc)
    assert path == root / "architecture" / "decisions" / "ADR-0001.md"
    assert adr.read_adr(path).requirement_ids == ["REQ-001"]
    assert [d.id for d in adr.list_adrs(root)] == ["ADR-0001"]
    loaded = pkgio.load(root)
    assert loaded.decisions[0].title == "Use TOTP"
    loaded.save()  # package save keeps the body (and thus the related section)
    assert adr.read_adr(path).requirement_ids == ["REQ-001"]
    (root / "architecture" / "decisions" / "ADR-0002.md").write_text(adr.render_adr(doc))
    with pytest.raises(adr.AdrError, match="does not match"):
        adr.list_adrs(root)
    with pytest.raises(adr.AdrError):
        adr.parse_adr("no front matter")
    assert adr.list_adrs(tmp_path / "nowhere") == []


def _codes(issues: list[object]) -> set[str]:
    return {i.code for i in issues}  # type: ignore[attr-defined]


def test_validate_adr_proposed_vs_accepted() -> None:
    proposed = ArchitectureDecision(id="ADR-0001", title="x")
    issues = adr.validate_adr(proposed)
    assert {i.code: i.severity for i in issues} == {
        "ADR_CONTEXT_EMPTY": IssueSeverity.WARNING,
        "ADR_DECISION_EMPTY": IssueSeverity.WARNING,
        "ADR_NO_CONSEQUENCES": IssueSeverity.WARNING,
        "ADR_NO_REQUIREMENTS": IssueSeverity.WARNING,
    }
    accepted = ArchitectureDecision(id="ADR-0002", title=" ", status=AdrStatus.ACCEPTED)
    codes = {i.code: i.severity for i in adr.validate_adr(accepted, requirement_ids=["REQ-001"])}
    assert codes["ADR_TITLE_EMPTY"] is IssueSeverity.ERROR
    assert codes["ADR_CONTEXT_EMPTY"] is IssueSeverity.ERROR
    assert codes["ADR_DECISION_EMPTY"] is IssueSeverity.ERROR
    assert {"ADR_NO_ALTERNATIVES", "ADR_NO_DECIDERS", "ADR_NO_DATE"} <= set(codes)
    assert "ADR_NO_REQUIREMENTS" not in codes


def test_validate_adr_references() -> None:
    old = ArchitectureDecision(
        id="ADR-0001", title="old", status=AdrStatus.ACCEPTED, context="c", decision="d"
    )
    new = ArchitectureDecision(
        id="ADR-0002",
        title="new",
        status=AdrStatus.ACCEPTED,
        context="c",
        decision="d",
        supersedes="ADR-0001",
    )
    codes = _codes(
        adr.validate_adr(
            new, known_adrs=[old, new], requirement_ids=["REQ-009"], known_requirements=["REQ-001"]
        )
    )
    assert {"ADR_SUPERSEDED_TARGET_STATUS", "ADR_UNKNOWN_REQUIREMENT"} <= codes
    dangling = new.model_copy(update={"supersedes": "ADR-0009"})
    assert "ADR_SUPERSEDES_UNKNOWN" in _codes(adr.validate_adr(dangling, known_adrs=[old]))
    selfref = new.model_copy(update={"supersedes": "ADR-0002"})
    assert "ADR_SUPERSEDES_SELF" in _codes(adr.validate_adr(selfref))
    orphan = old.model_copy(update={"status": AdrStatus.SUPERSEDED})
    assert "ADR_SUPERSEDED_NO_SUCCESSOR" in _codes(adr.validate_adr(orphan, known_adrs=[orphan]))
    assert "ADR_SUPERSEDED_NO_SUCCESSOR" not in _codes(
        adr.validate_adr(orphan, known_adrs=[orphan, new])
    )


def test_validate_adrs_duplicates_and_chain() -> None:
    a = adr.AdrDocument(
        decision=ArchitectureDecision(id="ADR-0001", title="a", context="c", decision="d"),
        requirement_ids=["REQ-001"],
    )
    b = adr.AdrDocument(
        decision=ArchitectureDecision(id="ADR-0001", title="b", context="c", decision="d")
    )
    issues = adr.validate_adrs([a, b], known_requirements=["REQ-001"])
    assert "ADR_DUPLICATE_ID" in _codes(issues)
    assert not any(
        i.severity is IssueSeverity.ERROR and i.code != "ADR_DUPLICATE_ID" for i in issues
    )
