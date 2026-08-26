"""Tests for aisdlc.schema.fingerprint."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.schema import fingerprint as fp
from aisdlc.schema.models import Requirement, Scenario


def _layout(root: Path) -> None:
    (root / "intent.md").write_text("---\nid: CHG-x\ntitle: x\n---\n")
    (root / "requirements.md").write_text("---\nrequirements: []\n---\n")
    (root / "architecture" / "decisions").mkdir(parents=True)
    (root / "architecture" / "decisions" / "ADR-0001.md").write_text("---\nid: ADR-0001\n---\n")
    (root / "evidence").mkdir()
    (root / "evidence" / "tests.json").write_text("[]\n")


def test_fingerprint_covers_only_authored_artifacts(tmp_path: Path) -> None:
    _layout(tmp_path)
    files = [p.relative_to(tmp_path).as_posix() for p in fp.canonical_files(tmp_path)]
    assert files == ["architecture/decisions/ADR-0001.md", "intent.md", "requirements.md"]
    base = fp.compute_fingerprint(tmp_path)
    assert len(base) == 64 and base == fp.compute_fingerprint(tmp_path)
    (tmp_path / "evidence" / "tests.json").write_text('[{"x": 1}]\n')
    (tmp_path / "final-verdict.json").write_text("{}\n")
    fp.write_fingerprint(tmp_path)
    assert fp.compute_fingerprint(tmp_path) == base
    (tmp_path / "requirements.md").write_text("---\nrequirements: [1]\n---\n")
    assert fp.compute_fingerprint(tmp_path) != base
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios" / "REQ-001.md").write_text("---\n---\n")
    assert len(fp.canonical_files(tmp_path)) == 4


def test_read_write_fingerprint(tmp_path: Path) -> None:
    _layout(tmp_path)
    assert fp.read_fingerprint(tmp_path) is None
    value = fp.write_fingerprint(tmp_path)
    assert (tmp_path / ".fingerprint").read_text() == value + "\n"
    assert fp.read_fingerprint(tmp_path) == value
    fp.write_fingerprint(tmp_path, "abc")
    assert fp.read_fingerprint(tmp_path) == "abc"
    (tmp_path / ".fingerprint").write_text("  \n")
    assert fp.read_fingerprint(tmp_path) is None


def test_check_and_update(tmp_path: Path) -> None:
    _layout(tmp_path)
    base = fp.write_fingerprint(tmp_path)
    assert fp.check_fingerprint(tmp_path, base) == base
    calls: list[str] = []

    def apply() -> None:
        (tmp_path / "intent.md").write_text("---\nid: CHG-x\ntitle: changed\n---\n")
        calls.append("applied")

    new = fp.check_and_update(tmp_path, base, apply)
    assert calls == ["applied"] and new != base and fp.read_fingerprint(tmp_path) == new
    # stale base: apply must not run
    with pytest.raises(fp.OptimisticConcurrencyError) as excinfo:
        fp.check_and_update(tmp_path, base, apply)
    assert calls == ["applied"]
    assert excinfo.value.expected == base and excinfo.value.actual == new
    assert excinfo.value.directory == tmp_path
    assert "changed concurrently" in str(excinfo.value)
    assert fp.check_and_update(tmp_path, new) == new


# --------------------------------------------------------------------------------------
# Semantic merge
# --------------------------------------------------------------------------------------


def _r(
    rid: str, text: str = "The system SHALL x.", scns: list[Scenario] | None = None, **kw: object
) -> Requirement:
    return Requirement(id=rid, text=text, scenarios=scns or [], **kw)  # type: ignore[arg-type]


def _s(sid: str, when: str = "w", then: str = "t") -> Scenario:
    return Scenario(id=sid, when=when, then=then)


def test_merge_no_changes_and_one_sided_changes() -> None:
    base = [_r("REQ-001", scns=[_s("SCN-001-01")]), _r("REQ-002")]
    result = fp.merge_requirements(base, base, base)
    assert result.clean and result.merged == base and not result.added and not result.removed

    ours = [_r("REQ-001", "The system SHALL y.", scns=[_s("SCN-001-01")]), _r("REQ-002")]
    theirs = [_r("REQ-001", scns=[_s("SCN-001-01")]), _r("REQ-002", priority="should")]
    merged = fp.merge_requirements(base, ours, theirs)
    assert merged.clean
    assert merged.merged[0].text == "The system SHALL y."
    assert merged.merged[1].priority.value == "should"


def test_merge_scalar_conflict_keeps_ours_and_reports() -> None:
    base = [_r("REQ-001")]
    ours = [_r("REQ-001", "The system SHALL ours.")]
    theirs = [_r("REQ-001", "The system SHALL theirs.")]
    result = fp.merge_requirements(base, ours, theirs)
    assert not result.clean
    assert result.merged[0].text == "The system SHALL ours."
    conflict = result.conflicts[0]
    assert (conflict.requirement_id, conflict.field) == ("REQ-001", "text")
    assert conflict.base == "The system SHALL x."
    assert conflict.theirs == "The system SHALL theirs."
    # same edit on both sides is not a conflict
    assert fp.merge_requirements(base, ours, ours).clean


def test_merge_scenarios_union_never_drops() -> None:
    base = [_r("REQ-001", scns=[_s("SCN-001-01"), _s("SCN-001-02")])]
    ours = [_r("REQ-001", scns=[_s("SCN-001-01"), _s("SCN-001-03")])]  # dropped 02, added 03
    theirs = [_r("REQ-001", scns=[_s("SCN-001-02", then="edited"), _s("SCN-001-04")])]  # dropped 01
    result = fp.merge_requirements(base, ours, theirs)
    assert result.clean
    scenario_ids = [s.id for s in result.merged[0].scenarios]
    assert scenario_ids == ["SCN-001-01", "SCN-001-02", "SCN-001-03", "SCN-001-04"]
    assert result.merged[0].scenarios[1].then == "edited"
    assert any("never dropped" in n for n in result.notes)
    both_drop = fp.merge_requirements(
        base, [_r("REQ-001", scns=[_s("SCN-001-01")])], [_r("REQ-001", scns=[_s("SCN-001-01")])]
    )
    assert [s.id for s in both_drop.merged[0].scenarios] == ["SCN-001-01", "SCN-001-02"]
    assert any("both sides" in n for n in both_drop.notes)


def test_merge_scenario_conflict() -> None:
    base = [_r("REQ-001", scns=[_s("SCN-001-01")])]
    ours = [_r("REQ-001", scns=[_s("SCN-001-01", then="ours")])]
    theirs = [_r("REQ-001", scns=[_s("SCN-001-01", then="theirs")])]
    result = fp.merge_requirements(base, ours, theirs)
    assert len(result.conflicts) == 1
    assert result.conflicts[0].scenario_id == "SCN-001-01"
    assert result.conflicts[0].field == "scenarios"
    assert result.merged[0].scenarios[0].then == "ours"


def test_merge_deletions() -> None:
    base = [_r("REQ-001"), _r("REQ-002"), _r("REQ-003")]
    ours = [_r("REQ-002", "The system SHALL edited."), _r("REQ-003")]  # deleted 001, edited 002
    theirs = [_r("REQ-001"), _r("REQ-003")]  # deleted 002 (which ours edited)
    result = fp.merge_requirements(base, ours, theirs)
    assert result.removed == ["REQ-001"]
    assert [r.id for r in result.merged] == ["REQ-002", "REQ-003"]
    assert len(result.conflicts) == 1 and result.conflicts[0].requirement_id == "REQ-002"
    assert result.conflicts[0].field == "*" and result.conflicts[0].theirs is None
    # mirror case: deleted on ours, edited on theirs
    mirror = fp.merge_requirements(base, theirs, ours)
    assert mirror.conflicts[0].ours is None and mirror.merged[0].text == "The system SHALL edited."
    # deleted on both
    both = fp.merge_requirements(base, [_r("REQ-003")], [_r("REQ-003")])
    assert both.removed == ["REQ-001", "REQ-002"] and both.clean


def test_merge_additions_and_order() -> None:
    base = [_r("REQ-001")]
    ours = [_r("REQ-001"), _r("REQ-003", scns=[_s("SCN-003-01")])]
    theirs = [_r("REQ-001"), _r("REQ-002"), _r("REQ-003", scns=[_s("SCN-003-02")])]
    result = fp.merge_requirements(base, ours, theirs)
    assert [r.id for r in result.merged] == ["REQ-001", "REQ-003", "REQ-002"]
    assert sorted(result.added) == ["REQ-002", "REQ-003"]
    assert result.clean  # identical scalar fields, scenarios unioned
    assert [s.id for s in result.merged[1].scenarios] == ["SCN-003-01", "SCN-003-02"]
    clash = fp.merge_requirements(
        base, [_r("REQ-001"), _r("REQ-002", "SHALL a")], [_r("REQ-001"), _r("REQ-002", "SHALL b")]
    )
    assert clash.conflicts[0].base is None and clash.merged[1].text == "SHALL a"
