"""Tests for aisdlc.ids."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from aisdlc import ids

VALID = {
    "CHG": "CHG-add-login-mfa",
    "REQ": "REQ-003",
    "SCN": "SCN-003-01",
    "ASM": "ASM-001",
    "OQ": "OQ-010",
    "ADR": "ADR-0001",
    "IFC": "IFC-001",
    "THR": "THR-002",
    "TASK": "TASK-001",
    "TEST": "TEST-999",
    "FND": "FND-001",
    "EVD": "EVD-tests-001",
    "BM": "BM-code-review-v1.2",
}

INVALID = [
    ("CHG", "CHG-Add-Login"),
    ("CHG", "CHG-"),
    ("CHG", "CHG--x"),
    ("REQ", "REQ-3"),
    ("REQ", "REQ-03"),
    ("REQ", "req-003"),
    ("SCN", "SCN-003"),
    ("SCN", "SCN-003-1"),
    ("ADR", "ADR-001"),
    ("EVD", "EVD-001"),
    ("EVD", "EVD-Tests-001"),
    ("BM", "BM-slug"),
    ("TASK", "TASK-001 "),
    ("TASK", ""),
]


@pytest.mark.parametrize(("kind", "value"), list(VALID.items()))
def test_valid_ids(kind: str, value: str) -> None:
    assert ids.is_valid(kind, value)
    assert ids.validate_id(kind, value) == value
    assert ids.kind_of(value) == kind


@pytest.mark.parametrize(("kind", "value"), INVALID)
def test_invalid_ids(kind: str, value: str) -> None:
    assert not ids.is_valid(kind, value)
    with pytest.raises(ids.InvalidIdError) as excinfo:
        ids.validate_id(kind, value)
    assert kind in str(excinfo.value)
    assert excinfo.value.kind == kind


def test_kinds_and_patterns_cover_all() -> None:
    assert set(ids.KINDS) == set(ids.PATTERNS)
    assert ids.kind_of("nonsense") is None
    assert not ids.is_valid("REQ", 42)


def test_unknown_kind_raises() -> None:
    with pytest.raises(ValueError, match="unknown identifier kind"):
        ids.is_valid("XYZ", "XYZ-001")
    with pytest.raises(ValueError, match="unknown identifier kind"):
        ids.next_id("XYZ", [])


def test_numeric_suffix_and_components() -> None:
    assert ids.numeric_suffix("REQ-042") == 42
    assert ids.numeric_suffix("ADR-0007") == 7
    assert ids.numeric_suffix("SCN-003-12") == 12
    assert ids.scenario_parent("SCN-003-12") == "REQ-003"
    assert ids.evidence_kind_of("EVD-security-002") == "security"
    with pytest.raises(ids.InvalidIdError):
        ids.numeric_suffix("CHG-slug")
    with pytest.raises(ids.InvalidIdError):
        ids.scenario_parent("REQ-001")
    with pytest.raises(ids.InvalidIdError):
        ids.evidence_kind_of("EVD-001")


def test_next_id_numeric() -> None:
    assert ids.next_id("REQ", []) == "REQ-001"
    assert ids.next_id("REQ", ["REQ-001", "REQ-003"]) == "REQ-004"
    assert ids.next_id("ADR", ["ADR-0009", "REQ-100"]) == "ADR-0010"
    assert ids.next_id("TASK", ["TASK-999"]) == "TASK-1000"
    # malformed and foreign ids are ignored
    assert ids.next_id("FND", ["FND-x", "TASK-005"]) == "FND-001"


def test_next_id_scenario_and_evidence() -> None:
    existing = ["SCN-001-01", "SCN-001-02", "SCN-002-01"]
    assert ids.next_id("SCN", existing, parent="REQ-001") == "SCN-001-03"
    assert ids.next_id("SCN", existing, parent="REQ-002") == "SCN-002-02"
    assert ids.next_id("SCN", existing, parent="REQ-003") == "SCN-003-01"
    with pytest.raises(ValueError, match="requires parent"):
        ids.next_id("SCN", existing)
    with pytest.raises(ids.InvalidIdError):
        ids.next_id("SCN", existing, parent="TASK-001")

    evidence = ["EVD-tests-001", "EVD-tests-002", "EVD-reviews-001"]
    assert ids.next_id("EVD", evidence, evidence_kind="tests") == "EVD-tests-003"
    assert ids.next_id("EVD", evidence, evidence_kind="security") == "EVD-security-001"
    with pytest.raises(ValueError, match="requires evidence_kind"):
        ids.next_id("EVD", evidence)
    with pytest.raises(ValueError, match="invalid evidence kind"):
        ids.next_id("EVD", evidence, evidence_kind="Bad Kind")


def test_next_id_slug_kinds_not_generated() -> None:
    with pytest.raises(ValueError, match="slug-based"):
        ids.next_id("CHG", [])
    with pytest.raises(ValueError, match="slug-based"):
        ids.next_id("BM", [])


def test_slugify_and_change_id() -> None:
    assert ids.slugify("Add Login MFA!") == "add-login-mfa"
    assert ids.slugify("  Ünïcode -- text ") == "unicode-text"
    assert ids.change_id("Add login MFA") == "CHG-add-login-mfa"
    assert ids.is_valid("CHG", ids.change_id("Rotate keys (v2)"))
    assert len(ids.slugify("x" * 100, max_length=10)) == 10
    with pytest.raises(ValueError, match="cannot derive"):
        ids.slugify("!!!")


def test_annotated_aliases_validate_in_models() -> None:
    class M(BaseModel):
        req: ids.RequirementId
        evd: ids.EvidenceId

    assert M(req="REQ-001", evd="EVD-cost-001").req == "REQ-001"
    with pytest.raises(ValidationError):
        M(req="REQ-1", evd="EVD-cost-001")
