"""Tests for aisdlc.schema.package."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisdlc.schema import fingerprint as fp
from aisdlc.schema import markdown as md
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import (
    ArchitectureDecision,
    AuditEvidence,
    ChangePackage,
    ChangeState,
    CostEvidence,
    EvidenceKind,
    FinalVerdict,
    GateResult,
    Intent,
    Interface,
    Kernel,
    OpenQuestion,
    Plan,
    Requirement,
    ReviewEvidence,
    Scenario,
    SecurityEvidence,
    Task,
    TaskStatus,
    TestEvidence,
    Threat,
    ThreatModel,
    Verification,
    Wave,
)


def _intent(change_id: str = "CHG-demo") -> Intent:
    return Intent(
        id=change_id,
        title="Demo",
        owner="kevin",
        kernel=Kernel(why="w", capabilities=["c"], non_goals=["n"], success_signal="s"),
    )


@pytest.fixture
def pkg(tmp_path: Path) -> ChangePackage:
    return pkgio.create(tmp_path, "CHG-demo", _intent())


def test_create_layout(tmp_path: Path, pkg: ChangePackage) -> None:
    root = tmp_path / "changes" / "CHG-demo"
    assert pkg.root == root
    for rel in (
        "intent.md",
        "requirements.md",
        "assumptions.md",
        "plan.md",
        "tasks.md",
        "architecture/context.md",
        "architecture/threat-model.md",
        "evidence/tests.json",
        "evidence/reviews.json",
        ".fingerprint",
    ):
        assert (root / rel).is_file(), rel
    for sub in ("scenarios", "architecture/decisions", "architecture/interfaces", "handoffs"):
        assert (root / sub).is_dir(), sub
    assert (root / "evidence/tests.json").read_text() == "[]\n"
    assert "# Intent" in (root / "intent.md").read_text()
    assert pkg.base_fingerprint == fp.read_fingerprint(root)


def test_create_errors(tmp_path: Path, pkg: ChangePackage) -> None:
    with pytest.raises(pkgio.PackageError, match="already exists"):
        pkgio.create(tmp_path, "CHG-demo", _intent())
    with pytest.raises(pkgio.PackageError, match="does not match"):
        pkgio.create(tmp_path, "CHG-other", _intent())
    again = pkgio.create(tmp_path, "CHG-demo", _intent(), exist_ok=True)
    assert again.root == pkg.root


def test_create_uses_embedded_bodies_without_templates(tmp_path: Path) -> None:
    created = pkgio.create(tmp_path, "CHG-x", _intent("CHG-x"), templates_dir=tmp_path / "none")
    assert created.bodies["plan.md"] == pkgio.DEFAULT_BODIES["plan.md"]
    # a templates dir whose files lack front-matter still yields the body
    tdir = tmp_path / "tpl"
    tdir.mkdir()
    (tdir / "intent.md").write_text("plain body only\n")
    (tdir / "plan.md").write_text("---\nbroken: [\n---\nx\n")
    created2 = pkgio.create(tmp_path, "CHG-y", _intent("CHG-y"), templates_dir=tdir)
    assert created2.bodies["intent.md"] == "plain body only\n"
    assert created2.bodies["plan.md"] == pkgio.DEFAULT_BODIES["plan.md"]


def test_default_templates_dir_exists_in_checkout() -> None:
    assert pkgio.default_templates_dir() is not None


def _populate(pkg: ChangePackage) -> None:
    pkg.requirements = [
        Requirement(
            id="REQ-001",
            text="The system SHALL x.",
            scenarios=[Scenario(id="SCN-001-01", when="w", then="t")],
        )
    ]
    pkg.open_questions = [OpenQuestion(id="OQ-001", question="q?")]
    pkg.decisions = [ArchitectureDecision(id="ADR-0001", title="d")]
    pkg.interfaces = [Interface(id="IFC-001", name="n")]
    pkg.threat_model = ThreatModel(threats=[Threat(id="THR-001", title="t")])
    pkg.plan = Plan(waves=[Wave(index=0, task_ids=["TASK-001"])])
    pkg.tasks = [
        Task(
            id="TASK-001",
            title="t",
            requirement_ids=["REQ-001"],
            verification=Verification(command="true"),
        )
    ]
    pkg.evidence.tests = [TestEvidence(id="EVD-tests-001", command="pytest", exit_code=0)]
    pkg.evidence.cost = CostEvidence(id="EVD-cost-001", total_cost_usd=2.0)
    pkg.final_verdict = FinalVerdict(
        change_id="CHG-demo", gate_results=[GateResult(gate="G0", passed=True)]
    )
    pkg.bodies["intent.md"] = "# Custom prose — kept verbatim\n\n- bullet\n"
    pkg.bodies["architecture/decisions/ADR-0001.md"] = "## Context\nbecause\n"
    pkg.bodies["architecture/context.md"] = "# Context\nfree text\n"


def test_save_load_round_trip(pkg: ChangePackage) -> None:
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    loaded = pkgio.load(pkg.root)
    assert loaded.model_dump(mode="json") == pkg.model_dump(mode="json")
    assert loaded.bodies["intent.md"] == "# Custom prose — kept verbatim\n\n- bullet\n"
    assert loaded.bodies["architecture/decisions/ADR-0001.md"] == "## Context\nbecause\n"
    assert loaded.bodies["architecture/context.md"] == "# Context\nfree text\n"
    assert loaded.base_fingerprint == pkg.base_fingerprint
    assert (pkg.root / "architecture/decisions/ADR-0001.md").is_file()
    assert (pkg.root / "architecture/interfaces/IFC-001.md").is_file()
    assert (pkg.root / "final-verdict.json").is_file()
    assert pkgio.derive_state(loaded) is ChangeState.PLANNED
    # ChangePackage classmethods delegate here
    assert ChangePackage.load(pkg.root).change_id == "CHG-demo"


def test_save_requires_directory() -> None:
    with pytest.raises(pkgio.PackageError, match="no directory"):
        pkgio.save(ChangePackage(intent=_intent()))


def test_save_to_explicit_directory(tmp_path: Path) -> None:
    package = ChangePackage(intent=_intent())
    out = package.save(tmp_path / "elsewhere")
    assert (out / "intent.md").is_file()
    assert package.root == out


def test_load_merges_scenarios_dir(pkg: ChangePackage) -> None:
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    (pkg.root / "scenarios" / "REQ-001.md").write_text(
        "---\nrequirement_id: REQ-001\nscenarios:\n"
        "  - {id: SCN-001-01, when: dup, then: ignored}\n"
        "  - {id: SCN-001-02, raw: 'WHEN more THEN merged'}\n---\nnotes\n"
    )
    loaded = pkgio.load(pkg.root)
    req = loaded.requirement("REQ-001")
    assert req is not None
    assert [s.id for s in req.scenarios] == ["SCN-001-01", "SCN-001-02"]
    assert req.scenarios[0].when == "dup"  # the scenario file wins over a duplicate
    assert loaded.bodies["scenarios/REQ-001.md"] == "notes\n"
    assert loaded.scenario_files["scenarios/REQ-001.md"].scenario_ids == [
        "SCN-001-01",
        "SCN-001-02",
    ]
    assert loaded.file_owned_scenario_ids() == {"SCN-001-01", "SCN-001-02"}
    (pkg.root / "scenarios" / "REQ-009.md").write_text(
        "---\nrequirement_id: REQ-009\nscenarios: []\n---\n"
    )
    with pytest.raises(pkgio.PackageError, match="unknown requirement"):
        pkgio.load(pkg.root)


def test_load_errors(tmp_path: Path, pkg: ChangePackage) -> None:
    with pytest.raises(pkgio.PackageError, match="missing intent.md"):
        pkgio.load(tmp_path)
    assert pkg.root is not None
    (pkg.root / "tasks.md").write_text("---\ntasks:\n  - {id: BAD, title: x}\n---\n")
    with pytest.raises(pkgio.PackageError, match="tasks.md"):
        pkgio.load(pkg.root)
    (pkg.root / "tasks.md").write_text("---\ntasks: []\n---\n")
    (pkg.root / "evidence" / "cost.json").write_text("{not json")
    with pytest.raises(pkgio.PackageError, match="invalid JSON"):
        pkgio.load(pkg.root)
    (pkg.root / "evidence" / "cost.json").write_text('{"id": "EVD-cost-001", "kind": "nope"}')
    with pytest.raises(pkgio.PackageError):
        pkgio.load(pkg.root)
    (pkg.root / "evidence" / "cost.json").unlink()
    (pkg.root / "architecture/decisions/ADR-0002.md").write_text(
        "---\nid: ADR-0001\ntitle: mismatch\n---\n"
    )
    with pytest.raises(pkgio.PackageError, match="does not match ADR id"):
        pkgio.load(pkg.root)
    (pkg.root / "architecture/decisions/ADR-0002.md").unlink()
    (pkg.root / "architecture/interfaces/IFC-002.md").write_text("---\nid: IFC-001\nname: m\n---\n")
    with pytest.raises(pkgio.PackageError, match="does not match interface id"):
        pkgio.load(pkg.root)
    (pkg.root / "architecture/interfaces/IFC-002.md").unlink()
    (pkg.root / "intent.md").write_text("no front matter\n")
    with pytest.raises(pkgio.PackageError, match="intent.md"):
        pkgio.load(pkg.root)


def test_load_rejects_duplicate_requirements_across_files(pkg: ChangePackage) -> None:
    assert pkg.root is not None
    (pkg.root / "requirements.md").write_text(
        "---\nrequirements:\n  - {id: REQ-001, text: SHALL}\n  - {id: REQ-001, text: SHALL}\n---\n"
    )
    with pytest.raises(pkgio.PackageError, match="duplicate requirement"):
        pkgio.load(pkg.root)


def test_evidence_read_write_kinds(pkg: ChangePackage) -> None:
    root = pkg.root
    assert root is not None
    tests = [TestEvidence(id="EVD-tests-001"), TestEvidence(id="EVD-tests-002")]
    pkgio.write_evidence(root, "tests", tests)
    assert pkgio.read_evidence(root, EvidenceKind.TESTS) == tests
    sec = SecurityEvidence(id="EVD-security-001", sbom_present=True)
    path = pkgio.write_evidence(root, EvidenceKind.SECURITY, sec)
    assert path.name == "security.json"
    assert json.loads(path.read_text())["sbom_present"] is True
    assert pkgio.read_evidence(root, "security") == [sec]
    assert pkgio.read_evidence(root, "audit") == []
    with pytest.raises(pkgio.PackageError, match="expects"):
        pkgio.write_evidence(root, "tests", [sec])
    with pytest.raises(pkgio.PackageError, match="exactly one"):
        pkgio.write_evidence(root, "security", [sec, sec])
    # single-kind files may also be stored as a one-element list
    pkgio.write_json(
        pkgio.evidence_path(root, "audit"),
        [AuditEvidence(id="EVD-audit-001").model_dump(mode="json")],
    )
    assert len(pkgio.read_evidence(root, "audit")) == 1
    bundle = pkgio.load_evidence_bundle(root)
    assert bundle.audit is not None and bundle.security == sec and len(bundle.tests) == 2
    pkgio.write_json(
        pkgio.evidence_path(root, "cost"),
        [
            CostEvidence(id="EVD-cost-001").model_dump(mode="json"),
            CostEvidence(id="EVD-cost-002").model_dump(mode="json"),
        ],
    )
    with pytest.raises(pkgio.PackageError, match="expected one record"):
        pkgio.load_evidence_bundle(root)


def test_append_evidence(pkg: ChangePackage) -> None:
    root = pkg.root
    assert root is not None
    pkgio.append_evidence(root, ReviewEvidence(id="EVD-reviews-001", round=1))
    pkgio.append_evidence(root, ReviewEvidence(id="EVD-reviews-002", round=2))
    pkgio.append_evidence(root, ReviewEvidence(id="EVD-reviews-001", round=3))  # replaces
    reviews = pkgio.read_evidence(root, "reviews")
    assert [(r.id, r.round) for r in reviews] == [("EVD-reviews-002", 2), ("EVD-reviews-001", 3)]  # type: ignore[attr-defined]
    pkgio.append_evidence(root, CostEvidence(id="EVD-cost-001"))
    pkgio.append_evidence(root, CostEvidence(id="EVD-cost-002"))
    assert [c.id for c in pkgio.read_evidence(root, "cost")] == ["EVD-cost-002"]


def test_handoffs_and_verdict(pkg: ChangePackage) -> None:
    root = pkg.root
    assert root is not None
    assert pkgio.list_handoffs(root) == []
    p1 = pkgio.write_handoff(root, "wave-0-TASK-001", {"z": 1, "a": [1, 2]})
    p2 = pkgio.write_handoff(root, "wave-1.json", FinalVerdict(change_id="CHG-demo"))
    assert [p.name for p in pkgio.list_handoffs(root)] == [p1.name, p2.name]
    assert p1.read_text() == '{\n  "a": [\n    1,\n    2\n  ],\n  "z": 1\n}\n'
    assert pkgio.read_handoff(root, "wave-0-TASK-001")["z"] == 1
    assert pkgio.read_handoff(root, "wave-1.json")["change_id"] == "CHG-demo"
    with pytest.raises(pkgio.PackageError, match="invalid handoff"):
        pkgio.write_handoff(root, "../escape", {})
    assert pkgio.read_final_verdict(root) is None
    verdict = FinalVerdict(change_id="CHG-demo", overall=True)
    pkgio.write_final_verdict(root, verdict)
    assert pkgio.read_final_verdict(root) == verdict
    assert pkgio.load(root).derive_state() is ChangeState.RELEASED


def test_dump_json_is_deterministic() -> None:
    assert pkgio.dump_json({"b": 1, "a": {"d": None, "c": "é"}}) == (
        '{\n  "a": {\n    "c": "é",\n    "d": null\n  },\n  "b": 1\n}\n'
    )


def test_list_packages_and_package_dir(tmp_path: Path, pkg: ChangePackage) -> None:
    (tmp_path / "changes" / "not-a-package").mkdir()
    (tmp_path / "changes" / "stray.txt").write_text("x")
    assert [p.name for p in pkgio.list_packages(tmp_path)] == ["CHG-demo"]
    assert pkgio.list_packages(tmp_path / "nowhere") == []
    with pytest.raises(Exception, match="CHG"):
        pkgio.package_dir(tmp_path, "bad id")


def test_save_with_base_fingerprint_detects_concurrent_edit(pkg: ChangePackage) -> None:
    root = pkg.root
    assert root is not None
    base = pkg.base_fingerprint
    assert base is not None
    # a concurrent editor touches requirements.md
    other = pkgio.load(root)
    other.requirements = [Requirement(id="REQ-001", text="The system SHALL y.")]
    other.save(base_fingerprint=base)
    assert other.base_fingerprint != base
    pkg.intent.title = "renamed"
    with pytest.raises(fp.OptimisticConcurrencyError):
        pkg.save(base_fingerprint=base)
    # nothing was written
    assert "renamed" not in (root / "intent.md").read_text()
    # reload, reapply, succeed
    fresh = pkgio.load(root)
    fresh.intent.title = "renamed"
    fresh.save(base_fingerprint=fresh.base_fingerprint)
    reloaded = pkgio.load(root)
    assert reloaded.intent.title == "renamed"
    assert reloaded.requirement("REQ-001") is not None


def _scenario_file(then: str) -> str:
    return (
        "---\nrequirement_id: REQ-001\nscenarios:\n"
        f"  - {{id: SCN-001-01, when: original, then: {then}}}\n---\nnotes\n"
    )


def test_scenario_file_edits_survive_save_round_trip(pkg: ChangePackage) -> None:
    """Regression: scenarios/REQ-nnn.md edits used to be ignored after the first save."""
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    scenario_file = pkg.root / "scenarios" / "REQ-001.md"
    scenario_file.write_text(_scenario_file("original"))
    loaded = pkgio.load(pkg.root)
    loaded.save()
    # requirements.md no longer carries the file-owned scenario
    on_disk, _ = md.requirements_from_markdown((pkg.root / "requirements.md").read_text())
    assert [s.id for r in on_disk for s in r.scenarios] == []
    assert "then: original" in scenario_file.read_text()
    assert scenario_file.read_text().endswith("notes\n")
    scenario_file.write_text(_scenario_file("HUMAN EDITED"))
    reloaded = pkgio.load(pkg.root)
    req = reloaded.requirement("REQ-001")
    assert req is not None and req.scenarios[0].then == "HUMAN EDITED"
    # in-memory edits go back to the file, not to requirements.md
    req.scenarios[0].then = "AGENT EDITED"
    reloaded.save()
    assert "AGENT EDITED" in scenario_file.read_text()
    assert "AGENT EDITED" not in (pkg.root / "requirements.md").read_text()
    assert pkgio.load(pkg.root).requirement("REQ-001").scenarios[0].then == "AGENT EDITED"  # type: ignore[union-attr]


def test_scenario_file_is_pruned_with_its_requirement(pkg: ChangePackage) -> None:
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    scenario_file = pkg.root / "scenarios" / "REQ-001.md"
    scenario_file.write_text(_scenario_file("x"))
    loaded = pkgio.load(pkg.root)
    req = loaded.requirement("REQ-001")
    assert req is not None
    # dropping the scenario drops it from the file's ownership record
    req.scenarios = [Scenario(id="SCN-001-09", when="new", then="in requirements.md")]
    loaded.save()
    assert loaded.scenario_files["scenarios/REQ-001.md"].scenario_ids == []
    again = pkgio.load(pkg.root)
    assert [s.id for s in again.requirement("REQ-001").scenarios] == ["SCN-001-09"]  # type: ignore[union-attr]
    assert "SCN-001-09" in (pkg.root / "requirements.md").read_text()
    # dropping the requirement removes the file (a file for an unknown requirement is an error)
    again.requirements = [r for r in again.requirements if r.id != "REQ-001"]
    again.save()
    assert not scenario_file.exists() and "scenarios/REQ-001.md" not in again.scenario_files
    assert pkgio.load(pkg.root).requirement("REQ-001") is None


def test_scenario_defined_in_two_files_is_rejected(pkg: ChangePackage) -> None:
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    (pkg.root / "scenarios" / "REQ-001.md").write_text(_scenario_file("a"))
    (pkg.root / "scenarios" / "REQ-001-more.md").write_text(_scenario_file("b"))
    with pytest.raises(pkgio.PackageError, match="also defined"):
        pkgio.load(pkg.root)


def test_save_produced_state_keeps_concurrent_authored_edits(pkg: ChangePackage) -> None:
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    producer = pkgio.load(pkg.root)
    # a human edits requirements.md and the plan while the producer runs
    human = pkgio.load(pkg.root)
    human.requirements[0].text = "The system SHALL do the HUMAN EDIT."
    human.bodies["requirements.md"] = "HUMAN EDIT\n"
    human.save(base_fingerprint=human.base_fingerprint)
    # the producer only changes task status and evidence
    producer.tasks[0].status = TaskStatus.DONE
    producer.evidence.tests.append(
        TestEvidence(id="EVD-tests-009", command="pytest", exit_code=0, passed=1)
    )
    pkgio.save_produced_state(producer)
    reloaded = pkgio.load(pkg.root)
    assert "HUMAN EDIT" in (pkg.root / "requirements.md").read_text()
    assert reloaded.requirements[0].text == "The system SHALL do the HUMAN EDIT."
    assert reloaded.tasks[0].status is TaskStatus.DONE
    assert [e.id for e in reloaded.evidence.tests][-1] == "EVD-tests-009"
    # the in-memory producer package adopted the merged content and a fresh base
    assert producer.requirements[0].text == "The system SHALL do the HUMAN EDIT."
    assert producer.base_fingerprint == reloaded.base_fingerprint
    # and a plain guarded save now succeeds again
    producer.save(base_fingerprint=producer.base_fingerprint)


def test_merge_packages_three_way(pkg: ChangePackage) -> None:
    _populate(pkg)
    pkg.save()
    assert pkg.root is not None
    base = pkgio.load(pkg.root)
    ours = base.model_copy(deep=True)
    theirs = base.model_copy(deep=True)
    ours.intent.kernel.why = "ours"
    theirs.requirements[0].text = "The system SHALL be theirs."
    theirs.bodies["plan.md"] = "their plan\n"
    result = fp.merge_packages(base, ours, theirs)
    assert result.clean
    assert result.package.intent.kernel.why == "ours"
    assert result.package.requirements[0].text == "The system SHALL be theirs."
    assert result.package.bodies["plan.md"] == "their plan\n"
    # both sides edit the same artifact differently -> conflict, ours kept
    ours.tasks[0].title = "ours"
    theirs.tasks[0].title = "theirs"
    ours.bodies["plan.md"] = "our plan\n"
    conflicted = fp.merge_packages(base, ours, theirs)
    assert conflicted.field_conflicts == ["tasks", "bodies[plan.md]"]
    assert not conflicted.clean
    assert conflicted.package.tasks[0].title == "ours"
