"""Tests for aisdlc.schema.markdown."""

from __future__ import annotations

import pytest

from aisdlc.schema import markdown as md
from aisdlc.schema.models import (
    ArchitectureDecision,
    Assumption,
    Intent,
    Interface,
    Kernel,
    OpenQuestion,
    Plan,
    Requirement,
    Scenario,
    Task,
    Threat,
    ThreatModel,
    ToolDataManifest,
    Verification,
    Wave,
)

BODIES = [
    "",
    "# Title\n\nSome prose.\n",
    "\n\nleading blank lines\n",
    "no trailing newline",
    "contains\n---\na horizontal rule\n---\n",
    "unicode: café — ✓\n",
    "  indented\n\ttabbed\n",
]


@pytest.mark.parametrize("body", BODIES)
def test_front_matter_round_trip_preserves_body(body: str) -> None:
    data = {"a": 1, "b": ["x", "y"], "c": {"d": None}}
    text = md.join_front_matter(data, body)
    parsed, out = md.split_front_matter(text)
    assert parsed == data
    assert out == body


def test_split_without_front_matter() -> None:
    assert md.split_front_matter("# just prose\n") == (None, "# just prose\n")
    assert md.split_front_matter("") == (None, "")


def test_split_errors() -> None:
    with pytest.raises(md.FrontMatterError, match="never closed"):
        md.split_front_matter("---\na: 1\n")
    with pytest.raises(md.FrontMatterError, match="mapping"):
        md.split_front_matter("---\n- a\n- b\n---\n")
    with pytest.raises(md.FrontMatterError, match="invalid YAML"):
        md.split_front_matter("---\na: [\n---\n")
    with pytest.raises(md.FrontMatterError, match="missing front-matter"):
        md.parse_model("no front matter", Intent)


def test_empty_front_matter_is_empty_mapping() -> None:
    assert md.split_front_matter("---\n---\nbody\n") == ({}, "body\n")


def test_crlf_delimiters_tolerated() -> None:
    data, body = md.split_front_matter("---\r\na: 1\r\n---\r\nbody")
    assert data == {"a": 1}
    assert body == "body"


def test_intent_round_trip() -> None:
    intent = Intent(
        id="CHG-x",
        title="X",
        owner="me",
        kernel=Kernel(
            why="w", capabilities=["a"], constraints=["c"], non_goals=["n"], success_signal="s"
        ),
        risk_class="high",
    )
    text = md.intent_to_markdown(intent, "# X\n")
    assert text.startswith("---\nid: CHG-x\n")
    back, body = md.intent_from_markdown(text)
    assert back == intent and body == "# X\n"


def test_requirements_round_trip() -> None:
    reqs = [
        Requirement(
            id="REQ-001",
            text="The system SHALL x.",
            scenarios=[
                Scenario(id="SCN-001-01", when="w", then="t"),
                Scenario(id="SCN-001-02", raw="WHEN a THEN b"),
            ],
            tags=["auth"],
        )
    ]
    back, body = md.requirements_from_markdown(md.requirements_to_markdown(reqs, "b\n"))
    assert back == reqs and body == "b\n"
    empty, _ = md.requirements_from_markdown("---\n---\n")
    assert empty == []
    with pytest.raises(md.FrontMatterError, match="must be a list"):
        md.requirements_from_markdown("---\nrequirements: nope\n---\n")
    with pytest.raises(md.FrontMatterError, match="missing"):
        md.requirements_from_markdown("prose only")


def test_assumptions_round_trip() -> None:
    asm = [Assumption(id="ASM-001", text="a", owner="o")]
    oqs = [OpenQuestion(id="OQ-001", question="q?", blocking=True)]
    a, q, body = md.assumptions_from_markdown(md.assumptions_to_markdown(asm, oqs, "body"))
    assert (a, q, body) == (asm, oqs, "body")
    with pytest.raises(md.FrontMatterError):
        md.assumptions_from_markdown("prose")


def test_plan_and_tasks_round_trip() -> None:
    plan = Plan(summary="s", waves=[Wave(index=0, task_ids=["TASK-001"], checkpoint=True)])
    back, _ = md.plan_from_markdown(md.plan_to_markdown(plan))
    assert back == plan
    tasks = [
        Task(
            id="TASK-001",
            title="t",
            requirement_ids=["REQ-001"],
            verification=Verification(command="pytest -q", expect_output_regex="passed"),
            wave=0,
            model_tier="standard",
        )
    ]
    back_tasks, body = md.tasks_from_markdown(md.tasks_to_markdown(tasks, "x"))
    assert back_tasks == tasks and body == "x"
    with pytest.raises(md.FrontMatterError):
        md.tasks_from_markdown("prose")


def test_threat_model_adr_interface_round_trip() -> None:
    tm = ThreatModel(
        assets=["db"],
        actors=["attacker"],
        threats=[Threat(id="THR-001", title="inj", category="prompt_injection", severity="high")],
        tool_data_manifest=ToolDataManifest(tools=["Read"], network_egress=["api.example.com"]),
    )
    back, _ = md.threat_model_from_markdown(md.threat_model_to_markdown(tm, ""))
    assert back == tm
    adr = ArchitectureDecision(id="ADR-0001", title="d", status="accepted", alternatives=["x"])
    back_adr, body = md.adr_from_markdown(md.adr_to_markdown(adr, "## Context\n"))
    assert back_adr == adr and body == "## Context\n"
    ifc = Interface(id="IFC-001", name="n", consumers=["svc"])
    back_ifc, _ = md.interface_from_markdown(md.interface_to_markdown(ifc))
    assert back_ifc == ifc


def test_scenarios_file_round_trip() -> None:
    scenarios = [Scenario(id="SCN-002-01", given="g", when="w", then="t")]
    text = md.scenarios_to_markdown("REQ-002", scenarios, "notes\n")
    rid, back, body = md.scenarios_from_markdown(text)
    assert (rid, back, body) == ("REQ-002", scenarios, "notes\n")
    with pytest.raises(md.FrontMatterError, match="requirement_id"):
        md.scenarios_from_markdown("---\nscenarios: []\n---\n")
    with pytest.raises(md.FrontMatterError, match="missing"):
        md.scenarios_from_markdown("prose")


def test_model_to_data_drops_none_keeps_defaults() -> None:
    data = md.model_to_data(Intent(id="CHG-x", title="t"))
    assert "owner" not in data
    assert data["risk_class"] == "standard"
    assert data["stakeholders"] == []
