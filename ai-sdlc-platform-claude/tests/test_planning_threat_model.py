"""Threat model seeding and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisdlc.planning import threat_model as tm
from aisdlc.policy.project_config import ProjectConfig
from aisdlc.schema import package as pkgio
from aisdlc.schema.grammar import IssueSeverity
from aisdlc.schema.models import (
    Intent,
    Interface,
    InterfaceKind,
    Kernel,
    Mitigation,
    Requirement,
    RiskClass,
    Scenario,
    Severity,
    Threat,
    ThreatCategory,
    ThreatModel,
    ThreatStatus,
    ToolDataManifest,
)


def _intent(title: str = "Add login MFA", risk: RiskClass = RiskClass.STANDARD) -> Intent:
    return Intent(id="CHG-demo", title=title, owner="kev", kernel=Kernel(why="w"), risk_class=risk)


def _req(num: int, text: str) -> Requirement:
    return Requirement(
        id=f"REQ-{num:03d}",
        text=text,
        scenarios=[Scenario(id=f"SCN-{num:03d}-01", when="x", then="y")],
    )


def _codes(issues: list[object]) -> set[str]:
    return {i.code for i in issues}  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("name", "tier"),
    [
        ("read_file", 0),
        ("grep_search", 0),
        ("write_file", 1),
        ("run_tests", 2),
        ("web_fetch", 2),
        ("git_push", 3),
        ("create_pull_request", 3),
        ("send_email", 3),
        ("deploy_service", 4),
        ("rotate_secrets", 4),
        ("delete_records", 4),
        ("mystery_tool", 3),  # unknown -> fail closed
    ],
)
def test_tool_tier_table(name: str, tier: int) -> None:
    assert tm.tool_tier(name) == tier


def test_tool_tier_overrides_clamped() -> None:
    assert tm.tool_tier("read_file", {"read_file": 9}) == 4
    assert tm.tool_tier("deploy", {"deploy": -1}) == 0


@pytest.mark.parametrize(
    ("entry", "ok"),
    [
        ("api.example.com", True),
        ("https://api.example.com/v1", True),
        ("localhost:8080", True),
        ("10.0.0.5", True),
        ("*.example.com", False),
        ("*", False),
        ("any", False),
        ("10.0.0.0/8", False),
        ("", False),
        ("not a host", False),
    ],
)
def test_is_enumerated_host(entry: str, ok: bool) -> None:
    assert tm.is_enumerated_host(entry) is ok


def test_init_seeds_from_manifest_interfaces_and_keywords() -> None:
    manifest = ToolDataManifest(
        tools=["web_fetch", "git_push", "read_file"],
        data_sources=["customer_db"],
        network_egress=["api.example.com"],
    )
    interfaces = [Interface(id="IFC-001", name="Device store", kind=InterfaceKind.API)]
    model = tm.init_threat_model(
        _intent(),
        [_req(1, "The system SHALL require MFA on login and store secrets in KMS.")],
        ProjectConfig(critical_modules=["src/core/"]),
        interfaces=interfaces,
        manifest=manifest,
    )
    assert {
        "source code",
        "credentials",
        "secrets",
        "module:src/core/",
        "interface:IFC-001",
        "tool:web_fetch",
        "data:customer_db",
        "egress:api.example.com",
    } <= set(model.assets)
    assert {
        "end user",
        "maintainer",
        "external attacker",
        "implementer agent",
        "third-party service",
        "untrusted content author",
    } <= set(model.actors)
    titles = {t.title for t in model.threats}
    assert "Credential theft or session hijack" in titles
    assert "Secret leakage" in titles
    assert "Unauthorised access to Device store" in titles
    assert "Prompt injection via web_fetch results" in titles
    assert "Unapproved privileged use of git_push (tier 3)" in titles
    assert "Disclosure of customer_db through agent output" in titles
    assert "Data exfiltration to api.example.com" in titles
    assert "Compromised third-party dependency" in titles
    # tool threats carry mitigations; keyword seeds stay open without one
    push = next(t for t in model.threats if "git_push (tier 3)" in t.title)
    assert push.severity is Severity.HIGH and push.category is ThreatCategory.ELEVATION_OF_PRIVILEGE
    mitigation = next(m for m in model.mitigations if m.id in push.mitigation_ids)
    assert "approval" in mitigation.description.lower() and push.id in mitigation.threat_ids
    assert not mitigation.verified
    ids = [t.id for t in model.threats]
    assert ids == sorted(ids) and ids[0] == "THR-001"
    assert model.tool_data_manifest == manifest
    # everything open and high blocks G1
    assert len(tm.unresolved_high_risk(model)) >= 5
    ThreatModel.model_validate(model.model_dump(mode="json"))


def test_init_is_idempotent_and_merges_manifest() -> None:
    first = tm.init_threat_model(_intent(), [], manifest=ToolDataManifest(tools=["web_fetch"]))
    count = len(first.threats)
    again = tm.init_threat_model(
        _intent(),
        [],
        existing=first,
        manifest=ToolDataManifest(tools=["web_fetch", "deploy_service"]),
    )
    assert len(again.threats) == count + 2  # prompt injection + tier-4 escalation for the new tool
    assert again.tool_data_manifest.tools == ["web_fetch", "deploy_service"]
    assert [t.id for t in again.threats[:count]] == [t.id for t in first.threats]
    critical = next(t for t in again.threats if "deploy_service" in t.title and "tier 4" in t.title)
    assert critical.severity is Severity.CRITICAL


def test_init_docs_only_is_minimal_and_interface_kinds() -> None:
    docs = tm.init_threat_model(_intent("Update docs", RiskClass.DOCS_ONLY), [])
    assert docs.threats == [] and "source code" not in docs.assets
    kinds = [
        Interface(id=f"IFC-00{i}", name=f"I{i}", kind=kind)
        for i, kind in enumerate(InterfaceKind, start=1)
    ]
    model = tm.init_threat_model(_intent("Plain change"), [], interfaces=kinds)
    categories = {t.category for t in model.threats}
    assert {
        ThreatCategory.SPOOFING,
        ThreatCategory.TAMPERING,
        ThreatCategory.REPUDIATION,
        ThreatCategory.INFORMATION_DISCLOSURE,
        ThreatCategory.ELEVATION_OF_PRIVILEGE,
        ThreatCategory.SUPPLY_CHAIN,
        ThreatCategory.DENIAL_OF_SERVICE,
    } <= categories


def test_validate_tool_coverage_egress_and_approvals() -> None:
    model = ThreatModel(
        assets=["a"],
        actors=["b"],
        threats=[
            Threat(
                id="THR-001",
                title="Prompt injection via web_fetch results",
                severity=Severity.LOW,
                status=ThreatStatus.MITIGATED,
                mitigation_ids=["MIT-001"],
            ),
            Threat(
                id="THR-002",
                title="Push abuse",
                assets=["tool:git_push"],
                severity=Severity.LOW,
                status=ThreatStatus.MITIGATED,
                mitigation_ids=["MIT-002"],
            ),
            Threat(
                id="THR-003", title="Something else", assets=["tool:orphan"], severity=Severity.LOW
            ),
        ],
        mitigations=[
            Mitigation(id="MIT-001", description="Screen results", threat_ids=["THR-001"]),
            Mitigation(id="MIT-002", description="Rate limit pushes", threat_ids=["THR-002"]),
        ],
        tool_data_manifest=ToolDataManifest(
            tools=["web_fetch", "git_push", "orphan", "ghost"],
            network_egress=["api.example.com", "*.evil.com"],
        ),
    )
    issues = tm.validate_threat_model(model)
    by_code = {}
    for issue in issues:
        by_code.setdefault(issue.code, set()).add(issue.artifact_id)
    assert by_code["TM_TOOL_NO_THREAT"] == {"ghost"}
    assert by_code["TM_TOOL_NO_MITIGATION"] == {"orphan"}
    assert by_code["TM_TIER3_TOOL_NO_APPROVAL"] == {"git_push", "orphan"}
    assert by_code["TM_EGRESS_NOT_ENUMERATED"] == {"*.evil.com"}
    assert "TM_UNRESOLVED_HIGH_RISK" not in by_code
    fixed = model.model_copy(deep=True)
    fixed.mitigations[1] = Mitigation(
        id="MIT-002", description="Require human approval before push", threat_ids=["THR-002"]
    )
    assert "git_push" not in {
        i.artifact_id
        for i in tm.validate_threat_model(fixed)
        if i.code == "TM_TIER3_TOOL_NO_APPROVAL"
    }
    assert "git_push" not in {
        i.artifact_id
        for i in tm.validate_threat_model(fixed, tool_tiers={"orphan": 1})
        if i.code == "TM_TIER3_TOOL_NO_APPROVAL"
    }


def test_validate_mitigation_consistency_and_unresolved() -> None:
    model = ThreatModel(
        threats=[
            Threat(id="THR-001", title="Open critical", severity=Severity.CRITICAL),
            Threat(
                id="THR-002",
                title="Mitigated but empty",
                severity=Severity.HIGH,
                status=ThreatStatus.MITIGATED,
            ),
            Threat(
                id="THR-003",
                title="Mitigated unverified",
                severity=Severity.HIGH,
                status=ThreatStatus.MITIGATED,
                mitigation_ids=["MIT-001"],
            ),
            Threat(
                id="THR-004",
                title="Accepted high",
                severity=Severity.HIGH,
                status=ThreatStatus.ACCEPTED,
            ),
            Threat(
                id="THR-005", title="Dangling", severity=Severity.LOW, mitigation_ids=["MIT-404"]
            ),
        ],
        mitigations=[
            Mitigation(id="MIT-001", description="x", threat_ids=["THR-003"]),
            Mitigation(id="MIT-002", description="orphan"),
        ],
    )
    issues = tm.validate_threat_model(model, risk_class=RiskClass.STANDARD)
    codes = _codes(issues)
    assert {
        "TM_NO_ASSETS",
        "TM_NO_ACTORS",
        "TM_UNRESOLVED_HIGH_RISK",
        "TM_MITIGATED_WITHOUT_MITIGATION",
        "TM_MITIGATION_UNVERIFIED",
        "TM_ACCEPTED_HIGH_RISK",
        "TM_UNKNOWN_MITIGATION",
        "TM_MITIGATION_ORPHAN",
    } == codes
    unresolved = [i.artifact_id for i in issues if i.code == "TM_UNRESOLVED_HIGH_RISK"]
    assert unresolved == ["THR-001"]
    report = tm.check_threat_model(model)
    assert not report.passed and report.unresolved_high_risk == ["THR-001"]
    assert all(i.severity is IssueSeverity.ERROR for i in report.errors)


def test_check_threat_model_missing_and_empty() -> None:
    assert not tm.check_threat_model(None).passed
    assert not tm.check_threat_model(None, risk_class=RiskClass.STANDARD).passed
    assert tm.check_threat_model(None, risk_class=RiskClass.DOCS_ONLY).passed
    empty = ThreatModel(assets=["a"], actors=["b"])
    report = tm.check_threat_model(empty, risk_class=RiskClass.LOW)
    assert report.passed and report.issues == []
    warned = tm.check_threat_model(empty, risk_class=RiskClass.STANDARD)
    assert warned.passed and _codes(warned.issues) == {"TM_NO_THREATS"}
    with_tools = ThreatModel(
        assets=["a"], actors=["b"], tool_data_manifest=ToolDataManifest(tools=["web_fetch"])
    )
    failed = tm.check_threat_model(with_tools)
    assert not failed.passed and {
        "TM_NO_THREATS",
        "TM_TOOL_NO_THREAT",
        "TM_EGRESS_MISSING",
    } <= _codes(failed.issues)


def test_seeded_model_survives_package_round_trip(tmp_path: Path) -> None:
    pkg = pkgio.create(tmp_path, "CHG-demo", _intent())
    pkg.threat_model = tm.init_threat_model(
        pkg.intent, [], manifest=ToolDataManifest(tools=["git_push"])
    )
    pkg.save()
    loaded = pkgio.load(pkg.root or tmp_path)
    assert loaded.threat_model == pkg.threat_model
    report = tm.check_threat_model(loaded.threat_model, risk_class=RiskClass.AI_AGENT)
    assert _codes(report.issues) == {"TM_UNRESOLVED_HIGH_RISK"}


def test_data_source_sensitivity_matches_whole_tokens() -> None:
    manifest = ToolDataManifest(data_sources=["dashboard metrics", "customers.json"])
    model = tm.init_threat_model(_intent("Ping"), [], manifest=manifest)
    by_title = {t.title: t for t in model.threats}
    assert (
        by_title["Disclosure of dashboard metrics through agent output"].severity is Severity.MEDIUM
    )
    assert by_title["Disclosure of customers.json through agent output"].severity is Severity.HIGH
