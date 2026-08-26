"""Tests for control_plane.server (FastAPI, optional) and the ``aisdlc cost`` CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aisdlc.cli.cmd_cost import NAME, app
from aisdlc.control_plane import server as server_mod
from aisdlc.control_plane.benchmark import BenchmarkCategory, BenchmarkResult, BenchmarkService
from aisdlc.control_plane.budget import Budget, BudgetPolicyEngine, Quotas, ScopeType
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.control_plane.registry import ModelRegistry

runner = CliRunner()


# ---------------------------------------------------------------------------- server
def test_server_module_imports_and_guards() -> None:
    assert hasattr(server_mod, "create_app")
    assert isinstance(server_mod.FASTAPI_AVAILABLE, bool)


def test_create_app_raises_clear_error_without_fastapi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_mod, "FASTAPI_AVAILABLE", False)
    with pytest.raises(server_mod.ServerUnavailableError, match="fastapi is not installed"):
        server_mod.create_app()


@pytest.fixture
def client() -> object:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    ledger = UsageLedger()
    engine = BudgetPolicyEngine(
        ledger,
        budgets=[Budget(scope_type=ScopeType.application, scope_id="pay", limit_usd=10)],
        quotas=Quotas(max_model_tier_by_role={"verifier": "low"}),
    )
    services = server_mod.ControlPlaneServices(
        registry=ModelRegistry.default(),
        ledger=ledger,
        benchmarks=BenchmarkService(),
        budget_engine=engine,
    )
    return TestClient(server_mod.create_app(services))


def test_health_and_registry_endpoints(client: object) -> None:
    from fastapi.testclient import TestClient

    c = client
    assert isinstance(c, TestClient)
    r = c.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    models = c.get("/registry/models").json()
    assert any(m["model"] == "claude-opus-5" for m in models)
    fam = c.get("/registry/families").json()
    assert "claude" in fam and "gpt" in fam
    no_claude = c.get("/registry/models", params={"exclude_family": "claude"}).json()
    assert all(m["family"] != "claude" for m in no_claude)
    vision = c.get("/registry/models", params={"capability": ["vision", "code"]}).json()
    assert all("vision" in m["capabilities"] for m in vision)
    assert c.get("/registry/models/claude-sonnet-5").json()["provider"] == "anthropic"
    assert c.get("/registry/models/nope").status_code == 404


def test_route_ledger_budget_benchmark_kpi_endpoints(client: object) -> None:
    from fastapi.testclient import TestClient

    c = client
    assert isinstance(c, TestClient)
    # route
    r = c.post("/route", json={"complexity": "high", "risk": "critical", "role": "implementer"})
    assert r.status_code == 200
    body = r.json()
    assert body["tier"] == "high" and body["reason"]
    bad = c.post("/route", json={"required_capabilities": ["telepathy"]})
    assert bad.status_code == 422
    assert c.post("/route", json={"bogus": 1}).status_code == 422
    # ledger
    ev = UsageEvent(
        change_id="CHG-1",
        model="claude-sonnet-5",
        application="pay",
        input_tokens=10,
        output_tokens=5,
        cost_usd=8.0,
        latency_ms=50,
    )
    r = c.post("/ledger/events", json=json.loads(ev.model_dump_json()))
    assert r.status_code == 201 and r.json()["event_id"] == ev.event_id
    events = c.get("/ledger/events", params={"change_id": "CHG-1"}).json()
    assert len(events) == 1
    summary = c.get("/ledger/summary", params={"group_by": ["model"]}).json()
    assert summary[0]["group"] == {"model": "claude-sonnet-5"} and summary[0]["calls"] == 1
    assert c.get("/ledger/summary", params={"group_by": ["cost_usd"]}).status_code == 422
    evidence = c.get("/ledger/changes/CHG-1/cost").json()
    assert evidence["status"] == "complete" and evidence["kind"] == "cost"
    # budget
    d = c.post("/budget/check", json={"scopes": ["application:pay"], "forecast_cost_usd": 1.0})
    assert d.status_code == 200 and d.json()["decision"] == "require_approval"
    d2 = c.post("/budget/check", json={"scopes": ["application:pay"], "forecast_cost_usd": 5.0})
    assert d2.json()["decision"] == "deny"
    d3 = c.post(
        "/budget/check",
        json={"scopes": [], "forecast_cost_usd": 0.1, "role": "verifier", "requested_tier": "high"},
    )
    assert d3.json()["decision"] == "deny"
    assert len(c.get("/budget/budgets").json()) == 1
    r = c.put("/budget/budgets", json={"scope_type": "team", "scope_id": "t", "limit_usd": 5})
    assert r.status_code == 201 and len(c.get("/budget/budgets").json()) == 2
    r = c.put("/budget/quotas", json={"max_agent_turns": 3})
    assert r.status_code == 200 and c.get("/budget/quotas").json()["max_agent_turns"] == 3
    # benchmarks
    bm = BenchmarkResult(
        benchmark_id="BM-swe-1",
        category=BenchmarkCategory.quality,
        model="claude-haiku-4-5-20251001",
        metric="pass",
        value=0.9,
        sample_size=3,
    )
    r = c.post("/benchmarks", json=json.loads(bm.model_dump_json()))
    assert r.status_code == 201
    assert len(c.get("/benchmarks", params={"category": "quality"}).json()) == 1
    best = c.get("/benchmarks/best/quality").json()
    assert best["model"] == "claude-haiku-4-5-20251001"
    assert c.get("/benchmarks/best/security").status_code == 404
    # routing now benchmark-backed for quality
    routed = c.post("/route", json={"complexity": "low", "role": "implementer"}).json()
    assert routed["benchmark_backed"] is True
    # kpis
    r = c.post("/kpis", json={"outcomes": {"merged_changes": 1}})
    assert r.status_code == 200
    assert r.json()["cost_per_merged_change"] == pytest.approx(8.0)
    assert c.post("/kpis", json={"filters": {"nope": 1}}).status_code == 422


# ---------------------------------------------------------------------------- CLI
def test_cli_name_and_discovery() -> None:
    from aisdlc.cli.main import app as root

    assert NAME == "cost"
    names = {g.name for g in root.registered_groups}
    assert "cost" in names


def test_cli_registry_list_and_route(tmp_path: Path) -> None:
    r = runner.invoke(app, ["registry", "list", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert any(m["model"] == "claude-fable-5" for m in data)
    r = runner.invoke(app, ["registry", "list", "--family", "gpt"])
    assert r.exit_code == 0 and "gpt-5" in r.output and "placeholder" in r.output
    r = runner.invoke(
        app,
        [
            "route",
            "--complexity",
            "high",
            "--risk",
            "critical",
            "--role",
            "reviewer",
            "--tier",
            "independent_review",
            "--exclude-family",
            "claude",
            "--json",
        ],
    )
    assert r.exit_code == 0, r.output
    decision = json.loads(r.output)
    assert decision["family"] != "claude" and decision["tier"] == "independent_review"
    r = runner.invoke(app, ["route", "--capability", "telepathy"])
    assert r.exit_code == 1 and "routing failed" in r.output
    # benchmark-backed routing through a benchmark db file
    bench_path = tmp_path / "bm.sqlite"
    svc = BenchmarkService(str(bench_path))
    svc.store(
        BenchmarkResult(
            benchmark_id="BM-swe-1",
            category=BenchmarkCategory.quality,
            model="claude-sonnet-5",
            metric="pass",
            value=0.95,
        )
    )
    svc.close()
    r = runner.invoke(app, ["route", "--benchmarks", str(bench_path), "--json"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["model"] == "claude-sonnet-5"


def test_cli_record_report_budget_kpis(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.sqlite"
    common = ["--ledger", str(ledger)]
    r = runner.invoke(
        app,
        [
            "record",
            "--model",
            "claude-sonnet-5",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "0",
            "--change",
            "CHG-1",
            "--role",
            "implementer",
            "--app",
            "pay",
            "--json",
            *common,
        ],
    )
    assert r.exit_code == 0, r.output
    ev = json.loads(r.output)
    assert ev["cost_usd"] == pytest.approx(2.0) and ev["provider"] == "anthropic"
    r = runner.invoke(
        app,
        [
            "record",
            "--model",
            "mystery",
            "--cost",
            "0.5",
            "--change",
            "CHG-1",
            "--app",
            "pay",
            "--tool-calls",
            "2",
            *common,
        ],
    )
    assert r.exit_code == 0, r.output
    # report
    r = runner.invoke(app, ["report", "-g", "model", "--json", *common])
    assert r.exit_code == 0, r.output
    rows = json.loads(r.output)
    assert {row["group"]["model"] for row in rows} == {"claude-sonnet-5", "mystery"}
    r = runner.invoke(app, ["report", "--change", "CHG-1", *common])
    assert r.exit_code == 0 and "usage" in r.output  # rich table (columns may be truncated)
    r = runner.invoke(app, ["report", "--change", "CHG-1", "--export", *common])
    assert r.exit_code == 0 and json.loads(r.output)["status"] == "complete"
    r = runner.invoke(app, ["report", "--export", *common])
    assert r.exit_code != 0
    r = runner.invoke(app, ["report", "-g", "cost_usd", *common])
    assert r.exit_code != 0
    # budget-check with config file
    cfg = tmp_path / "budgets.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "budgets": [{"scope_type": "application", "scope_id": "pay", "limit_usd": 3}],
                "quotas": {"max_model_tier_by_role": {"verifier": "low"}},
                "exceptions": [
                    {
                        "exception_id": "EXC-1",
                        "scope_type": "application",
                        "scope_id": "pay",
                        "approved_by": "cto",
                        "expires_at": (datetime.now(tz=UTC) + timedelta(days=1)).isoformat(),
                        "extra_limit_usd": 100,
                    }
                ],
            }
        )
    )
    strict = tmp_path / "budgets-strict.yaml"
    strict.write_text(
        yaml.safe_dump(
            {"budgets": [{"scope_type": "application", "scope_id": "pay", "limit_usd": 3}]}
        )
    )
    r = runner.invoke(app, ["budget-check", "-s", "application:pay", "--forecast", "1", *common])
    assert r.exit_code == 0 and "no budget configured" in r.output
    r = runner.invoke(
        app,
        [
            "budget-check",
            "-s",
            "application:pay",
            "--forecast",
            "1",
            "--budgets",
            str(strict),
            *common,
        ],
    )
    assert r.exit_code == 1, r.output  # 2.5 spent + 1 > 3 without exceptions
    r = runner.invoke(
        app,
        [
            "budget-check",
            "-s",
            "application:pay",
            "--forecast",
            "1",
            "--budgets",
            str(cfg),
            "--json",
            *common,
        ],
    )
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["applied_exceptions"] == ["EXC-1"]
    r = runner.invoke(
        app,
        [
            "budget-check",
            "-s",
            "application:pay",
            "--forecast",
            "1",
            "--budgets",
            str(cfg),
            "--role",
            "verifier",
            "--tier",
            "high",
            *common,
        ],
    )
    assert r.exit_code == 1
    r = runner.invoke(
        app,
        [
            "budget-check",
            "-s",
            "application:pay",
            "--forecast",
            "0.1",
            "--budgets",
            str(strict),
            *common,
        ],
    )
    assert r.exit_code == 2, r.output  # 2.6 > 0.8 * 3 soft limit -> require approval
    r = runner.invoke(app, ["budget-check", "-s", "bad-scope", "--forecast", "1", *common])
    assert r.exit_code != 0
    # kpis
    r = runner.invoke(app, ["kpis", "--merged-changes", "1", "--json", *common])
    assert r.exit_code == 0, r.output
    rep = json.loads(r.output)
    assert rep["cost_per_merged_change"] == pytest.approx(2.5)
    outcomes = tmp_path / "outcomes.json"
    outcomes.write_text(json.dumps({"accepted_requirements": 5}))
    r = runner.invoke(app, ["kpis", "--outcomes", str(outcomes), *common])
    assert r.exit_code == 0 and "cost_per_accepted_requirement" in r.output


def test_cli_default_ledger_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "env-ledger.sqlite"
    monkeypatch.setenv("AISDLC_LEDGER", str(path))
    r = runner.invoke(
        app, ["record", "--model", "claude-haiku-4-5-20251001", "--output-tokens", "10"]
    )
    assert r.exit_code == 0, r.output
    with UsageLedger(str(path)) as led:
        assert led.count() == 1
