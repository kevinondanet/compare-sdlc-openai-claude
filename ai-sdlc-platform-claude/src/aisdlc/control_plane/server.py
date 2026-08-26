"""Optional FastAPI server exposing the control plane over HTTP.

The module imports cleanly without ``fastapi``; :func:`create_app` raises
:class:`ServerUnavailableError` with install instructions when it is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.benchmark import BenchmarkCategory, BenchmarkResult, BenchmarkService
from aisdlc.control_plane.budget import Budget, BudgetPolicyEngine, Quotas
from aisdlc.control_plane.kpis import Outcomes, compute_kpis
from aisdlc.control_plane.ledger import UsageEvent, UsageLedger
from aisdlc.control_plane.registry import ModelNotFoundError, ModelRegistry
from aisdlc.control_plane.routing import RoutingError, RoutingPolicy, TaskProfile

try:  # pragma: no cover - exercised implicitly by tests
    from fastapi import FastAPI, HTTPException, Query

    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment,misc]  # optional dependency
    HTTPException = None  # type: ignore[assignment,misc]
    Query = None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False


class ServerUnavailableError(RuntimeError):
    """Raised by :func:`create_app` when FastAPI is not installed."""


@dataclass
class ControlPlaneServices:
    """Bundle of control-plane components served by the app."""

    registry: ModelRegistry = field(default_factory=ModelRegistry.default)
    ledger: UsageLedger = field(default_factory=UsageLedger)
    benchmarks: BenchmarkService = field(default_factory=BenchmarkService)
    routing_policy: RoutingPolicy = field(default_factory=RoutingPolicy)
    budget_engine: BudgetPolicyEngine | None = None

    def __post_init__(self) -> None:
        if self.budget_engine is None:
            self.budget_engine = BudgetPolicyEngine(self.ledger)


class BudgetCheckRequest(BaseModel):
    """Body for ``POST /budget/check``."""

    model_config = ConfigDict(extra="forbid")

    scopes: list[str] = Field(description="e.g. ['application:payments', 'team:core']")
    forecast_cost_usd: float = Field(ge=0)
    role: str | None = None
    requested_tier: str | None = None
    agent_turns: int | None = None
    parallel_agents: int | None = None
    review_rounds: int | None = None
    tool_calls: int | None = None
    context_tokens: int | None = None


class KpiRequest(BaseModel):
    """Body for ``POST /kpis``."""

    model_config = ConfigDict(extra="forbid")

    outcomes: Outcomes = Field(default_factory=Outcomes)
    filters: dict[str, Any] = Field(default_factory=dict)
    since: datetime | None = None
    until: datetime | None = None
    min_samples: int = 1
    score_tolerance: float = 0.0


def create_app(services: ControlPlaneServices | None = None) -> Any:
    """Build the FastAPI application.

    Raises :class:`ServerUnavailableError` if ``fastapi`` is not importable.
    """
    if not FASTAPI_AVAILABLE:
        raise ServerUnavailableError(
            "fastapi is not installed; install the 'server' extra: "
            "pip install 'ai-sdlc-platform[server]'"
        )
    svc = services or ControlPlaneServices()
    assert svc.budget_engine is not None
    engine = svc.budget_engine
    app = FastAPI(title="AI-SDLC control plane", version="0.1.0")
    app.state.services = svc

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "models": len(svc.registry),
            "events": svc.ledger.count(),
            "benchmarks": svc.benchmarks.count(),
        }

    # -------------------------------------------------------------- registry
    @app.get("/registry/models")
    def list_models(
        capability: list[str] | None = Query(default=None),
        family: str | None = None,
        exclude_family: list[str] | None = Query(default=None),
        provider: str | None = None,
        use_case: str | None = None,
    ) -> list[dict[str, Any]]:
        entries = svc.registry.filter(
            capabilities=capability,
            family=family,
            exclude_families=exclude_family,
            provider=provider,
            use_case=use_case,
        )
        return [e.model_dump() for e in entries]

    @app.get("/registry/families")
    def families() -> list[str]:
        return svc.registry.families()

    @app.get("/registry/models/{model}")
    def get_model(model: str) -> dict[str, Any]:
        try:
            return svc.registry.get(model).model_dump()
        except ModelNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"unknown model {model!r}") from exc

    # -------------------------------------------------------------- routing
    @app.post("/route")
    def route(profile: TaskProfile) -> dict[str, Any]:
        try:
            decision = svc.routing_policy.route(profile, svc.registry, benchmarks=svc.benchmarks)
        except RoutingError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return decision.model_dump(mode="json")

    # -------------------------------------------------------------- ledger
    @app.post("/ledger/events", status_code=201)
    def record_event(event: UsageEvent) -> dict[str, str]:
        return {"event_id": svc.ledger.record(event)}

    @app.get("/ledger/events")
    def list_events(
        change_id: str | None = None,
        model: str | None = None,
        agent_role: str | None = None,
        team: str | None = None,
        application: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=100, ge=1, le=10_000),
    ) -> list[dict[str, Any]]:
        filters = {
            k: v
            for k, v in {
                "change_id": change_id,
                "model": model,
                "agent_role": agent_role,
                "team": team,
                "application": application,
            }.items()
            if v is not None
        }
        events = svc.ledger.query(filters, since=since, until=until, limit=limit, newest_first=True)
        return [e.model_dump(mode="json") for e in events]

    @app.get("/ledger/summary")
    def summary(
        group_by: list[str] | None = Query(default=None),
        change_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        filters = {"change_id": change_id} if change_id else None
        try:
            rows = svc.ledger.summarize(group_by or (), filters=filters, since=since, until=until)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return [r.model_dump(mode="json") for r in rows]

    @app.get("/ledger/changes/{change_id}/cost")
    def change_cost(change_id: str) -> dict[str, Any]:
        return svc.ledger.export_change(change_id)

    # -------------------------------------------------------------- budget
    @app.post("/budget/check")
    def budget_check(req: BudgetCheckRequest) -> dict[str, Any]:
        try:
            decision = engine.check(
                req.scopes,
                req.forecast_cost_usd,
                req.role,
                req.requested_tier,
                agent_turns=req.agent_turns,
                parallel_agents=req.parallel_agents,
                review_rounds=req.review_rounds,
                tool_calls=req.tool_calls,
                context_tokens=req.context_tokens,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return decision.model_dump(mode="json")

    @app.get("/budget/budgets")
    def list_budgets() -> list[dict[str, Any]]:
        return [b.model_dump(mode="json") for b in engine.budgets]

    @app.put("/budget/budgets", status_code=201)
    def put_budget(budget: Budget) -> dict[str, Any]:
        engine.add_budget(budget)
        return budget.model_dump(mode="json")

    @app.get("/budget/quotas")
    def get_quotas() -> dict[str, Any]:
        return engine.quotas.model_dump(mode="json")

    @app.put("/budget/quotas")
    def put_quotas(quotas: Quotas) -> dict[str, Any]:
        engine.quotas = quotas
        return quotas.model_dump(mode="json")

    # -------------------------------------------------------------- benchmarks
    @app.post("/benchmarks", status_code=201)
    def store_benchmark(result: BenchmarkResult) -> dict[str, int]:
        return {"id": svc.benchmarks.store(result)}

    @app.get("/benchmarks")
    def list_benchmarks(
        category: BenchmarkCategory | None = None,
        model: str | None = None,
        limit: int = Query(default=100, ge=1, le=10_000),
    ) -> list[dict[str, Any]]:
        rows = svc.benchmarks.query(category=category, model=model, limit=limit)
        return [r.model_dump(mode="json") for r in rows]

    @app.get("/benchmarks/best/{category}")
    def best(category: BenchmarkCategory, min_samples: int = 1) -> dict[str, Any]:
        ms = svc.benchmarks.best_for(category, min_samples=min_samples)
        if ms is None:
            raise HTTPException(status_code=404, detail="no benchmark data for category")
        return ms.model_dump(mode="json")

    # -------------------------------------------------------------- kpis
    @app.post("/kpis")
    def kpis(req: KpiRequest) -> dict[str, Any]:
        try:
            report = compute_kpis(
                svc.ledger,
                req.outcomes,
                benchmarks=svc.benchmarks,
                registry=svc.registry,
                filters=req.filters or None,
                since=req.since,
                until=req.until,
                min_samples=req.min_samples,
                score_tolerance=req.score_tolerance,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return report.model_dump(mode="json")

    return app
