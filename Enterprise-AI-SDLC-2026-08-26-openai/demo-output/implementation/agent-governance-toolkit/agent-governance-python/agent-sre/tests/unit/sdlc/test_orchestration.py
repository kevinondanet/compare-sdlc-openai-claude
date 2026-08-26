# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for deterministic, policy-constrained SDLC orchestration."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

import agent_sre.sdlc as sdlc
from agent_sre.sdlc.change_contract import (
    AcceptanceScenario,
    Architecture,
    ArchitectureDecision,
    ChangePackage,
    Intent,
    Requirement,
    RiskClass,
    Task,
)
from agent_sre.sdlc.control_plane import PromptRegistry, RegisteredPrompt
from agent_sre.sdlc.model_registry import (
    ModelCapabilities,
    ModelIdentity,
    ModelPrice,
    ModelRegistry,
    ModelTier,
    PriceCatalog,
    RegisteredModel,
)
from agent_sre.sdlc.orchestration import (
    AssignmentRole,
    CheckpointPhase,
    ExecutionLimits,
    ModelRegistryRecord,
    OrchestrationManifest,
    OrchestrationPlanner,
    OrchestrationPolicy,
    PlanningError,
    PolicyWeakeningError,
    PromptRouteRecord,
    ReviewAttesterTrust,
    RoleToolPolicy,
    RouteProfile,
    TokenEstimate,
    ToolAction,
    ToolGovernancePolicy,
    model_price_record_digest,
)
from agent_sre.sdlc.routing import (
    BenchmarkRecord,
    BenchmarkRegistry,
    ModelRouter,
)
from agent_sre.sdlc.usage_ledger import PromptIdentity, ReservationRequest
from agent_sre.signing import ArtifactSigner

NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)
IMPLEMENTATION_PROMPT = PromptIdentity(
    prompt_id="enterprise:implementation",
    version="2026-08-25",
    digest="1" * 64,
)
REVIEW_PROMPT = PromptIdentity(
    prompt_id="enterprise:independent-review",
    version="2026-08-25",
    digest="2" * 64,
)
REVIEW_ATTESTER_ID = "test-review-semantic-attester"
REVIEW_ATTESTER_SIGNER = ArtifactSigner()
REVIEW_ATTESTERS = (
    ReviewAttesterTrust(
        attester_id=REVIEW_ATTESTER_ID,
        public_key=REVIEW_ATTESTER_SIGNER.public_key_bytes.hex(),
    ),
)


def test_model_and_prompt_route_records_are_public_contracts() -> None:
    assert sdlc.ModelRegistryRecord is ModelRegistryRecord
    assert sdlc.PromptRouteRecord is PromptRouteRecord
    assert sdlc.RoleToolPolicy is RoleToolPolicy
    assert sdlc.ToolAction is ToolAction
    assert sdlc.ToolGovernancePolicy is ToolGovernancePolicy


def make_prompt_registry(*, implementation_enabled: bool = True) -> PromptRegistry:
    return PromptRegistry(
        (
            RegisteredPrompt(
                identity=IMPLEMENTATION_PROMPT,
                provenance="prompt-repository:implementation@2026-08-25",
                enabled=implementation_enabled,
            ),
            RegisteredPrompt(
                identity=REVIEW_PROMPT,
                provenance="prompt-repository:review@2026-08-25",
            ),
        )
    )


def make_change() -> ChangePackage:
    """Build three tasks across two dependency waves."""

    return ChangePackage(
        change_id="CHG-ORCHESTRATION",
        title="Governed implementation plan",
        application="email-agent",
        repository="contoso/email-agent",
        source_revision="abcdef123456",
        owner="team-ai-platform",
        risk_class=RiskClass.TOOL_ENABLED_AGENT,
        intent=Intent(
            goal="Mediate all externally visible agent side effects.",
            non_goals=("Replace the provider.",),
            success_signals=("Every task is independently verified.",),
        ),
        requirements=(
            Requirement(
                requirement_id="REQ-001",
                title="Govern side effects",
                statement="The host MUST mediate every externally visible side effect.",
                acceptance_scenario_ids=("SCN-001",),
                architecture_decision_ids=("ADR-001",),
                task_ids=("TASK-001", "TASK-002", "TASK-003"),
                verification="pytest tests/test_governance.py",
            ),
        ),
        scenarios=(
            AcceptanceScenario(
                scenario_id="SCN-001",
                title="External action is mediated",
                requirement_ids=("REQ-001",),
                when="an agent proposes an external action",
                then="the host evaluates policy before the side effect",
            ),
        ),
        architecture=Architecture(
            context="The governed host owns execution and policy enforcement.",
            decisions=(
                ArchitectureDecision(
                    decision_id="ADR-001",
                    title="Host-owned mediation",
                    status="accepted",
                    context="Models cannot enforce their own privileges.",
                    decision="The host evaluates policy before invoking tools.",
                    consequences=("Denied calls cannot reach the provider.",),
                    requirement_ids=("REQ-001",),
                ),
            ),
        ),
        tasks=(
            Task(
                task_id="TASK-001",
                title="Implement network mediation",
                requirement_ids=("REQ-001",),
                verification_command="pytest tests/test_network_policy.py",
                owner_role="implementation",
                tool_scopes=("network", "read", "workspace_write"),
                risk_tier=3,
            ),
            Task(
                task_id="TASK-002",
                title="Implement audit events",
                requirement_ids=("REQ-001",),
                verification_command="pytest tests/test_audit.py",
                owner_role="implementation",
                tool_scopes=("read", "workspace_write"),
                risk_tier=1,
            ),
            Task(
                task_id="TASK-003",
                title="Verify integrated behavior",
                requirement_ids=("REQ-001",),
                depends_on=("TASK-001", "TASK-002"),
                verification_command="pytest tests/test_governance.py",
                owner_role="verification",
                tool_scopes=("execute", "read", "workspace_write"),
                risk_tier=2,
            ),
        ),
        implementation_model_family="family-a",
        created_at=NOW,
        updated_at=NOW,
    )


def registered_model(
    *,
    name: str,
    provider: str,
    family: str,
    price_per_million: str,
) -> tuple[RegisteredModel, ModelPrice]:
    identity = ModelIdentity(
        provider=provider,
        provider_family=family,
        model=name,
        version="2026-08",
        deployment=f"{name}-prod",
    )
    model = RegisteredModel(
        identity=identity,
        capabilities=ModelCapabilities(
            tier=ModelTier.STANDARD,
            max_context_tokens=64_000,
            capabilities=frozenset({"json", "tools"}),
            allowed_tools=frozenset(
                {"administrative", "execute", "network", "read", "workspace_write"}
            ),
            allowed_risk_levels=frozenset(f"tier-{tier}" for tier in range(5)),
            allowed_use_cases=frozenset({"implementation", "independent_review"}),
        ),
    )
    price = ModelPrice(
        identity=identity,
        effective_from=NOW - timedelta(days=30),
        effective_to=None,
        input_per_million=Decimal(price_per_million),
        output_per_million=Decimal(price_per_million),
        cached_input_per_million=Decimal(price_per_million),
        reasoning_per_million=Decimal(price_per_million),
        provenance="finance:v1",
    )
    return model, price


def make_router(*, include_reviewer: bool = True) -> ModelRouter:
    implementation, implementation_price = registered_model(
        name="implementer",
        provider="provider-a",
        family="family-a",
        price_per_million="1",
    )
    models = [implementation]
    prices = [implementation_price]
    if include_reviewer:
        reviewer, reviewer_price = registered_model(
            name="reviewer",
            provider="provider-b",
            family="family-b",
            price_per_million="2",
        )
        models.append(reviewer)
        prices.append(reviewer_price)

    benchmarks = [
        BenchmarkRecord(
            benchmark_id=f"bench:{model.identity.model}:{task_type}",
            identity=model.identity,
            task_type=task_type,
            quality_score=Decimal("0.95"),
            latency_ms=Decimal("400"),
            measured_at=NOW - timedelta(days=1),
            valid_until=NOW + timedelta(days=30),
            provenance="eval-suite:v4/dataset:sha256:abc",
            sample_size=100,
        )
        for model in models
        for task_type in ("code-change", "whole-change-review")
    ]
    return ModelRouter(
        models=ModelRegistry(models),
        prices=PriceCatalog(prices),
        benchmarks=BenchmarkRegistry(benchmarks),
    )


def make_policy(**overrides: object) -> OrchestrationPolicy:
    values: dict[str, object] = {
        "policy_id": "enterprise-ai-sdlc-v1",
        "organization_id": "contoso",
        "team_id": "ai-platform",
        "user_id": "automation-service",
        "environment": "ci",
        "allowed_tool_scopes": (
            "administrative",
            "execute",
            "network",
            "read",
            "workspace_write",
        ),
        "checkpoint_tool_scopes": ("administrative", "execute", "network"),
        "checkpoint_min_risk_tier": 3,
        "execution_approver_role": "security-owner",
        "release_approver_role": "release-manager",
        "reservation_ttl_seconds": 3600,
        "trusted_review_attesters": REVIEW_ATTESTERS,
        "implementation_route": RouteProfile(
            task_type="code-change",
            use_case="implementation",
            context_tokens=16_000,
            estimated_usage=TokenEstimate(input_tokens=1000, output_tokens=1000),
            max_benchmark_age_seconds=30 * 24 * 3600,
            max_tier=ModelTier.STANDARD,
            required_capabilities=("json", "tools"),
            min_quality=Decimal("0.90"),
            max_latency_ms=Decimal("1000"),
        ),
        "review_route": RouteProfile(
            task_type="whole-change-review",
            use_case="independent_review",
            context_tokens=24_000,
            estimated_usage=TokenEstimate(input_tokens=1000, output_tokens=1000),
            max_benchmark_age_seconds=30 * 24 * 3600,
            max_tier=ModelTier.STANDARD,
            required_capabilities=("json", "tools"),
            min_quality=Decimal("0.90"),
            max_latency_ms=Decimal("1000"),
        ),
        "limits": ExecutionLimits(
            max_turns_per_assignment=12,
            max_tool_calls_per_assignment=30,
            max_parallel_agents=2,
            max_cost_per_assignment_usd=Decimal("0.01"),
            max_total_cost_usd=Decimal("0.10"),
        ),
    }
    values.update(overrides)
    return OrchestrationPolicy(**values)  # type: ignore[arg-type]


def make_planner(
    *,
    policy: OrchestrationPolicy | None = None,
    router: ModelRouter | None = None,
) -> OrchestrationPlanner:
    return OrchestrationPlanner(
        router=router or make_router(),
        prompt_registry=make_prompt_registry(),
        implementation_prompt=IMPLEMENTATION_PROMPT,
        review_prompt=REVIEW_PROMPT,
        enterprise_policy=policy or make_policy(),
    )


def test_planner_builds_dependency_waves_with_isolated_fresh_work() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-20260825-001",
        planned_at=NOW,
    )

    assert [
        [assignment.contract_task_ids[0] for assignment in wave.assignments]
        for wave in manifest.execution_waves
    ] == [["TASK-001", "TASK-002"], ["TASK-003"]]
    assert [wave.dependency_wave_index for wave in manifest.execution_waves] == [0, 1]
    assert manifest.execution_waves[1].assignments[0].depends_on_assignment_ids == (
        "impl:TASK-001",
        "impl:TASK-002",
    )
    assignments = [
        assignment for wave in manifest.execution_waves for assignment in wave.assignments
    ] + [manifest.review_assignment]
    assert len({item.context_id for item in assignments}) == 4
    assert len({item.workspace_key for item in assignments}) == 4
    assert all(item.fresh_context and item.isolated_workspace for item in assignments)
    assert all(item.prompt.identity == IMPLEMENTATION_PROMPT for item in assignments[:-1])
    assert assignments[-1].prompt.identity == REVIEW_PROMPT


def test_planner_rejects_disabled_or_unregistered_prompt_versions() -> None:
    with pytest.raises(PlanningError, match="implementation prompt is disabled"):
        OrchestrationPlanner(
            router=make_router(),
            prompt_registry=make_prompt_registry(implementation_enabled=False),
            implementation_prompt=IMPLEMENTATION_PROMPT,
            review_prompt=REVIEW_PROMPT,
            enterprise_policy=make_policy(),
        )

    unknown = PromptIdentity(
        prompt_id=IMPLEMENTATION_PROMPT.prompt_id,
        version="unregistered",
        digest="3" * 64,
    )
    with pytest.raises(PlanningError, match="implementation prompt is not registered"):
        OrchestrationPlanner(
            router=make_router(),
            prompt_registry=make_prompt_registry(),
            implementation_prompt=unknown,
            review_prompt=REVIEW_PROMPT,
            enterprise_policy=make_policy(),
        )


def test_parallel_ceiling_splits_one_dependency_wave_deterministically() -> None:
    payload = make_policy().model_dump(mode="python")
    payload["limits"]["max_parallel_agents"] = 1
    policy = OrchestrationPolicy.model_validate(payload)

    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-20260825-002",
        planned_at=NOW,
    )

    assert [wave.dependency_wave_index for wave in manifest.execution_waves] == [0, 0, 1]
    assert [wave.batch_index for wave in manifest.execution_waves] == [0, 1, 0]
    assert [wave.schedule_index for wave in manifest.execution_waves] == [0, 1, 2]
    assert all(len(wave.assignments) == 1 for wave in manifest.execution_waves)


def test_routes_models_and_enforces_whole_change_review_diversity() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-20260825-003",
        planned_at=NOW,
    )
    implementation_routes = [
        assignment.route for wave in manifest.execution_waves for assignment in wave.assignments
    ]

    assert {route.provider_family for route in implementation_routes} == {"family-a"}
    assert manifest.review_assignment.role is AssignmentRole.INDEPENDENT_REVIEW
    assert manifest.review_assignment.route.provider_family == "family-b"
    assert manifest.review_assignment.depends_on_assignment_ids == (
        "impl:TASK-001",
        "impl:TASK-002",
        "impl:TASK-003",
    )
    assert manifest.review_assignment.contract_task_ids == (
        "TASK-001",
        "TASK-002",
        "TASK-003",
    )
    for route in (*implementation_routes, manifest.review_assignment.route):
        assert route.price_record_digest == model_price_record_digest(route.price_record)
        assert route.registry_record.identity == route.identity
        assert route.registry_record.record.enabled is True


def test_manifest_rejects_registry_projection_that_disallows_assignment_risk() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-20260825-RISK-AUTH",
        planned_at=NOW,
    )
    payload = manifest.model_dump(mode="python")
    assignment = payload["execution_waves"][0]["assignments"][0]
    risk_level = f"tier-{assignment['risk_tier']}"
    assignment["route"]["registry_record"]["allowed_risk_levels"] = tuple(
        item
        for item in assignment["route"]["registry_record"]["allowed_risk_levels"]
        if item != risk_level
    )

    with pytest.raises(ValidationError, match="does not allow the assignment risk tier"):
        OrchestrationManifest.model_validate(payload)


def test_price_record_digest_canonicalizes_equivalent_decimal_scales() -> None:
    model, scaled = registered_model(
        name="scaled-price",
        provider="provider-a",
        family="family-a",
        price_per_million="1.2300",
    )
    normalized = ModelPrice(
        identity=model.identity,
        effective_from=scaled.effective_from,
        effective_to=scaled.effective_to,
        input_per_million=Decimal("1.23"),
        output_per_million=Decimal("1.23"),
        cached_input_per_million=Decimal("1.23"),
        reasoning_per_million=Decimal("1.23"),
        provenance=scaled.provenance,
    )

    assert model_price_record_digest(scaled) == model_price_record_digest(normalized)


def test_manifest_costs_are_exact_and_convert_to_ledger_reservations() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-20260825-004",
        planned_at=NOW,
    )

    assert manifest.total_estimated_cost_usd == Decimal("0.010")
    requests = manifest.reservation_requests
    assert len(requests) == 4
    assert all(isinstance(item, ReservationRequest) for item in requests)
    assert [item.attribution.task_id for item in requests] == [
        "impl:TASK-001",
        "impl:TASK-002",
        "impl:TASK-003",
        "review:whole-change",
    ]
    assert sum((item.amount_usd for item in requests), Decimal("0")) == Decimal("0.010")
    assert all(item.expires_at == NOW + timedelta(hours=1) for item in requests)


def test_human_checkpoints_cover_privileged_work_and_final_release() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-20260825-005",
        planned_at=NOW,
    )
    before = [
        item
        for item in manifest.human_checkpoints
        if item.phase is CheckpointPhase.BEFORE_ASSIGNMENT
    ]
    release = [
        item for item in manifest.human_checkpoints if item.phase is CheckpointPhase.BEFORE_RELEASE
    ]

    before_by_assignment = {item.assignment_ids[0]: item for item in before}
    assert set(before_by_assignment) == {"impl:TASK-001", "impl:TASK-003"}
    assert before_by_assignment["impl:TASK-001"].reason_codes == (
        "risk_tier:3",
        "tool_scope:network",
    )
    assert before_by_assignment["impl:TASK-003"].reason_codes == ("tool_scope:execute",)
    assert all(item.approver_role == "security-owner" for item in before)
    assert len(release) == 1
    assert release[0].assignment_ids == ("review:whole-change",)
    assert release[0].approver_role == "release-manager"


def test_manifest_and_policy_are_canonical_immutable_and_strict() -> None:
    planner = make_planner()
    first = planner.plan(make_change(), run_id="RUN-stable", planned_at=NOW)
    second = OrchestrationManifest.model_validate_json(first.canonical_bytes())

    assert first == second
    assert first.digest == second.digest
    assert json.loads(first.canonical_bytes())["schema_version"] == (
        "agt.orchestration-manifest/v1"
    )
    with pytest.raises(ValidationError):
        first.run_id = "RUN-mutated"
    payload = make_policy().model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        OrchestrationPolicy.model_validate(payload)


def test_canonical_policy_normalizes_equivalent_decimal_spellings() -> None:
    first = make_policy()
    payload = first.model_dump(mode="python")
    payload["limits"]["max_cost_per_assignment_usd"] = Decimal("0.01000")
    payload["limits"]["max_total_cost_usd"] = Decimal("0.1000")
    payload["implementation_route"]["min_quality"] = Decimal("0.9000")
    second = OrchestrationPolicy.model_validate(payload)

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest == second.digest


def test_policy_rejects_boolean_limits_missing_read_and_disabled_invariants() -> None:
    boolean_limit = make_policy().model_dump(mode="python")
    boolean_limit["checkpoint_min_risk_tier"] = True
    with pytest.raises(ValidationError, match="must be an integer"):
        OrchestrationPolicy.model_validate(boolean_limit)

    missing_read = make_policy().model_dump(mode="python")
    missing_read["allowed_tool_scopes"] = (
        "administrative",
        "execute",
        "network",
        "workspace_write",
    )
    with pytest.raises(ValidationError, match="must include read"):
        OrchestrationPolicy.model_validate(missing_read)

    disabled_review = make_policy().model_dump(mode="python")
    disabled_review["require_independent_review"] = False
    with pytest.raises(ValidationError):
        OrchestrationPolicy.model_validate(disabled_review)

    bypassed = make_policy().model_copy(update={"require_independent_review": False})
    with pytest.raises(ValueError, match="strict revalidation"):
        OrchestrationPlanner(
            router=make_router(),
            prompt_registry=make_prompt_registry(),
            implementation_prompt=IMPLEMENTATION_PROMPT,
            review_prompt=REVIEW_PROMPT,
            enterprise_policy=bypassed,
        )


def test_different_run_ids_produce_new_contexts_but_repeat_is_idempotent() -> None:
    planner = make_planner()
    first = planner.plan(make_change(), run_id="RUN-fresh-a", planned_at=NOW)
    repeated = planner.plan(make_change(), run_id="RUN-fresh-a", planned_at=NOW)
    second = planner.plan(make_change(), run_id="RUN-fresh-b", planned_at=NOW)

    first_contexts = {
        assignment.context_id for wave in first.execution_waves for assignment in wave.assignments
    } | {first.review_assignment.context_id}
    second_contexts = {
        assignment.context_id for wave in second.execution_waves for assignment in wave.assignments
    } | {second.review_assignment.context_id}
    assert first.canonical_bytes() == repeated.canonical_bytes()
    assert first_contexts.isdisjoint(second_contexts)


def test_tool_governance_keeps_sensitive_actions_privileged_and_approval_bound() -> None:
    for field_name in ("approval_required_actions", "privileged_actions"):
        payload = ToolGovernancePolicy().model_dump(mode="python")
        payload[field_name] = tuple(
            action for action in payload[field_name] if action is not ToolAction.NETWORK
        )
        with pytest.raises(ValidationError, match="must (require approval|remain privileged)"):
            ToolGovernancePolicy.model_validate(payload)


def test_manifest_rejects_checkpoint_that_does_not_exactly_cover_tool_scopes() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-checkpoint-scope-binding",
        planned_at=NOW,
    )
    payload = manifest.model_dump(mode="python")
    checkpoint = next(
        item
        for item in payload["human_checkpoints"]
        if item["assignment_ids"] == ("impl:TASK-001",)
    )
    checkpoint["reason_codes"] = ("risk_tier:3",)

    with pytest.raises(ValidationError, match="exactly authorize its risk and tool scopes"):
        OrchestrationManifest.model_validate(payload)


def test_project_policy_may_only_narrow_enterprise_policy() -> None:
    enterprise = make_policy()
    payload = enterprise.model_dump(mode="python")
    payload["policy_id"] = "project-ai-sdlc-v1"
    payload["limits"]["max_turns_per_assignment"] = 8
    payload["limits"]["max_parallel_agents"] = 1
    payload["limits"]["max_total_cost_usd"] = Decimal("0.05")
    payload["checkpoint_min_risk_tier"] = 2
    payload["implementation_route"]["min_quality"] = Decimal("0.95")
    payload["review_route"]["max_benchmark_age_seconds"] = 7 * 24 * 3600
    project = OrchestrationPolicy.model_validate(payload)

    project.assert_narrows(enterprise)
    planner = OrchestrationPlanner(
        router=make_router(),
        prompt_registry=make_prompt_registry(),
        implementation_prompt=IMPLEMENTATION_PROMPT,
        review_prompt=REVIEW_PROMPT,
        enterprise_policy=enterprise,
        project_policy=project,
    )
    assert planner.policy is project


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        (("limits", "max_parallel_agents"), 3, "limits.max_parallel_agents_increased"),
        (
            ("limits", "max_assignment_duration_seconds"),
            901,
            "limits.max_assignment_duration_seconds_increased",
        ),
        (
            ("implementation_route", "min_quality"),
            Decimal("0.80"),
            "implementation_route.minimum_quality_reduced",
        ),
        (
            ("review_route", "max_benchmark_age_seconds"),
            60 * 24 * 3600,
            "review_route.benchmark_freshness_weakened",
        ),
        (("checkpoint_min_risk_tier",), 4, "policy.checkpoint_risk_threshold_increased"),
        (
            ("tool_governance", "allowed_network_hosts"),
            ("api.example.com",),
            "tool_governance.network_hosts_expanded",
        ),
    ],
)
def test_project_policy_rejects_weakening(
    path: tuple[str, ...],
    value: object,
    reason: str,
) -> None:
    enterprise = make_policy()
    payload = enterprise.model_dump(mode="python")
    payload["policy_id"] = "project-ai-sdlc-v1"
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    if path == ("checkpoint_min_risk_tier",):
        # The built-in maximum is itself fail-closed before overlay comparison.
        with pytest.raises(ValidationError):
            OrchestrationPolicy.model_validate(payload)
        return
    project = OrchestrationPolicy.model_validate(payload)
    with pytest.raises(PolicyWeakeningError) as exc_info:
        project.assert_narrows(enterprise)
    assert reason in exc_info.value.reasons


def test_planner_rejects_unready_contract_and_disallowed_scope() -> None:
    change_payload = make_change().model_dump(mode="python")
    change_payload["requirements"][0]["statement"] = "TODO decide how to govern it"
    unready = ChangePackage.model_validate(change_payload)
    with pytest.raises(PlanningError, match="not ready"):
        make_planner().plan(unready, run_id="RUN-unready", planned_at=NOW)

    policy_payload = make_policy().model_dump(mode="python")
    policy_payload["allowed_tool_scopes"] = ("execute", "read", "workspace_write")
    policy_payload["checkpoint_tool_scopes"] = ("execute",)
    restricted = OrchestrationPolicy.model_validate(policy_payload)
    with pytest.raises(PlanningError, match="policy-disallowed.*network"):
        make_planner(policy=restricted).plan(
            make_change(),
            run_id="RUN-disallowed",
            planned_at=NOW,
        )


def test_planner_fails_closed_on_total_cost_and_review_route() -> None:
    policy_payload = make_policy().model_dump(mode="python")
    policy_payload["limits"]["max_cost_per_assignment_usd"] = Decimal("0.009")
    policy_payload["limits"]["max_total_cost_usd"] = Decimal("0.009")
    tight = OrchestrationPolicy.model_validate(policy_payload)
    with pytest.raises(PlanningError, match="planned cost .* exceeds total limit"):
        make_planner(policy=tight).plan(
            make_change(),
            run_id="RUN-over-budget",
            planned_at=NOW,
        )

    with pytest.raises(PlanningError, match="no safe model route"):
        make_planner(router=make_router(include_reviewer=False)).plan(
            make_change(),
            run_id="RUN-no-reviewer",
            planned_at=NOW,
        )


def test_planner_enforces_change_model_family_binding() -> None:
    change = make_change().model_copy(update={"implementation_model_family": "family-other"})

    with pytest.raises(PlanningError, match="does not match the change contract"):
        make_planner().plan(change, run_id="RUN-family-mismatch", planned_at=NOW)


def test_manifest_rejects_context_reuse_and_missing_release_checkpoint() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-invalid-manifest",
        planned_at=NOW,
    )
    duplicate_context = manifest.model_dump(mode="python")
    duplicate_context["execution_waves"][1]["assignments"][0]["context_id"] = duplicate_context[
        "execution_waves"
    ][0]["assignments"][0]["context_id"]
    with pytest.raises(ValidationError, match="unique fresh context_id"):
        OrchestrationManifest.model_validate(duplicate_context)

    missing_release = manifest.model_dump(mode="python")
    missing_release["human_checkpoints"] = [
        item
        for item in missing_release["human_checkpoints"]
        if item["phase"] != CheckpointPhase.BEFORE_RELEASE
    ]
    with pytest.raises(ValidationError, match="final human release checkpoint"):
        OrchestrationManifest.model_validate(missing_release)

    privileged_review = manifest.model_dump(mode="python")
    privileged_review["review_assignment"]["tool_scopes"] = ("network", "read")
    with pytest.raises(ValidationError, match="read-only"):
        OrchestrationManifest.model_validate(privileged_review)

    stale_reservation = manifest.model_dump(mode="python")
    stale_reservation["review_assignment"]["reservation"]["expires_at"] += timedelta(seconds=1)
    with pytest.raises(ValidationError, match="expiry does not match"):
        OrchestrationManifest.model_validate(stale_reservation)

    tampered_price = manifest.model_dump(mode="python")
    tampered_price["review_assignment"]["route"]["price_input_per_million"] = Decimal("0")
    with pytest.raises(ValidationError, match="price_record_digest"):
        OrchestrationManifest.model_validate(tampered_price)

    tampered_registry = manifest.model_dump(mode="python")
    tampered_registry["review_assignment"]["route"]["registry_record"]["provider_family"] = (
        "substituted-family"
    )
    with pytest.raises(ValidationError, match="registry_record identity"):
        OrchestrationManifest.model_validate(tampered_registry)


def test_policy_review_rounds_and_remediation_paths_can_only_narrow() -> None:
    base = make_policy()
    enterprise = make_policy(
        remediation_path_scopes=("src",),
        limits=base.limits.model_copy(update={"max_review_rounds": 2}),
    )
    narrower = make_policy(
        remediation_path_scopes=("src/agent",),
        limits=base.limits.model_copy(update={"max_review_rounds": 1}),
    )
    narrower.assert_narrows(enterprise)

    weaker_rounds = make_policy(
        remediation_path_scopes=("src",),
        limits=base.limits.model_copy(update={"max_review_rounds": 3}),
    )
    with pytest.raises(PolicyWeakeningError) as rounds_error:
        weaker_rounds.assert_narrows(enterprise)
    assert "limits.max_review_rounds_increased" in rounds_error.value.reasons

    weaker_paths = make_policy(
        remediation_path_scopes=(".",),
        limits=base.limits.model_copy(update={"max_review_rounds": 2}),
    )
    with pytest.raises(PolicyWeakeningError) as paths_error:
        weaker_paths.assert_narrows(enterprise)
    assert "policy.remediation_path_scopes_expanded" in paths_error.value.reasons

    attacker = ArtifactSigner()
    weaker_attesters = make_policy(
        trusted_review_attesters=tuple(
            sorted(
                (
                    *REVIEW_ATTESTERS,
                    ReviewAttesterTrust(
                        attester_id="untrusted-review-attester",
                        public_key=attacker.public_key_bytes.hex(),
                    ),
                ),
                key=lambda item: (item.attester_id, item.public_key),
            )
        )
    )
    with pytest.raises(PolicyWeakeningError) as attester_error:
        weaker_attesters.assert_narrows(base)
    assert "policy.trusted_review_attesters_expanded" in attester_error.value.reasons


def test_planner_predeclares_every_bounded_fix_and_fresh_rereview() -> None:
    base = make_policy()
    policy = make_policy(
        remediation_path_scopes=("src",),
        limits=base.limits.model_copy(update={"max_review_rounds": 3}),
    )
    manifest = make_planner(policy=policy).plan(
        make_change(),
        run_id="RUN-conditional-review-plan",
        planned_at=NOW,
    )

    assert tuple(item.round_number for item in manifest.conditional_review_rounds) == (2, 3)
    planned = [
        manifest.review_assignment,
        *(
            assignment
            for item in manifest.conditional_review_rounds
            for assignment in (item.remediation_assignment, item.review_assignment)
        ),
    ]
    assert len({item.context_id for item in planned}) == len(planned)
    assert len({item.workspace_key for item in planned}) == len(planned)
    assert all(item.fresh_context and item.isolated_workspace for item in planned)
    assert all(
        item.remediation_assignment.remediation_path_scopes == ("src",)
        for item in manifest.conditional_review_rounds
    )
    assert len(manifest.reservation_requests) == 8
    release = next(
        item for item in manifest.human_checkpoints if item.phase is CheckpointPhase.BEFORE_RELEASE
    )
    assert release.assignment_ids == (
        "review:whole-change",
        "review:whole-change:round-2",
        "review:whole-change:round-3",
    )

    incomplete = manifest.model_dump(mode="python")
    incomplete["conditional_review_rounds"] = incomplete["conditional_review_rounds"][:-1]
    with pytest.raises(ValidationError, match="predeclare every allowed"):
        OrchestrationManifest.model_validate(incomplete)


def test_manifest_recomputes_route_freshness_and_estimated_cost_from_policy() -> None:
    manifest = make_planner().plan(
        make_change(),
        run_id="RUN-route-reseal-attack",
        planned_at=NOW,
    )

    stale = manifest.model_dump(mode="python")
    stale_route = stale["execution_waves"][0]["assignments"][0]["route"]
    stale_route["benchmark_measured_at"] = NOW - timedelta(
        seconds=manifest.implementation_route.max_benchmark_age_seconds + 1
    )
    stale_route["benchmark_valid_until"] = None
    with pytest.raises(ValidationError, match="protected maximum age"):
        OrchestrationManifest.model_validate(stale)

    zero_cost = manifest.model_dump(mode="python")
    assignment = zero_cost["execution_waves"][0]["assignments"][0]
    original_cost = assignment["route"]["estimated_cost_usd"]
    assignment["route"]["estimated_cost_usd"] = Decimal("0")
    assignment["reservation"]["amount_usd"] = Decimal("0")
    zero_cost["total_estimated_cost_usd"] -= original_cost
    with pytest.raises(ValidationError, match="protected usage and price"):
        OrchestrationManifest.model_validate(zero_cost)
