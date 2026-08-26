"""Agent roles (ARCHITECTURE.md §6) with default tool-tier ceilings and routing complexity.

A :class:`RoleProfile` is the single place that says, for each role, how much a running
agent may do (the highest :class:`~aisdlc.governance.tiers.RiskTier` it may act at), what
canonical tool actions it is granted, and what model complexity it is routed at by
default. The profiles double as the source for the AGT policy documents the orchestrator
enforces (:func:`orchestration_policy_spec`).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.control_plane.routing import Complexity
from aisdlc.governance.policy import PolicySpec, RoleSpec
from aisdlc.governance.tiers import RiskTier

__all__ = [
    "AgentRole",
    "RoleProfile",
    "ROLE_PROFILES",
    "READ_ONLY_ACTIONS",
    "WORKTREE_WRITE_ACTIONS",
    "LOCAL_EXEC_ACTIONS",
    "profile_for",
    "default_tool_tier",
    "default_complexity",
    "role_spec",
    "orchestration_policy_spec",
]


class AgentRole(StrEnum):
    """The agent roles the orchestrator can run."""

    PLANNER = "planner"
    PLAN_CHECKER = "plan_checker"
    IMPLEMENTER = "implementer"
    REVIEWER = "reviewer"
    VERIFIER = "verifier"
    UAT = "uat"
    SECURITY_TESTER = "security_tester"


READ_ONLY_ACTIONS: tuple[str, ...] = (
    "read",
    "search",
    "explain",
    "list",
    "glob",
    "grep",
    "inspect",
)
WORKTREE_WRITE_ACTIONS: tuple[str, ...] = (
    "write",
    "edit",
    "create_file",
    "delete_file",
    "move_file",
)
LOCAL_EXEC_ACTIONS: tuple[str, ...] = (
    "run_tests",
    "build",
    "lint",
    "typecheck",
    "execute",
    "git_commit",
)


class RoleProfile(BaseModel):
    """Defaults for one agent role.

    Attributes:
        role: The role.
        description: What the role does.
        max_tool_tier: Highest risk tier the role may act at (tier 4 is never granted).
        default_complexity: Routing complexity used when the task carries no hint.
        allowed_actions: Canonical tool action types granted to the role.
        approvers: Default approver identities for the role's tier-3 requests.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: AgentRole
    description: str = ""
    max_tool_tier: RiskTier = RiskTier.AUTOMATIC_AUDIT
    default_complexity: Complexity = Complexity.standard
    allowed_actions: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)


ROLE_PROFILES: dict[AgentRole, RoleProfile] = {
    AgentRole.PLANNER: RoleProfile(
        role=AgentRole.PLANNER,
        description="Turns requirements into tasks with verification; edits plan artifacts.",
        max_tool_tier=RiskTier.APPROVAL,
        default_complexity=Complexity.high,
        allowed_actions=[*READ_ONLY_ACTIONS, "write", "edit", "create_file", "update_backlog"],
        approvers=["product-owner"],
    ),
    AgentRole.PLAN_CHECKER: RoleProfile(
        role=AgentRole.PLAN_CHECKER,
        description="Goal-backward validation of a plan; read-only.",
        max_tool_tier=RiskTier.AUTOMATIC,
        default_complexity=Complexity.standard,
        allowed_actions=[*READ_ONLY_ACTIONS],
    ),
    AgentRole.IMPLEMENTER: RoleProfile(
        role=AgentRole.IMPLEMENTER,
        description=(
            "Implements one task in an isolated worktree; apply-back/push/PR need approval."
        ),
        max_tool_tier=RiskTier.APPROVAL,
        default_complexity=Complexity.standard,
        allowed_actions=[
            *READ_ONLY_ACTIONS,
            *WORKTREE_WRITE_ACTIONS,
            *LOCAL_EXEC_ACTIONS,
            "network_egress",
            "install_package",
            "git_push",
            "create_pr",
            "update_pr",
            "modify_shared_state",
        ],
        approvers=["tech-lead"],
    ),
    AgentRole.REVIEWER: RoleProfile(
        role=AgentRole.REVIEWER,
        description="Independent reviewer of the actual diff; may run verification only.",
        max_tool_tier=RiskTier.POLICY_CONTROLLED,
        default_complexity=Complexity.standard,
        allowed_actions=[*READ_ONLY_ACTIONS, "run_tests", "lint", "typecheck", "build"],
    ),
    AgentRole.VERIFIER: RoleProfile(
        role=AgentRole.VERIFIER,
        description="Runs the verification commands and captures evidence.",
        max_tool_tier=RiskTier.POLICY_CONTROLLED,
        default_complexity=Complexity.low,
        allowed_actions=[*READ_ONLY_ACTIONS, *LOCAL_EXEC_ACTIONS],
    ),
    AgentRole.UAT: RoleProfile(
        role=AgentRole.UAT,
        description="Exercises scenarios end-to-end against a local build.",
        max_tool_tier=RiskTier.POLICY_CONTROLLED,
        default_complexity=Complexity.low,
        allowed_actions=[*READ_ONLY_ACTIONS, "run_tests", "execute", "build"],
    ),
    AgentRole.SECURITY_TESTER: RoleProfile(
        role=AgentRole.SECURITY_TESTER,
        description="Runs adversarial campaigns against allow-listed targets; writes reports.",
        max_tool_tier=RiskTier.POLICY_CONTROLLED,
        default_complexity=Complexity.standard,
        allowed_actions=[
            *READ_ONLY_ACTIONS,
            "write",
            "create_file",
            "run_tests",
            "execute",
            "run_campaign",
            "network_egress",
        ],
    ),
}


def profile_for(role: AgentRole | str) -> RoleProfile:
    """Profile for ``role`` (accepts the enum or its value)."""
    return ROLE_PROFILES[AgentRole(role)]


def default_tool_tier(role: AgentRole | str) -> RiskTier:
    """Default tool-tier ceiling for ``role``."""
    return profile_for(role).max_tool_tier


def default_complexity(role: AgentRole | str) -> Complexity:
    """Default routing complexity for ``role``."""
    return profile_for(role).default_complexity


def role_spec(role: AgentRole | str) -> RoleSpec:
    """Governance :class:`RoleSpec` derived from the role profile."""
    profile = profile_for(role)
    return RoleSpec(
        role=profile.role.value,
        description=profile.description,
        allowed_actions=list(profile.allowed_actions),
        max_tier=profile.max_tool_tier,
        approvers=list(profile.approvers),
    )


def orchestration_policy_spec(
    *,
    workspace_roots: list[str] | None = None,
    allowed_egress_hosts: list[str] | None = None,
    name: str = "aisdlc-orchestration",
) -> PolicySpec:
    """AGT policy spec covering every orchestration role.

    ``workspace_roots`` should list the worktree root(s) so that writes inside them are
    tier 1 while writes anywhere else are tier 3.
    """
    return PolicySpec(
        name=name,
        roles=[role_spec(role) for role in AgentRole],
        workspace_roots=list(workspace_roots or []),
        allowed_egress_hosts=list(allowed_egress_hosts or []),
    )
