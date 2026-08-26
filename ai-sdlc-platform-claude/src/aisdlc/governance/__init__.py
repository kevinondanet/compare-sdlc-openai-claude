"""Plane 2 — tool and execution governance built on the Agent Governance Toolkit.

Public surface:

* :mod:`aisdlc.governance.tiers` — :class:`RiskTier`, :class:`ToolAction`, :func:`classify`
* :mod:`aisdlc.governance.policy` — AGT policy generation/validation from tiers and roles
* :mod:`aisdlc.governance.enforce` — :class:`PolicyEnforcer`, :func:`govern_callable`
* :mod:`aisdlc.governance.audit` — :class:`AuditTrail` (HMAC hash-chained evidence)
* :mod:`aisdlc.governance.mcp` — MCP gateway config and tool-result injection screening
* :mod:`aisdlc.governance.claude_code_plugin` — Claude Code hook/plugin configuration

Only :mod:`tiers` and :mod:`mcp` are importable without the ``governance`` extra; the
others raise :class:`GovernanceUnavailableError` at call time when AGT is missing.
"""

from aisdlc.governance.audit import AuditTrail, IntegrityReport, verify_audit_file
from aisdlc.governance.enforce import (
    ApprovalOutcome,
    ApprovalRequestInfo,
    EnforcementDecision,
    GovernedTool,
    PlatformDenied,
    PolicyEnforcer,
    govern_callable,
)
from aisdlc.governance.mcp import (
    MCPGatewayConfig,
    MCPServerConfig,
    ScreeningResult,
    screen_tool_result,
    screened,
)
from aisdlc.governance.policy import (
    GovernanceUnavailableError,
    PolicySpec,
    RoleSpec,
    default_roles,
    render_policy_yaml,
    validate_policy_yaml,
)
from aisdlc.governance.tiers import (
    RiskTier,
    Scope,
    TierConfig,
    ToolAction,
    classify,
    classify_action,
)

__all__ = [
    "ApprovalOutcome",
    "ApprovalRequestInfo",
    "AuditTrail",
    "EnforcementDecision",
    "GovernanceUnavailableError",
    "GovernedTool",
    "IntegrityReport",
    "MCPGatewayConfig",
    "MCPServerConfig",
    "PlatformDenied",
    "PolicyEnforcer",
    "PolicySpec",
    "RiskTier",
    "RoleSpec",
    "Scope",
    "ScreeningResult",
    "TierConfig",
    "ToolAction",
    "classify",
    "classify_action",
    "default_roles",
    "govern_callable",
    "render_policy_yaml",
    "screen_tool_result",
    "screened",
    "validate_policy_yaml",
    "verify_audit_file",
]
