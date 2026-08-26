"""Tier policy, rule-based approval and audit trail for the assistant's tools.

The policy is generated from the platform tier taxonomy (the same generator behind
``aisdlc governance policy generate``) for a custom ``support-assistant`` role:

* ``search_customers`` -> action ``search`` — tightened to tier 1 (reads private data) so
  every call is audited;
* ``send_email`` -> tier 3 — ``require_approval``; the approval rule only accepts the
  address on file for the customer concerned;
* ``delete_record`` -> ``delete_data`` — tier 4, always denied to the agent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aisdlc.governance.audit import AuditTrail
from aisdlc.governance.enforce import ApprovalOutcome, ApprovalRequestInfo, PolicyEnforcer
from aisdlc.governance.policy import PolicySpec, RoleSpec, render_policy_yaml
from aisdlc.governance.tiers import RiskTier, TierConfig

from assistant.tools import CustomerDirectory

ROLE = "support-assistant"
APPROVERS: tuple[str, ...] = ("support-lead",)
ACTION_TYPES: dict[str, str] = {
    "search_customers": "search",
    "send_email": "send_email",
    "delete_record": "delete_data",
}
"""Tool name -> canonical action type of the platform tier table."""

RULE_APPROVER = "rule:recipient-on-file"


def build_policy_spec() -> PolicySpec:
    """The policy inputs for the assistant role."""
    return PolicySpec(
        name="pilot",
        roles=[
            RoleSpec(
                role=ROLE,
                description="Answers customer questions; reads the customer file, e-mails "
                "customers at their address on file, never deletes.",
                allowed_actions=["search", "read", "send_email"],
                max_tier=RiskTier.APPROVAL,
                approvers=list(APPROVERS),
            )
        ],
        tier_config=TierConfig(
            overrides={"search": RiskTier.AUTOMATIC_AUDIT, "send_email": RiskTier.APPROVAL}
        ),
    )


def policy_yaml() -> str:
    """Generated ``governance.toolkit/v1`` policy for the assistant."""
    return render_policy_yaml(build_policy_spec(), ROLE)


def write_policy(path: str | Path) -> Path:
    """Write the generated policy to *path* (for ``aisdlc governance policy validate``)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(policy_yaml(), encoding="utf-8")
    return target


def recipient_on_file(directory: CustomerDirectory) -> Any:
    """Rule-based approver: an e-mail may only go to the customer's address on file."""

    def approve(request: ApprovalRequestInfo) -> ApprovalOutcome:
        params = request.action.parameters
        to = str(params.get("to", "")).strip().lower()
        customer = directory.get(str(params.get("customer_id", "")))
        if customer is not None and to and to == str(customer["email"]).lower():
            return ApprovalOutcome(
                approved=True,
                approver=RULE_APPROVER,
                reason=f"{to} is the address on file for {customer['id']}",
            )
        return ApprovalOutcome(
            approved=False,
            approver=RULE_APPROVER,
            reason=f"{to or '<no recipient>'} is not the address on file for the customer",
        )

    return approve


class Governance:
    """Policy enforcement plus the signed audit trail for one assistant instance."""

    def __init__(
        self,
        directory: CustomerDirectory,
        *,
        audit_log: str | Path | None = None,
        session_id: str | None = None,
    ) -> None:
        spec = build_policy_spec()
        self.trail = AuditTrail(audit_log, session_id=session_id)
        self.enforcer = PolicyEnforcer(
            policy_yaml(),
            ROLE,
            approval_handler=recipient_on_file(directory),
            audit_sink=self.trail,
            tier_config=spec.effective_tier_config(),
        )

    def check(self, tool: str, params: dict[str, Any], *, resource: str) -> Any:
        """Classify and evaluate a tool request; the decision is audited by the enforcer."""
        action = self.enforcer.classify(tool, ACTION_TYPES[tool], resource, params)
        return self.enforcer.check(action)

    def record_screening(self, source: str, patterns: list[str]) -> None:
        """Audit a quarantined input (user message or tool result)."""
        self.trail.record_event(
            "input_screened",
            agent_id=ROLE,
            action=f"screen.{source}",
            outcome="quarantined",
            data={"patterns": list(patterns)},
        )

    def close(self) -> None:
        """Release the audit file."""
        self.trail.close()
