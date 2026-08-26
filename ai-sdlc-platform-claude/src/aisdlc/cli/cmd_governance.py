"""``aisdlc governance`` — policy generation/checking, audit verification, plugin emission,
MCP result screening and the Claude Code hook entry point."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer

from aisdlc.cli import _common as common
from aisdlc.governance.audit import AuditTrail, record_audit_evidence, verify_audit_file
from aisdlc.governance.claude_code_plugin import (
    build_agt_plugin_policy,
    emit_plugin_config,
    handle_hook_event,
    role_scope_summary,
)
from aisdlc.governance.enforce import (
    ApprovalOutcome,
    ApprovalRequestInfo,
    DeferredApproval,
    PolicyEnforcer,
)
from aisdlc.governance.mcp import screen_tool_result
from aisdlc.governance.policy import (
    PolicySpec,
    render_all_policies,
    render_policy_yaml,
    validate_policy_yaml,
    write_policies,
)
from aisdlc.governance.tiers import RiskTier, TierConfig, ToolAction, classify_action

NAME = "governance"

#: Environment variable the orchestrator sets to the brief's allowed tool tier; the hook
#: uses it as the session ceiling when ``--max-tier`` is not given.
TOOL_TIER_ENV = "AISDLC_TOOL_TIER"
app = typer.Typer(help="Tool/execution governance (risk tiers, AGT policies, audit).")
policy_app = typer.Typer(help="Generate and check AGT tier policies.")
audit_app = typer.Typer(help="Audit trail operations.")
plugin_app = typer.Typer(help="Claude Code plugin/hook configuration.")
mcp_app = typer.Typer(help="MCP gateway and tool-result screening.")
app.add_typer(policy_app, name="policy")
app.add_typer(audit_app, name="audit")
app.add_typer(plugin_app, name="plugin")
app.add_typer(mcp_app, name="mcp")


def _spec(
    workspace_roots: list[str] | None, egress_hosts: list[str] | None, name: str = "aisdlc"
) -> PolicySpec:
    return PolicySpec(
        name=name,
        workspace_roots=list(workspace_roots or []),
        allowed_egress_hosts=list(egress_hosts or []),
    )


def _echo_json(doc: Any) -> None:
    typer.echo(json.dumps(doc, indent=2, default=str))


def _policy_source(
    policy: Path | None, policy_dir: Path | None, role: str, spec: PolicySpec
) -> Any:
    if policy is not None:
        return policy
    if policy_dir is not None:
        candidate = policy_dir / f"{role}.yaml"
        if not candidate.exists():
            raise typer.BadParameter(f"no policy for role {role!r} in {policy_dir}")
        return candidate
    return render_policy_yaml(spec, role)


# --------------------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------------------


@policy_app.command("generate")
def policy_generate(
    role: str | None = typer.Option(None, help="Only this role (default: all roles)."),
    out_dir: Path | None = typer.Option(None, "--out-dir", "-o", help="Write <role>.yaml files."),
    workspace_root: list[str] = typer.Option(
        [], "--workspace-root", help="Isolated worktree root."
    ),
    egress_host: list[str] = typer.Option([], "--egress-host", help="Allowed egress host."),
    name: str = typer.Option("aisdlc", help="Policy name prefix."),
) -> None:
    """Generate governance.toolkit/v1 policy YAML from the tier taxonomy and role allow-lists."""
    spec = _spec(workspace_root, egress_host, name)
    docs = {role: render_policy_yaml(spec, role)} if role else render_all_policies(spec)
    for text in docs.values():
        errors = validate_policy_yaml(text)
        if errors:
            typer.echo("generated policy failed validation: " + "; ".join(errors), err=True)
            raise typer.Exit(code=2)
    if out_dir is not None:
        if role:
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"{role}.yaml"
            path.write_text(docs[role], encoding="utf-8")
            typer.echo(str(path))
        else:
            for path in write_policies(spec, out_dir):
                typer.echo(str(path))
        return
    for text in docs.values():
        typer.echo(text)


@policy_app.command("check")
def policy_check(
    action: str = typer.Argument(
        ...,
        help='JSON: {"tool_name","action_type","resource","parameters"} or a full ToolAction.',
    ),
    role: str = typer.Option("implementer", help="Agent/role id to evaluate as."),
    policy: Path | None = typer.Option(None, help="Policy YAML file."),
    policy_dir: Path | None = typer.Option(None, help="Directory with <role>.yaml policies."),
    workspace_root: list[str] = typer.Option([], "--workspace-root"),
    egress_host: list[str] = typer.Option([], "--egress-host"),
    auto_approve_as: str | None = typer.Option(
        None, help="Rule-based approval: approve tier-3 requests as this approver identity."
    ),
    shadow: bool = typer.Option(False, help="Shadow mode: report without enforcing."),
    audit_log: Path | None = typer.Option(None, help="Append the decision to this audit log."),
) -> None:
    """Evaluate one action against the policy; exit 0 when allowed, 1 when denied."""
    try:
        data = json.loads(action)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"action must be JSON: {exc}") from exc
    spec = _spec(workspace_root, egress_host)
    cfg = spec.effective_tier_config()
    tool_action = _tool_action(data, cfg)
    handler = None
    if auto_approve_as:
        approver = auto_approve_as

        def handler(req: ApprovalRequestInfo) -> ApprovalOutcome:
            return ApprovalOutcome(approved=True, approver=approver, reason="rule-based approval")

    trail = AuditTrail(audit_log) if audit_log else None
    enforcer = PolicyEnforcer(
        _policy_source(policy, policy_dir, role, spec),
        role,
        approval_handler=handler,
        audit_sink=trail,
        shadow=shadow,
        tier_config=cfg,
    )
    decision = enforcer.check(tool_action)
    _echo_json(decision.model_dump(mode="json"))
    raise typer.Exit(code=0 if decision.allowed else 1)


def _tool_action(data: dict[str, Any], cfg: TierConfig) -> ToolAction:
    if "tier" in data and "scope" in data:
        return ToolAction.model_validate(data)
    return classify_action(
        str(data.get("tool_name", "unknown")),
        str(data.get("action_type", "execute")),
        data.get("resource"),
        data.get("parameters") or {},
        config=cfg,
        in_worktree=data.get("in_worktree"),
    )


@policy_app.command("validate")
def policy_validate(path: Path = typer.Argument(..., help="Policy YAML file.")) -> None:
    """Validate a policy file by loading it into the AGT PolicyEngine."""
    errors = validate_policy_yaml(path.read_text(encoding="utf-8"))
    _echo_json({"path": str(path), "valid": not errors, "errors": errors})
    raise typer.Exit(code=0 if not errors else 1)


@policy_app.command("tiers")
def policy_tiers() -> None:
    """Print the default tier table."""
    from aisdlc.governance.tiers import tier_table_markdown

    typer.echo(tier_table_markdown())
    for tier in RiskTier:
        typer.echo(f"tier {int(tier)}: {tier.name.lower()} -> {tier.default_behaviour}")


# --------------------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------------------


@audit_app.command("verify")
def audit_verify(
    path: Path = typer.Argument(..., help="Signed JSON-lines audit log."),
    key_file: Path | None = typer.Option(None, help="Hex HMAC key file (default: <log>.key)."),
) -> None:
    """Verify the HMAC hash chain of an audit log; exit 1 on tampering."""
    report = verify_audit_file(path, key_file=key_file)
    _echo_json(report.model_dump(mode="json"))
    raise typer.Exit(code=0 if report.ok else 1)


@audit_app.command("export")
def audit_export(
    path: Path = typer.Argument(..., help="Signed JSON-lines audit log."),
    out: Path | None = typer.Option(None, help="Write evidence JSON here (default: stdout)."),
    package: Path | None = typer.Option(
        None,
        "--package",
        "-p",
        help="Change package (dir or CHG-<slug> id): write the canonical evidence/audit.json "
        "plus the evidence/audit-entries.json sidecar.",
        callback=common.optional_package_arg,
    ),
    environment: str = typer.Option("local", "--environment", "-e", help="Evidence environment."),
    commit_sha: str | None = typer.Option(None, "--commit-sha", help="Default: git HEAD."),
) -> None:
    """Export an audit log: detailed entries (+integrity); --package also records the canonical."""
    trail = AuditTrail(path)
    evidence = trail.export_evidence()
    file_report = verify_audit_file(path)
    evidence["integrity_ok"] = bool(file_report.ok)
    evidence["integrity_error"] = file_report.error
    from agentmesh.governance.audit_backends import FileAuditSink

    sink = FileAuditSink(path=path, secret_key=trail.secret_key)
    evidence["entries"] = [e.to_dict() for e in sink.read_entries()]
    evidence["privileged_calls"] = sum(
        1 for e in evidence["entries"] if int(e.get("data", {}).get("tier", 0)) >= 1
    )
    # The trail was opened fresh, so counts derived from its in-memory records are empty;
    # derive them from the signed file like privileged_calls above.
    outcomes = [str(e.get("outcome", "")) for e in evidence["entries"]]
    evidence["denied_calls"] = sum(1 for o in outcomes if o.endswith("denied"))
    evidence["approved_calls"] = sum(1 for o in outcomes if o.endswith("approved"))
    if package is not None:
        from aisdlc.gates.verdict import git_head

        if not (package / "intent.md").is_file():
            typer.echo(f"error: {package} is not a change package (no intent.md)", err=True)
            raise typer.Exit(code=2)
        record, sidecar = record_audit_evidence(
            package,
            evidence,
            commit_sha=commit_sha or git_head(package) or "",
            environment=environment,
        )
        typer.echo(
            f"recorded {record.id} ({record.status.value}, {record.entries} entries) in "
            f"{package / 'evidence/audit.json'}; entries in {sidecar}"
        )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence, indent=2, default=str) + "\n", encoding="utf-8")
        typer.echo(str(out))
    elif package is None:
        _echo_json(evidence)


# --------------------------------------------------------------------------------------
# plugin
# --------------------------------------------------------------------------------------


@plugin_app.command("emit")
def plugin_emit(
    out_dir: Path = typer.Option(Path(".claude/aisdlc"), "--out-dir", "-o"),
    role: list[str] = typer.Option([], help="Roles to emit (default: all)."),
    workspace_root: list[str] = typer.Option([], "--workspace-root"),
    egress_host: list[str] = typer.Option([], "--egress-host"),
    policy_dir: str | None = typer.Option(None, help="Where <role>.yaml policies live."),
    audit_log: str | None = typer.Option(None, help="Audit log path for the platform hook."),
    mode: str = typer.Option("enforce", help="enforce | advisory"),
) -> None:
    """Emit AGT Claude Code plugin policy/hook files and the platform hook wiring."""
    spec = _spec(workspace_root, egress_host)
    for path in emit_plugin_config(
        spec, out_dir, roles=role or None, policy_dir=policy_dir, audit_log=audit_log, mode=mode
    ):
        typer.echo(str(path))


@plugin_app.command("show")
def plugin_show(
    role: str = typer.Option("implementer"),
    workspace_root: list[str] = typer.Option([], "--workspace-root"),
    egress_host: list[str] = typer.Option([], "--egress-host"),
) -> None:
    """Print the AGT plugin policy JSON and capability summary for a role."""
    spec = _spec(workspace_root, egress_host)
    _echo_json(
        {
            "summary": role_scope_summary(spec.role(role), spec.effective_tier_config()),
            "policy": build_agt_plugin_policy(spec, role),
        }
    )


# --------------------------------------------------------------------------------------
# mcp
# --------------------------------------------------------------------------------------


@mcp_app.command("screen")
def mcp_screen(
    text: str | None = typer.Argument(None, help="Text to screen (default: stdin)."),
    file: Path | None = typer.Option(None, "--file", "-f", help="Read text from this file."),
    no_sanitize: bool = typer.Option(False, help="Do not filter matched spans."),
) -> None:
    """Screen tool/web/issue text for prompt-injection patterns; exit 1 if suspicious."""
    if file is not None:
        text = file.read_text(encoding="utf-8")
    elif text is None:
        text = sys.stdin.read()
    result = screen_tool_result(text, sanitize=not no_sanitize)
    _echo_json(result.model_dump(mode="json"))
    raise typer.Exit(code=1 if result.suspicious else 0)


# --------------------------------------------------------------------------------------
# hook
# --------------------------------------------------------------------------------------


@app.command("hook")
def hook(
    role: str = typer.Option("implementer", help="Role the session runs as."),
    policy: Path | None = typer.Option(None, help="Policy YAML file."),
    policy_dir: Path | None = typer.Option(None, help="Directory with <role>.yaml policies."),
    workspace_root: list[str] = typer.Option([], "--workspace-root"),
    egress_host: list[str] = typer.Option([], "--egress-host"),
    audit_log: Path | None = typer.Option(None, help="Signed audit log to append to."),
    shadow: bool = typer.Option(
        False,
        help="Shadow mode: allow tier 0-3 and only record; tier-4 denials stay enforced.",
    ),
    max_tier: int | None = typer.Option(
        None,
        "--max-tier",
        min=0,
        max=4,
        help="Session tier ceiling (the brief's allowed tool tier): deny anything classified "
        f"above it. Falls back to ${TOOL_TIER_ENV} when omitted.",
    ),
) -> None:
    """Claude Code hook: read hook JSON on stdin, print allow/deny/ask JSON on stdout.

    Tier-3 approvals are deferred to Claude Code's permission prompt (``ask``) and audited
    as pending; the PostToolUse event records the executed call. Governance errors fail
    closed (deny) for PreToolUse. Actions above ``--max-tier`` (or ``$AISDLC_TOOL_TIER``)
    are denied outright, in addition to the role policy.
    """
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"hook_event_name": "PreToolUse"}
    if not isinstance(payload, dict):
        payload = {"hook_event_name": "PreToolUse"}
    spec = _spec(workspace_root, egress_host)
    cfg = spec.effective_tier_config()
    if shadow:
        typer.echo(
            "warning: governance shadow mode — tier 0-3 denials are logged, not enforced "
            "(tier 4 stays enforced)",
            err=True,
        )
    try:
        ceiling = _session_tier_ceiling(max_tier)
        enforcer = PolicyEnforcer(
            _policy_source(policy, policy_dir, role, spec),
            role,
            approval_handler=DeferredApproval("claude-code"),
            audit_sink=AuditTrail(audit_log) if audit_log else None,
            shadow=shadow,
            tier_config=cfg,
        )
        reply = handle_hook_event(
            payload,
            enforcer=enforcer,
            config=cfg,
            role_spec=spec.role(role),
            max_tier=ceiling,
        )
    except Exception as exc:
        if payload.get("hook_event_name") == "PreToolUse":
            reply = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Governance failed closed: {exc}",
                }
            }
        else:
            reply = {}
    typer.echo(json.dumps(reply))


def _session_tier_ceiling(max_tier: int | None) -> RiskTier | None:
    """``--max-tier`` if given, else ``$AISDLC_TOOL_TIER`` if set, else no ceiling.

    A malformed environment value raises (the caller fails closed for PreToolUse) rather
    than silently running without a ceiling.
    """
    if max_tier is not None:
        return RiskTier.coerce(max_tier)
    raw = os.environ.get(TOOL_TIER_ENV, "").strip()
    if not raw:
        return None
    try:
        return RiskTier.coerce(raw)
    except ValueError as exc:
        raise ValueError(f"{TOOL_TIER_ENV}={raw!r} is not a risk tier (0-4)") from exc
