"""Audit trail: HMAC hash chain, key handling, evidence export (real AGT AuditLog)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from aisdlc.governance.audit import (
    AUDIT_KEY_ENV,
    AuditTrail,
    key_file_for,
    resolve_audit_key,
    verify_audit_file,
)
from aisdlc.governance.enforce import EnforcementDecision
from aisdlc.governance.tiers import RiskTier, Scope, ToolAction

pytestmark = pytest.mark.integration
agentmesh = pytest.importorskip("agentmesh")


def _decision(
    action: ToolAction, *, allowed: bool = True, approver: str | None = None
) -> EnforcementDecision:
    return EnforcementDecision(
        allowed=allowed,
        action=action,
        tier=action.tier,
        policy_action="allow" if allowed else "deny",
        matched_rule="rule-x",
        policy_name="p",
        reason="because",
        approver=approver,
        agent_id="implementer",
    )


def _action(tier: int, action_type: str = "write") -> ToolAction:
    return ToolAction(
        tool_name="Write",
        action_type=action_type,
        resource="/wt/a.py",
        parameters={"n": 1},
        tier=tier,
        scope=Scope.WRITE,
        in_worktree=True,
    )


def test_generated_key_stored_with_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_KEY_ENV, raising=False)
    log = tmp_path / "evidence" / "audit.jsonl"
    trail = AuditTrail(log)
    key_path = key_file_for(log)
    assert key_path.exists()
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert bytes.fromhex(key_path.read_text().strip()) == trail.secret_key
    # a second trail on the same log reuses the key so the chain stays verifiable
    assert AuditTrail(log).secret_key == trail.secret_key


def test_env_key_takes_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUDIT_KEY_ENV, "ab" * 32)
    assert resolve_audit_key(tmp_path / "x.jsonl") == bytes.fromhex("ab" * 32)
    monkeypatch.setenv(AUDIT_KEY_ENV, "plain-text-secret")
    assert resolve_audit_key(tmp_path / "x.jsonl") == b"plain-text-secret"
    assert not key_file_for(tmp_path / "x.jsonl").exists()
    assert resolve_audit_key(None, secret_key=b"explicit") == b"explicit"


def test_record_verify_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_KEY_ENV, raising=False)
    log = tmp_path / "audit.jsonl"
    trail = AuditTrail(log, session_id="CHG-x")
    ids = [
        trail.record(_decision(_action(1)), _action(1)),
        trail.record(_decision(_action(3), allowed=True, approver="lead"), _action(3, "git_push")),
        trail.record(_decision(_action(4), allowed=False), _action(4, "deploy")),
        trail.record_event(
            "injection_screening", agent_id="implementer", action="screen", outcome="suspicious"
        ),
    ]
    assert len(set(ids)) == 4
    report = trail.verify_integrity()
    assert report.ok and report.entries == 4 and report.file_verified

    evidence = trail.export_evidence()
    assert evidence["integrity_ok"] is True
    assert evidence["privileged_calls"] == 3
    assert evidence["denied_calls"] == 1 and evidence["approved_calls"] == 1
    assert evidence["log_path"] == str(log) and evidence["merkle_root"]
    entries = evidence["entries"]
    assert all(isinstance(e, dict) for e in entries)
    assert {e["outcome"] for e in entries} == {"allowed", "approved", "denied", "suspicious"}
    assert entries[0]["data"]["session_id"] == "CHG-x"
    assert entries[1]["approver"] == "lead"
    assert entries[0]["arguments_hash"] and len(entries[0]["arguments_hash"]) == 64
    json.dumps(evidence)  # must be JSON serialisable with no AGT types
    out = trail.write_evidence(tmp_path / "evidence" / "audit.json")
    assert json.loads(out.read_text())["privileged_calls"] == 3

    file_report = verify_audit_file(log)
    assert file_report.ok and file_report.entries == 4


def test_tampering_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_KEY_ENV, raising=False)
    log = tmp_path / "audit.jsonl"
    trail = AuditTrail(log)
    trail.record(_decision(_action(1)), _action(1))
    trail.record(_decision(_action(2)), _action(2, "run_tests"))
    lines = log.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["outcome"] = "denied"
    lines[0] = json.dumps(tampered, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    report = verify_audit_file(log)
    assert not report.ok and report.error and "hash" in report.error.lower()
    assert not trail.verify_integrity().ok

    wrong_key = verify_audit_file(log, secret_key=b"wrong")
    assert not wrong_key.ok
    assert not verify_audit_file(tmp_path / "missing.jsonl").ok


def test_verify_requires_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_KEY_ENV, raising=False)
    log = tmp_path / "audit.jsonl"
    log.write_text("")
    report = verify_audit_file(log)
    assert not report.ok and "key" in (report.error or "")
    key_file = tmp_path / "k.hex"
    key_file.write_text("cd" * 32)
    trail = AuditTrail(log, secret_key=bytes.fromhex("cd" * 32))
    trail.record(_decision(_action(1)), _action(1))
    assert verify_audit_file(log, key_file=key_file).ok


def test_in_memory_trail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_KEY_ENV, raising=False)
    trail = AuditTrail()
    assert trail.path is None
    trail.record(_decision(_action(2)), _action(2, "build"))
    report = trail.verify_integrity()
    assert report.ok and not report.file_verified
    assert trail.export_evidence()["log_path"] is None
    assert trail.agt_log.verify_integrity()[0]
    assert trail.entries()[0]["tier"] == 2 and RiskTier(trail.entries()[0]["tier"]).requires_audit
    trail.close()
