"""Audit trail adapter: AGT ``AuditLog`` + HMAC-signed ``FileAuditSink`` -> evidence/audit.json.

The trail records every enforcement decision at tier >= 1 (and every non-allow decision
at any tier). Entries are hash-chained in memory (Merkle chain) and, when a path is
configured, appended as HMAC-signed JSON lines. The HMAC key comes from the
``AISDLC_AUDIT_KEY`` environment variable, or a per-run random key is generated and
stored next to the log (``<log>.key``, mode 0600) so the file can be verified later.

Nothing AGT-specific leaks out of :meth:`AuditTrail.export_evidence`: entries are plain
dictionaries matching the ``AuditEvidence`` shape (``entries``, ``integrity_ok``,
``privileged_calls``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from aisdlc import __version__
from aisdlc.governance.policy import agt_governance
from aisdlc.governance.tiers import RiskTier, ToolAction
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import AuditEvidence, EvidenceKind, EvidenceStatus

AUDIT_KEY_ENV = "AISDLC_AUDIT_KEY"
KEY_FILE_SUFFIX = ".key"

_SECRET_PARAM_RE = re.compile(
    r"\b(token|secret|password|passwd|pwd|api[_-]?key|apikey|auth|authorization|credential|"
    r"cookie|session|private[_-]?key|access[_-]?key|client[_-]?secret|sig|signature|"
    r"sas|key)=[^&\s'\"]*",
    re.IGNORECASE,
)


def redact_resource(resource: str | None) -> str | None:
    """Strip secret-bearing parts from a resource string before it is audited.

    URLs keep ``scheme://host[:port]/path`` only (userinfo, query string and fragment are
    dropped — a query string is where tokens travel); other strings have ``token=...``-style
    parameters replaced by ``[REDACTED]``. Paths and command names pass through unchanged.
    """
    if not resource:
        return resource
    if "://" in resource:
        parts = urlsplit(resource)
        if parts.scheme and parts.hostname:
            host = parts.hostname
            if parts.port:
                host = f"{host}:{parts.port}"
            redacted = f"{parts.scheme}://{host}{parts.path}"
            if parts.query:
                redacted += "?[REDACTED]"
            return redacted
    return _SECRET_PARAM_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", resource)


class DecisionView(Protocol):
    """The subset of an enforcement decision the audit trail needs (avoids a cycle)."""

    allowed: bool
    policy_action: str
    tier: RiskTier
    matched_rule: str | None
    policy_name: str | None
    reason: str
    approver: str | None
    shadow: bool


class IntegrityReport(BaseModel):
    """Result of verifying the audit chain."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    entries: int
    error: str | None = None
    file_verified: bool = False


class AuditEvidenceExport(BaseModel):
    """Plain evidence record for ``evidence/audit.json`` (``AuditEvidence`` shape)."""

    model_config = ConfigDict(extra="forbid")

    kind: str = "audit"
    entries: list[dict[str, Any]]
    integrity_ok: bool
    integrity_error: str | None = None
    privileged_calls: int
    denied_calls: int
    approved_calls: int
    merkle_root: str | None = None
    log_path: str | None = None
    exported_at: str


def resolve_audit_key(
    log_path: Path | None,
    *,
    secret_key: bytes | None = None,
    env_var: str = AUDIT_KEY_ENV,
) -> bytes:
    """Resolve the HMAC key: explicit > environment > key file next to the log > generated.

    The environment value is hex-decoded when it is an even-length hex string, otherwise
    used as UTF-8 bytes. A generated key is persisted hex-encoded to ``<log>.key`` with
    permissions ``0600`` (only when a log path is given).
    """
    if secret_key:
        return secret_key
    env_value = os.environ.get(env_var, "").strip()
    if env_value:
        return _decode_key(env_value)
    if log_path is None:
        return secrets.token_bytes(32)
    key_path = key_file_for(log_path)
    if key_path.exists():
        stored = key_path.read_text(encoding="utf-8").strip()
        if stored:
            return _decode_key(stored)
    key = secrets.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key.hex() + "\n")
    os.chmod(key_path, 0o600)
    return key


def key_file_for(log_path: Path | str) -> Path:
    """Path of the key file stored next to ``log_path``."""
    path = Path(log_path)
    return path.with_name(path.name + KEY_FILE_SUFFIX)


def _decode_key(value: str) -> bytes:
    text = value.strip()
    if len(text) >= 32 and len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text)
    return text.encode("utf-8")


class AuditTrail:
    """Append-only audit trail for governed tool calls.

    Args:
        path: JSON-lines log file (``None`` keeps the trail in memory only).
        secret_key: HMAC key; resolved via :func:`resolve_audit_key` when omitted.
        session_id: Optional session/change identifier stamped on every entry.
    """

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        secret_key: bytes | None = None,
        session_id: str | None = None,
    ) -> None:
        gov = agt_governance()
        self._path = Path(path) if path is not None else None
        self._key = resolve_audit_key(self._path, secret_key=secret_key)
        self._session_id = session_id
        self._sink: Any | None = None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._sink = gov.FileAuditSink(path=self._path, secret_key=self._key)
        self._log = gov.AuditLog(sink=self._sink)
        self._records: list[dict[str, Any]] = []

    @property
    def path(self) -> Path | None:
        """Log file path (``None`` for in-memory trails)."""
        return self._path

    @property
    def secret_key(self) -> bytes:
        """HMAC key in use (needed to verify the file out of process)."""
        return self._key

    @property
    def agt_log(self) -> Any:
        """The underlying AGT ``AuditLog`` (for telemetry importers)."""
        return self._log

    def record(self, decision: DecisionView, action: ToolAction) -> str:
        """Record an enforcement decision for ``action``; returns the audit entry id.

        Outcomes: ``allowed``, ``approved`` (allowed after an approval), ``denied``, and
        ``approval_pending`` (the decision was handed to a human outside the process, see
        :class:`~aisdlc.governance.enforce.DeferredApproval`); ``shadow:`` prefixes dry-run
        decisions. Resources are passed through :func:`redact_resource`.
        """
        outcome = "allowed" if decision.allowed else "denied"
        if decision.policy_action == "require_approval":
            outcome = "approval_pending"
        elif decision.approver and decision.allowed:
            outcome = "approved"
        if decision.shadow:
            outcome = f"shadow:{outcome}"
        if decision.allowed:
            event_type = "tool_invocation"
        elif outcome.endswith("approval_pending"):
            event_type = "approval_requested"
        else:
            event_type = "tool_blocked"
        data: dict[str, Any] = {
            "tool_name": action.tool_name,
            "tier": int(action.tier),
            "scope": action.scope.value,
            "in_worktree": action.in_worktree,
            "rule": decision.matched_rule or "",
            "policy": decision.policy_name or "",
            "reason": decision.reason,
            "approver": decision.approver or "",
            "shadow": decision.shadow,
            "session_id": self._session_id or "",
        }
        entry = self._log.log(
            event_type=event_type,
            agent_did=_agent_of(decision),
            action=action.action_type,
            resource=redact_resource(action.resource) or None,
            data=data,
            outcome=outcome,
            policy_decision=decision.policy_action,
            arguments_hash=_arguments_hash(action.parameters),
            approver_did=decision.approver or None,
        )
        self._records.append(self._entry_to_dict(entry, tier=int(action.tier)))
        return str(entry.entry_id)

    def record_event(
        self,
        event_type: str,
        *,
        agent_id: str,
        action: str,
        resource: str | None = None,
        outcome: str = "success",
        data: dict[str, Any] | None = None,
        tier: int = 0,
    ) -> str:
        """Record a free-form governance event (approvals, screening hits, session start)."""
        payload = dict(data or {})
        payload.setdefault("session_id", self._session_id or "")
        entry = self._log.log(
            event_type=event_type,
            agent_did=agent_id,
            action=action,
            resource=redact_resource(resource),
            data=payload,
            outcome=outcome,
        )
        self._records.append(self._entry_to_dict(entry, tier=tier))
        return str(entry.entry_id)

    def entries(self) -> list[dict[str, Any]]:
        """All recorded entries as plain dictionaries."""
        return [dict(e) for e in self._records]

    def verify_integrity(self) -> IntegrityReport:
        """Verify the in-memory hash chain and, when present, the signed file."""
        ok, error = self._log.verify_integrity()
        file_verified = False
        if ok and self._sink is not None:
            ok, file_error = self._sink.verify_integrity()
            error = file_error if not ok else None
            file_verified = ok
        return IntegrityReport(
            ok=bool(ok), entries=len(self._records), error=error, file_verified=file_verified
        )

    def export_evidence(self) -> dict[str, Any]:
        """Export an ``AuditEvidence``-shaped record with plain-dict entries."""
        report = self.verify_integrity()
        export = self._log.export()
        privileged = sum(1 for e in self._records if e["tier"] >= 1)
        denied = sum(1 for e in self._records if e["outcome"].endswith("denied"))
        approved = sum(1 for e in self._records if e["outcome"].endswith("approved"))
        evidence = AuditEvidenceExport(
            entries=self.entries(),
            integrity_ok=report.ok,
            integrity_error=report.error,
            privileged_calls=privileged,
            denied_calls=denied,
            approved_calls=approved,
            merkle_root=export.get("merkle_root"),
            log_path=str(self._path) if self._path else None,
            exported_at=datetime.now(UTC).isoformat(),
        )
        return evidence.model_dump(mode="json")

    def to_audit_evidence(
        self,
        *,
        commit_sha: str = "",
        environment: str = "local",
        evidence_id: str = "EVD-audit-001",
        report_uri: str | None = None,
    ) -> AuditEvidence:
        """Canonical :class:`~aisdlc.schema.models.AuditEvidence` summary of this trail."""
        return audit_evidence_from_export(
            self.export_evidence(),
            commit_sha=commit_sha,
            environment=environment,
            evidence_id=evidence_id,
            report_uri=report_uri,
        )

    def write_evidence(self, path: Path | str) -> Path:
        """Write the detailed :meth:`export_evidence` JSON (entries + integrity) to ``path``.

        This is the *entries* export, not the canonical ``evidence/audit.json`` record; use
        :func:`record_audit_evidence` to store both in a change package.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.export_evidence(), indent=2) + "\n", encoding="utf-8")
        return target

    def close(self) -> None:
        """Release the file sink."""
        if self._sink is not None:
            self._sink.close()

    def _entry_to_dict(self, entry: Any, *, tier: int) -> dict[str, Any]:
        return {
            "entry_id": str(entry.entry_id),
            "timestamp": entry.timestamp.isoformat(),
            "event_type": str(entry.event_type),
            "agent_id": str(entry.agent_did),
            "action": str(entry.action),
            "resource": entry.resource,
            "outcome": str(entry.outcome),
            "policy_decision": entry.policy_decision,
            "tier": tier,
            "data": dict(entry.data),
            "arguments_hash": entry.arguments_hash,
            "approver": entry.approver_did,
            "previous_hash": str(entry.previous_hash),
            "entry_hash": str(entry.entry_hash),
        }


def verify_audit_file(
    path: Path | str, *, secret_key: bytes | None = None, key_file: Path | str | None = None
) -> IntegrityReport:
    """Verify a signed JSON-lines audit file out of process.

    The key is taken from ``secret_key``, then ``key_file`` (hex), then the environment,
    then ``<log>.key`` next to the file.
    """
    log_path = Path(path)
    if not log_path.exists():
        return IntegrityReport(ok=False, entries=0, error=f"{log_path} does not exist")
    if secret_key is None and key_file is not None:
        secret_key = _decode_key(Path(key_file).read_text(encoding="utf-8"))
    if secret_key is None:
        env_value = os.environ.get(AUDIT_KEY_ENV, "").strip()
        if env_value:
            secret_key = _decode_key(env_value)
        elif key_file_for(log_path).exists():
            secret_key = _decode_key(key_file_for(log_path).read_text(encoding="utf-8"))
        else:
            return IntegrityReport(
                ok=False, entries=0, error="no HMAC key: set AISDLC_AUDIT_KEY or pass a key file"
            )
    gov = agt_governance()
    verifier = gov.audit_backends.HashChainVerifier()
    ok, errors = verifier.verify_file(log_path, secret_key)
    count = sum(1 for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip())
    return IntegrityReport(
        ok=bool(ok), entries=count, error="; ".join(errors) if errors else None, file_verified=ok
    )


def _arguments_hash(parameters: dict[str, Any]) -> str:
    canonical = json.dumps(parameters, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _agent_of(decision: Any) -> str:
    agent = getattr(decision, "agent_id", None)
    return str(agent) if agent else "unknown"


AUDIT_PRODUCED_BY = f"aisdlc.governance.audit/{__version__}"


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def audit_evidence_from_export(
    export: Mapping[str, Any],
    *,
    commit_sha: str = "",
    environment: str = "local",
    evidence_id: str = "EVD-audit-001",
    report_uri: str | None = None,
    produced_by: str = AUDIT_PRODUCED_BY,
) -> AuditEvidence:
    """Fold a detailed export (:meth:`AuditTrail.export_evidence`) into the canonical record.

    The canonical :class:`~aisdlc.schema.models.AuditEvidence` carries counts and the
    integrity verdict only; ``status`` is ``complete`` iff the hash chain verified, so a
    tampered or unverifiable log fails G4/G6 closed. ``report_uri`` should point at the
    detailed entries (sidecar file or the signed log) so the per-call detail stays reachable.
    """
    entries = export.get("entries")
    entry_list = entries if isinstance(entries, list) else []
    count = len(entry_list) if isinstance(entries, list) else int(entries or 0)
    timestamps = sorted(
        ts
        for ts in (_parse_ts(e.get("timestamp")) for e in entry_list if isinstance(e, Mapping))
        if ts
    )
    integrity_ok = bool(export.get("integrity_ok"))
    return AuditEvidence(
        id=evidence_id,
        kind=EvidenceKind.AUDIT,
        commit_sha=commit_sha,
        environment=environment,
        produced_by=produced_by,
        started_at=timestamps[0] if timestamps else None,
        finished_at=timestamps[-1] if timestamps else _parse_ts(export.get("exported_at")),
        report_uri=report_uri if report_uri is not None else export.get("log_path"),
        status=EvidenceStatus.COMPLETE if integrity_ok else EvidenceStatus.INCOMPLETE,
        entries=count,
        integrity_ok=integrity_ok,
        privileged_calls=int(export.get("privileged_calls", 0) or 0),
        denied_calls=int(export.get("denied_calls", 0) or 0),
        approvals=int(export.get("approved_calls", export.get("approvals", 0)) or 0),
    )


def record_audit_evidence(
    package_dir: str | Path,
    export: Mapping[str, Any],
    *,
    commit_sha: str = "",
    environment: str = "local",
    evidence_id: str = "EVD-audit-001",
) -> tuple[AuditEvidence, Path]:
    """Store audit evidence in a change package: canonical record + detailed entries sidecar.

    Writes ``evidence/audit-entries.json`` (the detailed export, consumed by the manifest
    drift check) and ``evidence/audit.json`` (the canonical summary, ``report_uri`` set to
    the sidecar). Returns the record and the sidecar path.
    """
    root = Path(package_dir)
    sidecar = pkgio.audit_entries_path(root)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(json.dumps(dict(export), indent=2, default=str) + "\n", encoding="utf-8")
    record = audit_evidence_from_export(
        export,
        commit_sha=commit_sha,
        environment=environment,
        evidence_id=evidence_id,
        report_uri=str(sidecar),
    )
    pkgio.write_evidence(root, EvidenceKind.AUDIT, record)
    return record, sidecar
