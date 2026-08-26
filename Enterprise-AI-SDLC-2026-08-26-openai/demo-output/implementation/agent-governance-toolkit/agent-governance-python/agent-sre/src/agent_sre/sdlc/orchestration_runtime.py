# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Durable, fail-closed execution of governed orchestration manifests.

The planner in :mod:`agent_sre.sdlc.orchestration` is intentionally side-effect
free.  This module is the corresponding host boundary: it executes the immutable
assignments through an injected adapter while keeping authority, accounting, and
restart state outside the model process.
"""

from __future__ import annotations

import hmac
import json
import math
import os
import queue
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, Self, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.canonical import canonical_json_bytes, digest_without, load_json_strict
from agent_sre.sdlc.control_plane import PromptRegistry
from agent_sre.sdlc.model_registry import ModelIdentity, ModelRegistry, PriceCatalog, TokenUsage
from agent_sre.sdlc.orchestration import (
    AssignmentRole,
    CheckpointPhase,
    HumanCheckpoint,
    OrchestrationManifest,
    PromptRouteRecord,
    ToolAction,
    WorkAssignment,
    model_price_record_digest,
)
from agent_sre.sdlc.review_loop import (
    RemediationExecutionHistory,
    RemediationScopeBinding,
    ReviewFinding,
    ReviewFindingSet,
    ReviewRoundHistory,
    ReviewSemanticOutcome,
    ReviewVerdict,
    path_is_within_scope,
)
from agent_sre.sdlc.usage_ledger import (
    PromptIdentity,
    UsageAttribution,
    UsageEvent,
    UsageLedger,
)
from agent_sre.signing import ArtifactSigner

GRANT_SCHEMA_VERSION: Literal["agt.checkpoint-grant/v1"] = "agt.checkpoint-grant/v1"
REQUEST_SCHEMA_VERSION: Literal["agt.assignment-execution-request/v1"] = (
    "agt.assignment-execution-request/v1"
)
TOOL_ACTION_SCHEMA_VERSION: Literal["agt.tool-action-request/v1"] = "agt.tool-action-request/v1"
TOOL_RESULT_SCHEMA_VERSION: Literal["agt.tool-action-result/v1"] = "agt.tool-action-result/v1"
TOOL_AUDIT_SCHEMA_VERSION: Literal["agt.tool-call-audit/v1"] = "agt.tool-call-audit/v1"
RECEIPT_SCHEMA_VERSION: Literal["agt.orchestration-execution-receipt/v1"] = (
    "agt.orchestration-execution-receipt/v1"
)

__all__ = [
    "AssignmentExecutionReceipt",
    "AssignmentExecutionRequest",
    "AssignmentExecutionState",
    "AssignmentHost",
    "AssignmentHostOutcome",
    "CancellationProbe",
    "CheckpointDecision",
    "CheckpointGrant",
    "CheckpointGrantError",
    "CheckpointGrantVerifier",
    "CooperativeCancellationError",
    "ExecutionBudgetExceededError",
    "ExecutionInProgressError",
    "ExecutionReceipt",
    "ExecutionStatus",
    "Ed25519CheckpointGrantVerifier",
    "GovernedOrchestrationRuntime",
    "HostOutcomeStatus",
    "HostActionAuthorizer",
    "HostBudgetSnapshot",
    "HostExecutionTimeoutError",
    "HostResultScreener",
    "ManifestIdempotencyError",
    "OrchestrationRuntimeError",
    "PinnedCheckpointGrantVerifier",
    "RuntimePathSafetyError",
    "RemediationExecutionHistory",
    "RemediationScopeBinding",
    "ReviewRoundHistory",
    "ReviewFinding",
    "ReviewFindingSet",
    "ReviewSemanticOutcome",
    "ReviewVerdict",
    "ToolActionRequest",
    "ToolActionResult",
    "ToolAuditDecision",
    "ToolCallAudit",
    "ToolGovernanceError",
    "TrustedBindingError",
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")


class OrchestrationRuntimeError(RuntimeError):
    """Base error for the governed execution boundary."""


class RuntimePathSafetyError(OrchestrationRuntimeError):
    """Raised when the durable state path escapes its configured safe root."""


class TrustedBindingError(OrchestrationRuntimeError):
    """Raised when independently trusted digests do not bind the manifest."""


class ManifestIdempotencyError(OrchestrationRuntimeError):
    """Raised when an existing manifest or run identifier is reused with new facts."""


class CheckpointGrantError(OrchestrationRuntimeError):
    """Raised when a supplied checkpoint grant is malformed, stale, or misbound."""


class ExecutionInProgressError(OrchestrationRuntimeError):
    """Raised when another runtime owns the durable execution lease."""


class CooperativeCancellationError(OrchestrationRuntimeError):
    """Raised by a host after the supplied cancellation probe returns true."""


class ExecutionBudgetExceededError(OrchestrationRuntimeError):
    """Raised before a cooperatively mediated host action would exceed a limit."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ToolGovernanceError(OrchestrationRuntimeError):
    """Raised before an unapproved or policy-disallowed host action can run."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class HostExecutionTimeoutError(OrchestrationRuntimeError):
    """Raised when a synchronous host does not return before its hard deadline."""


class _CancellationWonFinalizationError(RuntimeError):
    """Internal signal when cancellation commits before a success receipt."""


@dataclass(frozen=True, slots=True)
class _ExecutionLease:
    manifest_id: str
    token: str
    epoch: int


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _time_text(value: datetime) -> str:
    return _utc(value, field_name="datetime").isoformat(timespec="microseconds")


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite() or value < 0:
        raise ValueError("cost must be finite and non-negative")
    return "0" if value == 0 else format(value.normalize(), "f")


def _validate_digest(value: str, *, field_name: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _sorted_unique(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{field_name} must be sorted and unique")
    return values


class RuntimeContractModel(BaseModel):
    """Strict, immutable wire model used at the execution trust boundary."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        allow_inf_nan=False,
        arbitrary_types_allowed=True,
    )


class CheckpointDecision(StrEnum):
    """Explicit human disposition for a checkpoint."""

    APPROVE = "approve"
    DENY = "deny"


class CheckpointGrant(RuntimeContractModel):
    """Digest-bound, expiring authorization for one exact manifest checkpoint."""

    schema_version: Literal["agt.checkpoint-grant/v1"] = GRANT_SCHEMA_VERSION
    grant_id: str = Field(min_length=1, max_length=256)
    checkpoint_id: str = Field(min_length=1, max_length=256)
    assignment_id: str = Field(min_length=1, max_length=256)
    manifest_id: str = Field(min_length=1, max_length=256)
    manifest_digest: str
    change_digest: str
    policy_digest: str
    signer_id: str = Field(min_length=1, max_length=256)
    approver_id: str = Field(min_length=1, max_length=256)
    approver_role: str = Field(min_length=1, max_length=256)
    decision: CheckpointDecision
    review_outcome_digest: str | None = None
    review_output_digest: str | None = None
    issued_at: datetime
    expires_at: datetime
    grant_digest: str
    signature: str

    @field_validator(
        "grant_id",
        "checkpoint_id",
        "assignment_id",
        "manifest_id",
        "signer_id",
        "approver_id",
        "approver_role",
    )
    @classmethod
    def _safe_ids(cls, value: str, info: Any) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator(
        "manifest_digest",
        "change_digest",
        "policy_digest",
        "review_outcome_digest",
        "review_output_digest",
        "grant_digest",
    )
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _validate_digest(value, field_name=info.field_name)

    @field_validator("signature")
    @classmethod
    def _signature(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{128}", value) is None:
            raise ValueError("signature must be a canonical Ed25519 signature")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _times(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        if (self.review_outcome_digest is None) != (self.review_output_digest is None):
            raise ValueError(
                "review_outcome_digest and review_output_digest must be supplied together"
            )
        expected = digest_without(self, "grant_digest", "signature")
        if self.grant_digest != expected:
            raise ValueError(f"grant_digest mismatch: expected {expected}, got {self.grant_digest}")
        return self

    @classmethod
    def issue(
        cls,
        *,
        grant_id: str,
        checkpoint: HumanCheckpoint,
        assignment_id: str,
        manifest: OrchestrationManifest,
        signer: ArtifactSigner,
        signer_id: str,
        approver_id: str,
        approver_role: str,
        decision: CheckpointDecision,
        issued_at: datetime,
        expires_at: datetime,
        review_outcome_digest: str | None = None,
        review_output_digest: str | None = None,
    ) -> CheckpointGrant:
        """Create a canonical grant; release grants bind the completed review output."""

        release_checkpoint = checkpoint.phase is CheckpointPhase.BEFORE_RELEASE
        review_binding_present = (
            review_outcome_digest is not None and review_output_digest is not None
        )
        if assignment_id not in checkpoint.assignment_ids:
            raise ValueError("assignment_id is not authorized by the checkpoint plan")
        if release_checkpoint and not review_binding_present:
            raise ValueError("release checkpoint grants require review outcome and output digests")
        if not release_checkpoint and (
            review_outcome_digest is not None or review_output_digest is not None
        ):
            raise ValueError("before-assignment grants cannot bind a review outcome or output")

        payload: dict[str, Any] = {
            "schema_version": GRANT_SCHEMA_VERSION,
            "grant_id": grant_id,
            "checkpoint_id": checkpoint.checkpoint_id,
            "assignment_id": assignment_id,
            "manifest_id": manifest.manifest_id,
            "manifest_digest": manifest.digest,
            "change_digest": manifest.change_digest,
            "policy_digest": manifest.policy_digest,
            "signer_id": signer_id,
            "approver_id": approver_id,
            "approver_role": approver_role,
            "decision": decision,
            "review_outcome_digest": review_outcome_digest,
            "review_output_digest": review_output_digest,
            "issued_at": _utc(issued_at, field_name="issued_at"),
            "expires_at": _utc(expires_at, field_name="expires_at"),
        }
        provisional = cls.model_construct(
            **payload,
            grant_digest="0" * 64,
            signature="0" * 128,
        )
        payload["grant_digest"] = digest_without(provisional, "grant_digest", "signature")
        signed = cls.model_construct(**payload, signature="0" * 128)
        payload["signature"] = signer.sign_payload(signed.signature_payload()).hex()
        return cls.model_validate(payload)

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes including the verified digest."""

        return canonical_json_bytes(self)

    def signature_payload(self) -> bytes:
        """Return domain-separated bytes authenticated by the grant issuer."""

        return canonical_json_bytes(
            {
                "schema_version": "agt.checkpoint-grant-signature/v1",
                "signer_id": self.signer_id,
                "grant_digest": self.grant_digest,
            }
        )


class CheckpointGrantVerifier(Protocol):
    """Independent trust anchor for authentic checkpoint grants.

    A grant's self-digest proves integrity, not who issued it. Implementations can
    verify an IdP assertion, a detached signature, or an out-of-band digest pin.
    """

    def verify(self, grant: CheckpointGrant) -> bool:
        """Return whether the grant is authentic under the host's trust policy."""


class PinnedCheckpointGrantVerifier:
    """Immutable verifier for grant digests approved through a trusted channel."""

    def __init__(self, trusted_grant_digests: Iterable[str]) -> None:
        trusted: list[str] = []
        for digest in trusted_grant_digests:
            trusted.append(_validate_digest(digest, field_name="trusted grant digest"))
        self._trusted = tuple(sorted(set(trusted)))

    def verify(self, grant: CheckpointGrant) -> bool:
        """Compare the verified grant digest against immutable trusted pins."""

        return any(hmac.compare_digest(grant.grant_digest, digest) for digest in self._trusted)


class Ed25519CheckpointGrantVerifier:
    """Verify grants against independently pinned Ed25519 issuer keys."""

    def __init__(self, trusted_public_keys: Mapping[str, bytes]) -> None:
        normalized: dict[str, bytes] = {}
        for signer_id, public_key in trusted_public_keys.items():
            if not isinstance(signer_id, str) or not _SAFE_ID.fullmatch(signer_id):
                raise ValueError("trusted signer_id contains unsupported characters")
            if not isinstance(public_key, bytes) or len(public_key) != 32:
                raise ValueError("trusted Ed25519 public keys must be exactly 32 bytes")
            normalized[signer_id] = bytes(public_key)
        if not normalized:
            raise ValueError("at least one trusted Ed25519 public key is required")
        self._trusted_public_keys = normalized

    def verify(self, grant: CheckpointGrant) -> bool:
        """Verify the signature without trusting a key carried by the grant."""

        public_key = self._trusted_public_keys.get(grant.signer_id)
        if public_key is None:
            return False
        try:
            signature = bytes.fromhex(grant.signature)
        except ValueError:
            return False
        return ArtifactSigner.verify_payload(
            grant.signature_payload(),
            signature,
            public_key,
        )


class AssignmentExecutionRequest(RuntimeContractModel):
    """Immutable request sent to the injected assignment host."""

    schema_version: Literal["agt.assignment-execution-request/v1"] = REQUEST_SCHEMA_VERSION
    manifest_id: str
    manifest_digest: str
    run_id: str
    change_id: str
    change_digest: str
    policy_digest: str
    assignment: WorkAssignment
    review_round_number: int | None = Field(default=None, ge=1, le=32)
    remediation_binding: RemediationScopeBinding | None = None
    checkpoint_grant_digests: tuple[str, ...]
    requested_at: datetime
    request_digest: str

    @field_validator("manifest_digest", "change_digest", "policy_digest", "request_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _validate_digest(value, field_name=info.field_name)

    @field_validator("checkpoint_grant_digests")
    @classmethod
    def _grant_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="checkpoint_grant_digests")
        for digest in result:
            _validate_digest(digest, field_name="checkpoint_grant_digests entry")
        return result

    @field_validator("requested_at")
    @classmethod
    def _requested_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="requested_at")

    @field_validator("review_round_number", mode="before")
    @classmethod
    def _review_round_number(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("review_round_number must be an integer")
        return value

    @model_validator(mode="after")
    def _digest(self) -> Self:
        remediation = self.assignment.role is AssignmentRole.REMEDIATION
        review = self.assignment.role is AssignmentRole.INDEPENDENT_REVIEW
        if remediation != (self.remediation_binding is not None):
            raise ValueError("only remediation requests require a prior-review binding")
        if review != (self.review_round_number is not None):
            raise ValueError("only review requests require review_round_number")
        if self.remediation_binding is not None:
            binding = self.remediation_binding
            if not set(binding.task_ids) <= set(self.assignment.contract_task_ids):
                raise ValueError("remediation binding contains an unplanned task")
            if any(
                not any(
                    path_is_within_scope(path, scope)
                    for scope in self.assignment.remediation_path_scopes
                )
                for path in binding.paths
            ):
                raise ValueError("remediation binding contains an unplanned path")
        expected = digest_without(self, "request_digest")
        if self.request_digest != expected:
            raise ValueError(
                f"request_digest mismatch: expected {expected}, got {self.request_digest}"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        checkpoint_grant_digests: tuple[str, ...],
        requested_at: datetime,
        remediation_binding: RemediationScopeBinding | None = None,
    ) -> AssignmentExecutionRequest:
        review_assignments = (
            manifest.review_assignment,
            *(item.review_assignment for item in manifest.conditional_review_rounds),
        )
        review_round_number = next(
            (
                index + 1
                for index, review in enumerate(review_assignments)
                if review.assignment_id == assignment.assignment_id
            ),
            None,
        )
        payload: dict[str, Any] = {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "manifest_id": manifest.manifest_id,
            "manifest_digest": manifest.digest,
            "run_id": manifest.run_id,
            "change_id": manifest.change_id,
            "change_digest": manifest.change_digest,
            "policy_digest": manifest.policy_digest,
            "assignment": assignment,
            "review_round_number": review_round_number,
            "remediation_binding": remediation_binding,
            "checkpoint_grant_digests": tuple(sorted(checkpoint_grant_digests)),
            "requested_at": _utc(requested_at, field_name="requested_at"),
        }
        provisional = cls.model_construct(**payload, request_digest="0" * 64)
        payload["request_digest"] = digest_without(provisional, "request_digest")
        return cls.model_validate(payload)


class ToolActionRequest(RuntimeContractModel):
    """Canonical per-call authority request submitted before a host side effect."""

    schema_version: Literal["agt.tool-action-request/v1"] = TOOL_ACTION_SCHEMA_VERSION
    action_id: str = Field(min_length=1, max_length=256)
    tool: str = Field(min_length=1, max_length=128)
    action: ToolAction
    resource: str = Field(min_length=1, max_length=4096)
    path: str | None = Field(default=None, max_length=4096)
    url: str | None = Field(default=None, max_length=4096)
    scopes: tuple[str, ...] = Field(min_length=1, max_length=16)
    command: tuple[str, ...] = Field(default=(), max_length=128)
    secret_reference: str | None = Field(default=None, max_length=128)
    approval_grant_digest: str | None = None
    request_digest: str

    @field_validator("action_id")
    @classmethod
    def _action_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("action_id contains unsupported characters")
        return value

    @field_validator("tool")
    @classmethod
    def _tool(cls, value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
            raise ValueError("tool contains unsupported characters")
        return value

    @field_validator("resource", "path", "url", "secret_reference")
    @classmethod
    def _canonical_strings(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        if value != value.strip() or not value or any(ord(char) < 32 for char in value):
            raise ValueError(f"{info.field_name} must be a canonical printable string")
        return value

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(value, field_name="scopes")

    @field_validator("command")
    @classmethod
    def _command(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not token
            or token != token.strip()
            or any(ord(char) < 32 for char in token)
            or len(token.encode("utf-8")) > 4096
            for token in value
        ):
            raise ValueError("command must contain bounded canonical argv tokens")
        return value

    @field_validator("approval_grant_digest", "request_digest")
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _validate_digest(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _shape_and_digest(self) -> Self:
        workspace_action = self.action in {ToolAction.READ, ToolAction.WRITE}
        if workspace_action:
            if (
                self.path is None
                or self.resource != self.path
                or self.url is not None
                or self.command
                or self.secret_reference is not None
            ):
                raise ValueError("read/write actions require one exact workspace path")
        elif self.action is ToolAction.EXECUTE:
            if (
                self.path is None
                or not self.command
                or self.url is not None
                or self.secret_reference is not None
            ):
                raise ValueError("execute actions require argv and a workspace path")
        elif self.action is ToolAction.NETWORK:
            if (
                self.url is None
                or self.resource != self.url
                or self.path is not None
                or self.command
                or self.secret_reference is not None
            ):
                raise ValueError("network actions require one exact URL")
        elif self.action is ToolAction.SECRET_ACCESS:
            if (
                self.secret_reference is None
                or self.resource != self.secret_reference
                or self.path is not None
                or self.url is not None
                or self.command
            ):
                raise ValueError("secret access requires one exact secret reference")
        elif self.path is not None or self.url is not None or self.command or self.secret_reference:
            raise ValueError("administrative actions accept only a logical resource")
        expected = digest_without(self, "request_digest")
        if self.request_digest != expected:
            raise ValueError(
                f"request_digest mismatch: expected {expected}, got {self.request_digest}"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        action_id: str,
        tool: str,
        action: ToolAction,
        resource: str,
        scopes: tuple[str, ...],
        path: str | None = None,
        url: str | None = None,
        command: tuple[str, ...] = (),
        secret_reference: str | None = None,
        approval_grant_digest: str | None = None,
    ) -> ToolActionRequest:
        payload: dict[str, Any] = {
            "schema_version": TOOL_ACTION_SCHEMA_VERSION,
            "action_id": action_id,
            "tool": tool,
            "action": action,
            "resource": resource,
            "path": path,
            "url": url,
            "scopes": scopes,
            "command": command,
            "secret_reference": secret_reference,
            "approval_grant_digest": approval_grant_digest,
        }
        provisional = cls.model_construct(**payload, request_digest="0" * 64)
        payload["request_digest"] = digest_without(provisional, "request_digest")
        return cls.model_validate(payload)


class ToolActionResult(RuntimeContractModel):
    """Untrusted tool output that must pass runtime screening before use."""

    schema_version: Literal["agt.tool-action-result/v1"] = TOOL_RESULT_SCHEMA_VERSION
    action_id: str = Field(min_length=1, max_length=256)
    request_digest: str
    content_type: Literal["text", "json"]
    content: str = Field(max_length=16 * 1024 * 1024)
    result_digest: str

    @field_validator("action_id")
    @classmethod
    def _action_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("action_id contains unsupported characters")
        return value

    @field_validator("request_digest", "result_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _validate_digest(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _digest(self) -> Self:
        expected = digest_without(self, "result_digest")
        if self.result_digest != expected:
            raise ValueError(
                f"result_digest mismatch: expected {expected}, got {self.result_digest}"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        action: ToolActionRequest,
        content_type: Literal["text", "json"],
        content: str,
    ) -> ToolActionResult:
        payload: dict[str, Any] = {
            "schema_version": TOOL_RESULT_SCHEMA_VERSION,
            "action_id": action.action_id,
            "request_digest": action.request_digest,
            "content_type": content_type,
            "content": content,
        }
        provisional = cls.model_construct(**payload, result_digest="0" * 64)
        payload["result_digest"] = digest_without(provisional, "result_digest")
        return cls.model_validate(payload)


class ToolAuditDecision(StrEnum):
    """Durable disposition of a mediated tool action."""

    AUTHORIZED = "authorized"
    DENIED = "denied"
    SCREENED = "screened"


class ToolCallAudit(RuntimeContractModel):
    """Digest-bound audit record for one authorized or denied host action."""

    schema_version: Literal["agt.tool-call-audit/v1"] = TOOL_AUDIT_SCHEMA_VERSION
    manifest_id: str
    assignment_id: str
    action_id: str
    tool: str
    action: ToolAction
    resource: str
    request_digest: str
    result_digest: str | None
    privileged: bool
    approval_grant_digest: str | None
    decision: ToolAuditDecision
    reason_code: str | None
    authorized_at: datetime
    completed_at: datetime | None
    audit_digest: str

    @field_validator("manifest_id", "assignment_id", "action_id")
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator("request_digest", "result_digest", "approval_grant_digest", "audit_digest")
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _validate_digest(value, field_name=info.field_name)

    @field_validator("authorized_at", "completed_at")
    @classmethod
    def _times(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.decision is ToolAuditDecision.AUTHORIZED and (
            self.result_digest is not None
            or self.reason_code is not None
            or self.completed_at is not None
        ):
            raise ValueError("authorized audit must remain open for result screening")
        if self.decision is ToolAuditDecision.SCREENED and (
            self.result_digest is None or self.reason_code is not None or self.completed_at is None
        ):
            raise ValueError("screened audit requires a completed result digest")
        if self.decision is ToolAuditDecision.DENIED and (
            self.reason_code is None or self.completed_at is None
        ):
            raise ValueError("denied audit requires a reason and completion time")
        if self.completed_at is not None and self.completed_at < self.authorized_at:
            raise ValueError("tool audit completion precedes authorization")
        expected = digest_without(self, "audit_digest")
        if self.audit_digest != expected:
            raise ValueError(f"audit_digest mismatch: expected {expected}, got {self.audit_digest}")
        return self

    @classmethod
    def create(
        cls,
        *,
        manifest_id: str,
        assignment_id: str,
        request: ToolActionRequest,
        privileged: bool,
        decision: ToolAuditDecision,
        authorized_at: datetime,
        result_digest: str | None = None,
        reason_code: str | None = None,
        completed_at: datetime | None = None,
    ) -> ToolCallAudit:
        payload: dict[str, Any] = {
            "schema_version": TOOL_AUDIT_SCHEMA_VERSION,
            "manifest_id": manifest_id,
            "assignment_id": assignment_id,
            "action_id": request.action_id,
            "tool": request.tool,
            "action": request.action,
            "resource": request.resource,
            "request_digest": request.request_digest,
            "result_digest": result_digest,
            "privileged": privileged,
            "approval_grant_digest": request.approval_grant_digest,
            "decision": decision,
            "reason_code": reason_code,
            "authorized_at": _utc(authorized_at, field_name="authorized_at"),
            "completed_at": (
                None if completed_at is None else _utc(completed_at, field_name="completed_at")
            ),
        }
        provisional = cls.model_construct(**payload, audit_digest="0" * 64)
        payload["audit_digest"] = digest_without(provisional, "audit_digest")
        return cls.model_validate(payload)

    def complete(
        self,
        *,
        decision: Literal[ToolAuditDecision.DENIED, ToolAuditDecision.SCREENED],
        completed_at: datetime,
        result_digest: str | None = None,
        reason_code: str | None = None,
    ) -> ToolCallAudit:
        """Transition one open authorization to a terminal audit disposition."""

        if self.decision is not ToolAuditDecision.AUTHORIZED:
            raise ValueError("only an authorized audit can be completed")
        payload = self.model_dump(mode="python", exclude={"audit_digest"})
        payload.update(
            {
                "decision": decision,
                "completed_at": _utc(completed_at, field_name="completed_at"),
                "result_digest": result_digest,
                "reason_code": reason_code,
            }
        )
        provisional = type(self).model_construct(**payload, audit_digest="0" * 64)
        payload["audit_digest"] = digest_without(provisional, "audit_digest")
        return type(self).model_validate(payload)

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes including the verified audit digest."""

        return canonical_json_bytes(self.model_dump(mode="json"))


class HostOutcomeStatus(StrEnum):
    """Host-reported disposition after a real assignment attempt."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AssignmentHostOutcome:
    """Observed host result, including the real usage event for reconciliation."""

    assignment_id: str
    manifest_id: str
    manifest_digest: str
    change_digest: str
    policy_digest: str
    context_id: str
    workspace_key: str
    status: HostOutcomeStatus
    usage_event: UsageEvent
    output_digest: str
    failure_reason: str | None = None
    review_semantic_outcome: ReviewSemanticOutcome | None = None
    remediation_binding: RemediationScopeBinding | None = None

    def __post_init__(self) -> None:
        for field_name in ("manifest_digest", "change_digest", "policy_digest", "output_digest"):
            _validate_digest(str(getattr(self, field_name)), field_name=field_name)
        for field_name in ("assignment_id", "manifest_id", "context_id", "workspace_key"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise ValueError(f"{field_name} contains unsupported characters")
        if not isinstance(self.status, HostOutcomeStatus):
            raise ValueError("status must be a HostOutcomeStatus")
        if not isinstance(self.usage_event, UsageEvent):
            raise ValueError("usage_event must be a UsageEvent")
        if self.status is HostOutcomeStatus.SUCCEEDED and self.failure_reason is not None:
            raise ValueError("successful outcomes cannot include failure_reason")
        if self.status is HostOutcomeStatus.FAILED and not self.failure_reason:
            raise ValueError("failed outcomes must include failure_reason")
        if self.review_semantic_outcome is not None and not isinstance(
            self.review_semantic_outcome, ReviewSemanticOutcome
        ):
            raise ValueError("review_semantic_outcome has the wrong type")
        if self.remediation_binding is not None and not isinstance(
            self.remediation_binding, RemediationScopeBinding
        ):
            raise ValueError("remediation_binding has the wrong type")
        if self.review_semantic_outcome is not None and self.remediation_binding is not None:
            raise ValueError("one host outcome cannot be both review and remediation")

    @property
    def digest(self) -> str:
        """Digest every host claim and the exact unpriced usage event."""

        return digest_without(_host_outcome_payload(self))


def _host_outcome_payload(outcome: AssignmentHostOutcome) -> dict[str, Any]:
    return {
        "assignment_id": outcome.assignment_id,
        "manifest_id": outcome.manifest_id,
        "manifest_digest": outcome.manifest_digest,
        "change_digest": outcome.change_digest,
        "policy_digest": outcome.policy_digest,
        "context_id": outcome.context_id,
        "workspace_key": outcome.workspace_key,
        "status": outcome.status.value,
        "usage_event": outcome.usage_event.canonical_payload(cost=None, price=None),
        "output_digest": outcome.output_digest,
        "failure_reason": outcome.failure_reason,
        "review_semantic_outcome": (
            None
            if outcome.review_semantic_outcome is None
            else outcome.review_semantic_outcome.model_dump(mode="json")
        ),
        "remediation_binding": (
            None
            if outcome.remediation_binding is None
            else outcome.remediation_binding.model_dump(mode="json")
        ),
    }


def _host_outcome_from_payload(payload: object) -> AssignmentHostOutcome:
    expected = {
        "assignment_id",
        "manifest_id",
        "manifest_digest",
        "change_digest",
        "policy_digest",
        "context_id",
        "workspace_key",
        "status",
        "usage_event",
        "output_digest",
        "failure_reason",
        "review_semantic_outcome",
        "remediation_binding",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ManifestIdempotencyError("stored outcome intent has an invalid shape")
    event = payload["usage_event"]
    event_fields = {
        "event_id",
        "occurred_at",
        "attribution",
        "model",
        "prompt",
        "usage",
        "latency_ms",
        "tool_calls",
        "turns",
        "outcome",
        "metadata",
        "cost_usd",
        "price_effective_from",
    }
    if (
        not isinstance(event, dict)
        or set(event) != event_fields
        or event["cost_usd"] is not None
        or event["price_effective_from"] is not None
        or not isinstance(event["attribution"], dict)
        or not isinstance(event["model"], dict)
        or not isinstance(event["prompt"], dict)
        or not isinstance(event["usage"], dict)
        or not isinstance(event["metadata"], dict)
    ):
        raise ManifestIdempotencyError("stored outcome usage event is invalid")
    try:
        usage_event = UsageEvent(
            event_id=event["event_id"],
            occurred_at=datetime.fromisoformat(event["occurred_at"]),
            attribution=UsageAttribution(**event["attribution"]),
            model=ModelIdentity(**event["model"]),
            prompt=PromptIdentity(**event["prompt"]),
            usage=TokenUsage(**event["usage"]),
            latency_ms=event["latency_ms"],
            tool_calls=event["tool_calls"],
            turns=event["turns"],
            outcome=event["outcome"],
            metadata=event["metadata"],
        )
        return AssignmentHostOutcome(
            assignment_id=payload["assignment_id"],
            manifest_id=payload["manifest_id"],
            manifest_digest=payload["manifest_digest"],
            change_digest=payload["change_digest"],
            policy_digest=payload["policy_digest"],
            context_id=payload["context_id"],
            workspace_key=payload["workspace_key"],
            status=HostOutcomeStatus(payload["status"]),
            usage_event=usage_event,
            output_digest=payload["output_digest"],
            failure_reason=payload["failure_reason"],
            review_semantic_outcome=(
                None
                if payload["review_semantic_outcome"] is None
                else ReviewSemanticOutcome.model_validate_json(
                    canonical_json_bytes(payload["review_semantic_outcome"])
                )
            ),
            remediation_binding=(
                None
                if payload["remediation_binding"] is None
                else RemediationScopeBinding.model_validate_json(
                    canonical_json_bytes(payload["remediation_binding"])
                )
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ManifestIdempotencyError("stored outcome intent failed validation") from exc


@dataclass(frozen=True, slots=True)
class _OutcomeIntent:
    assignment_id: str
    outcome: AssignmentHostOutcome
    checkpoint_grant_digests: tuple[str, ...]
    forced_failures: tuple[str, ...]
    reconciled_at: datetime


CancellationProbe = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class HostBudgetSnapshot:
    """Atomic post-authorization view of one assignment and the whole run."""

    turns: int
    tool_calls: int
    estimated_cost_usd: Decimal
    actual_cost_usd: Decimal
    assignment_projected_cost_usd: Decimal
    run_projected_cost_usd: Decimal


class HostActionAuthorizer(Protocol):
    """Host callback invoked immediately before a turn, tool call, or paid action."""

    def __call__(
        self,
        *,
        turns: int = 0,
        tool_calls: int = 0,
        estimated_cost_usd: Decimal = Decimal("0"),
        actual_cost_usd: Decimal = Decimal("0"),
        action: ToolActionRequest | None = None,
    ) -> HostBudgetSnapshot:
        """Atomically reserve non-negative action deltas or reject before execution."""


class HostResultScreener(Protocol):
    """Runtime callback required before a host consumes untrusted tool output."""

    def __call__(self, result: ToolActionResult) -> str:
        """Screen and durably audit *result*, returning its audit digest."""


@dataclass(slots=True)
class _AssignmentBudgetState:
    turns: int = 0
    tool_calls: int = 0
    estimated_cost_usd: Decimal = Decimal("0")
    actual_cost_usd: Decimal = Decimal("0")

    @property
    def projected_cost_usd(self) -> Decimal:
        return max(self.estimated_cost_usd, self.actual_cost_usd)


class _ExecutionBudgetMeter:
    """Thread-safe cooperative budget pool shared by parallel host adapters."""

    def __init__(self, manifest: OrchestrationManifest, *, committed_cost_usd: Decimal) -> None:
        self._assignments = {
            assignment.assignment_id: (assignment, _AssignmentBudgetState())
            for assignment in GovernedOrchestrationRuntime._assignments(manifest)
        }
        self._committed_cost_usd = committed_cost_usd
        self._max_total_cost_usd = manifest.limits.max_total_cost_usd
        self._lock = threading.Lock()

    @staticmethod
    def _nonnegative_delta(value: Decimal, *, field_name: str) -> Decimal:
        if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
            raise ValueError(f"{field_name} must be a finite non-negative Decimal")
        return value

    def authorizer(self, assignment: WorkAssignment) -> HostActionAuthorizer:
        """Bind an atomic authorizer to one immutable assignment."""

        def authorize_action(
            *,
            turns: int = 0,
            tool_calls: int = 0,
            estimated_cost_usd: Decimal = Decimal("0"),
            actual_cost_usd: Decimal = Decimal("0"),
            action: ToolActionRequest | None = None,
        ) -> HostBudgetSnapshot:
            if action is not None or tool_calls:
                raise ToolGovernanceError("tool.governance_session_required")
            return self._authorize(
                assignment,
                turns=turns,
                tool_calls=tool_calls,
                estimated_cost_usd=estimated_cost_usd,
                actual_cost_usd=actual_cost_usd,
            )

        return authorize_action

    def _authorize(
        self,
        assignment: WorkAssignment,
        *,
        turns: int,
        tool_calls: int,
        estimated_cost_usd: Decimal,
        actual_cost_usd: Decimal,
    ) -> HostBudgetSnapshot:
        if isinstance(turns, bool) or not isinstance(turns, int) or turns < 0:
            raise ValueError("turns must be a non-negative integer delta")
        if isinstance(tool_calls, bool) or not isinstance(tool_calls, int) or tool_calls < 0:
            raise ValueError("tool_calls must be a non-negative integer delta")
        estimated_delta = self._nonnegative_delta(
            estimated_cost_usd,
            field_name="estimated_cost_usd",
        )
        actual_delta = self._nonnegative_delta(
            actual_cost_usd,
            field_name="actual_cost_usd",
        )
        with self._lock:
            registered_assignment, current = self._assignments[assignment.assignment_id]
            if registered_assignment != assignment:
                raise OrchestrationRuntimeError("host action authorizer assignment changed")
            next_turns = current.turns + turns
            next_tool_calls = current.tool_calls + tool_calls
            next_estimated = current.estimated_cost_usd + estimated_delta
            next_actual = current.actual_cost_usd + actual_delta
            next_projected = max(next_estimated, next_actual)
            if next_turns > assignment.max_turns:
                raise ExecutionBudgetExceededError("limit.turns_exceeded")
            if next_tool_calls > assignment.max_tool_calls:
                raise ExecutionBudgetExceededError("limit.tool_calls_exceeded")
            if next_projected > assignment.max_cost_usd:
                raise ExecutionBudgetExceededError("limit.assignment_cost_exceeded")
            other_projected = sum(
                (
                    state.projected_cost_usd
                    for assignment_id, (_item, state) in self._assignments.items()
                    if assignment_id != assignment.assignment_id
                ),
                Decimal("0"),
            )
            run_projected = self._committed_cost_usd + other_projected + next_projected
            if run_projected > self._max_total_cost_usd:
                raise ExecutionBudgetExceededError("limit.total_cost_exceeded")
            current.turns = next_turns
            current.tool_calls = next_tool_calls
            current.estimated_cost_usd = next_estimated
            current.actual_cost_usd = next_actual
            return HostBudgetSnapshot(
                turns=next_turns,
                tool_calls=next_tool_calls,
                estimated_cost_usd=next_estimated,
                actual_cost_usd=next_actual,
                assignment_projected_cost_usd=next_projected,
                run_projected_cost_usd=run_projected,
            )

    def finish(self, assignment: WorkAssignment, *, actual_cost_usd: Decimal) -> None:
        """Replace cooperative estimates with the reconciled assignment cost."""

        actual = self._nonnegative_delta(actual_cost_usd, field_name="actual_cost_usd")
        with self._lock:
            registered_assignment, current = self._assignments[assignment.assignment_id]
            if registered_assignment != assignment:
                raise OrchestrationRuntimeError("host action authorizer assignment changed")
            current.estimated_cost_usd = actual
            current.actual_cost_usd = actual


class _ToolGovernanceSession:
    """One deadline-fenced, durable Plane-2 mediation session for an assignment."""

    def __init__(
        self,
        *,
        runtime: GovernedOrchestrationRuntime,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        checkpoint_grant_digests: tuple[str, ...],
        checkpoint_grants: tuple[CheckpointGrant, ...],
        remediation_binding: RemediationScopeBinding | None,
        budget_meter: _ExecutionBudgetMeter,
        deadline_monotonic: float,
        cancellation_probe: CancellationProbe,
    ) -> None:
        self._runtime = runtime
        self._manifest = manifest
        self._assignment = assignment
        self._checkpoint_grant_digests = frozenset(checkpoint_grant_digests)
        self._checkpoint_grants = {grant.grant_digest: grant for grant in checkpoint_grants}
        self._remediation_binding = remediation_binding
        if set(self._checkpoint_grants) != self._checkpoint_grant_digests:
            raise OrchestrationRuntimeError(
                "checkpoint grant records do not match assignment authorization digests"
            )
        self._budget_meter = budget_meter
        self._deadline_monotonic = deadline_monotonic
        self._cancellation_probe = cancellation_probe
        self._closed_reason: str | None = None
        self._lock = threading.RLock()

    def _assert_live(self) -> None:
        if self._closed_reason is not None:
            raise ToolGovernanceError(self._closed_reason)
        if time.monotonic() >= self._deadline_monotonic:
            self._closed_reason = "host.execution_timeout"
            raise HostExecutionTimeoutError("host.execution_timeout")
        if self._cancellation_probe():
            self._closed_reason = "execution.cancelled"
            raise CooperativeCancellationError("host observed cancellation")

    def close(self, reason_code: str = "tool.session_closed") -> None:
        """Fence all later callbacks from a stale or returned host invocation."""

        with self._lock:
            if self._closed_reason is None:
                self._closed_reason = reason_code

    def authorize(
        self,
        *,
        turns: int = 0,
        tool_calls: int = 0,
        estimated_cost_usd: Decimal = Decimal("0"),
        actual_cost_usd: Decimal = Decimal("0"),
        action: ToolActionRequest | None = None,
    ) -> HostBudgetSnapshot:
        """Authorize one action and persist its decision before side effects."""

        with self._lock:
            self._assert_live()
            if action is None:
                if tool_calls:
                    raise ToolGovernanceError("tool.authorization_metadata_missing")
                return self._budget_meter._authorize(
                    self._assignment,
                    turns=turns,
                    tool_calls=tool_calls,
                    estimated_cost_usd=estimated_cost_usd,
                    actual_cost_usd=actual_cost_usd,
                )
            if not isinstance(action, ToolActionRequest):
                raise ToolGovernanceError("tool.authorization_request_invalid")
            try:
                action = ToolActionRequest.model_validate_json(
                    canonical_json_bytes(action.model_dump(mode="json"))
                )
            except Exception as exc:
                raise ToolGovernanceError("tool.authorization_request_invalid") from exc
            privileged = action.action in self._manifest.tool_governance.privileged_actions
            reason = self._runtime._tool_action_denial_reason(
                self._manifest,
                self._assignment,
                action,
                checkpoint_grants=self._checkpoint_grants,
                now=self._runtime._now(),
                remediation_binding=self._remediation_binding,
            )
            if tool_calls != 1:
                reason = reason or "tool.call_delta_must_equal_one"
            now = self._runtime._now()
            if reason is not None:
                audit = ToolCallAudit.create(
                    manifest_id=self._manifest.manifest_id,
                    assignment_id=self._assignment.assignment_id,
                    request=action,
                    privileged=privileged,
                    decision=ToolAuditDecision.DENIED,
                    authorized_at=now,
                    reason_code=reason,
                    completed_at=now,
                )
                self._runtime._insert_tool_audit(audit)
                raise ToolGovernanceError(reason)
            try:
                snapshot = self._budget_meter._authorize(
                    self._assignment,
                    turns=turns,
                    tool_calls=tool_calls,
                    estimated_cost_usd=estimated_cost_usd,
                    actual_cost_usd=actual_cost_usd,
                )
            except ExecutionBudgetExceededError as exc:
                denied = ToolCallAudit.create(
                    manifest_id=self._manifest.manifest_id,
                    assignment_id=self._assignment.assignment_id,
                    request=action,
                    privileged=privileged,
                    decision=ToolAuditDecision.DENIED,
                    authorized_at=now,
                    reason_code=exc.reason_code,
                    completed_at=now,
                )
                self._runtime._insert_tool_audit(denied)
                raise
            audit = ToolCallAudit.create(
                manifest_id=self._manifest.manifest_id,
                assignment_id=self._assignment.assignment_id,
                request=action,
                privileged=privileged,
                decision=ToolAuditDecision.AUTHORIZED,
                authorized_at=now,
            )
            self._runtime._insert_tool_audit(audit)
            return snapshot

    def screen(self, result: ToolActionResult) -> str:
        """Screen an untrusted result and close its durable authorization."""

        with self._lock:
            self._assert_live()
            if not isinstance(result, ToolActionResult):
                raise ToolGovernanceError("tool.result_invalid")
            try:
                result = ToolActionResult.model_validate_json(
                    canonical_json_bytes(result.model_dump(mode="json"))
                )
            except Exception as exc:
                raise ToolGovernanceError("tool.result_invalid") from exc
            existing = self._runtime._get_tool_audit(
                self._manifest.manifest_id,
                self._assignment.assignment_id,
                result.action_id,
            )
            if existing is None or existing.request_digest != result.request_digest:
                raise ToolGovernanceError("tool.result_authorization_missing")
            reason = self._runtime._tool_result_denial_reason(
                self._manifest,
                result,
            )
            completed_at = self._runtime._now()
            if reason is not None:
                denied = existing.complete(
                    decision=ToolAuditDecision.DENIED,
                    completed_at=completed_at,
                    result_digest=result.result_digest,
                    reason_code=reason,
                )
                self._runtime._replace_tool_audit(existing, denied)
                raise ToolGovernanceError(reason)
            screened = existing.complete(
                decision=ToolAuditDecision.SCREENED,
                completed_at=completed_at,
                result_digest=result.result_digest,
            )
            self._runtime._replace_tool_audit(existing, screened)
            return screened.audit_digest

    def completion_failures(self, *, observed_tool_calls: int) -> tuple[str, ...]:
        """Return fail-stop reasons for denied, missing, or unscreened actions."""

        self.close()
        audits = self._runtime._load_tool_audits(
            self._manifest.manifest_id,
            self._assignment.assignment_id,
        )
        failures: list[str] = []
        if any(item.decision is ToolAuditDecision.DENIED for item in audits):
            failures.append("tool.authorization_or_result_denied")
        if any(item.decision is ToolAuditDecision.AUTHORIZED for item in audits):
            failures.append("tool.result_unscreened")
        screened = sum(item.decision is ToolAuditDecision.SCREENED for item in audits)
        if screened != observed_tool_calls:
            failures.append("tool.call_count_mismatch")
        return tuple(sorted(set(failures)))


class AssignmentHost(Protocol):
    """Side-effecting adapter invoked only after runtime authorization and reservation."""

    def execute(
        self,
        request: AssignmentExecutionRequest,
        *,
        is_cancelled: CancellationProbe,
        authorize_action: HostActionAuthorizer,
        screen_result: HostResultScreener,
    ) -> AssignmentHostOutcome:
        """Execute one assignment, consulting host callbacks before every action."""


class AssignmentExecutionState(StrEnum):
    """Durable assignment state."""

    PENDING = "pending"
    RUNNING = "running"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class ExecutionStatus(StrEnum):
    """Run-level status included in every canonical receipt."""

    AWAITING_CHECKPOINT = "awaiting_checkpoint"
    CANCELLED = "cancelled"
    FAILED = "failed"
    SUCCEEDED = "succeeded"


class AssignmentExecutionReceipt(RuntimeContractModel):
    """Canonical durable projection of one assignment state."""

    assignment_id: str
    role: AssignmentRole
    prompt: PromptRouteRecord
    state: AssignmentExecutionState
    attempt_count: int = Field(ge=0)
    host_invoked: bool
    request_digest: str | None = None
    requested_at: datetime | None = None
    finished_at: datetime | None = None
    checkpoint_grant_digests: tuple[str, ...]
    outcome_digest: str | None
    usage_event_id: str | None
    actual_cost_usd: Decimal | None = Field(default=None, ge=0)
    turns: int | None = Field(default=None, ge=0)
    tool_calls: int | None = Field(default=None, ge=0)
    tool_call_audits: tuple[ToolCallAudit, ...] = ()
    output_digest: str | None
    failure_code: str | None

    @field_validator("checkpoint_grant_digests")
    @classmethod
    def _grants(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result = _sorted_unique(value, field_name="checkpoint_grant_digests")
        for digest in result:
            _validate_digest(digest, field_name="checkpoint_grant_digests entry")
        return result

    @field_validator("request_digest", "outcome_digest", "output_digest")
    @classmethod
    def _optional_digests(cls, value: str | None, info: Any) -> str | None:
        if value is not None:
            _validate_digest(value, field_name=info.field_name)
        return value

    @field_validator("requested_at", "finished_at")
    @classmethod
    def _optional_times(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _state_invariants(self) -> Self:
        action_ids = tuple(item.action_id for item in self.tool_call_audits)
        if action_ids != tuple(sorted(set(action_ids))):
            raise ValueError("tool_call_audits must be ordered by unique action_id")
        observed = (
            self.outcome_digest,
            self.usage_event_id,
            self.actual_cost_usd,
            self.turns,
            self.tool_calls,
            self.output_digest,
        )
        if self.state is AssignmentExecutionState.SUCCEEDED and any(
            value is None for value in observed
        ):
            raise ValueError("succeeded assignment receipts require complete observed usage")
        if self.state is AssignmentExecutionState.SUCCEEDED and not self.host_invoked:
            raise ValueError("succeeded assignment receipts require a host invocation")
        if self.host_invoked != (self.request_digest is not None and self.requested_at is not None):
            raise ValueError(
                "host invocation must retain the exact assignment request digest and time"
            )
        if self.host_invoked and self.attempt_count < 1:
            raise ValueError("host invocation requires at least one assignment attempt")
        if (
            self.finished_at is not None
            and self.requested_at is not None
            and self.finished_at < self.requested_at
        ):
            raise ValueError("assignment finished_at must not precede requested_at")
        if (
            self.state
            in {
                AssignmentExecutionState.SUCCEEDED,
                AssignmentExecutionState.FAILED,
                AssignmentExecutionState.BLOCKED,
                AssignmentExecutionState.CANCELLED,
                AssignmentExecutionState.SKIPPED,
            }
            and self.finished_at is None
        ):
            raise ValueError("completed assignment states require finished_at")
        if (
            self.state
            in {
                AssignmentExecutionState.PENDING,
                AssignmentExecutionState.RUNNING,
            }
            and self.finished_at is not None
        ):
            raise ValueError("unfinished assignment states cannot include finished_at")
        if self.state in {
            AssignmentExecutionState.PENDING,
            AssignmentExecutionState.BLOCKED,
            AssignmentExecutionState.SKIPPED,
        } and (self.host_invoked or any(value is not None for value in observed)):
            raise ValueError("unexecuted assignment receipts cannot include a host invocation")
        if self.state is AssignmentExecutionState.CANCELLED and (
            not self.host_invoked or any(value is not None for value in observed)
        ):
            raise ValueError(
                "cooperatively cancelled assignment receipts require an invocation "
                "without observed usage"
            )
        if not self.host_invoked and any(value is not None for value in observed):
            raise ValueError("observed usage requires a host invocation")
        if not self.host_invoked and self.tool_call_audits:
            raise ValueError("tool call audits require a host invocation")
        if (
            self.state
            in {
                AssignmentExecutionState.PENDING,
                AssignmentExecutionState.BLOCKED,
                AssignmentExecutionState.SKIPPED,
            }
            and self.tool_call_audits
        ):
            raise ValueError("unexecuted assignments cannot include tool call audits")
        screened = sum(
            item.decision is ToolAuditDecision.SCREENED for item in self.tool_call_audits
        )
        if (
            self.state is AssignmentExecutionState.SUCCEEDED
            and self.tool_calls is not None
            and screened != self.tool_calls
        ):
            raise ValueError("screened tool audit count must equal observed tool calls")
        if self.state is AssignmentExecutionState.SUCCEEDED and any(
            item.decision is not ToolAuditDecision.SCREENED for item in self.tool_call_audits
        ):
            raise ValueError("succeeded assignments require every tool result to be screened")
        if self.state is AssignmentExecutionState.FAILED:
            present = sum(value is not None for value in observed)
            if present not in {0, len(observed)}:
                raise ValueError("failed assignment observed usage must be complete or absent")
        if (
            self.state
            in {
                AssignmentExecutionState.FAILED,
                AssignmentExecutionState.BLOCKED,
                AssignmentExecutionState.CANCELLED,
            }
            and self.failure_code is None
        ):
            raise ValueError("failed or blocked assignment receipts require failure_code")
        if (
            self.state
            in {
                AssignmentExecutionState.PENDING,
                AssignmentExecutionState.SUCCEEDED,
                AssignmentExecutionState.SKIPPED,
            }
            and self.failure_code is not None
        ):
            raise ValueError("pending or succeeded assignment receipts cannot include failure_code")
        return self


class ExecutionReceipt(RuntimeContractModel):
    """Canonical, digest-bound execution result; terminal receipts are replayed exactly."""

    schema_version: Literal["agt.orchestration-execution-receipt/v1"] = RECEIPT_SCHEMA_VERSION
    manifest_id: str
    manifest_digest: str
    run_id: str
    change_id: str
    change_digest: str
    policy_digest: str
    status: ExecutionStatus
    final: bool
    started_at: datetime
    evaluated_at: datetime
    release_checkpoint_valid_until: datetime | None = None
    assignments: tuple[AssignmentExecutionReceipt, ...] = Field(min_length=1)
    review_history: tuple[ReviewRoundHistory, ...] = ()
    total_actual_cost_usd: Decimal | None = Field(default=None, ge=0)
    cost_complete: bool
    unknown_cost_assignment_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    receipt_digest: str

    @field_validator("manifest_digest", "change_digest", "policy_digest", "receipt_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _validate_digest(value, field_name=info.field_name)

    @field_validator("started_at", "evaluated_at", "release_checkpoint_valid_until")
    @classmethod
    def _times(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name=info.field_name)

    @field_validator("reason_codes")
    @classmethod
    def _reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(value, field_name="reason_codes")

    @field_validator("unknown_cost_assignment_ids")
    @classmethod
    def _unknown_cost_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(value, field_name="unknown_cost_assignment_ids")

    @model_validator(mode="after")
    def _receipt_invariants(self) -> Self:
        if self.evaluated_at < self.started_at:
            raise ValueError("evaluated_at must not precede started_at")
        terminal = self.status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED}
        if self.final is not terminal:
            raise ValueError("final must exactly identify succeeded or failed receipts")
        if self.status is ExecutionStatus.SUCCEEDED:
            if self.release_checkpoint_valid_until is None:
                raise ValueError("succeeded receipt requires release_checkpoint_valid_until")
            if self.evaluated_at >= self.release_checkpoint_valid_until:
                raise ValueError(
                    "succeeded receipt must be finalized before its release checkpoint expires"
                )
        elif self.release_checkpoint_valid_until is not None:
            raise ValueError("release_checkpoint_valid_until is only valid for succeeded receipts")
        assignment_ids = tuple(item.assignment_id for item in self.assignments)
        if len(set(assignment_ids)) != len(assignment_ids):
            raise ValueError("assignment receipts must have unique assignment_id values")
        usage_event_ids = tuple(
            item.usage_event_id for item in self.assignments if item.usage_event_id is not None
        )
        if len(set(usage_event_ids)) != len(usage_event_ids):
            raise ValueError("assignment receipts must have unique usage_event_id values")
        if self.status is ExecutionStatus.SUCCEEDED:
            if self.reason_codes:
                raise ValueError("succeeded receipt cannot include reason_codes")
            if any(
                item.state
                not in {
                    AssignmentExecutionState.SUCCEEDED,
                    AssignmentExecutionState.SKIPPED,
                }
                for item in self.assignments
            ):
                raise ValueError("succeeded receipt requires planned work to succeed or be skipped")
            if (
                not self.review_history
                or self.review_history[-1].semantic_outcome.verdict is not ReviewVerdict.CLEAN
            ):
                raise ValueError("succeeded receipt requires a final clean runtime review")
        round_numbers = tuple(item.round_number for item in self.review_history)
        if round_numbers != tuple(range(1, len(self.review_history) + 1)):
            raise ValueError("review_history must be contiguous and ordered")
        if any(
            item.semantic_outcome.verdict is ReviewVerdict.CLEAN
            for item in self.review_history[:-1]
        ):
            raise ValueError("review history cannot continue after a clean verdict")
        if any(
            item.semantic_outcome.verdict is ReviewVerdict.BLOCKING and item.remediation is None
            for item in self.review_history[:-1]
        ):
            raise ValueError("every non-final blocking review requires exact remediation")
        if self.status is ExecutionStatus.FAILED and not self.reason_codes:
            raise ValueError("failed receipt requires at least one reason code")
        expected_unknown = tuple(
            sorted(
                item.assignment_id
                for item in self.assignments
                if item.host_invoked and item.actual_cost_usd is None
            )
        )
        if self.unknown_cost_assignment_ids != expected_unknown:
            raise ValueError("unknown_cost_assignment_ids does not match assignment receipts")
        if self.cost_complete != (not expected_unknown):
            raise ValueError("cost_complete must be false exactly when invoked cost is unknown")
        expected_cost = (
            sum(
                (
                    cast(Decimal, item.actual_cost_usd)
                    for item in self.assignments
                    if item.host_invoked
                ),
                Decimal("0"),
            )
            if not expected_unknown
            else None
        )
        if self.total_actual_cost_usd != expected_cost:
            raise ValueError("total_actual_cost_usd does not match assignment receipts")
        expected = digest_without(self, "receipt_digest")
        if self.receipt_digest != expected:
            raise ValueError(
                f"receipt_digest mismatch: expected {expected}, got {self.receipt_digest}"
            )
        return self

    @classmethod
    def create(cls, **values: Any) -> ExecutionReceipt:
        payload = dict(values)
        payload["schema_version"] = RECEIPT_SCHEMA_VERSION
        provisional = cls.model_construct(**payload, receipt_digest="0" * 64)
        payload["receipt_digest"] = digest_without(provisional, "receipt_digest")
        return cls.model_validate(payload)

    def canonical_bytes(self) -> bytes:
        """Return canonical JSON bytes including the verified receipt digest."""

        return canonical_json_bytes(self)


_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS orchestration_runs (
    manifest_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    manifest_digest TEXT NOT NULL,
    change_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    status TEXT NOT NULL,
    reason_code TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    lease_token TEXT,
    lease_expires_at TEXT,
    lease_epoch INTEGER NOT NULL DEFAULT 0,
    final_receipt_json TEXT,
    final_receipt_digest TEXT
);
CREATE TABLE IF NOT EXISTS orchestration_runtime_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO orchestration_runtime_metadata (key, value)
VALUES ('schema_version', '1');
CREATE TABLE IF NOT EXISTS orchestration_assignments (
    manifest_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    role TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    state TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    host_invoked INTEGER NOT NULL DEFAULT 0 CHECK (host_invoked IN (0, 1)),
    request_digest TEXT,
    checkpoint_grant_digests_json TEXT NOT NULL DEFAULT '[]',
    outcome_digest TEXT,
    usage_event_id TEXT,
    actual_cost_usd TEXT,
    turns INTEGER,
    tool_calls INTEGER,
    output_digest TEXT,
    failure_code TEXT,
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY (manifest_id, assignment_id),
    UNIQUE (manifest_id, ordinal),
    FOREIGN KEY (manifest_id) REFERENCES orchestration_runs(manifest_id)
);
CREATE TABLE IF NOT EXISTS orchestration_outcome_intents (
    manifest_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    intent_digest TEXT NOT NULL,
    outcome_digest TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    checkpoint_grant_digests_json TEXT NOT NULL,
    forced_failures_json TEXT NOT NULL,
    reconciled_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (manifest_id, assignment_id),
    FOREIGN KEY (manifest_id, assignment_id)
        REFERENCES orchestration_assignments(manifest_id, assignment_id)
);
CREATE TABLE IF NOT EXISTS orchestration_tool_audits (
    manifest_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('authorized', 'denied', 'screened')),
    request_digest TEXT NOT NULL,
    audit_digest TEXT NOT NULL,
    audit_json TEXT NOT NULL,
    PRIMARY KEY (manifest_id, assignment_id, action_id),
    FOREIGN KEY (manifest_id, assignment_id)
        REFERENCES orchestration_assignments(manifest_id, assignment_id)
);
"""


class GovernedOrchestrationRuntime:
    """Execute manifests with durable idempotency, checkpoints, and accounting."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        allowed_root: str | os.PathLike[str],
        host: AssignmentHost,
        usage_ledger: UsageLedger,
        models: ModelRegistry,
        prices: PriceCatalog,
        prompts: PromptRegistry,
        checkpoint_grant_verifier: CheckpointGrantVerifier,
        workspace_root: str | os.PathLike[str] | None = None,
        assignment_timeout_seconds: float | None = None,
        clock: Callable[[], datetime] | None = None,
        timeout_seconds: float = 30.0,
        lease_seconds: int = 14_400,
        max_checkpoint_grant_age_seconds: int = 900,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise OrchestrationRuntimeError("timeout_seconds must be finite and positive")
        if assignment_timeout_seconds is not None and (
            isinstance(assignment_timeout_seconds, bool)
            or not isinstance(assignment_timeout_seconds, int | float)
            or not math.isfinite(assignment_timeout_seconds)
            or assignment_timeout_seconds <= 0
        ):
            raise OrchestrationRuntimeError(
                "assignment_timeout_seconds must be finite and positive"
            )
        if isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise OrchestrationRuntimeError("lease_seconds must be a positive integer")
        if (
            isinstance(max_checkpoint_grant_age_seconds, bool)
            or max_checkpoint_grant_age_seconds <= 0
            or max_checkpoint_grant_age_seconds > 86_400
        ):
            raise OrchestrationRuntimeError(
                "max_checkpoint_grant_age_seconds must be between 1 and 86400"
            )
        if not hasattr(host, "execute"):
            raise OrchestrationRuntimeError("host must implement AssignmentHost.execute")
        if not isinstance(usage_ledger, UsageLedger):
            raise OrchestrationRuntimeError("usage_ledger must be a UsageLedger")
        if not isinstance(models, ModelRegistry):
            raise OrchestrationRuntimeError("models must be a ModelRegistry")
        if not isinstance(prices, PriceCatalog):
            raise OrchestrationRuntimeError("prices must be a PriceCatalog")
        if not isinstance(prompts, PromptRegistry):
            raise OrchestrationRuntimeError("prompts must be a PromptRegistry")
        if not hasattr(checkpoint_grant_verifier, "verify"):
            raise OrchestrationRuntimeError(
                "checkpoint_grant_verifier must provide an independent trust anchor"
            )
        self._allowed_root, self._path = self._safe_database_path(
            database_path,
            allowed_root=allowed_root,
        )
        root_stat = self._allowed_root.stat(follow_symlinks=False)
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        directory_identities: list[tuple[Path, tuple[int, int]]] = []
        cursor = self._allowed_root
        for part in self._path.parent.relative_to(self._allowed_root).parts:
            cursor /= part
            directory_stat = cursor.stat(follow_symlinks=False)
            if cursor.is_symlink() or not stat.S_ISDIR(directory_stat.st_mode):
                raise RuntimePathSafetyError("orchestration state parent must be a real directory")
            directory_identities.append((cursor, (directory_stat.st_dev, directory_stat.st_ino)))
        self._directory_identities = tuple(directory_identities)
        self._database_identity: tuple[int, int] | None = None
        self._workspace_root = self._safe_workspace_root(
            self._allowed_root if workspace_root is None else workspace_root
        )
        workspace_stat = self._workspace_root.stat(follow_symlinks=False)
        self._workspace_root_identity = (workspace_stat.st_dev, workspace_stat.st_ino)
        self._host = host
        self._usage_ledger = usage_ledger
        self._models = models
        self._prices = prices
        self._prompts = prompts
        self._checkpoint_grant_verifier = checkpoint_grant_verifier
        self._clock = clock or _system_utc_now
        self._timeout_seconds = timeout_seconds
        self._assignment_timeout_seconds = assignment_timeout_seconds
        self._lease_seconds = lease_seconds
        self._max_checkpoint_grant_age_seconds = max_checkpoint_grant_age_seconds
        self._thread_lock = threading.RLock()
        self._lease_state_lock = threading.Lock()
        self._active_lease: _ExecutionLease | None = None
        self._initialize()
        self._pin_database_identity()

    @staticmethod
    def _safe_database_path(
        database_path: str | os.PathLike[str],
        *,
        allowed_root: str | os.PathLike[str],
    ) -> tuple[Path, Path]:
        raw_root = os.fspath(allowed_root)
        if not raw_root or "\x00" in raw_root:
            raise RuntimePathSafetyError("allowed_root must be an existing directory")
        root_candidate = Path(raw_root).expanduser()
        if root_candidate.is_symlink():
            raise RuntimePathSafetyError("allowed_root must not be a symbolic link")
        try:
            root = root_candidate.resolve(strict=True)
        except OSError as exc:
            raise RuntimePathSafetyError("allowed_root must be an existing directory") from exc
        if not root.is_dir():
            raise RuntimePathSafetyError("allowed_root must be an existing directory")

        raw = os.fspath(database_path)
        if not raw or "\x00" in raw or raw == ":memory:" or raw.startswith("file:"):
            raise RuntimePathSafetyError(
                "database_path must be a filesystem path, not a SQLite URI"
            )
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        lexical = Path(os.path.abspath(candidate))
        resolved = lexical.resolve(strict=False)
        try:
            relative = resolved.relative_to(root)
        except ValueError as exc:
            raise RuntimePathSafetyError("database_path escapes allowed_root") from exc
        if not relative.parts:
            raise RuntimePathSafetyError("database_path must identify a regular file")
        # Ancestor aliases such as macOS' /var -> /private/var are outside the
        # caller-controlled root and are safe after canonicalization.  Within
        # the configured root, every component must remain a real directory or
        # file rather than a link that can redirect later operations.
        cursor = root
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise RuntimePathSafetyError("database_path must not traverse a symbolic link")
        root_lexical = Path(os.path.abspath(root_candidate))
        try:
            lexical_relative = lexical.relative_to(root_lexical)
        except ValueError:
            lexical_relative = None
        if lexical_relative is not None:
            cursor = root_lexical
            for part in lexical_relative.parts:
                cursor /= part
                if cursor.is_symlink():
                    raise RuntimePathSafetyError("database_path must not traverse a symbolic link")
        if resolved.exists() and not resolved.is_file():
            raise RuntimePathSafetyError("database_path must identify a regular file")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        for path in (
            resolved,
            Path(f"{resolved}-journal"),
            Path(f"{resolved}-shm"),
            Path(f"{resolved}-wal"),
        ):
            if path.is_symlink():
                raise RuntimePathSafetyError(
                    "orchestration SQLite paths must not be symbolic links"
                )
        return root, resolved

    @staticmethod
    def _safe_workspace_root(root: str | os.PathLike[str]) -> Path:
        raw = os.fspath(root)
        if not raw or "\x00" in raw:
            raise RuntimePathSafetyError("workspace_root must be an existing directory")
        candidate = Path(raw).expanduser()
        if candidate.is_symlink():
            raise RuntimePathSafetyError("workspace_root must not be a symbolic link")
        try:
            resolved = candidate.resolve(strict=True)
            root_stat = resolved.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimePathSafetyError("workspace_root must be an existing directory") from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise RuntimePathSafetyError("workspace_root must be an existing directory")
        return resolved

    def _assert_workspace_root_safe(self) -> None:
        try:
            root_stat = self._workspace_root.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimePathSafetyError(
                "workspace_root changed after runtime construction"
            ) from exc
        if (
            self._workspace_root.is_symlink()
            or not stat.S_ISDIR(root_stat.st_mode)
            or (root_stat.st_dev, root_stat.st_ino) != self._workspace_root_identity
        ):
            raise RuntimePathSafetyError("workspace_root changed after runtime construction")

    def _resolve_workspace_path(self, value: str) -> Path:
        self._assert_workspace_root_safe()
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise RuntimePathSafetyError("tool path escapes workspace_root")
        resolved = Path(os.path.abspath(self._workspace_root / candidate))
        try:
            relative = resolved.relative_to(self._workspace_root)
        except ValueError as exc:
            raise RuntimePathSafetyError("tool path escapes workspace_root") from exc
        cursor = self._workspace_root
        for part in relative.parts:
            cursor /= part
            try:
                mode = cursor.lstat().st_mode
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RuntimePathSafetyError("cannot inspect governed tool path") from exc
            if stat.S_ISLNK(mode):
                raise RuntimePathSafetyError("tool path must not traverse a symbolic link")
        return resolved

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise OrchestrationRuntimeError("trusted clock failed") from exc
        if not isinstance(value, datetime):
            raise OrchestrationRuntimeError("trusted clock must return datetime")
        try:
            return _utc(value, field_name="trusted clock")
        except ValueError as exc:
            raise OrchestrationRuntimeError(str(exc)) from exc

    def _assert_state_paths_safe(self) -> None:
        if self._allowed_root.is_symlink() or not self._allowed_root.is_dir():
            raise RuntimePathSafetyError("allowed_root changed after runtime construction")
        try:
            root_stat = self._allowed_root.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimePathSafetyError("allowed_root changed after runtime construction") from exc
        if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
            raise RuntimePathSafetyError("allowed_root changed after runtime construction")
        for directory, identity in self._directory_identities:
            try:
                directory_stat = directory.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimePathSafetyError(
                    "orchestration state parent changed after runtime construction"
                ) from exc
            if (
                directory.is_symlink()
                or not stat.S_ISDIR(directory_stat.st_mode)
                or (directory_stat.st_dev, directory_stat.st_ino) != identity
            ):
                raise RuntimePathSafetyError(
                    "orchestration state parent changed after runtime construction"
                )
        companions = tuple(
            Path(f"{self._path}{suffix}") for suffix in ("", "-journal", "-shm", "-wal")
        )
        for candidate in companions:
            try:
                candidate_stat = candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RuntimePathSafetyError(
                    f"cannot inspect orchestration SQLite path: {candidate.name}"
                ) from exc
            if stat.S_ISLNK(candidate_stat.st_mode):
                raise RuntimePathSafetyError(
                    f"orchestration SQLite path must not be a symbolic link: {candidate.name}"
                )
            if not stat.S_ISREG(candidate_stat.st_mode):
                raise RuntimePathSafetyError(f"unsafe orchestration SQLite path: {candidate.name}")
        if self._database_identity is not None:
            try:
                database_stat = self._path.lstat()
            except OSError as exc:
                raise RuntimePathSafetyError(
                    "orchestration state database changed after runtime construction"
                ) from exc
            if (
                not stat.S_ISREG(database_stat.st_mode)
                or (database_stat.st_dev, database_stat.st_ino) != self._database_identity
            ):
                raise RuntimePathSafetyError(
                    "orchestration state database changed after runtime construction"
                )

    def _pin_database_identity(self) -> None:
        """Pin the initialized primary database so rollback-by-replacement fails closed."""

        self._assert_state_paths_safe()
        try:
            database_stat = self._path.lstat()
        except OSError as exc:
            raise RuntimePathSafetyError(
                "orchestration state database was not durably initialized"
            ) from exc
        if not stat.S_ISREG(database_stat.st_mode):
            raise RuntimePathSafetyError("orchestration state database was not durably initialized")
        self._database_identity = (database_stat.st_dev, database_stat.st_ino)
        self._assert_state_paths_safe()

    def _connect(self) -> sqlite3.Connection:
        self._assert_state_paths_safe()
        connection = sqlite3.connect(
            str(self._path),
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        try:
            self._assert_state_paths_safe()
        except Exception:
            connection.close()
            raise
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(_STATE_SCHEMA)
            run_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(orchestration_runs)")
            }
            if "lease_epoch" not in run_columns:
                connection.execute(
                    "ALTER TABLE orchestration_runs "
                    "ADD COLUMN lease_epoch INTEGER NOT NULL DEFAULT 0"
                )
            assignment_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(orchestration_assignments)")
            }
            if "host_invoked" not in assignment_columns:
                connection.execute(
                    "ALTER TABLE orchestration_assignments "
                    "ADD COLUMN host_invoked INTEGER NOT NULL DEFAULT 0"
                )
            if "request_digest" not in assignment_columns:
                connection.execute(
                    "ALTER TABLE orchestration_assignments ADD COLUMN request_digest TEXT"
                )
            intent_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(orchestration_outcome_intents)")
            }
            if "intent_digest" not in intent_columns:
                connection.execute(
                    "ALTER TABLE orchestration_outcome_intents " "ADD COLUMN intent_digest TEXT"
                )
            schema = connection.execute(
                "SELECT value FROM orchestration_runtime_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if schema is None or schema[0] != "1":
                raise OrchestrationRuntimeError("unsupported orchestration runtime schema")
        finally:
            connection.close()
        with suppress(OSError):
            self._path.chmod(0o600)

    @contextmanager
    def _transaction(
        self,
        *,
        enforce_active_lease: bool = True,
    ) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            with self._lease_state_lock:
                lease = self._active_lease if enforce_active_lease else None
            if lease is not None:
                renewed_until = datetime.now(UTC) + timedelta(seconds=self._lease_seconds)
                cursor = connection.execute(
                    """
                    UPDATE orchestration_runs
                    SET lease_expires_at = ?
                    WHERE manifest_id = ? AND lease_token = ? AND lease_epoch = ?
                    """,
                    (
                        _time_text(renewed_until),
                        lease.manifest_id,
                        lease.token,
                        lease.epoch,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ExecutionInProgressError("execution lease was fenced by another runtime")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _strict_manifest(manifest: OrchestrationManifest) -> OrchestrationManifest:
        if not isinstance(manifest, OrchestrationManifest):
            raise TrustedBindingError("manifest must be an OrchestrationManifest")
        try:
            validated = OrchestrationManifest.model_validate_json(manifest.canonical_bytes())
        except Exception as exc:
            raise TrustedBindingError("manifest failed strict revalidation") from exc
        if validated != manifest:
            raise TrustedBindingError("manifest changed during strict revalidation")
        return validated

    @staticmethod
    def _assert_trusted_bindings(
        manifest: OrchestrationManifest,
        *,
        trusted_manifest_digest: str,
        trusted_change_digest: str,
        trusted_policy_digest: str,
    ) -> None:
        supplied = {
            "trusted_manifest_digest": trusted_manifest_digest,
            "trusted_change_digest": trusted_change_digest,
            "trusted_policy_digest": trusted_policy_digest,
        }
        try:
            for name, digest in supplied.items():
                _validate_digest(digest, field_name=name)
        except ValueError as exc:
            raise TrustedBindingError(str(exc)) from exc
        mismatches: list[str] = []
        if trusted_manifest_digest != manifest.digest:
            mismatches.append("manifest")
        if trusted_change_digest != manifest.change_digest:
            mismatches.append("change")
        if trusted_policy_digest != manifest.policy_digest:
            mismatches.append("policy")
        if mismatches:
            raise TrustedBindingError("trusted digest mismatch: " + ", ".join(sorted(mismatches)))

    @staticmethod
    def _assignments(manifest: OrchestrationManifest) -> tuple[WorkAssignment, ...]:
        implementations = tuple(
            assignment for wave in manifest.execution_waves for assignment in wave.assignments
        )
        conditional = tuple(
            assignment
            for item in manifest.conditional_review_rounds
            for assignment in (item.remediation_assignment, item.review_assignment)
        )
        return (*implementations, manifest.review_assignment, *conditional)

    def _assert_assignment_price_binding(
        self,
        assignment: WorkAssignment,
        *,
        at: datetime,
    ) -> None:
        selected = self._prices.get(assignment.route.identity, at=at)
        if selected is None:
            raise TrustedBindingError(
                f"no independently supplied price is effective for {assignment.assignment_id!r}"
            )
        if not hmac.compare_digest(
            model_price_record_digest(selected),
            assignment.route.price_record_digest,
        ):
            raise TrustedBindingError(
                f"price record mismatch for assignment {assignment.assignment_id!r}"
            )

    def _assert_assignment_model_binding(self, assignment: WorkAssignment) -> None:
        """Require the exact selected deployment facts to remain enabled."""

        registered = self._models.get(assignment.route.identity)
        if registered is None:
            raise TrustedBindingError(
                f"model is not registered for assignment {assignment.assignment_id!r}"
            )
        if not registered.enabled:
            raise TrustedBindingError(
                f"model is disabled for assignment {assignment.assignment_id!r}"
            )
        if registered != assignment.route.registry_record.record:
            raise TrustedBindingError(
                f"model registry record mismatch for assignment {assignment.assignment_id!r}"
            )

    def _assert_assignment_prompt_binding(self, assignment: WorkAssignment) -> None:
        """Require the exact manifest prompt to remain centrally registered and enabled."""

        registered = self._prompts.get(assignment.prompt.identity)
        if registered is None:
            raise TrustedBindingError(
                f"prompt is not registered for assignment {assignment.assignment_id!r}"
            )
        if not registered.enabled:
            raise TrustedBindingError(
                f"prompt is disabled for assignment {assignment.assignment_id!r}"
            )
        if registered != assignment.prompt.record:
            raise TrustedBindingError(
                f"prompt record mismatch for assignment {assignment.assignment_id!r}"
            )

    def _assert_manifest_price_bindings(
        self,
        manifest: OrchestrationManifest,
        *,
        at: datetime,
    ) -> None:
        for assignment in self._assignments(manifest):
            self._assert_assignment_price_binding(assignment, at=at)

    def _tool_action_denial_reason(
        self,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        action: ToolActionRequest,
        *,
        checkpoint_grants: Mapping[str, CheckpointGrant],
        now: datetime,
        remediation_binding: RemediationScopeBinding | None,
    ) -> str | None:
        """Return one stable fail-closed reason, or ``None`` when authorized."""

        policy = manifest.tool_governance
        try:
            role_policy = policy.for_role(
                "implementation"
                if assignment.role is AssignmentRole.REMEDIATION
                else assignment.role.value
            )
        except ValueError:
            return "tool.role_policy_missing"
        if action.tool not in role_policy.allowed_tools:
            return "tool.tool_not_allowed_for_role"
        if action.action not in role_policy.allowed_actions:
            return "tool.action_not_allowed_for_role"
        required_scope = {
            ToolAction.ADMINISTRATIVE: "administrative",
            ToolAction.EXECUTE: "execute",
            ToolAction.NETWORK: "network",
            ToolAction.READ: "read",
            ToolAction.SECRET_ACCESS: "administrative",
            ToolAction.WRITE: "workspace_write",
        }[action.action]
        scopes = set(action.scopes)
        if required_scope not in scopes:
            return "tool.required_scope_missing"
        if not scopes <= set(role_policy.allowed_scopes):
            return "tool.scope_not_allowed_for_role"
        if not scopes <= set(assignment.tool_scopes):
            return "tool.scope_not_bound_to_assignment"
        if assignment.role is AssignmentRole.REMEDIATION:
            if remediation_binding is None:
                return "remediation.prior_review_binding_missing"
            if (
                action.action in {ToolAction.WRITE, ToolAction.EXECUTE}
                and action.path not in remediation_binding.paths
            ):
                return "remediation.path_not_in_finding_set"
        if action.action in {ToolAction.READ, ToolAction.WRITE, ToolAction.EXECUTE}:
            assert action.path is not None
            try:
                self._resolve_workspace_path(action.path)
            except RuntimePathSafetyError:
                return "tool.workspace_path_denied"
            if action.resource != action.path:
                return "tool.resource_binding_mismatch"
        if action.action is ToolAction.EXECUTE:
            shell_tokens = {"&", "&&", ";", "<", ">", ">>", "|", "||"}
            if any(token in shell_tokens for token in action.command):
                return "tool.command_shell_operator_denied"
            if not any(
                action.command[: len(prefix)] == prefix
                for prefix in policy.allowed_command_prefixes
            ):
                return "tool.command_not_allowlisted"
        if action.action is ToolAction.NETWORK:
            assert action.url is not None
            try:
                parsed = urlsplit(action.url)
                port = parsed.port
            except ValueError:
                return "tool.network_url_invalid"
            if (
                parsed.scheme != "https"
                or parsed.hostname is None
                or parsed.hostname != parsed.hostname.lower()
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
                or port not in {None, 443}
            ):
                return "tool.network_url_denied"
            if parsed.hostname not in policy.allowed_network_hosts:
                return "tool.network_host_not_allowlisted"
        if action.action is ToolAction.SECRET_ACCESS and (
            action.secret_reference not in policy.allowed_secret_references
        ):
            return "tool.secret_reference_not_allowlisted"
        if action.action in policy.approval_required_actions:
            if action.approval_grant_digest is None:
                return "tool.approval_missing"
            grant = checkpoint_grants.get(action.approval_grant_digest)
            if grant is None:
                return "tool.approval_not_bound_to_assignment"
            if grant.decision is not CheckpointDecision.APPROVE:
                return "tool.approval_denied"
            if grant.assignment_id != assignment.assignment_id:
                return "tool.approval_not_bound_to_assignment"
            if action.action in {
                ToolAction.ADMINISTRATIVE,
                ToolAction.EXECUTE,
                ToolAction.NETWORK,
                ToolAction.SECRET_ACCESS,
            }:
                checkpoint = next(
                    (
                        item
                        for item in manifest.human_checkpoints
                        if item.checkpoint_id == grant.checkpoint_id
                    ),
                    None,
                )
                if (
                    checkpoint is None
                    or f"tool_scope:{required_scope}" not in checkpoint.reason_codes
                ):
                    return "tool.approval_scope_mismatch"
            try:
                authentic = bool(self._checkpoint_grant_verifier.verify(grant))
            except Exception:
                authentic = False
            if not authentic:
                return "tool.approval_trust_failed"
            if grant.issued_at > now:
                return "tool.approval_not_yet_valid"
            valid_until = min(
                grant.expires_at,
                grant.issued_at + timedelta(seconds=self._max_checkpoint_grant_age_seconds),
            )
            if now >= valid_until:
                return "tool.approval_stale_or_expired"
        elif action.approval_grant_digest is not None:
            return "tool.unexpected_approval"
        return None

    @staticmethod
    def _tool_result_denial_reason(
        manifest: OrchestrationManifest,
        result: ToolActionResult,
    ) -> str | None:
        policy = manifest.tool_governance
        if len(result.content.encode("utf-8")) > policy.max_result_bytes:
            return "tool.result_too_large"
        bidi_controls = {
            "\u202a",
            "\u202b",
            "\u202d",
            "\u202e",
            "\u2066",
            "\u2067",
            "\u2068",
            "\u2069",
        }
        if any(
            (ord(char) < 32 and char not in {"\t", "\n", "\r"}) or char in bidi_controls
            for char in result.content
        ):
            return "tool.result_control_characters"
        lowered = result.content.lower()
        if any(marker in lowered for marker in policy.blocked_result_substrings):
            return "tool.result_blocked_content"
        if result.content_type == "json":
            try:
                load_json_strict(result.content)
            except Exception:
                return "tool.result_invalid_json"
        return None

    def _insert_tool_audit(self, audit: ToolCallAudit) -> None:
        encoded = audit.canonical_bytes().decode("utf-8")
        with self._transaction() as connection:
            assignment = connection.execute(
                """
                SELECT state, host_invoked FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (audit.manifest_id, audit.assignment_id),
            ).fetchone()
            if (
                assignment is None
                or assignment["state"] != AssignmentExecutionState.RUNNING.value
                or not bool(assignment["host_invoked"])
            ):
                raise ToolGovernanceError("tool.assignment_not_active")
            try:
                connection.execute(
                    """
                    INSERT INTO orchestration_tool_audits (
                        manifest_id, assignment_id, action_id, decision,
                        request_digest, audit_digest, audit_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit.manifest_id,
                        audit.assignment_id,
                        audit.action_id,
                        audit.decision.value,
                        audit.request_digest,
                        audit.audit_digest,
                        encoded,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ToolGovernanceError("tool.action_id_reused") from exc

    @staticmethod
    def _tool_audit_from_row(row: sqlite3.Row) -> ToolCallAudit:
        try:
            audit = ToolCallAudit.model_validate_json(str(row["audit_json"]))
        except Exception as exc:
            raise ManifestIdempotencyError("stored tool audit failed validation") from exc
        if (
            audit.manifest_id != row["manifest_id"]
            or audit.assignment_id != row["assignment_id"]
            or audit.action_id != row["action_id"]
            or audit.decision.value != row["decision"]
            or audit.request_digest != row["request_digest"]
            or audit.audit_digest != row["audit_digest"]
            or audit.canonical_bytes().decode("utf-8") != row["audit_json"]
        ):
            raise ManifestIdempotencyError("stored tool audit disagrees with its index")
        return audit

    def _get_tool_audit(
        self,
        manifest_id: str,
        assignment_id: str,
        action_id: str,
    ) -> ToolCallAudit | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM orchestration_tool_audits
                WHERE manifest_id = ? AND assignment_id = ? AND action_id = ?
                """,
                (manifest_id, assignment_id, action_id),
            ).fetchone()
        return None if row is None else self._tool_audit_from_row(row)

    def _replace_tool_audit(
        self,
        existing: ToolCallAudit,
        replacement: ToolCallAudit,
    ) -> None:
        if (
            existing.decision is not ToolAuditDecision.AUTHORIZED
            or replacement.manifest_id != existing.manifest_id
            or replacement.assignment_id != existing.assignment_id
            or replacement.action_id != existing.action_id
            or replacement.request_digest != existing.request_digest
        ):
            raise ToolGovernanceError("tool.audit_transition_invalid")
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE orchestration_tool_audits
                SET decision = ?, audit_digest = ?, audit_json = ?
                WHERE manifest_id = ? AND assignment_id = ? AND action_id = ?
                    AND decision = ? AND audit_digest = ?
                """,
                (
                    replacement.decision.value,
                    replacement.audit_digest,
                    replacement.canonical_bytes().decode("utf-8"),
                    existing.manifest_id,
                    existing.assignment_id,
                    existing.action_id,
                    ToolAuditDecision.AUTHORIZED.value,
                    existing.audit_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise ToolGovernanceError("tool.audit_transition_conflict")

    def _load_tool_audits(
        self,
        manifest_id: str,
        assignment_id: str,
    ) -> tuple[ToolCallAudit, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM orchestration_tool_audits
                WHERE manifest_id = ? AND assignment_id = ? ORDER BY action_id
                """,
                (manifest_id, assignment_id),
            ).fetchall()
        audits = tuple(self._tool_audit_from_row(row) for row in rows)
        if tuple(item.action_id for item in audits) != tuple(
            sorted({item.action_id for item in audits})
        ):
            raise ManifestIdempotencyError("stored tool audits are not canonically ordered")
        return audits

    def _register(self, manifest: OrchestrationManifest, *, now: datetime) -> None:
        manifest_json = manifest.canonical_bytes().decode("utf-8")
        assignments = self._assignments(manifest)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM orchestration_runs WHERE manifest_id = ? OR run_id = ?",
                (manifest.manifest_id, manifest.run_id),
            ).fetchone()
            if existing is not None:
                if (
                    existing["manifest_id"] != manifest.manifest_id
                    or existing["run_id"] != manifest.run_id
                    or existing["manifest_digest"] != manifest.digest
                    or existing["change_digest"] != manifest.change_digest
                    or existing["policy_digest"] != manifest.policy_digest
                    or existing["manifest_json"] != manifest_json
                ):
                    raise ManifestIdempotencyError(
                        "manifest_id or run_id was reused with different canonical facts"
                    )
                return
            timestamp = _time_text(now)
            connection.execute(
                """
                INSERT INTO orchestration_runs (
                    manifest_id, run_id, manifest_digest, change_digest, policy_digest,
                    manifest_json, status, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.manifest_id,
                    manifest.run_id,
                    manifest.digest,
                    manifest.change_digest,
                    manifest.policy_digest,
                    manifest_json,
                    "pending",
                    timestamp,
                    timestamp,
                ),
            )
            connection.executemany(
                """
                INSERT INTO orchestration_assignments (
                    manifest_id, assignment_id, role, ordinal, state
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        manifest.manifest_id,
                        assignment.assignment_id,
                        assignment.role.value,
                        ordinal,
                        AssignmentExecutionState.PENDING.value,
                    )
                    for ordinal, assignment in enumerate(assignments)
                ],
            )

    def _acquire_lease(self, manifest_id: str) -> _ExecutionLease:
        token = secrets.token_hex(24)
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=self._lease_seconds)
        with self._transaction(enforce_active_lease=False) as connection:
            row = connection.execute(
                """
                SELECT lease_token, lease_expires_at, lease_epoch
                FROM orchestration_runs WHERE manifest_id = ?
                """,
                (manifest_id,),
            ).fetchone()
            if row is None:
                raise ManifestIdempotencyError("manifest state is missing")
            if row["lease_token"] is not None and row["lease_expires_at"] is not None:
                lease_expires = datetime.fromisoformat(row["lease_expires_at"])
                if lease_expires > now:
                    raise ExecutionInProgressError("another runtime owns the execution lease")
            epoch = int(row["lease_epoch"]) + 1
            connection.execute(
                """
                UPDATE orchestration_runs
                SET lease_token = ?, lease_expires_at = ?, lease_epoch = ?
                WHERE manifest_id = ?
                """,
                (token, _time_text(expires), epoch, manifest_id),
            )
        return _ExecutionLease(manifest_id=manifest_id, token=token, epoch=epoch)

    def _renew_lease(self, lease: _ExecutionLease) -> None:
        expires = datetime.now(UTC) + timedelta(seconds=self._lease_seconds)
        with self._transaction(enforce_active_lease=False) as connection:
            cursor = connection.execute(
                """
                UPDATE orchestration_runs
                SET lease_expires_at = ?
                WHERE manifest_id = ? AND lease_token = ? AND lease_epoch = ?
                """,
                (_time_text(expires), lease.manifest_id, lease.token, lease.epoch),
            )
            if cursor.rowcount != 1:
                raise ExecutionInProgressError("execution lease was fenced by another runtime")

    def _start_lease_heartbeat(
        self,
        lease: _ExecutionLease,
    ) -> tuple[threading.Event, threading.Thread, list[BaseException]]:
        stop = threading.Event()
        failures: list[BaseException] = []
        interval = max(0.1, min(5.0, self._lease_seconds / 3))

        def heartbeat() -> None:
            while not stop.wait(interval):
                try:
                    self._renew_lease(lease)
                except BaseException as exc:  # preserve the exact fencing failure
                    failures.append(exc)
                    return

        thread = threading.Thread(
            target=heartbeat,
            name=f"agt-lease-{lease.manifest_id}",
            daemon=True,
        )
        thread.start()
        return stop, thread, failures

    def _release_lease(self, lease: _ExecutionLease) -> None:
        with self._transaction(enforce_active_lease=False) as connection:
            connection.execute(
                """
                UPDATE orchestration_runs
                SET lease_token = NULL, lease_expires_at = NULL
                WHERE manifest_id = ? AND lease_token = ? AND lease_epoch = ?
                """,
                (lease.manifest_id, lease.token, lease.epoch),
            )

    def request_cancellation(
        self,
        manifest_id: str,
        *,
        trusted_manifest_digest: str,
        trusted_change_digest: str,
        trusted_policy_digest: str,
    ) -> None:
        """Persist a cancellation request that an active host can observe."""

        for name, value in {
            "trusted_manifest_digest": trusted_manifest_digest,
            "trusted_change_digest": trusted_change_digest,
            "trusted_policy_digest": trusted_policy_digest,
        }.items():
            try:
                _validate_digest(value, field_name=name)
            except ValueError as exc:
                raise TrustedBindingError(str(exc)) from exc
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM orchestration_runs WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchone()
            if row is None:
                raise ManifestIdempotencyError("unknown manifest_id")
            if (
                row["manifest_digest"] != trusted_manifest_digest
                or row["change_digest"] != trusted_change_digest
                or row["policy_digest"] != trusted_policy_digest
            ):
                raise TrustedBindingError("cancellation trusted digest mismatch")
            if row["final_receipt_json"] is None:
                connection.execute(
                    "UPDATE orchestration_runs SET cancel_requested = 1 WHERE manifest_id = ?",
                    (manifest_id,),
                )

    def _cancel_requested(self, manifest_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM orchestration_runs WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchone()
        return row is not None and bool(row["cancel_requested"])

    def _set_run_state(
        self,
        manifest_id: str,
        *,
        status: str,
        now: datetime,
        reason_code: str | None = None,
        clear_cancellation: bool = False,
    ) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE orchestration_runs
                SET status = ?, reason_code = ?, updated_at = ?,
                    cancel_requested = CASE WHEN ? THEN 0 ELSE cancel_requested END
                WHERE manifest_id = ?
                """,
                (
                    status,
                    reason_code,
                    _time_text(now),
                    1 if clear_cancellation else 0,
                    manifest_id,
                ),
            )
            if clear_cancellation:
                connection.execute(
                    """
                    DELETE FROM orchestration_tool_audits
                    WHERE manifest_id = ? AND assignment_id IN (
                        SELECT assignment_id FROM orchestration_assignments
                        WHERE manifest_id = ? AND state = ?
                    )
                    """,
                    (
                        manifest_id,
                        manifest_id,
                        AssignmentExecutionState.CANCELLED.value,
                    ),
                )
                connection.execute(
                    """
                    UPDATE orchestration_assignments
                    SET state = ?, host_invoked = 0,
                        request_digest = NULL,
                        checkpoint_grant_digests_json = '[]',
                        outcome_digest = NULL, usage_event_id = NULL,
                        actual_cost_usd = NULL, turns = NULL, tool_calls = NULL,
                        output_digest = NULL, failure_code = NULL,
                        started_at = NULL, finished_at = NULL
                    WHERE manifest_id = ? AND state = ?
                    """,
                    (
                        AssignmentExecutionState.PENDING.value,
                        manifest_id,
                        AssignmentExecutionState.CANCELLED.value,
                    ),
                )

    def _validate_grants(
        self,
        manifest: OrchestrationManifest,
        grants: Iterable[CheckpointGrant],
        *,
        now: datetime,
        temporal_checkpoint_ids: frozenset[str] | None = None,
    ) -> dict[str, CheckpointGrant]:
        checkpoints = {item.checkpoint_id: item for item in manifest.human_checkpoints}
        expected_assignments = {
            checkpoint_id: assignment.assignment_id
            for assignment in self._assignments(manifest)
            for checkpoint_id in assignment.checkpoint_ids
        }
        by_id: dict[str, CheckpointGrant] = {}
        for grant in grants:
            if not isinstance(grant, CheckpointGrant):
                raise CheckpointGrantError("checkpoint_grants must contain CheckpointGrant values")
            try:
                grant = CheckpointGrant.model_validate_json(grant.canonical_bytes())
            except Exception as exc:
                raise CheckpointGrantError("checkpoint grant failed strict revalidation") from exc
            try:
                authentic = bool(self._checkpoint_grant_verifier.verify(grant))
            except Exception as exc:
                raise CheckpointGrantError("checkpoint grant trust verification failed") from exc
            if not authentic:
                raise CheckpointGrantError(
                    f"checkpoint grant {grant.grant_id!r} is not authentic under a pinned trust anchor"
                )
            checkpoint = checkpoints.get(grant.checkpoint_id)
            if checkpoint is None:
                raise CheckpointGrantError(
                    f"grant references unknown checkpoint {grant.checkpoint_id!r}"
                )
            release_grant = checkpoint.phase is CheckpointPhase.BEFORE_RELEASE
            if grant.checkpoint_id not in expected_assignments and not release_grant:
                raise CheckpointGrantError(
                    f"grant references unused checkpoint {grant.checkpoint_id!r}"
                )
            if grant.checkpoint_id in by_id:
                raise CheckpointGrantError(
                    f"multiple grants supplied for checkpoint {grant.checkpoint_id!r}"
                )
            expected_assignment = (
                grant.assignment_id if release_grant else expected_assignments[grant.checkpoint_id]
            )
            mismatches: list[str] = []
            if release_grant:
                if grant.assignment_id not in checkpoint.assignment_ids:
                    mismatches.append("checkpoint_assignment_binding")
            elif checkpoint.assignment_ids != (expected_assignment,):
                mismatches.append("checkpoint_assignment_binding")
            if grant.assignment_id != expected_assignment:
                mismatches.append("assignment")
            if grant.manifest_id != manifest.manifest_id:
                mismatches.append("manifest_id")
            if grant.manifest_digest != manifest.digest:
                mismatches.append("manifest_digest")
            if grant.change_digest != manifest.change_digest:
                mismatches.append("change_digest")
            if grant.policy_digest != manifest.policy_digest:
                mismatches.append("policy_digest")
            if grant.approver_role != checkpoint.approver_role:
                mismatches.append("approver_role")
            if grant.issued_at < manifest.planned_at:
                mismatches.append("issued_before_manifest")
            if checkpoint.phase is CheckpointPhase.BEFORE_RELEASE:
                with self._connect() as connection:
                    review_completion = connection.execute(
                        """
                        SELECT state, finished_at, outcome_digest, output_digest
                        FROM orchestration_assignments
                        WHERE manifest_id = ? AND assignment_id = ?
                        """,
                        (manifest.manifest_id, grant.assignment_id),
                    ).fetchone()
                if (
                    review_completion is None
                    or review_completion["state"] != AssignmentExecutionState.SUCCEEDED.value
                    or review_completion["finished_at"] is None
                    or review_completion["outcome_digest"] is None
                    or review_completion["output_digest"] is None
                ):
                    mismatches.append("review_not_completed")
                else:
                    review_finished_at = datetime.fromisoformat(
                        str(review_completion["finished_at"])
                    )
                    if grant.issued_at <= review_finished_at:
                        mismatches.append("issued_before_review_completion")
                    if grant.review_outcome_digest != review_completion["outcome_digest"]:
                        mismatches.append("review_outcome_digest")
                    if grant.review_output_digest != review_completion["output_digest"]:
                        mismatches.append("review_output_digest")
                    review_assignments = {
                        item.assignment_id: item
                        for item in (
                            manifest.review_assignment,
                            *(
                                round_plan.review_assignment
                                for round_plan in manifest.conditional_review_rounds
                            ),
                        )
                    }
                    review_assignment = review_assignments.get(grant.assignment_id)
                    if review_assignment is None:
                        mismatches.append("assignment")
                    else:
                        raw_review = self._completed_outcome(manifest, review_assignment)
                        if (
                            raw_review.review_semantic_outcome is None
                            or raw_review.review_semantic_outcome.verdict is not ReviewVerdict.CLEAN
                        ):
                            mismatches.append("review_not_clean")
            elif grant.review_outcome_digest is not None or grant.review_output_digest is not None:
                mismatches.append("unexpected_review_binding")
            check_time = (
                temporal_checkpoint_ids is None or grant.checkpoint_id in temporal_checkpoint_ids
            )
            if check_time:
                if grant.issued_at > now:
                    mismatches.append("issued_in_future")
                if now - grant.issued_at > timedelta(
                    seconds=self._max_checkpoint_grant_age_seconds
                ):
                    mismatches.append("stale")
                if now >= grant.expires_at:
                    mismatches.append("expired")
            if mismatches:
                raise CheckpointGrantError(
                    f"checkpoint grant {grant.grant_id!r} is invalid: "
                    + ", ".join(sorted(mismatches))
                )
            by_id[grant.checkpoint_id] = grant
        return by_id

    @staticmethod
    def _checkpoint_authorization(
        checkpoint_ids: tuple[str, ...],
        grants: dict[str, CheckpointGrant],
    ) -> tuple[str, tuple[str, ...]]:
        approved: list[str] = []
        for checkpoint_id in checkpoint_ids:
            grant = grants.get(checkpoint_id)
            if grant is None:
                return "missing", ()
            if grant.decision is CheckpointDecision.DENY:
                return "denied", (grant.grant_digest,)
            approved.append(grant.grant_digest)
        return "approved", tuple(sorted(approved))

    def _assignment_state(self, manifest_id: str, assignment_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT state FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest_id, assignment_id),
            ).fetchone()
        if row is None:
            raise ManifestIdempotencyError("assignment state is missing")
        return str(row["state"])

    def _mark_failed_without_host(
        self,
        manifest_id: str,
        assignment_id: str,
        *,
        failure_code: str,
        checkpoint_grant_digests: tuple[str, ...] = (),
        now: datetime,
    ) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE orchestration_assignments
                SET state = ?, checkpoint_grant_digests_json = ?,
                    failure_code = ?, finished_at = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                """,
                (
                    AssignmentExecutionState.FAILED.value,
                    json.dumps(
                        list(checkpoint_grant_digests),
                        separators=(",", ":"),
                    ),
                    failure_code,
                    _time_text(now),
                    manifest_id,
                    assignment_id,
                    AssignmentExecutionState.PENDING.value,
                ),
            )

    def _claim_assignment(
        self,
        manifest_id: str,
        assignment_id: str,
        *,
        checkpoint_grant_digests: tuple[str, ...],
        now: datetime,
    ) -> bool:
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE orchestration_assignments
                SET state = ?, attempt_count = attempt_count + 1,
                    checkpoint_grant_digests_json = ?, started_at = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                """,
                (
                    AssignmentExecutionState.RUNNING.value,
                    json.dumps(
                        list(checkpoint_grant_digests),
                        separators=(",", ":"),
                    ),
                    _time_text(now),
                    manifest_id,
                    assignment_id,
                    AssignmentExecutionState.PENDING.value,
                ),
            )
        return cursor.rowcount == 1

    def _record_host_failure(
        self,
        manifest_id: str,
        assignment_id: str,
        *,
        failure_code: str,
        now: datetime,
    ) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE orchestration_assignments
                SET state = ?, failure_code = ?, finished_at = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                """,
                (
                    AssignmentExecutionState.FAILED.value,
                    failure_code,
                    _time_text(now),
                    manifest_id,
                    assignment_id,
                    AssignmentExecutionState.RUNNING.value,
                ),
            )

    def _record_cooperative_cancellation(
        self,
        manifest_id: str,
        assignment_id: str,
        *,
        now: datetime,
    ) -> None:
        """Persist an invoked assignment as cancelled without making it terminal."""

        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE orchestration_assignments
                SET state = ?, failure_code = ?, finished_at = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                    AND host_invoked = 1
                """,
                (
                    AssignmentExecutionState.CANCELLED.value,
                    "execution.cancelled",
                    _time_text(now),
                    manifest_id,
                    assignment_id,
                    AssignmentExecutionState.RUNNING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ManifestIdempotencyError(
                    "cooperative cancellation could not be committed exactly once"
                )

    def _mark_host_invoked(
        self,
        manifest_id: str,
        assignment_id: str,
        *,
        request_digest: str,
        requested_at: datetime,
    ) -> None:
        """Cross the host side-effect boundary under the active lease fence.

        The flag is committed immediately before calling the adapter.  A crash
        after this commit is therefore reported as unknown cost instead of the
        misleading zero that an unobserved side effect would otherwise imply.
        """

        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE orchestration_assignments
                SET host_invoked = 1, request_digest = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                    AND host_invoked = 0 AND request_digest IS NULL
                    AND started_at = ?
                """,
                (
                    _validate_digest(request_digest, field_name="request_digest"),
                    manifest_id,
                    assignment_id,
                    AssignmentExecutionState.RUNNING.value,
                    _time_text(requested_at),
                ),
            )
            if cursor.rowcount != 1:
                raise ManifestIdempotencyError(
                    "host invocation boundary could not be committed exactly once"
                )

    @staticmethod
    def _outcome_binding_failures(
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        outcome: AssignmentHostOutcome,
        *,
        requested_at: datetime,
        finished_at: datetime,
        request_digest: str,
        review_round_number: int | None,
        remediation_binding: RemediationScopeBinding | None,
    ) -> list[str]:
        failures: list[str] = []
        expected = {
            "assignment_id": assignment.assignment_id,
            "manifest_id": manifest.manifest_id,
            "manifest_digest": manifest.digest,
            "change_digest": manifest.change_digest,
            "policy_digest": manifest.policy_digest,
            "context_id": assignment.context_id,
            "workspace_key": assignment.workspace_key,
        }
        for field_name, value in expected.items():
            if getattr(outcome, field_name) != value:
                failures.append(f"host.binding.{field_name}")
        event = outcome.usage_event
        if event.attribution != assignment.reservation.attribution.to_usage_attribution():
            failures.append("host.usage.attribution")
        if event.model != assignment.route.identity:
            failures.append("host.usage.model")
        if event.prompt != assignment.prompt.identity:
            failures.append("host.usage.prompt")
        if event.occurred_at < requested_at:
            failures.append("host.usage.occurred_before_request")
        if event.occurred_at > finished_at:
            failures.append("host.usage.occurred_after_host_return")
        if outcome.status is HostOutcomeStatus.SUCCEEDED and event.outcome != "accepted":
            failures.append("host.usage.outcome")
        if outcome.status is HostOutcomeStatus.FAILED and event.outcome == "accepted":
            failures.append("host.usage.outcome")
        if assignment.role is AssignmentRole.INDEPENDENT_REVIEW:
            if (
                outcome.status is HostOutcomeStatus.SUCCEEDED
                and outcome.review_semantic_outcome is None
            ):
                failures.append("review.semantic_outcome_missing")
            elif (
                outcome.status is HostOutcomeStatus.SUCCEEDED
                and outcome.review_semantic_outcome is not None
                and outcome.output_digest != outcome.review_semantic_outcome.report_digest
            ):
                failures.append("review.semantic_report_digest_mismatch")
            if (
                outcome.status is HostOutcomeStatus.SUCCEEDED
                and outcome.review_semantic_outcome is not None
            ):
                semantics = outcome.review_semantic_outcome
                semantic_bindings = {
                    "manifest_id": manifest.manifest_id,
                    "manifest_digest": manifest.digest,
                    "run_id": manifest.run_id,
                    "change_digest": manifest.change_digest,
                    "policy_digest": manifest.policy_digest,
                    "review_assignment_id": assignment.assignment_id,
                    "context_id": assignment.context_id,
                    "workspace_key": assignment.workspace_key,
                    "reviewer_model_id": assignment.route.identity.canonical_id,
                    "reviewer_model_family": assignment.route.provider_family,
                    "review_round_number": review_round_number,
                    "request_digest": request_digest,
                }
                for field_name, expected_value in semantic_bindings.items():
                    if getattr(semantics, field_name) != expected_value:
                        failures.append(f"review.semantic_{field_name}_mismatch")
                if not semantics.verify_attestation(manifest.trusted_review_attesters):
                    failures.append("review.semantic_attestation_untrusted")
                if not requested_at <= semantics.issued_at <= finished_at:
                    failures.append("review.semantic_issuance_time_invalid")
                if semantics.expires_at <= finished_at:
                    failures.append("review.semantic_attestation_expired")
                if semantics.expires_at > semantics.issued_at + timedelta(
                    seconds=manifest.review_attestation_ttl_seconds
                ):
                    failures.append("review.semantic_attestation_ttl_exceeded")
            if outcome.remediation_binding is not None:
                failures.append("review.unexpected_remediation_binding")
        elif assignment.role is AssignmentRole.REMEDIATION:
            if remediation_binding is None:
                failures.append("remediation.prior_review_binding_missing")
            elif outcome.remediation_binding != remediation_binding:
                failures.append("remediation.prior_review_binding_mismatch")
            if outcome.review_semantic_outcome is not None:
                failures.append("remediation.unexpected_review_semantics")
        elif outcome.review_semantic_outcome is not None or outcome.remediation_binding is not None:
            failures.append("implementation.unexpected_review_loop_facts")
        return failures

    @staticmethod
    def _intent_digest_payload(
        *,
        manifest_id: str,
        assignment_id: str,
        outcome: AssignmentHostOutcome,
        checkpoint_grant_digests: tuple[str, ...],
        forced_failures: tuple[str, ...],
        reconciled_at: datetime,
    ) -> dict[str, Any]:
        return {
            "manifest_id": manifest_id,
            "assignment_id": assignment_id,
            "outcome": _host_outcome_payload(outcome),
            "outcome_digest": outcome.digest,
            "checkpoint_grant_digests": list(checkpoint_grant_digests),
            "forced_failures": list(forced_failures),
            "reconciled_at": _time_text(reconciled_at),
        }

    def _store_outcome_intent(
        self,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        outcome: AssignmentHostOutcome,
        *,
        checkpoint_grant_digests: tuple[str, ...],
        forced_failures: tuple[str, ...],
        reconciled_at: datetime,
    ) -> _OutcomeIntent:
        grants = tuple(sorted(set(checkpoint_grant_digests)))
        for digest in grants:
            _validate_digest(digest, field_name="checkpoint_grant_digests entry")
        failures = tuple(sorted(set(forced_failures)))
        if any(
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}", value) is None
            for value in failures
        ):
            raise OrchestrationRuntimeError("forced outcome failures are invalid")
        reconciled_at = _utc(reconciled_at, field_name="reconciled_at")
        outcome_payload = _host_outcome_payload(outcome)
        outcome_json = canonical_json_bytes(outcome_payload).decode("utf-8")
        grants_json = canonical_json_bytes(grants).decode("utf-8")
        failures_json = canonical_json_bytes(failures).decode("utf-8")
        intent_payload = self._intent_digest_payload(
            manifest_id=manifest.manifest_id,
            assignment_id=assignment.assignment_id,
            outcome=outcome,
            checkpoint_grant_digests=grants,
            forced_failures=failures,
            reconciled_at=reconciled_at,
        )
        intent_digest = digest_without(intent_payload)
        with self._transaction() as connection:
            run_row = connection.execute(
                "SELECT cancel_requested FROM orchestration_runs WHERE manifest_id = ?",
                (manifest.manifest_id,),
            ).fetchone()
            if run_row is None:
                raise ManifestIdempotencyError("manifest state is missing")
            if bool(run_row["cancel_requested"]):
                raise _CancellationWonFinalizationError
            assignment_row = connection.execute(
                """
                SELECT state, host_invoked FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest.manifest_id, assignment.assignment_id),
            ).fetchone()
            if assignment_row is None:
                raise ManifestIdempotencyError("assignment state is missing")
            existing = connection.execute(
                """
                SELECT * FROM orchestration_outcome_intents
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest.manifest_id, assignment.assignment_id),
            ).fetchone()
            if existing is not None:
                exact = (
                    existing["intent_digest"] == intent_digest
                    and existing["outcome_digest"] == outcome.digest
                    and existing["outcome_json"] == outcome_json
                    and existing["checkpoint_grant_digests_json"] == grants_json
                    and existing["forced_failures_json"] == failures_json
                    and existing["reconciled_at"] == _time_text(reconciled_at)
                    and existing["state"] in {"pending", "completed"}
                )
                if not exact:
                    raise ManifestIdempotencyError(
                        "assignment outcome intent was reused with different facts"
                    )
            else:
                if assignment_row["state"] != AssignmentExecutionState.RUNNING.value or not bool(
                    assignment_row["host_invoked"]
                ):
                    raise ManifestIdempotencyError(
                        "outcome intent requires a running, invoked assignment"
                    )
                connection.execute(
                    """
                    INSERT INTO orchestration_outcome_intents (
                        manifest_id, assignment_id, intent_digest, outcome_digest,
                        outcome_json, checkpoint_grant_digests_json,
                        forced_failures_json, reconciled_at, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        manifest.manifest_id,
                        assignment.assignment_id,
                        intent_digest,
                        outcome.digest,
                        outcome_json,
                        grants_json,
                        failures_json,
                        _time_text(reconciled_at),
                        _time_text(self._now()),
                    ),
                )
        return _OutcomeIntent(
            assignment_id=assignment.assignment_id,
            outcome=outcome,
            checkpoint_grant_digests=grants,
            forced_failures=failures,
            reconciled_at=reconciled_at,
        )

    def _load_pending_outcome_intents(
        self,
        manifest: OrchestrationManifest,
    ) -> tuple[_OutcomeIntent, ...]:
        assignments = {item.assignment_id: item for item in self._assignments(manifest)}
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM orchestration_outcome_intents
                WHERE manifest_id = ? AND state = 'pending'
                ORDER BY assignment_id
                """,
                (manifest.manifest_id,),
            ).fetchall()
        intents: list[_OutcomeIntent] = []
        for row in rows:
            assignment_id = str(row["assignment_id"])
            if assignment_id not in assignments:
                raise ManifestIdempotencyError(
                    "stored outcome intent references an unknown assignment"
                )
            try:
                outcome_payload = load_json_strict(str(row["outcome_json"]))
                outcome = _host_outcome_from_payload(outcome_payload)
                raw_grants = load_json_strict(str(row["checkpoint_grant_digests_json"]))
                raw_failures = load_json_strict(str(row["forced_failures_json"]))
                reconciled_at = datetime.fromisoformat(str(row["reconciled_at"]))
            except Exception as exc:
                raise ManifestIdempotencyError(
                    "stored outcome intent failed strict decoding"
                ) from exc
            if (
                not isinstance(raw_grants, list)
                or not all(isinstance(value, str) for value in raw_grants)
                or not isinstance(raw_failures, list)
                or not all(isinstance(value, str) for value in raw_failures)
            ):
                raise ManifestIdempotencyError("stored outcome intent arrays are invalid")
            grants = tuple(cast(list[str], raw_grants))
            failures = tuple(cast(list[str], raw_failures))
            try:
                _sorted_unique(grants, field_name="checkpoint_grant_digests")
                for digest in grants:
                    _validate_digest(digest, field_name="checkpoint_grant_digests entry")
                _sorted_unique(failures, field_name="forced_failures")
                reconciled_at = _utc(reconciled_at, field_name="reconciled_at")
            except ValueError as exc:
                raise ManifestIdempotencyError("stored outcome intent is not canonical") from exc
            canonical_outcome = canonical_json_bytes(_host_outcome_payload(outcome)).decode("utf-8")
            if canonical_outcome != row["outcome_json"] or outcome.digest != row["outcome_digest"]:
                raise ManifestIdempotencyError("stored outcome intent digest is invalid")
            intent_payload = self._intent_digest_payload(
                manifest_id=manifest.manifest_id,
                assignment_id=assignment_id,
                outcome=outcome,
                checkpoint_grant_digests=grants,
                forced_failures=failures,
                reconciled_at=reconciled_at,
            )
            if (
                row["intent_digest"] != digest_without(intent_payload)
                or row["reconciled_at"] != _time_text(reconciled_at)
                or row["checkpoint_grant_digests_json"]
                != canonical_json_bytes(grants).decode("utf-8")
                or row["forced_failures_json"] != canonical_json_bytes(failures).decode("utf-8")
            ):
                raise ManifestIdempotencyError("stored outcome intent is not canonical")
            intents.append(
                _OutcomeIntent(
                    assignment_id=assignment_id,
                    outcome=outcome,
                    checkpoint_grant_digests=grants,
                    forced_failures=failures,
                    reconciled_at=reconciled_at,
                )
            )
        return tuple(intents)

    def _reconcile_outcome_intent(
        self,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        intent: _OutcomeIntent,
    ) -> None:
        if intent.assignment_id != assignment.assignment_id:
            raise ManifestIdempotencyError("outcome intent assignment binding changed")
        outcome = intent.outcome
        event = outcome.usage_event
        manifest_price = PriceCatalog((assignment.route.price_record,))
        reconciliation = self._usage_ledger.reconcile(
            assignment.reservation.reservation_id,
            event,
            prices=manifest_price,
            reconciliation_id=f"runtime:{manifest.manifest_id}:{assignment.assignment_id}",
            reconciled_at=intent.reconciled_at,
        )
        failures = list(intent.forced_failures)
        if event.turns > assignment.max_turns:
            failures.append("limit.turns_exceeded")
        if event.tool_calls > assignment.max_tool_calls:
            failures.append("limit.tool_calls_exceeded")
        if reconciliation.actual_usd > assignment.max_cost_usd:
            failures.append("limit.assignment_cost_exceeded")
        if reconciliation.breached_budget_ids:
            failures.append("budget.actual_spend_exceeded")
        if outcome.status is HostOutcomeStatus.FAILED:
            failures.append("host.assignment_failed")

        with self._transaction() as connection:
            intent_row = connection.execute(
                """
                SELECT state FROM orchestration_outcome_intents
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest.manifest_id, assignment.assignment_id),
            ).fetchone()
            if intent_row is None:
                raise ManifestIdempotencyError("durable outcome intent is missing")
            assignment_row = connection.execute(
                """
                SELECT state, host_invoked, outcome_digest, usage_event_id,
                       actual_cost_usd, turns, tool_calls, output_digest
                FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest.manifest_id, assignment.assignment_id),
            ).fetchone()
            if assignment_row is None:
                raise ManifestIdempotencyError("assignment state is missing")
            if intent_row["state"] == "completed":
                if (
                    assignment_row["state"]
                    not in {
                        AssignmentExecutionState.SUCCEEDED.value,
                        AssignmentExecutionState.FAILED.value,
                    }
                    or not bool(assignment_row["host_invoked"])
                    or assignment_row["outcome_digest"] != outcome.digest
                    or assignment_row["usage_event_id"] != event.event_id
                    or assignment_row["actual_cost_usd"] != _decimal_text(reconciliation.actual_usd)
                    or assignment_row["turns"] != event.turns
                    or assignment_row["tool_calls"] != event.tool_calls
                    or assignment_row["output_digest"] != outcome.output_digest
                ):
                    raise ManifestIdempotencyError(
                        "completed outcome intent disagrees with assignment state"
                    )
                return
            if (
                intent_row["state"] != "pending"
                or assignment_row["state"] != AssignmentExecutionState.RUNNING.value
                or not bool(assignment_row["host_invoked"])
            ):
                raise ManifestIdempotencyError(
                    "pending outcome intent has an invalid assignment state"
                )
            current_cost_rows = connection.execute(
                """
                SELECT actual_cost_usd
                FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id != ?
                    AND actual_cost_usd IS NOT NULL
                """,
                (manifest.manifest_id, assignment.assignment_id),
            ).fetchall()
            current_total = sum(
                (Decimal(str(row["actual_cost_usd"])) for row in current_cost_rows),
                Decimal("0"),
            )
            if current_total + reconciliation.actual_usd > manifest.limits.max_total_cost_usd:
                failures.append("limit.total_cost_exceeded")
            failures = sorted(set(failures))
            state = (
                AssignmentExecutionState.FAILED if failures else AssignmentExecutionState.SUCCEEDED
            )
            assignment_cursor = connection.execute(
                """
                UPDATE orchestration_assignments
                SET state = ?, checkpoint_grant_digests_json = ?, outcome_digest = ?,
                    usage_event_id = ?, actual_cost_usd = ?, turns = ?, tool_calls = ?,
                    output_digest = ?, failure_code = ?, finished_at = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                    AND host_invoked = 1
                """,
                (
                    state.value,
                    canonical_json_bytes(intent.checkpoint_grant_digests).decode("utf-8"),
                    outcome.digest,
                    event.event_id,
                    _decimal_text(reconciliation.actual_usd),
                    event.turns,
                    event.tool_calls,
                    outcome.output_digest,
                    ",".join(failures) if failures else None,
                    _time_text(intent.reconciled_at),
                    manifest.manifest_id,
                    assignment.assignment_id,
                    AssignmentExecutionState.RUNNING.value,
                ),
            )
            intent_cursor = connection.execute(
                """
                UPDATE orchestration_outcome_intents
                SET state = 'completed', completed_at = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = 'pending'
                """,
                (
                    _time_text(self._now()),
                    manifest.manifest_id,
                    assignment.assignment_id,
                ),
            )
            if assignment_cursor.rowcount != 1 or intent_cursor.rowcount != 1:
                raise ManifestIdempotencyError("outcome intent could not be committed exactly once")

    def _recover_pending_outcome_intents(self, manifest: OrchestrationManifest) -> None:
        assignments = {item.assignment_id: item for item in self._assignments(manifest)}
        for intent in self._load_pending_outcome_intents(manifest):
            self._reconcile_outcome_intent(
                manifest,
                assignments[intent.assignment_id],
                intent,
            )

    def _record_outcome(
        self,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        outcome: AssignmentHostOutcome,
        *,
        checkpoint_grant_digests: tuple[str, ...],
        now: datetime,
        forced_failures: tuple[str, ...] = (),
    ) -> None:
        intent = self._store_outcome_intent(
            manifest,
            assignment,
            outcome,
            checkpoint_grant_digests=checkpoint_grant_digests,
            forced_failures=forced_failures,
            reconciled_at=max(now, outcome.usage_event.occurred_at),
        )
        self._reconcile_outcome_intent(manifest, assignment, intent)

    def _execution_budget_meter(
        self,
        manifest: OrchestrationManifest,
    ) -> _ExecutionBudgetMeter:
        """Seed a cooperative meter from already reconciled durable costs."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT actual_cost_usd FROM orchestration_assignments
                WHERE manifest_id = ? AND actual_cost_usd IS NOT NULL
                """,
                (manifest.manifest_id,),
            ).fetchall()
        try:
            committed = sum(
                (Decimal(str(row["actual_cost_usd"])) for row in rows),
                Decimal("0"),
            )
        except Exception as exc:
            raise ManifestIdempotencyError("stored assignment cost is invalid") from exc
        if not committed.is_finite() or committed < 0:
            raise ManifestIdempotencyError("stored assignment cost is invalid")
        return _ExecutionBudgetMeter(manifest, committed_cost_usd=committed)

    def _invoke_host_with_deadline(
        self,
        request: AssignmentExecutionRequest,
        *,
        cancellation_probe: CancellationProbe,
        governance: _ToolGovernanceSession,
        deadline_monotonic: float,
    ) -> AssignmentHostOutcome:
        """Run a synchronous adapter behind a hard deadline and stale-result fence."""

        results: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                outcome = self._host.execute(
                    request,
                    is_cancelled=cancellation_probe,
                    authorize_action=governance.authorize,
                    screen_result=governance.screen,
                )
            except BaseException as exc:
                results.put((False, exc))
            else:
                results.put((True, outcome))

        worker = threading.Thread(
            target=invoke,
            name=f"agt-host-{request.assignment.assignment_id}",
            daemon=True,
        )
        worker.start()
        while True:
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                governance.close("host.execution_timeout")
                raise HostExecutionTimeoutError("host.execution_timeout")
            try:
                succeeded, value = results.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                if cancellation_probe():
                    governance.close("execution.cancelled")
                    raise CooperativeCancellationError("host observed cancellation") from None
                continue
            if time.monotonic() >= deadline_monotonic:
                governance.close("host.execution_timeout")
                raise HostExecutionTimeoutError("host.execution_timeout")
            if cancellation_probe():
                governance.close("execution.cancelled")
                raise CooperativeCancellationError("host observed cancellation")
            if not succeeded:
                assert isinstance(value, BaseException)
                raise value
            if not isinstance(value, AssignmentHostOutcome):
                raise TypeError("host returned a value other than AssignmentHostOutcome")
            return value

    def _execute_one(
        self,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
        *,
        checkpoint_grant_digests: tuple[str, ...],
        checkpoint_grants: tuple[CheckpointGrant, ...],
        external_cancellation: CancellationProbe | None,
        budget_meter: _ExecutionBudgetMeter,
        remediation_binding: RemediationScopeBinding | None = None,
    ) -> None:
        # A sibling host may have persisted cancellation while this item was
        # queued behind the executor's worker limit.  Never cross another host
        # invocation boundary after that durable observation.
        if self._cancel_requested(manifest.manifest_id):
            return
        started_at = self._now()
        self._assert_assignment_model_binding(assignment)
        self._assert_assignment_price_binding(assignment, at=started_at)
        self._assert_assignment_prompt_binding(assignment)
        if not self._claim_assignment(
            manifest.manifest_id,
            assignment.assignment_id,
            checkpoint_grant_digests=checkpoint_grant_digests,
            now=started_at,
        ):
            return
        if started_at >= assignment.reservation.expires_at:
            self._record_host_failure(
                manifest.manifest_id,
                assignment.assignment_id,
                failure_code="reservation.expired",
                now=started_at,
            )
            return
        try:
            self._usage_ledger.reserve(assignment.reservation.to_request())
        except Exception as exc:
            self._record_host_failure(
                manifest.manifest_id,
                assignment.assignment_id,
                failure_code=f"reservation.failed:{type(exc).__name__}",
                now=self._now(),
            )
            return

        request = AssignmentExecutionRequest.create(
            manifest=manifest,
            assignment=assignment,
            checkpoint_grant_digests=checkpoint_grant_digests,
            requested_at=started_at,
            remediation_binding=remediation_binding,
        )

        def cancellation_probe() -> bool:
            return self._cancelled(
                manifest,
                external_cancellation=external_cancellation,
            )

        effective_timeout = float(manifest.limits.max_assignment_duration_seconds)
        if self._assignment_timeout_seconds is not None:
            effective_timeout = min(effective_timeout, self._assignment_timeout_seconds)
        deadline_monotonic = time.monotonic() + effective_timeout
        governance = _ToolGovernanceSession(
            runtime=self,
            manifest=manifest,
            assignment=assignment,
            checkpoint_grant_digests=checkpoint_grant_digests,
            checkpoint_grants=checkpoint_grants,
            remediation_binding=remediation_binding,
            budget_meter=budget_meter,
            deadline_monotonic=deadline_monotonic,
            cancellation_probe=cancellation_probe,
        )
        self._mark_host_invoked(
            manifest.manifest_id,
            assignment.assignment_id,
            request_digest=request.request_digest,
            requested_at=request.requested_at,
        )
        try:
            outcome = self._invoke_host_with_deadline(
                request,
                cancellation_probe=cancellation_probe,
                governance=governance,
                deadline_monotonic=deadline_monotonic,
            )
        except CooperativeCancellationError:
            governance.close("execution.cancelled")
            if self._cancel_requested(manifest.manifest_id):
                self._record_cooperative_cancellation(
                    manifest.manifest_id,
                    assignment.assignment_id,
                    now=self._now(),
                )
            else:
                self._record_host_failure(
                    manifest.manifest_id,
                    assignment.assignment_id,
                    failure_code="host.invalid_cooperative_cancellation",
                    now=self._now(),
                )
            return
        except HostExecutionTimeoutError:
            governance.close("host.execution_timeout")
            self._record_host_failure(
                manifest.manifest_id,
                assignment.assignment_id,
                failure_code="host.execution_timeout",
                now=self._now(),
            )
            return
        except ToolGovernanceError as exc:
            governance.close(exc.reason_code)
            self._record_host_failure(
                manifest.manifest_id,
                assignment.assignment_id,
                failure_code=exc.reason_code,
                now=self._now(),
            )
            return
        except ExecutionBudgetExceededError as exc:
            governance.close(exc.reason_code)
            self._record_host_failure(
                manifest.manifest_id,
                assignment.assignment_id,
                failure_code=exc.reason_code,
                now=self._now(),
            )
            return
        except Exception as exc:
            governance.close(f"host.failed:{type(exc).__name__}")
            self._record_host_failure(
                manifest.manifest_id,
                assignment.assignment_id,
                failure_code=f"host.failed:{type(exc).__name__}",
                now=self._now(),
            )
            return

        finished_at = self._now()
        binding_failures = self._outcome_binding_failures(
            manifest,
            assignment,
            outcome,
            requested_at=started_at,
            finished_at=finished_at,
            request_digest=request.request_digest,
            review_round_number=request.review_round_number,
            remediation_binding=remediation_binding,
        )
        binding_failures.extend(
            governance.completion_failures(
                observed_tool_calls=outcome.usage_event.tool_calls,
            )
        )
        if binding_failures:
            untrusted_usage = bool(
                {
                    "host.usage.attribution",
                    "host.usage.model",
                    "host.usage.prompt",
                    "host.usage.occurred_before_request",
                    "host.usage.occurred_after_host_return",
                }
                & set(binding_failures)
            )
            if untrusted_usage:
                self._record_host_failure(
                    manifest.manifest_id,
                    assignment.assignment_id,
                    failure_code=",".join(sorted(binding_failures)),
                    now=finished_at,
                )
                return
            try:
                self._record_outcome(
                    manifest,
                    assignment,
                    outcome,
                    checkpoint_grant_digests=checkpoint_grant_digests,
                    now=finished_at,
                    forced_failures=tuple(binding_failures),
                )
            except _CancellationWonFinalizationError:
                self._record_cooperative_cancellation(
                    manifest.manifest_id,
                    assignment.assignment_id,
                    now=self._now(),
                )
                return
            budget_meter.finish(
                assignment,
                actual_cost_usd=assignment.route.price_record.calculate(outcome.usage_event.usage),
            )
            return
        try:
            self._record_outcome(
                manifest,
                assignment,
                outcome,
                checkpoint_grant_digests=checkpoint_grant_digests,
                now=finished_at,
            )
        except _CancellationWonFinalizationError:
            self._record_cooperative_cancellation(
                manifest.manifest_id,
                assignment.assignment_id,
                now=self._now(),
            )
            return
        budget_meter.finish(
            assignment,
            actual_cost_usd=assignment.route.price_record.calculate(outcome.usage_event.usage),
        )

    def _execute_batch(
        self,
        manifest: OrchestrationManifest,
        assignments: tuple[WorkAssignment, ...],
        *,
        grants_by_assignment: dict[str, tuple[str, ...]],
        grant_records_by_assignment: dict[str, tuple[CheckpointGrant, ...]],
        external_cancellation: CancellationProbe | None,
        budget_meter: _ExecutionBudgetMeter,
        remediation_bindings_by_assignment: Mapping[str, RemediationScopeBinding] | None = None,
    ) -> None:
        pending = tuple(
            assignment
            for assignment in assignments
            if self._assignment_state(manifest.manifest_id, assignment.assignment_id)
            == AssignmentExecutionState.PENDING.value
        )
        if not pending:
            return
        workers = min(len(pending), manifest.limits.max_parallel_agents)
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="agt-orchestration"
        ) as pool:
            futures = [
                pool.submit(
                    self._execute_one,
                    manifest,
                    assignment,
                    checkpoint_grant_digests=grants_by_assignment[assignment.assignment_id],
                    checkpoint_grants=grant_records_by_assignment[assignment.assignment_id],
                    external_cancellation=external_cancellation,
                    budget_meter=budget_meter,
                    remediation_binding=(
                        None
                        if remediation_bindings_by_assignment is None
                        else remediation_bindings_by_assignment.get(assignment.assignment_id)
                    ),
                )
                for assignment in pending
            ]
            for future in futures:
                future.result()

    def _has_assignment_failure(self, manifest_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM orchestration_assignments
                WHERE manifest_id = ? AND state IN (?, ?) LIMIT 1
                """,
                (
                    manifest_id,
                    AssignmentExecutionState.FAILED.value,
                    AssignmentExecutionState.BLOCKED.value,
                ),
            ).fetchone()
        return row is not None

    def _block_pending(self, manifest_id: str, *, now: datetime) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE orchestration_assignments
                SET state = ?, failure_code = ?, finished_at = ?
                WHERE manifest_id = ? AND state = ?
                """,
                (
                    AssignmentExecutionState.BLOCKED.value,
                    "dependency.failed",
                    _time_text(now),
                    manifest_id,
                    AssignmentExecutionState.PENDING.value,
                ),
            )

    def _append_checkpoint_digest(
        self,
        manifest_id: str,
        assignment_id: str,
        digest: str,
    ) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT checkpoint_grant_digests_json FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest_id, assignment_id),
            ).fetchone()
            if row is None:
                raise ManifestIdempotencyError("assignment state is missing")
            values = set(json.loads(row["checkpoint_grant_digests_json"]))
            values.add(digest)
            connection.execute(
                """
                UPDATE orchestration_assignments
                SET checkpoint_grant_digests_json = ?
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (
                    json.dumps(sorted(values), separators=(",", ":")),
                    manifest_id,
                    assignment_id,
                ),
            )

    def _skip_future_conditional_assignments(
        self,
        manifest: OrchestrationManifest,
        *,
        clean_round_number: int,
        now: datetime,
    ) -> None:
        """Durably short-circuit only work whose predeclared condition is false."""

        assignment_ids = tuple(
            assignment.assignment_id
            for item in manifest.conditional_review_rounds
            if item.round_number > clean_round_number
            for assignment in (item.remediation_assignment, item.review_assignment)
        )
        if not assignment_ids:
            return
        placeholders = ",".join("?" for _ in assignment_ids)
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT assignment_id, state FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id IN ({placeholders})
                """,
                (manifest.manifest_id, *assignment_ids),
            ).fetchall()
            states = {str(row["assignment_id"]): str(row["state"]) for row in rows}
            if set(states) != set(assignment_ids) or any(
                state
                not in {
                    AssignmentExecutionState.PENDING.value,
                    AssignmentExecutionState.SKIPPED.value,
                }
                for state in states.values()
            ):
                raise ManifestIdempotencyError(
                    "work after a clean review was already invoked or changed"
                )
            connection.execute(
                f"""
                UPDATE orchestration_assignments
                SET state = ?, finished_at = ?
                WHERE manifest_id = ? AND assignment_id IN ({placeholders})
                    AND state = ?
                """,
                (
                    AssignmentExecutionState.SKIPPED.value,
                    _time_text(now),
                    manifest.manifest_id,
                    *assignment_ids,
                    AssignmentExecutionState.PENDING.value,
                ),
            )

    def _completed_outcome(
        self,
        manifest: OrchestrationManifest,
        assignment: WorkAssignment,
    ) -> AssignmentHostOutcome:
        """Load and revalidate the raw durable outcome for one succeeded assignment."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT a.state AS assignment_state, a.outcome_digest AS assignment_digest,
                       i.state AS intent_state, i.outcome_digest AS intent_digest,
                       i.outcome_json AS outcome_json
                FROM orchestration_assignments AS a
                JOIN orchestration_outcome_intents AS i
                  ON i.manifest_id = a.manifest_id
                 AND i.assignment_id = a.assignment_id
                WHERE a.manifest_id = ? AND a.assignment_id = ?
                """,
                (manifest.manifest_id, assignment.assignment_id),
            ).fetchone()
        if (
            row is None
            or row["assignment_state"] != AssignmentExecutionState.SUCCEEDED.value
            or row["intent_state"] != "completed"
        ):
            raise ManifestIdempotencyError("completed assignment raw outcome is missing")
        try:
            payload = load_json_strict(str(row["outcome_json"]))
            outcome = _host_outcome_from_payload(payload)
        except Exception as exc:
            raise ManifestIdempotencyError("completed raw outcome failed validation") from exc
        if (
            outcome.digest != row["assignment_digest"]
            or outcome.digest != row["intent_digest"]
            or outcome.assignment_id != assignment.assignment_id
            or outcome.manifest_id != manifest.manifest_id
        ):
            raise ManifestIdempotencyError("completed raw outcome digest binding changed")
        return outcome

    def _review_history(self, manifest: OrchestrationManifest) -> tuple[ReviewRoundHistory, ...]:
        """Derive ordered semantic review/fix history from raw durable outcomes."""

        reviews = (
            manifest.review_assignment,
            *(item.review_assignment for item in manifest.conditional_review_rounds),
        )
        history: list[ReviewRoundHistory] = []
        for index, review in enumerate(reviews):
            if (
                self._assignment_state(manifest.manifest_id, review.assignment_id)
                != AssignmentExecutionState.SUCCEEDED.value
            ):
                break
            outcome = self._completed_outcome(manifest, review)
            semantics = outcome.review_semantic_outcome
            if semantics is None:
                raise ManifestIdempotencyError("successful review raw outcome lacks semantic facts")
            remediation_history: RemediationExecutionHistory | None = None
            if semantics.verdict is ReviewVerdict.BLOCKING and index < len(
                manifest.conditional_review_rounds
            ):
                remediation = manifest.conditional_review_rounds[index].remediation_assignment
                if (
                    self._assignment_state(manifest.manifest_id, remediation.assignment_id)
                    == AssignmentExecutionState.SUCCEEDED.value
                ):
                    fix_outcome = self._completed_outcome(manifest, remediation)
                    if fix_outcome.remediation_binding is None:
                        raise ManifestIdempotencyError(
                            "successful remediation raw outcome lacks its review binding"
                        )
                    remediation_history = RemediationExecutionHistory.create(
                        assignment_id=remediation.assignment_id,
                        context_id=remediation.context_id,
                        workspace_key=remediation.workspace_key,
                        outcome_digest=fix_outcome.digest,
                        output_digest=fix_outcome.output_digest,
                        binding=fix_outcome.remediation_binding,
                    )
            history.append(
                ReviewRoundHistory.create(
                    round_number=index + 1,
                    review_assignment_id=review.assignment_id,
                    context_id=review.context_id,
                    workspace_key=review.workspace_key,
                    reviewer_model_family=review.route.provider_family,
                    outcome_digest=outcome.digest,
                    output_digest=outcome.output_digest,
                    semantic_outcome=semantics,
                    remediation=remediation_history,
                )
            )
            if semantics.verdict is ReviewVerdict.CLEAN or remediation_history is None:
                break
        return tuple(history)

    def _receipt_rows(
        self,
        manifest: OrchestrationManifest,
    ) -> tuple[AssignmentExecutionReceipt, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM orchestration_assignments
                WHERE manifest_id = ? ORDER BY ordinal
                """,
                (manifest.manifest_id,),
            ).fetchall()
        expected = tuple(
            (assignment.assignment_id, assignment.role)
            for assignment in self._assignments(manifest)
        )
        stored = tuple(
            (str(row["assignment_id"]), AssignmentRole(str(row["role"]))) for row in rows
        )
        if stored != expected:
            raise ManifestIdempotencyError(
                "durable assignment state does not exactly match the manifest"
            )
        assignments = {
            assignment.assignment_id: assignment for assignment in self._assignments(manifest)
        }
        return tuple(
            AssignmentExecutionReceipt(
                assignment_id=str(row["assignment_id"]),
                role=AssignmentRole(str(row["role"])),
                prompt=assignments[str(row["assignment_id"])].prompt,
                state=AssignmentExecutionState(str(row["state"])),
                attempt_count=int(row["attempt_count"]),
                host_invoked=bool(row["host_invoked"]),
                request_digest=(
                    str(row["request_digest"])
                    if bool(row["host_invoked"]) and row["request_digest"]
                    else None
                ),
                requested_at=(
                    datetime.fromisoformat(str(row["started_at"]))
                    if bool(row["host_invoked"]) and row["started_at"]
                    else None
                ),
                finished_at=(
                    datetime.fromisoformat(str(row["finished_at"])) if row["finished_at"] else None
                ),
                checkpoint_grant_digests=tuple(
                    str(value) for value in json.loads(row["checkpoint_grant_digests_json"])
                ),
                outcome_digest=(str(row["outcome_digest"]) if row["outcome_digest"] else None),
                usage_event_id=(str(row["usage_event_id"]) if row["usage_event_id"] else None),
                actual_cost_usd=(
                    Decimal(str(row["actual_cost_usd"]))
                    if row["actual_cost_usd"] is not None
                    else None
                ),
                turns=int(row["turns"]) if row["turns"] is not None else None,
                tool_calls=int(row["tool_calls"]) if row["tool_calls"] is not None else None,
                tool_call_audits=self._load_tool_audits(
                    manifest.manifest_id,
                    str(row["assignment_id"]),
                ),
                output_digest=(str(row["output_digest"]) if row["output_digest"] else None),
                failure_code=(str(row["failure_code"]) if row["failure_code"] else None),
            )
            for row in rows
        )

    def _make_receipt(
        self,
        manifest: OrchestrationManifest,
        *,
        status: ExecutionStatus,
        now: datetime,
        reason_codes: tuple[str, ...],
        release_checkpoint_valid_until: datetime | None = None,
    ) -> ExecutionReceipt:
        with self._connect() as connection:
            run = connection.execute(
                "SELECT started_at FROM orchestration_runs WHERE manifest_id = ?",
                (manifest.manifest_id,),
            ).fetchone()
        if run is None:
            raise ManifestIdempotencyError("manifest state is missing")
        assignments = self._receipt_rows(manifest)
        unknown_cost_assignment_ids = tuple(
            sorted(
                item.assignment_id
                for item in assignments
                if item.host_invoked and item.actual_cost_usd is None
            )
        )
        total_actual_cost_usd = (
            None
            if unknown_cost_assignment_ids
            else sum(
                (cast(Decimal, item.actual_cost_usd) for item in assignments if item.host_invoked),
                Decimal("0"),
            )
        )
        return ExecutionReceipt.create(
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.digest,
            run_id=manifest.run_id,
            change_id=manifest.change_id,
            change_digest=manifest.change_digest,
            policy_digest=manifest.policy_digest,
            status=status,
            final=status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED},
            started_at=datetime.fromisoformat(str(run["started_at"])),
            evaluated_at=now,
            release_checkpoint_valid_until=release_checkpoint_valid_until,
            assignments=assignments,
            review_history=self._review_history(manifest),
            total_actual_cost_usd=total_actual_cost_usd,
            cost_complete=not unknown_cost_assignment_ids,
            unknown_cost_assignment_ids=unknown_cost_assignment_ids,
            reason_codes=tuple(sorted(set(reason_codes))),
        )

    def _persist_final_receipt(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        encoded = receipt.canonical_bytes().decode("utf-8")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT final_receipt_json, final_receipt_digest, cancel_requested
                FROM orchestration_runs WHERE manifest_id = ?
                """,
                (receipt.manifest_id,),
            ).fetchone()
            if row is None:
                raise ManifestIdempotencyError("manifest state is missing")
            if receipt.status is ExecutionStatus.SUCCEEDED and bool(row["cancel_requested"]):
                raise _CancellationWonFinalizationError
            if row["final_receipt_json"] is not None:
                if (
                    row["final_receipt_json"] != encoded
                    or row["final_receipt_digest"] != receipt.receipt_digest
                ):
                    raise ManifestIdempotencyError("final receipt changed after issuance")
                return receipt
            connection.execute(
                """
                UPDATE orchestration_runs
                SET status = ?, reason_code = ?, updated_at = ?,
                    final_receipt_json = ?, final_receipt_digest = ?
                WHERE manifest_id = ?
                """,
                (
                    receipt.status.value,
                    ",".join(receipt.reason_codes) if receipt.reason_codes else None,
                    _time_text(receipt.evaluated_at),
                    encoded,
                    receipt.receipt_digest,
                    receipt.manifest_id,
                ),
            )
        return receipt

    def _persist_release_success(
        self,
        manifest: OrchestrationManifest,
        *,
        release_grant: CheckpointGrant,
        final_review: WorkAssignment,
        now: datetime,
    ) -> ExecutionReceipt:
        """Atomically bind the winning release grant and persist success.

        Cancellation and release success contend on the same SQLite write lock.  A
        cancellation that commits first leaves no orphaned release digest; a success
        that commits first makes later cancellation a no-op because the final receipt
        already exists.  Replacing any pre-final review digest also repairs state left
        by older runtimes that appended a grant before checking cancellation.
        """

        release_grant_digest = _validate_digest(
            release_grant.grant_digest,
            field_name="release_grant_digest",
        )
        release_checkpoint_valid_until = min(
            release_grant.expires_at,
            release_grant.issued_at + timedelta(seconds=self._max_checkpoint_grant_age_seconds),
        )
        if now >= release_checkpoint_valid_until:
            raise CheckpointGrantError(
                "release checkpoint grant expired before success finalization"
            )
        provisional = self._make_receipt(
            manifest,
            status=ExecutionStatus.SUCCEEDED,
            now=now,
            reason_codes=(),
            release_checkpoint_valid_until=release_checkpoint_valid_until,
        )
        review_id = final_review.assignment_id
        if review_id not in {
            manifest.review_assignment.assignment_id,
            *(item.review_assignment.assignment_id for item in manifest.conditional_review_rounds),
        }:
            raise ManifestIdempotencyError("final review is not predeclared by the manifest")
        if release_grant.assignment_id != review_id:
            raise CheckpointGrantError("release grant does not bind the final clean review")
        assignments = tuple(
            AssignmentExecutionReceipt.model_validate(
                {
                    **assignment.model_dump(mode="python"),
                    "checkpoint_grant_digests": (release_grant_digest,),
                }
            )
            if assignment.assignment_id == review_id
            else assignment
            for assignment in provisional.assignments
        )
        receipt = ExecutionReceipt.create(
            manifest_id=provisional.manifest_id,
            manifest_digest=provisional.manifest_digest,
            run_id=provisional.run_id,
            change_id=provisional.change_id,
            change_digest=provisional.change_digest,
            policy_digest=provisional.policy_digest,
            status=provisional.status,
            final=provisional.final,
            started_at=provisional.started_at,
            evaluated_at=provisional.evaluated_at,
            release_checkpoint_valid_until=provisional.release_checkpoint_valid_until,
            assignments=assignments,
            review_history=provisional.review_history,
            total_actual_cost_usd=provisional.total_actual_cost_usd,
            cost_complete=provisional.cost_complete,
            unknown_cost_assignment_ids=provisional.unknown_cost_assignment_ids,
            reason_codes=provisional.reason_codes,
        )
        encoded = receipt.canonical_bytes().decode("utf-8")
        checkpoint_json = json.dumps([release_grant_digest], separators=(",", ":"))
        with self._transaction() as connection:
            run = connection.execute(
                """
                SELECT final_receipt_json, final_receipt_digest, cancel_requested
                FROM orchestration_runs WHERE manifest_id = ?
                """,
                (manifest.manifest_id,),
            ).fetchone()
            assignment = connection.execute(
                """
                SELECT state, checkpoint_grant_digests_json
                FROM orchestration_assignments
                WHERE manifest_id = ? AND assignment_id = ?
                """,
                (manifest.manifest_id, review_id),
            ).fetchone()
            if run is None or assignment is None:
                raise ManifestIdempotencyError("manifest or review assignment state is missing")
            if run["final_receipt_json"] is not None:
                if (
                    run["final_receipt_json"] != encoded
                    or run["final_receipt_digest"] != receipt.receipt_digest
                    or assignment["checkpoint_grant_digests_json"] != checkpoint_json
                ):
                    raise ManifestIdempotencyError("final release receipt changed after issuance")
                return receipt
            if bool(run["cancel_requested"]):
                raise _CancellationWonFinalizationError
            if self._now() >= release_checkpoint_valid_until:
                raise CheckpointGrantError(
                    "release checkpoint grant expired before success finalization"
                )
            if assignment["state"] != AssignmentExecutionState.SUCCEEDED.value:
                raise ManifestIdempotencyError("release review is not durably successful")
            checkpoint_cursor = connection.execute(
                """
                UPDATE orchestration_assignments
                SET checkpoint_grant_digests_json = ?
                WHERE manifest_id = ? AND assignment_id = ? AND state = ?
                """,
                (
                    checkpoint_json,
                    manifest.manifest_id,
                    review_id,
                    AssignmentExecutionState.SUCCEEDED.value,
                ),
            )
            receipt_cursor = connection.execute(
                """
                UPDATE orchestration_runs
                SET status = ?, reason_code = NULL, updated_at = ?,
                    final_receipt_json = ?, final_receipt_digest = ?
                WHERE manifest_id = ? AND final_receipt_json IS NULL
                    AND cancel_requested = 0
                """,
                (
                    ExecutionStatus.SUCCEEDED.value,
                    _time_text(receipt.evaluated_at),
                    encoded,
                    receipt.receipt_digest,
                    manifest.manifest_id,
                ),
            )
            if checkpoint_cursor.rowcount != 1 or receipt_cursor.rowcount != 1:
                raise ManifestIdempotencyError(
                    "release grant and success receipt could not be committed exactly once"
                )
        return receipt

    def _load_final_receipt(
        self,
        manifest_id: str,
        *,
        now: datetime,
    ) -> ExecutionReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT final_receipt_json, final_receipt_digest
                FROM orchestration_runs WHERE manifest_id = ?
                """,
                (manifest_id,),
            ).fetchone()
        if row is None or row["final_receipt_json"] is None:
            return None
        try:
            receipt = ExecutionReceipt.model_validate_json(str(row["final_receipt_json"]))
        except Exception as exc:
            raise ManifestIdempotencyError("stored final receipt failed validation") from exc
        if receipt.receipt_digest != row["final_receipt_digest"]:
            raise ManifestIdempotencyError("stored final receipt digest does not match state")
        if receipt.status is ExecutionStatus.SUCCEEDED and (
            receipt.release_checkpoint_valid_until is None
            or now >= receipt.release_checkpoint_valid_until
        ):
            raise CheckpointGrantError(
                "stored success release checkpoint authorization is no longer valid"
            )
        return receipt

    def _cancelled(
        self,
        manifest: OrchestrationManifest,
        *,
        external_cancellation: CancellationProbe | None,
    ) -> bool:
        if self._cancel_requested(manifest.manifest_id):
            return True
        if external_cancellation is None:
            return False
        try:
            requested = bool(external_cancellation())
        except Exception:
            requested = True
        if requested:
            self.request_cancellation(
                manifest.manifest_id,
                trusted_manifest_digest=manifest.digest,
                trusted_change_digest=manifest.change_digest,
                trusted_policy_digest=manifest.policy_digest,
            )
            self._set_run_state(
                manifest.manifest_id,
                status=ExecutionStatus.CANCELLED.value,
                now=self._now(),
                reason_code="execution.cancelled",
            )
        return requested

    def execute(
        self,
        manifest: OrchestrationManifest,
        *,
        trusted_manifest_digest: str,
        trusted_change_digest: str,
        trusted_policy_digest: str,
        checkpoint_grants: Iterable[CheckpointGrant] = (),
        cancellation: CancellationProbe | None = None,
        resume_cancelled: bool = False,
    ) -> ExecutionReceipt:
        """Execute all genuinely pending work and return a canonical state receipt.

        Terminal receipts are immutable and replayed byte-for-byte.  Cancelled or
        checkpoint-waiting receipts are non-final; a later call can resume pending work,
        while completed assignments are never invoked again.
        """

        execution_time = self._now()
        manifest = self._strict_manifest(manifest)
        if execution_time < manifest.planned_at:
            raise TrustedBindingError("execution time precedes manifest.planned_at")
        self._assert_trusted_bindings(
            manifest,
            trusted_manifest_digest=trusted_manifest_digest,
            trusted_change_digest=trusted_change_digest,
            trusted_policy_digest=trusted_policy_digest,
        )
        grant_values = tuple(checkpoint_grants)
        with self._thread_lock:
            self._register(manifest, now=execution_time)
            final = self._load_final_receipt(
                manifest.manifest_id,
                now=execution_time,
            )
            if final is not None:
                expected_assignments = tuple(
                    (assignment.assignment_id, assignment.role, assignment.prompt)
                    for assignment in self._assignments(manifest)
                )
                received_assignments = tuple(
                    (assignment.assignment_id, assignment.role, assignment.prompt)
                    for assignment in final.assignments
                )
                if (
                    final.manifest_id != manifest.manifest_id
                    or final.manifest_digest != manifest.digest
                    or final.run_id != manifest.run_id
                    or final.change_id != manifest.change_id
                    or final.change_digest != manifest.change_digest
                    or final.policy_digest != manifest.policy_digest
                    or received_assignments != expected_assignments
                ):
                    raise ManifestIdempotencyError(
                        "stored final receipt is not bound to the registered manifest"
                    )
                return final
            self._validate_grants(
                manifest,
                grant_values,
                now=self._now(),
                temporal_checkpoint_ids=frozenset(),
            )
            lease = self._acquire_lease(manifest.manifest_id)
            with self._lease_state_lock:
                self._active_lease = lease
            heartbeat_stop, heartbeat_thread, heartbeat_failures = self._start_lease_heartbeat(
                lease
            )
            try:
                # A host outcome is first committed to the runtime outbox and
                # then reconciled into the separate usage ledger.  Recover
                # those intents before classifying any other RUNNING row as an
                # indeterminate interruption.
                self._recover_pending_outcome_intents(manifest)
                with self._transaction() as connection:
                    running = connection.execute(
                        """
                        SELECT assignment_id FROM orchestration_assignments
                        WHERE manifest_id = ? AND state = ?
                        """,
                        (manifest.manifest_id, AssignmentExecutionState.RUNNING.value),
                    ).fetchall()
                    if running:
                        connection.execute(
                            """
                            UPDATE orchestration_assignments
                            SET state = ?, failure_code = ?, finished_at = ?
                            WHERE manifest_id = ? AND state = ?
                            """,
                            (
                                AssignmentExecutionState.FAILED.value,
                                "runtime.interrupted_indeterminate",
                                _time_text(self._now()),
                                manifest.manifest_id,
                                AssignmentExecutionState.RUNNING.value,
                            ),
                        )

                if resume_cancelled:
                    self._set_run_state(
                        manifest.manifest_id,
                        status="running",
                        now=self._now(),
                        clear_cancellation=True,
                    )
                elif self._cancel_requested(manifest.manifest_id):
                    return self._make_receipt(
                        manifest,
                        status=ExecutionStatus.CANCELLED,
                        now=self._now(),
                        reason_codes=("execution.cancelled",),
                    )
                else:
                    self._set_run_state(
                        manifest.manifest_id,
                        status="running",
                        now=self._now(),
                    )

                if self._has_assignment_failure(manifest.manifest_id):
                    decision_time = self._now()
                    self._block_pending(manifest.manifest_id, now=decision_time)
                    receipt = self._make_receipt(
                        manifest,
                        status=ExecutionStatus.FAILED,
                        now=decision_time,
                        reason_codes=("assignment.failed",),
                    )
                    return self._persist_final_receipt(receipt)

                budget_meter = self._execution_budget_meter(manifest)
                for wave in manifest.execution_waves:
                    if self._cancelled(
                        manifest,
                        external_cancellation=cancellation,
                    ):
                        return self._make_receipt(
                            manifest,
                            status=ExecutionStatus.CANCELLED,
                            now=self._now(),
                            reason_codes=("execution.cancelled",),
                        )
                    grants_by_assignment: dict[str, tuple[str, ...]] = {}
                    grant_records_by_assignment: dict[str, tuple[CheckpointGrant, ...]] = {}
                    waiting = False
                    denied: list[str] = []
                    pending_assignments = tuple(
                        assignment
                        for assignment in wave.assignments
                        if self._assignment_state(
                            manifest.manifest_id,
                            assignment.assignment_id,
                        )
                        == AssignmentExecutionState.PENDING.value
                    )
                    checkpoint_ids = frozenset(
                        checkpoint_id
                        for assignment in pending_assignments
                        for checkpoint_id in assignment.checkpoint_ids
                    )
                    grants = self._validate_grants(
                        manifest,
                        grant_values,
                        now=self._now(),
                        temporal_checkpoint_ids=checkpoint_ids,
                    )
                    for assignment in wave.assignments:
                        if (
                            self._assignment_state(
                                manifest.manifest_id,
                                assignment.assignment_id,
                            )
                            != AssignmentExecutionState.PENDING.value
                        ):
                            continue
                        authorization, digests = self._checkpoint_authorization(
                            assignment.checkpoint_ids,
                            grants,
                        )
                        if authorization == "missing":
                            waiting = True
                        elif authorization == "denied":
                            denied.append(assignment.assignment_id)
                        grants_by_assignment[assignment.assignment_id] = digests
                        grant_records_by_assignment[assignment.assignment_id] = tuple(
                            grants[checkpoint_id]
                            for checkpoint_id in assignment.checkpoint_ids
                            if checkpoint_id in grants
                        )
                    if denied:
                        decision_time = self._now()
                        for assignment_id in denied:
                            self._mark_failed_without_host(
                                manifest.manifest_id,
                                assignment_id,
                                failure_code="checkpoint.denied",
                                checkpoint_grant_digests=grants_by_assignment[assignment_id],
                                now=decision_time,
                            )
                        self._block_pending(manifest.manifest_id, now=decision_time)
                        receipt = self._make_receipt(
                            manifest,
                            status=ExecutionStatus.FAILED,
                            now=decision_time,
                            reason_codes=("checkpoint.denied",),
                        )
                        return self._persist_final_receipt(receipt)
                    if waiting:
                        decision_time = self._now()
                        self._set_run_state(
                            manifest.manifest_id,
                            status=ExecutionStatus.AWAITING_CHECKPOINT.value,
                            now=decision_time,
                            reason_code="checkpoint.required",
                        )
                        return self._make_receipt(
                            manifest,
                            status=ExecutionStatus.AWAITING_CHECKPOINT,
                            now=decision_time,
                            reason_codes=("checkpoint.required",),
                        )
                    self._execute_batch(
                        manifest,
                        wave.assignments,
                        grants_by_assignment=grants_by_assignment,
                        grant_records_by_assignment=grant_records_by_assignment,
                        external_cancellation=cancellation,
                        budget_meter=budget_meter,
                    )
                    if self._has_assignment_failure(manifest.manifest_id):
                        decision_time = self._now()
                        self._block_pending(manifest.manifest_id, now=decision_time)
                        receipt = self._make_receipt(
                            manifest,
                            status=ExecutionStatus.FAILED,
                            now=decision_time,
                            reason_codes=("assignment.failed",),
                        )
                        return self._persist_final_receipt(receipt)

                review_assignments = (
                    manifest.review_assignment,
                    *(item.review_assignment for item in manifest.conditional_review_rounds),
                )
                final_review: WorkAssignment | None = None
                for review_index, review in enumerate(review_assignments):
                    review_round_number = review_index + 1
                    if (
                        self._assignment_state(manifest.manifest_id, review.assignment_id)
                        == AssignmentExecutionState.PENDING.value
                    ):
                        if self._cancelled(
                            manifest,
                            external_cancellation=cancellation,
                        ):
                            return self._make_receipt(
                                manifest,
                                status=ExecutionStatus.CANCELLED,
                                now=self._now(),
                                reason_codes=("execution.cancelled",),
                            )
                        self._execute_batch(
                            manifest,
                            (review,),
                            grants_by_assignment={review.assignment_id: ()},
                            grant_records_by_assignment={review.assignment_id: ()},
                            external_cancellation=cancellation,
                            budget_meter=budget_meter,
                        )
                    if self._has_assignment_failure(manifest.manifest_id):
                        decision_time = self._now()
                        self._block_pending(manifest.manifest_id, now=decision_time)
                        receipt = self._make_receipt(
                            manifest,
                            status=ExecutionStatus.FAILED,
                            now=decision_time,
                            reason_codes=("review.failed",),
                        )
                        return self._persist_final_receipt(receipt)
                    if self._cancelled(
                        manifest,
                        external_cancellation=cancellation,
                    ):
                        return self._make_receipt(
                            manifest,
                            status=ExecutionStatus.CANCELLED,
                            now=self._now(),
                            reason_codes=("execution.cancelled",),
                        )
                    raw_review = self._completed_outcome(manifest, review)
                    semantics = raw_review.review_semantic_outcome
                    if semantics is None:
                        raise ManifestIdempotencyError(
                            "successful review has no durable semantic outcome"
                        )
                    if semantics.verdict is ReviewVerdict.CLEAN:
                        self._skip_future_conditional_assignments(
                            manifest,
                            clean_round_number=review_round_number,
                            now=self._now(),
                        )
                        final_review = review
                        break
                    if review_round_number >= manifest.limits.max_review_rounds:
                        receipt = self._make_receipt(
                            manifest,
                            status=ExecutionStatus.FAILED,
                            now=self._now(),
                            reason_codes=("review.round_limit_exhausted",),
                        )
                        return self._persist_final_receipt(receipt)

                    conditional = manifest.conditional_review_rounds[review_index]
                    remediation = conditional.remediation_assignment
                    remediation_binding = RemediationScopeBinding.create(
                        prior_review_assignment_id=review.assignment_id,
                        prior_review_outcome_digest=raw_review.digest,
                        finding_set=semantics.finding_set,
                    )
                    if not set(remediation_binding.task_ids) <= set(
                        remediation.contract_task_ids
                    ) or any(
                        not any(
                            path_is_within_scope(path, scope)
                            for scope in remediation.remediation_path_scopes
                        )
                        for path in remediation_binding.paths
                    ):
                        decision_time = self._now()
                        self._mark_failed_without_host(
                            manifest.manifest_id,
                            remediation.assignment_id,
                            failure_code="review.finding_scope_invalid",
                            now=decision_time,
                        )
                        self._block_pending(manifest.manifest_id, now=decision_time)
                        receipt = self._make_receipt(
                            manifest,
                            status=ExecutionStatus.FAILED,
                            now=decision_time,
                            reason_codes=("review.finding_scope_invalid",),
                        )
                        return self._persist_final_receipt(receipt)

                    remediation_state = self._assignment_state(
                        manifest.manifest_id,
                        remediation.assignment_id,
                    )
                    if remediation_state == AssignmentExecutionState.PENDING.value:
                        grants = self._validate_grants(
                            manifest,
                            grant_values,
                            now=self._now(),
                            temporal_checkpoint_ids=frozenset(remediation.checkpoint_ids),
                        )
                        authorization, remediation_grant_digests = self._checkpoint_authorization(
                            remediation.checkpoint_ids,
                            grants,
                        )
                        if authorization == "missing":
                            decision_time = self._now()
                            self._set_run_state(
                                manifest.manifest_id,
                                status=ExecutionStatus.AWAITING_CHECKPOINT.value,
                                now=decision_time,
                                reason_code="remediation.checkpoint_required",
                            )
                            return self._make_receipt(
                                manifest,
                                status=ExecutionStatus.AWAITING_CHECKPOINT,
                                now=decision_time,
                                reason_codes=("remediation.checkpoint_required",),
                            )
                        if authorization == "denied":
                            decision_time = self._now()
                            self._mark_failed_without_host(
                                manifest.manifest_id,
                                remediation.assignment_id,
                                failure_code="checkpoint.denied",
                                checkpoint_grant_digests=remediation_grant_digests,
                                now=decision_time,
                            )
                            self._block_pending(manifest.manifest_id, now=decision_time)
                            receipt = self._make_receipt(
                                manifest,
                                status=ExecutionStatus.FAILED,
                                now=decision_time,
                                reason_codes=("checkpoint.denied",),
                            )
                            return self._persist_final_receipt(receipt)
                        remediation_grants = tuple(
                            grants[checkpoint_id] for checkpoint_id in remediation.checkpoint_ids
                        )
                        self._execute_batch(
                            manifest,
                            (remediation,),
                            grants_by_assignment={
                                remediation.assignment_id: remediation_grant_digests
                            },
                            grant_records_by_assignment={
                                remediation.assignment_id: remediation_grants
                            },
                            external_cancellation=cancellation,
                            budget_meter=budget_meter,
                            remediation_bindings_by_assignment={
                                remediation.assignment_id: remediation_binding
                            },
                        )
                    if self._has_assignment_failure(manifest.manifest_id):
                        decision_time = self._now()
                        self._block_pending(manifest.manifest_id, now=decision_time)
                        receipt = self._make_receipt(
                            manifest,
                            status=ExecutionStatus.FAILED,
                            now=decision_time,
                            reason_codes=("remediation.failed",),
                        )
                        return self._persist_final_receipt(receipt)
                    completed_remediation = self._completed_outcome(manifest, remediation)
                    if completed_remediation.remediation_binding != remediation_binding:
                        raise ManifestIdempotencyError(
                            "durable remediation binding changed before re-review"
                        )
                    if self._cancelled(
                        manifest,
                        external_cancellation=cancellation,
                    ):
                        return self._make_receipt(
                            manifest,
                            status=ExecutionStatus.CANCELLED,
                            now=self._now(),
                            reason_codes=("execution.cancelled",),
                        )

                if final_review is None:
                    raise ManifestIdempotencyError(
                        "review loop ended without a clean or exhausted terminal verdict"
                    )

                release_checkpoint = next(
                    checkpoint
                    for checkpoint in manifest.human_checkpoints
                    if checkpoint.phase is CheckpointPhase.BEFORE_RELEASE
                )
                for completed_assignment in self._assignments(manifest):
                    self._assert_assignment_model_binding(completed_assignment)
                    self._assert_assignment_prompt_binding(completed_assignment)
                grants = self._validate_grants(
                    manifest,
                    grant_values,
                    now=self._now(),
                    temporal_checkpoint_ids=frozenset((release_checkpoint.checkpoint_id,)),
                )
                authorization, release_digests = self._checkpoint_authorization(
                    (release_checkpoint.checkpoint_id,),
                    grants,
                )
                if authorization == "missing":
                    decision_time = self._now()
                    self._set_run_state(
                        manifest.manifest_id,
                        status=ExecutionStatus.AWAITING_CHECKPOINT.value,
                        now=decision_time,
                        reason_code="release.checkpoint_required",
                    )
                    return self._make_receipt(
                        manifest,
                        status=ExecutionStatus.AWAITING_CHECKPOINT,
                        now=decision_time,
                        reason_codes=("release.checkpoint_required",),
                    )
                if authorization == "denied":
                    self._append_checkpoint_digest(
                        manifest.manifest_id,
                        final_review.assignment_id,
                        release_digests[0],
                    )
                    receipt = self._make_receipt(
                        manifest,
                        status=ExecutionStatus.FAILED,
                        now=self._now(),
                        reason_codes=("release.checkpoint_denied",),
                    )
                    return self._persist_final_receipt(receipt)
                if self._cancelled(
                    manifest,
                    external_cancellation=cancellation,
                ):
                    return self._make_receipt(
                        manifest,
                        status=ExecutionStatus.CANCELLED,
                        now=self._now(),
                        reason_codes=("execution.cancelled",),
                    )
                try:
                    return self._persist_release_success(
                        manifest,
                        release_grant=grants[release_checkpoint.checkpoint_id],
                        final_review=final_review,
                        now=self._now(),
                    )
                except _CancellationWonFinalizationError:
                    return self._make_receipt(
                        manifest,
                        status=ExecutionStatus.CANCELLED,
                        now=self._now(),
                        reason_codes=("execution.cancelled",),
                    )
            finally:
                body_failed = sys.exc_info()[0] is not None
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=max(1.0, self._lease_seconds / 2))
                try:
                    self._release_lease(lease)
                finally:
                    with self._lease_state_lock:
                        if self._active_lease == lease:
                            self._active_lease = None
                if heartbeat_failures and not body_failed:
                    raise ExecutionInProgressError(
                        "execution lease heartbeat failed"
                    ) from heartbeat_failures[0]
