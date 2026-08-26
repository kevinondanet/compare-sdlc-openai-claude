# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical semantic facts for bounded review and remediation loops.

The models in this module contain no execution logic.  They are the strict wire
contracts shared by the planner, governed host boundary, durable receipt, and
release gates.  In particular, remediation authority is derived from the exact
blocking finding set emitted by the preceding whole-change review; it is never a
free-form caller assertion.
"""

from __future__ import annotations

import hmac
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_sre.sdlc.canonical import canonical_json_bytes, digest_without
from agent_sre.signing import ArtifactSigner

FINDING_SET_SCHEMA_VERSION: Literal["agt.review-finding-set/v1"] = "agt.review-finding-set/v1"
REVIEW_SEMANTIC_SCHEMA_VERSION: Literal["agt.review-semantic-outcome/v1"] = (
    "agt.review-semantic-outcome/v1"
)
REMEDIATION_BINDING_SCHEMA_VERSION: Literal["agt.remediation-scope-binding/v1"] = (
    "agt.remediation-scope-binding/v1"
)
REMEDIATION_HISTORY_SCHEMA_VERSION: Literal["agt.remediation-execution-history/v1"] = (
    "agt.remediation-execution-history/v1"
)
REVIEW_ROUND_HISTORY_SCHEMA_VERSION: Literal["agt.review-round-history/v1"] = (
    "agt.review-round-history/v1"
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ED25519_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")


class ReviewLoopModel(BaseModel):
    """Strict immutable base for review-loop trust-boundary records."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        str_strip_whitespace=False,
    )


def canonical_relative_path(value: str, *, allow_root: bool = False) -> str:
    """Validate and return one canonical POSIX path confined to a workspace."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("path must be a non-empty canonical string")
    if "\\" in value or "\x00" in value:
        raise ValueError("path must use canonical POSIX separators")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("path must be relative and must not traverse parents")
    normalized = candidate.as_posix()
    if normalized != value or (normalized == "." and not allow_root):
        raise ValueError("path is not in canonical relative form")
    return normalized


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def path_is_within_scope(path: str, scope: str) -> bool:
    """Return whether canonical *path* is inside canonical *scope*."""

    path = canonical_relative_path(path, allow_root=True)
    scope = canonical_relative_path(scope, allow_root=True)
    if scope == ".":
        return True
    path_parts = PurePosixPath(path).parts
    scope_parts = PurePosixPath(scope).parts
    return path_parts[: len(scope_parts)] == scope_parts


class ReviewVerdict(StrEnum):
    """Machine-actionable whole-change review verdict."""

    BLOCKING = "blocking"
    CLEAN = "clean"


class ReviewAttesterTrust(ReviewLoopModel):
    """One policy-pinned semantic reviewer identity and Ed25519 trust anchor."""

    attester_id: str = Field(min_length=1, max_length=256)
    public_key: str

    @field_validator("attester_id")
    @classmethod
    def _attester_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("attester_id contains unsupported characters")
        return value

    @field_validator("public_key")
    @classmethod
    def _public_key(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("public_key must be a canonical Ed25519 public key")
        return value


class ReviewFinding(ReviewLoopModel):
    """One grounded blocking finding with exact task and path scope."""

    finding_id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=256)
    path: str = Field(min_length=1, max_length=4096)
    rule_id: str = Field(min_length=1, max_length=256)
    description_digest: str

    @field_validator("finding_id", "task_id", "rule_id")
    @classmethod
    def _safe_ids(cls, value: str, info: Any) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return canonical_relative_path(value)

    @field_validator("description_digest")
    @classmethod
    def _description_digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("description_digest must be a lowercase SHA-256 digest")
        return value


class ReviewFindingSet(ReviewLoopModel):
    """Canonical complete set of blocking findings from one review round."""

    schema_version: Literal["agt.review-finding-set/v1"] = FINDING_SET_SCHEMA_VERSION
    findings: tuple[ReviewFinding, ...] = ()
    finding_set_digest: str

    @field_validator("finding_set_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("finding_set_digest must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        keys = tuple(item.finding_id for item in self.findings)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("findings must be ordered by unique finding_id")
        semantic_keys = tuple((item.task_id, item.path, item.rule_id) for item in self.findings)
        if len(set(semantic_keys)) != len(semantic_keys):
            raise ValueError("findings must not repeat the same task, path, and rule")
        expected = digest_without(self, "finding_set_digest")
        if self.finding_set_digest != expected:
            raise ValueError(
                "finding_set_digest mismatch: "
                f"expected {expected}, got {self.finding_set_digest}"
            )
        return self

    @classmethod
    def create(cls, findings: tuple[ReviewFinding, ...] = ()) -> ReviewFindingSet:
        """Create a canonically ordered finding set with its integrity digest."""

        ordered = tuple(sorted(findings, key=lambda item: item.finding_id))
        provisional = cls.model_construct(
            schema_version=FINDING_SET_SCHEMA_VERSION,
            findings=ordered,
            finding_set_digest="0" * 64,
        )
        return cls.model_validate(
            {
                **provisional.model_dump(mode="python", exclude={"finding_set_digest"}),
                "finding_set_digest": digest_without(provisional, "finding_set_digest"),
            }
        )


class ReviewSemanticOutcome(ReviewLoopModel):
    """Authenticated semantic interpretation of a whole-change review output."""

    schema_version: Literal["agt.review-semantic-outcome/v1"] = REVIEW_SEMANTIC_SCHEMA_VERSION
    verdict: ReviewVerdict
    whole_change: Literal[True] = True
    finding_set: ReviewFindingSet
    report_digest: str
    manifest_id: str = Field(min_length=1, max_length=256)
    manifest_digest: str
    run_id: str = Field(min_length=1, max_length=256)
    change_digest: str
    policy_digest: str
    review_assignment_id: str = Field(min_length=1, max_length=256)
    context_id: str = Field(min_length=1, max_length=256)
    workspace_key: str = Field(min_length=1, max_length=256)
    reviewer_model_id: str = Field(min_length=1, max_length=1024)
    reviewer_model_family: str = Field(min_length=1, max_length=256)
    review_round_number: int = Field(gt=0, le=32)
    request_digest: str
    issued_at: datetime
    expires_at: datetime
    attester_id: str = Field(min_length=1, max_length=256)
    attester_public_key: str
    attestation_signature: str
    semantic_digest: str

    @field_validator(
        "report_digest",
        "manifest_digest",
        "change_digest",
        "policy_digest",
        "request_digest",
        "attester_public_key",
        "semantic_digest",
    )
    @classmethod
    def _digest(cls, value: str, info: Any) -> str:
        if _SHA256.fullmatch(value) is None:
            label = (
                "a canonical Ed25519 public key"
                if info.field_name == "attester_public_key"
                else "a lowercase SHA-256 digest"
            )
            raise ValueError(f"{info.field_name} must be {label}")
        return value

    @field_validator(
        "manifest_id",
        "run_id",
        "review_assignment_id",
        "context_id",
        "workspace_key",
        "attester_id",
    )
    @classmethod
    def _attester_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("attester_id contains unsupported characters")
        return value

    @field_validator("review_round_number", mode="before")
    @classmethod
    def _round_number(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("review_round_number must be an integer")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _times(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, field_name=info.field_name)

    @field_validator("attestation_signature")
    @classmethod
    def _signature(cls, value: str) -> str:
        if _ED25519_SIGNATURE.fullmatch(value) is None:
            raise ValueError("attestation_signature must be a canonical Ed25519 signature")
        return value

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.verdict is ReviewVerdict.CLEAN and self.finding_set.findings:
            raise ValueError("a clean review cannot contain blocking findings")
        if self.verdict is ReviewVerdict.BLOCKING and not self.finding_set.findings:
            raise ValueError("a blocking review requires at least one finding")
        if self.expires_at <= self.issued_at:
            raise ValueError("review semantic attestation must expire after issuance")
        expected = digest_without(self, "semantic_digest")
        if self.semantic_digest != expected:
            raise ValueError(
                f"semantic_digest mismatch: expected {expected}, got {self.semantic_digest}"
            )
        if not ArtifactSigner.verify_payload(
            self.attestation_payload(),
            bytes.fromhex(self.attestation_signature),
            bytes.fromhex(self.attester_public_key),
        ):
            raise ValueError("review semantic attestation signature is invalid")
        return self

    @staticmethod
    def _attestation_payload(
        *,
        verdict: ReviewVerdict,
        finding_set: ReviewFindingSet,
        report_digest: str,
        manifest_id: str,
        manifest_digest: str,
        run_id: str,
        change_digest: str,
        policy_digest: str,
        review_assignment_id: str,
        context_id: str,
        workspace_key: str,
        reviewer_model_id: str,
        reviewer_model_family: str,
        review_round_number: int,
        request_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        attester_id: str,
        attester_public_key: str,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": REVIEW_SEMANTIC_SCHEMA_VERSION,
                "verdict": verdict.value,
                "whole_change": True,
                "finding_set": finding_set.model_dump(mode="json"),
                "report_digest": report_digest,
                "manifest_id": manifest_id,
                "manifest_digest": manifest_digest,
                "run_id": run_id,
                "change_digest": change_digest,
                "policy_digest": policy_digest,
                "review_assignment_id": review_assignment_id,
                "context_id": context_id,
                "workspace_key": workspace_key,
                "reviewer_model_id": reviewer_model_id,
                "reviewer_model_family": reviewer_model_family,
                "review_round_number": review_round_number,
                "request_digest": request_digest,
                "issued_at": _utc(issued_at, field_name="issued_at").isoformat(),
                "expires_at": _utc(expires_at, field_name="expires_at").isoformat(),
                "attester_id": attester_id,
                "attester_public_key": attester_public_key,
            }
        )

    def attestation_payload(self) -> bytes:
        """Return the exact domain-separated semantic facts covered by the signature."""

        return self._attestation_payload(
            verdict=self.verdict,
            finding_set=self.finding_set,
            report_digest=self.report_digest,
            manifest_id=self.manifest_id,
            manifest_digest=self.manifest_digest,
            run_id=self.run_id,
            change_digest=self.change_digest,
            policy_digest=self.policy_digest,
            review_assignment_id=self.review_assignment_id,
            context_id=self.context_id,
            workspace_key=self.workspace_key,
            reviewer_model_id=self.reviewer_model_id,
            reviewer_model_family=self.reviewer_model_family,
            review_round_number=self.review_round_number,
            request_digest=self.request_digest,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            attester_id=self.attester_id,
            attester_public_key=self.attester_public_key,
        )

    def verify_attestation(
        self,
        trusted_attesters: tuple[ReviewAttesterTrust, ...],
    ) -> bool:
        """Verify this signature against the protected identity/key allowlist."""

        trusted = any(
            hmac.compare_digest(item.attester_id, self.attester_id)
            and hmac.compare_digest(item.public_key, self.attester_public_key)
            for item in trusted_attesters
        )
        return trusted and ArtifactSigner.verify_payload(
            self.attestation_payload(),
            bytes.fromhex(self.attestation_signature),
            bytes.fromhex(self.attester_public_key),
        )

    @classmethod
    def create(
        cls,
        *,
        verdict: ReviewVerdict,
        report_digest: str,
        manifest_id: str,
        manifest_digest: str,
        run_id: str,
        change_digest: str,
        policy_digest: str,
        review_assignment_id: str,
        context_id: str,
        workspace_key: str,
        reviewer_model_id: str,
        reviewer_model_family: str,
        review_round_number: int,
        request_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        attester_id: str,
        signer: ArtifactSigner,
        findings: tuple[ReviewFinding, ...] = (),
    ) -> ReviewSemanticOutcome:
        """Create reviewer-authenticated facts from the exact complete finding set."""

        finding_set = ReviewFindingSet.create(findings)
        public_key = signer.public_key_bytes.hex()
        signature = signer.sign_payload(
            cls._attestation_payload(
                verdict=verdict,
                finding_set=finding_set,
                report_digest=report_digest,
                manifest_id=manifest_id,
                manifest_digest=manifest_digest,
                run_id=run_id,
                change_digest=change_digest,
                policy_digest=policy_digest,
                review_assignment_id=review_assignment_id,
                context_id=context_id,
                workspace_key=workspace_key,
                reviewer_model_id=reviewer_model_id,
                reviewer_model_family=reviewer_model_family,
                review_round_number=review_round_number,
                request_digest=request_digest,
                issued_at=issued_at,
                expires_at=expires_at,
                attester_id=attester_id,
                attester_public_key=public_key,
            )
        ).hex()
        provisional = cls.model_construct(
            schema_version=REVIEW_SEMANTIC_SCHEMA_VERSION,
            verdict=verdict,
            whole_change=True,
            finding_set=finding_set,
            report_digest=report_digest,
            manifest_id=manifest_id,
            manifest_digest=manifest_digest,
            run_id=run_id,
            change_digest=change_digest,
            policy_digest=policy_digest,
            review_assignment_id=review_assignment_id,
            context_id=context_id,
            workspace_key=workspace_key,
            reviewer_model_id=reviewer_model_id,
            reviewer_model_family=reviewer_model_family,
            review_round_number=review_round_number,
            request_digest=request_digest,
            issued_at=_utc(issued_at, field_name="issued_at"),
            expires_at=_utc(expires_at, field_name="expires_at"),
            attester_id=attester_id,
            attester_public_key=public_key,
            attestation_signature=signature,
            semantic_digest="0" * 64,
        )
        return cls.model_validate(
            {
                **provisional.model_dump(mode="python", exclude={"semantic_digest"}),
                "semantic_digest": digest_without(provisional, "semantic_digest"),
            }
        )


class RemediationScopeBinding(ReviewLoopModel):
    """Exact prior-review authority carried into one scoped fix invocation."""

    schema_version: Literal["agt.remediation-scope-binding/v1"] = REMEDIATION_BINDING_SCHEMA_VERSION
    prior_review_assignment_id: str = Field(min_length=1, max_length=256)
    prior_review_outcome_digest: str
    finding_set: ReviewFindingSet
    task_ids: tuple[str, ...] = Field(min_length=1)
    paths: tuple[str, ...] = Field(min_length=1)
    binding_digest: str

    @field_validator("prior_review_assignment_id")
    @classmethod
    def _review_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("prior_review_assignment_id contains unsupported characters")
        return value

    @field_validator("prior_review_outcome_digest", "binding_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be a lowercase SHA-256 digest")
        return value

    @field_validator("task_ids")
    @classmethod
    def _tasks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            _SAFE_ID.fullmatch(item) is None for item in value
        ):
            raise ValueError("task_ids must be sorted, unique, and canonical")
        return value

    @field_validator("paths")
    @classmethod
    def _paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("paths must be sorted and unique")
        return tuple(canonical_relative_path(item) for item in value)

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if not self.finding_set.findings:
            raise ValueError("remediation requires a non-empty blocking finding set")
        expected_tasks = tuple(sorted({item.task_id for item in self.finding_set.findings}))
        expected_paths = tuple(sorted({item.path for item in self.finding_set.findings}))
        if self.task_ids != expected_tasks or self.paths != expected_paths:
            raise ValueError("remediation task_ids and paths must exactly match the finding set")
        expected = digest_without(self, "binding_digest")
        if self.binding_digest != expected:
            raise ValueError(
                f"binding_digest mismatch: expected {expected}, got {self.binding_digest}"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        prior_review_assignment_id: str,
        prior_review_outcome_digest: str,
        finding_set: ReviewFindingSet,
    ) -> RemediationScopeBinding:
        """Bind a fix to every and only blocking fact in the prior review."""

        tasks = tuple(sorted({item.task_id for item in finding_set.findings}))
        paths = tuple(sorted({item.path for item in finding_set.findings}))
        provisional = cls.model_construct(
            schema_version=REMEDIATION_BINDING_SCHEMA_VERSION,
            prior_review_assignment_id=prior_review_assignment_id,
            prior_review_outcome_digest=prior_review_outcome_digest,
            finding_set=finding_set,
            task_ids=tasks,
            paths=paths,
            binding_digest="0" * 64,
        )
        return cls.model_validate(
            {
                **provisional.model_dump(mode="python", exclude={"binding_digest"}),
                "binding_digest": digest_without(provisional, "binding_digest"),
            }
        )


class RemediationExecutionHistory(ReviewLoopModel):
    """Digest-bound durable facts for the fix after one blocking review."""

    schema_version: Literal["agt.remediation-execution-history/v1"] = (
        REMEDIATION_HISTORY_SCHEMA_VERSION
    )
    assignment_id: str = Field(min_length=1, max_length=256)
    context_id: str = Field(min_length=1, max_length=256)
    workspace_key: str = Field(min_length=1, max_length=256)
    outcome_digest: str
    output_digest: str
    binding: RemediationScopeBinding
    history_digest: str

    @field_validator("assignment_id", "context_id", "workspace_key")
    @classmethod
    def _safe_ids(cls, value: str, info: Any) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator("outcome_digest", "output_digest", "history_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        expected = digest_without(self, "history_digest")
        if self.history_digest != expected:
            raise ValueError(
                f"history_digest mismatch: expected {expected}, got {self.history_digest}"
            )
        return self

    @classmethod
    def create(cls, **values: Any) -> RemediationExecutionHistory:
        payload = {"schema_version": REMEDIATION_HISTORY_SCHEMA_VERSION, **values}
        provisional = cls.model_construct(**payload, history_digest="0" * 64)
        payload["history_digest"] = digest_without(provisional, "history_digest")
        return cls.model_validate(payload)


class ReviewRoundHistory(ReviewLoopModel):
    """Ordered authenticated review facts and its conditional scoped fix."""

    schema_version: Literal["agt.review-round-history/v1"] = REVIEW_ROUND_HISTORY_SCHEMA_VERSION
    round_number: int = Field(gt=0, le=32)
    review_assignment_id: str = Field(min_length=1, max_length=256)
    context_id: str = Field(min_length=1, max_length=256)
    workspace_key: str = Field(min_length=1, max_length=256)
    reviewer_model_family: str = Field(min_length=1, max_length=256)
    outcome_digest: str
    output_digest: str
    semantic_outcome: ReviewSemanticOutcome
    remediation: RemediationExecutionHistory | None = None
    history_digest: str

    @field_validator("round_number", mode="before")
    @classmethod
    def _round_number(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("round_number must be an integer")
        return value

    @field_validator("review_assignment_id", "context_id", "workspace_key", "reviewer_model_family")
    @classmethod
    def _safe_ids(cls, value: str, info: Any) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator("outcome_digest", "output_digest", "history_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if (
            self.semantic_outcome.review_assignment_id != self.review_assignment_id
            or self.semantic_outcome.context_id != self.context_id
            or self.semantic_outcome.workspace_key != self.workspace_key
            or self.semantic_outcome.reviewer_model_family != self.reviewer_model_family
        ):
            raise ValueError("review history does not match its signed semantic subject")
        if self.semantic_outcome.verdict is ReviewVerdict.CLEAN and self.remediation is not None:
            raise ValueError("a clean review round cannot have remediation")
        if self.remediation is not None:
            if self.semantic_outcome.verdict is not ReviewVerdict.BLOCKING:
                raise ValueError("only a blocking review can authorize remediation")
            binding = self.remediation.binding
            if (
                binding.prior_review_assignment_id != self.review_assignment_id
                or binding.prior_review_outcome_digest != self.outcome_digest
                or binding.finding_set != self.semantic_outcome.finding_set
            ):
                raise ValueError("remediation is not exactly bound to this review round")
        expected = digest_without(self, "history_digest")
        if self.history_digest != expected:
            raise ValueError(
                f"history_digest mismatch: expected {expected}, got {self.history_digest}"
            )
        return self

    @classmethod
    def create(cls, **values: Any) -> ReviewRoundHistory:
        payload = {"schema_version": REVIEW_ROUND_HISTORY_SCHEMA_VERSION, **values}
        provisional = cls.model_construct(**payload, history_digest="0" * 64)
        payload["history_digest"] = digest_without(provisional, "history_digest")
        return cls.model_validate(payload)

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes including every nested integrity digest."""

        return canonical_json_bytes(self.model_dump(mode="json"))


__all__ = [
    "FINDING_SET_SCHEMA_VERSION",
    "REMEDIATION_BINDING_SCHEMA_VERSION",
    "REMEDIATION_HISTORY_SCHEMA_VERSION",
    "REVIEW_ROUND_HISTORY_SCHEMA_VERSION",
    "REVIEW_SEMANTIC_SCHEMA_VERSION",
    "ReviewAttesterTrust",
    "RemediationExecutionHistory",
    "RemediationScopeBinding",
    "ReviewFinding",
    "ReviewFindingSet",
    "ReviewRoundHistory",
    "ReviewSemanticOutcome",
    "ReviewVerdict",
    "canonical_relative_path",
    "path_is_within_scope",
]
