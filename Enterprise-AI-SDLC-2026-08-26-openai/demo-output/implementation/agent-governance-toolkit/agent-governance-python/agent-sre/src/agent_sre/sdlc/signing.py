# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Signing and verification of canonical release-verdict bundles."""

from __future__ import annotations

import hmac
import os
import re
import stat
import tempfile
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from agent_sre.sbom import AgentSBOM
from agent_sre.sdlc.canonical import canonical_json_bytes, load_json_file_strict
from agent_sre.sdlc.evaluator import ReleaseEvaluator, parse_release_verdict
from agent_sre.sdlc.models import ReleasePolicy, VerdictStatus
from agent_sre.signing import ArtifactSigner, SignatureBundle

if TYPE_CHECKING:
    from agent_sre.sdlc.pyrit import PyRITSecurityEvidence

_SIGNATURE_KEYS = {"signature", "public_key", "artifact_hash", "timestamp", "signer_did"}


def sign_release_bundle(
    bundle_path: str | Path,
    *,
    policy: ReleasePolicy,
    evidence: PyRITSecurityEvidence,
    private_key_path: str,
    signer_did: str | None = None,
) -> SignatureBundle:
    """Re-evaluate and Ed25519-sign a passing canonical release verdict.

    The policy and evidence are required trust inputs.  A verdict is signed only
    when it exactly reproduces from those inputs at its recorded evaluation time
    and the same inputs still pass when checked against the current wall clock.
    """

    candidate = Path(bundle_path)
    encoded = candidate.read_bytes()
    verdict = parse_release_verdict(encoded)
    if encoded != canonical_json_bytes(verdict) + b"\n":
        raise ValueError("release verdict file must be canonical JSON with one final newline")

    reproduced = ReleaseEvaluator().evaluate(policy, evidence, evaluated_at=verdict.evaluated_at)
    if reproduced != verdict:
        raise ValueError("release verdict does not reproduce from the trusted policy and evidence")
    if verdict.status is not VerdictStatus.PASS:
        raise ValueError("refusing to sign a failing release verdict")

    signed_at = _now_utc()
    current = ReleaseEvaluator().evaluate(policy, evidence, evaluated_at=signed_at)
    if current.status is not VerdictStatus.PASS:
        raise ValueError("release evidence is not passing at signing time")

    signer = ArtifactSigner(private_key_path=private_key_path)
    artifact_hash = AgentSBOM.hash_file(str(candidate))
    bundle = SignatureBundle(
        signature=b"",
        public_key=signer.public_key_bytes,
        artifact_hash=artifact_hash,
        timestamp=signed_at.isoformat(),
        signer_did=signer_did,
    )
    bundle.signature = signer.sign_payload(_signature_payload(bundle))
    return bundle


def write_signature_bundle(path: str | Path, bundle: SignatureBundle) -> None:
    """Atomically write a deterministic JSON signature envelope."""

    destination = Path(path)
    destination.parent.mkdir(parents=False, exist_ok=True)
    payload = canonical_json_bytes(bundle.to_dict()) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def load_signature_bundle(path: str | Path) -> SignatureBundle:
    """Strictly load an existing signature bundle."""

    payload = load_json_file_strict(path, max_bytes=64 * 1024)
    if not isinstance(payload, dict) or set(payload) != _SIGNATURE_KEYS:
        raise ValueError("signature bundle has an invalid shape")
    for name in ("signature", "public_key", "artifact_hash"):
        if not isinstance(payload[name], str):
            raise ValueError(f"signature bundle field {name!r} must be a string")
    if re.fullmatch(r"[0-9a-f]{128}", payload["signature"]) is None:
        raise ValueError("signature bundle signature must be a canonical Ed25519 signature")
    if re.fullmatch(r"[0-9a-f]{64}", payload["public_key"]) is None:
        raise ValueError("signature bundle public_key must be a canonical Ed25519 key")
    if re.fullmatch(r"[0-9a-f]{64}", payload["artifact_hash"]) is None:
        raise ValueError("signature bundle artifact_hash must be SHA-256")
    if not isinstance(payload["timestamp"], str):
        raise ValueError("signature bundle timestamp must be a string")
    try:
        timestamp = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("signature bundle timestamp must be ISO-8601") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("signature bundle timestamp must be timezone-aware")
    if timestamp.utcoffset() != timedelta(0):
        raise ValueError("signature bundle timestamp must use UTC")
    if payload["signer_did"] is not None and (
        not isinstance(payload["signer_did"], str) or not payload["signer_did"]
    ):
        raise ValueError("signature bundle signer_did must be a non-empty string or null")
    try:
        bundle = SignatureBundle.from_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("signature bundle contains invalid hexadecimal data") from exc
    if len(bundle.signature) != 64 or len(bundle.public_key) != 32:
        raise ValueError("signature bundle has an invalid Ed25519 key or signature length")
    return bundle


def verify_release_bundle(
    bundle_path: str | Path,
    signature: SignatureBundle,
    *,
    trusted_public_key: bytes | None = None,
    expected_policy: ReleasePolicy | None = None,
    expected_evidence: PyRITSecurityEvidence | None = None,
) -> bool:
    """Verify a current passing verdict against explicit policy/evidence anchors."""

    if trusted_public_key is None or expected_policy is None or expected_evidence is None:
        return False
    candidate = Path(bundle_path)
    try:
        encoded = candidate.read_bytes()
        verdict = parse_release_verdict(encoded)
        if encoded != canonical_json_bytes(verdict) + b"\n":
            return False
        if verdict.status is not VerdictStatus.PASS:
            return False
        reproduced = ReleaseEvaluator().evaluate(
            expected_policy,
            expected_evidence,
            evaluated_at=verdict.evaluated_at,
        )
        if reproduced != verdict:
            return False

        now = _now_utc()
        current = ReleaseEvaluator().evaluate(
            expected_policy,
            expected_evidence,
            evaluated_at=now,
        )
        if current.status is not VerdictStatus.PASS:
            return False
        signed_at = datetime.fromisoformat(signature.timestamp.replace("Z", "+00:00"))
        maximum_age = timedelta(seconds=expected_policy.freshness.max_age_seconds)
        future_skew = timedelta(seconds=expected_policy.freshness.max_future_skew_seconds)
        if not now - maximum_age <= signed_at <= now + future_skew:
            return False

        actual_hash = AgentSBOM.hash_file(str(candidate))
        if not hmac.compare_digest(actual_hash, signature.artifact_hash):
            return False
        if not hmac.compare_digest(trusted_public_key, signature.public_key):
            return False
        return ArtifactSigner.verify_payload(
            _signature_payload(signature), signature.signature, signature.public_key
        )
    except (ImportError, OSError, TypeError, ValueError):
        return False


def load_trusted_public_key(value: str | Path) -> bytes:
    """Load a raw public key from canonical hex or an explicit absolute file."""

    raw = str(value)
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return bytes.fromhex(raw)

    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("trusted public key file path must be absolute")
    if candidate.is_symlink():
        raise ValueError("trusted public key file must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ValueError("trusted public key file must be a regular non-symlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("trusted public key file must be a regular file")
        if metadata.st_size > 1024:
            raise ValueError("trusted public key file is too large")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            encoded = handle.read(1025).strip()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if re.fullmatch(r"[0-9a-fA-F]{64}", encoded) is None:
        raise ValueError("trusted public key must be 64 hexadecimal characters")
    return bytes.fromhex(encoded)


def _signature_payload(bundle: SignatureBundle) -> bytes:
    """Return the domain-separated payload authenticated by a release signature."""

    return canonical_json_bytes(
        {
            "schema": "agt.release-verdict-signature/v1",
            "artifact_hash": bundle.artifact_hash,
            "public_key": bundle.public_key.hex(),
            "timestamp": bundle.timestamp,
            "signer_did": bundle.signer_did,
        }
    )


def _now_utc() -> datetime:
    """Return the current wall clock; kept private so callers cannot backdate trust."""

    return datetime.now(UTC)
