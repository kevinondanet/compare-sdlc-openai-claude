"""Final verdict, human approvals and the signed evidence bundle (ARCHITECTURE.md §3, G6).

The *evidence bundle* is a canonical JSON manifest (``evidence-bundle.json`` in the change
package) that records, for one change at one commit and one package fingerprint:

* the sha256 of every evidence file (and the approvals file) it covers,
* the gate results and overall outcome of the verdict it certifies,
* the human approvals (role, approver, timestamp),
* one or more signatures over the manifest digest — HMAC-SHA256 with the key from
  ``$AISDLC_SIGNING_KEY`` and, when ``cryptography`` is importable, Ed25519 with a key
  pair stored on disk.

``final-verdict.json`` mirrors the manifest signatures and carries ``bundle_digest`` so
the two files cross-reference each other. :func:`verify_bundle` is what release
automation calls: it re-hashes every file (tamper detection), verifies signatures against
*trusted* key material only, checks the verdict on disk matches the manifest, and flags
staleness against the current git ``HEAD`` and package fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aisdlc.schema import fingerprint as fp
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import FinalVerdict, GateResult, Signature, utcnow

__all__ = [
    "SIGNING_KEY_ENV",
    "ED25519_PRIVATE_KEY_ENV",
    "ED25519_PUBLIC_KEY_ENV",
    "BUNDLE_FILE",
    "APPROVALS_FILE",
    "BUNDLE_VERSION",
    "SIGNED_PAYLOAD_PREFIX",
    "BundleError",
    "Approval",
    "BundleFile",
    "BundleManifest",
    "BundleVerification",
    "read_approvals",
    "write_approvals",
    "add_approval",
    "write_verdict",
    "read_verdict",
    "sha256_file",
    "git_head",
    "collect_files",
    "build_bundle",
    "hmac_key_from_env",
    "SIGNING_KEY_FILE",
    "local_signing_key_path",
    "read_local_signing_key",
    "discover_hmac_key",
    "ed25519_available",
    "generate_ed25519_keypair",
    "load_ed25519_private_key",
    "load_ed25519_public_key",
    "signing_available",
    "sign_bundle",
    "write_bundle",
    "read_bundle",
    "verify_signature",
    "verify_bundle",
    "publish_bundle",
]

SIGNING_KEY_ENV = "AISDLC_SIGNING_KEY"
"""Environment variable holding the HMAC-SHA256 signing key (raw string)."""

ED25519_PRIVATE_KEY_ENV = "AISDLC_ED25519_PRIVATE_KEY"
"""Environment variable holding the path of a PEM Ed25519 private key."""

ED25519_PUBLIC_KEY_ENV = "AISDLC_ED25519_PUBLIC_KEY"
"""Environment variable holding the path of a PEM Ed25519 public key (verification)."""

BUNDLE_FILE = "evidence-bundle.json"
APPROVALS_FILE = "approvals.json"
BUNDLE_VERSION = 1
SIGNED_PAYLOAD_PREFIX = "aisdlc-evidence-bundle-v1:"
SIGNING_KEY_FILE = Path(".aisdlc") / "signing.key"
"""Repository-local HMAC key written by ``aisdlc init`` (relative to the repo root)."""


class BundleError(RuntimeError):
    """The bundle could not be built, signed, read or written."""


# --------------------------------------------------------------------------------------
# Approvals
# --------------------------------------------------------------------------------------


class Approval(BaseModel):
    """A human approval recorded for release (G6)."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(description="Approver role, e.g. ``owner``, ``security``, ``release``.")
    approver: str = Field(description="Human identity (name/email/handle).")
    approved_at: datetime = Field(default_factory=utcnow)
    note: str = ""


def _approvals_path(directory: str | Path) -> Path:
    return Path(directory) / APPROVALS_FILE


def read_approvals(directory: str | Path) -> list[Approval]:
    """Approvals stored in ``<dir>/approvals.json`` (empty when absent)."""
    path = _approvals_path(directory)
    if not path.is_file():
        return []
    data = pkgio.read_json(path)
    if not isinstance(data, list):
        raise BundleError(f"{path}: expected a JSON list")
    try:
        return [Approval.model_validate(item) for item in data]
    except ValidationError as exc:
        raise BundleError(f"{path}: {exc}") from exc


def write_approvals(directory: str | Path, approvals: Sequence[Approval]) -> Path:
    """Write ``approvals.json`` deterministically."""
    path = _approvals_path(directory)
    pkgio.write_json(path, [a.model_dump(mode="json") for a in approvals])
    return path


def add_approval(directory: str | Path, approval: Approval) -> list[Approval]:
    """Append *approval* (replacing an earlier one by the same role + approver)."""
    existing = [
        a
        for a in read_approvals(directory)
        if not (a.role == approval.role and a.approver == approval.approver)
    ]
    updated = [*existing, approval]
    write_approvals(directory, updated)
    return updated


# --------------------------------------------------------------------------------------
# Verdict file
# --------------------------------------------------------------------------------------


def write_verdict(directory: str | Path, verdict: FinalVerdict) -> Path:
    """Write ``final-verdict.json`` (deterministic JSON)."""
    return pkgio.write_final_verdict(directory, verdict)


def read_verdict(directory: str | Path) -> FinalVerdict | None:
    """Read ``final-verdict.json`` if present."""
    return pkgio.read_final_verdict(directory)


# --------------------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------------------


class BundleFile(BaseModel):
    """One file covered by the bundle."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Path relative to the change package root (POSIX).")
    sha256: str
    size: int = Field(ge=0)


class BundleManifest(BaseModel):
    """Canonical, signable statement about a change's evidence at one commit."""

    model_config = ConfigDict(extra="forbid")

    version: int = BUNDLE_VERSION
    change_id: str
    commit_sha: str = ""
    fingerprint: str = ""
    produced_at: datetime | None = None
    gate_results: list[GateResult] = Field(default_factory=list)
    overall: bool = False
    approvals: list[Approval] = Field(default_factory=list)
    files: list[BundleFile] = Field(default_factory=list)
    signatures: list[Signature] = Field(default_factory=list)

    def canonical(self) -> str:
        """Canonical JSON of everything except the signatures."""
        data = self.model_dump(mode="json", exclude={"signatures"})
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def digest(self) -> str:
        """sha256 hex digest over :meth:`canonical`."""
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def signed_payload(self) -> bytes:
        """The bytes every signature is computed over."""
        return (SIGNED_PAYLOAD_PREFIX + self.digest()).encode("ascii")


class BundleVerification(BaseModel):
    """Outcome of :func:`verify_bundle`."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    digest: str | None = None
    reasons: list[str] = Field(default_factory=list)
    tampered: bool = False
    stale: bool = False
    valid_signatures: int = 0
    invalid_signatures: int = 0
    approvals: int = 0
    overall: bool | None = None


def sha256_file(path: str | Path) -> str:
    """sha256 hex digest of a file's bytes."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head(path: str | Path) -> str | None:
    """Commit sha of ``HEAD`` for the repository containing *path*, or ``None``."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def collect_files(directory: str | Path) -> list[BundleFile]:
    """Evidence files (``evidence/*.json``) plus ``approvals.json`` when present."""
    root = Path(directory)
    candidates: list[Path] = sorted((root / pkgio.EVIDENCE_DIR).glob("*.json"))
    approvals = root / APPROVALS_FILE
    if approvals.is_file():
        candidates.append(approvals)
    return [
        BundleFile(
            path=p.relative_to(root).as_posix(), sha256=sha256_file(p), size=p.stat().st_size
        )
        for p in candidates
        if p.is_file()
    ]


def build_bundle(
    directory: str | Path,
    verdict: FinalVerdict,
    *,
    approvals: Sequence[Approval] | None = None,
    commit_sha: str | None = None,
    fingerprint: str | None = None,
    now: datetime | None = None,
) -> BundleManifest:
    """Build the (unsigned) manifest for the package at *directory* certifying *verdict*.

    ``commit_sha`` defaults to the verdict's commit, then git ``HEAD``; ``fingerprint``
    defaults to the current content fingerprint of the package; ``approvals`` default to
    ``approvals.json``.
    """
    root = Path(directory)
    if not (root / pkgio.INTENT_FILE).is_file():
        raise BundleError(f"not a change package: {root}")
    resolved_commit = commit_sha or verdict.commit_sha or git_head(root) or ""
    resolved_fp = fingerprint if fingerprint is not None else fp.compute_fingerprint(root)
    if verdict.fingerprint and verdict.fingerprint != resolved_fp:
        raise BundleError(
            "verdict is stale: it was evaluated against package fingerprint "
            f"{verdict.fingerprint[:12]}… but the package is now {resolved_fp[:12]}…; "
            "re-evaluate the gates before bundling"
        )
    if verdict.commit_sha and resolved_commit and verdict.commit_sha != resolved_commit:
        raise BundleError(
            f"verdict was evaluated at commit {verdict.commit_sha[:12]} but the bundle "
            f"would certify {resolved_commit[:12]}; re-evaluate the gates before bundling"
        )
    return BundleManifest(
        change_id=verdict.change_id,
        commit_sha=resolved_commit,
        fingerprint=resolved_fp,
        produced_at=now or verdict.produced_at or utcnow(),
        gate_results=list(verdict.gate_results),
        overall=verdict.overall,
        approvals=list(approvals if approvals is not None else read_approvals(root)),
        files=collect_files(root),
    )


# --------------------------------------------------------------------------------------
# Key material
# --------------------------------------------------------------------------------------


def hmac_key_from_env() -> bytes | None:
    """The HMAC key from ``$AISDLC_SIGNING_KEY`` (``None`` when unset/empty)."""
    value = os.environ.get(SIGNING_KEY_ENV, "")
    return value.encode("utf-8") if value else None


def ed25519_available() -> bool:
    """Whether the optional ``cryptography`` package can be imported."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    except ImportError:
        return False
    return True


def _ed25519_module() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without cryptography
        raise BundleError("ed25519 signing requires the 'cryptography' package") from exc
    return serialization, ed25519


def generate_ed25519_keypair(
    private_path: str | Path, public_path: str | Path | None = None
) -> tuple[Path, Path]:
    """Generate an Ed25519 key pair as PEM files; returns ``(private, public)`` paths.

    The public path defaults to ``<private>.pub``. The private file is created with mode
    ``0600``.
    """
    serialization, ed25519 = _ed25519_module()
    priv = Path(private_path)
    pub = Path(public_path) if public_path is not None else priv.with_name(priv.name + ".pub")
    key = ed25519.Ed25519PrivateKey.generate()
    priv.parent.mkdir(parents=True, exist_ok=True)
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        priv.chmod(0o600)
    except OSError:  # pragma: no cover - filesystem without POSIX modes
        pass
    pub.parent.mkdir(parents=True, exist_ok=True)
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv, pub


def load_ed25519_private_key(path: str | Path) -> Any:
    """Load a PEM Ed25519 private key."""
    serialization, ed25519 = _ed25519_module()
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise BundleError(f"cannot load ed25519 private key {path}: {exc}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise BundleError(f"{path} is not an ed25519 private key")
    return key


def load_ed25519_public_key(path: str | Path) -> Any:
    """Load a PEM Ed25519 public key."""
    serialization, ed25519 = _ed25519_module()
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise BundleError(f"cannot load ed25519 public key {path}: {exc}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise BundleError(f"{path} is not an ed25519 public key")
    return key


def _private_key_path(explicit: str | Path | None) -> Path | None:
    if explicit is not None:
        return Path(explicit)
    value = os.environ.get(ED25519_PRIVATE_KEY_ENV, "")
    return Path(value) if value else None


def _public_key_paths(explicit: Iterable[str | Path] | None) -> list[Path]:
    if explicit is not None:
        return [Path(p) for p in explicit]
    value = os.environ.get(ED25519_PUBLIC_KEY_ENV, "")
    return [Path(value)] if value else []


def local_signing_key_path(package_dir: str | Path) -> Path | None:
    """``<repo>/.aisdlc/signing.key`` for a package under ``<repo>/changes/``, else ``None``."""
    root = Path(package_dir).resolve()
    if root.parent.name != pkgio.CHANGES_DIR:
        return None
    return root.parent.parent / SIGNING_KEY_FILE


def read_local_signing_key(path: str | Path | None) -> bytes | None:
    """Bytes of an HMAC key file (hex is decoded, anything else is raw), or ``None``."""
    if path is None:
        return None
    key_path = Path(path)
    if not key_path.is_file():
        return None
    text = key_path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return text.encode("utf-8")


def discover_hmac_key(package_dir: str | Path | None = None) -> bytes | None:
    """HMAC key from ``$AISDLC_SIGNING_KEY``, else the repo-local key file for the package.

    This is the same discovery ``aisdlc gate bundle`` signs with, so gate G6 reports the
    key as available exactly when bundling would succeed.
    """
    env_key = hmac_key_from_env()
    if env_key:
        return env_key
    if package_dir is None:
        return None
    return read_local_signing_key(local_signing_key_path(package_dir))


def signing_available(
    *,
    hmac_key: bytes | None = None,
    ed25519_private_key: str | Path | None = None,
    package_dir: str | Path | None = None,
) -> bool:
    """Whether at least one usable signing key is configured.

    Checks the explicit *hmac_key*, ``$AISDLC_SIGNING_KEY``, the repo-local
    ``.aisdlc/signing.key`` of *package_dir* (when given) and the Ed25519 key.
    """
    if hmac_key or discover_hmac_key(package_dir):
        return True
    path = _private_key_path(ed25519_private_key)
    return path is not None and path.is_file() and ed25519_available()


# --------------------------------------------------------------------------------------
# Signing and verification
# --------------------------------------------------------------------------------------


def sign_bundle(
    manifest: BundleManifest,
    *,
    signer: str,
    hmac_key: bytes | None = None,
    ed25519_private_key: str | Path | None = None,
    now: datetime | None = None,
) -> BundleManifest:
    """Return a copy of *manifest* with fresh signatures.

    Signs with HMAC-SHA256 when a key is given or ``$AISDLC_SIGNING_KEY`` is set, and with
    Ed25519 when a private key path is given or ``$AISDLC_ED25519_PRIVATE_KEY`` points at
    one and ``cryptography`` is importable. Raises :class:`BundleError` when no key
    material is available (never produces an unsigned "signed" bundle).
    """
    payload = manifest.signed_payload()
    signed_at = now or utcnow()
    signatures: list[Signature] = []

    key = hmac_key if hmac_key is not None else hmac_key_from_env()
    if key:
        mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
        signatures.append(
            Signature(signer=signer, algorithm="hmac-sha256", value=mac, signed_at=signed_at)
        )

    key_path = _private_key_path(ed25519_private_key)
    if key_path is not None:
        private_key = load_ed25519_private_key(key_path)
        raw = private_key.sign(payload)
        signatures.append(
            Signature(
                signer=signer,
                algorithm="ed25519",
                value=base64.b64encode(raw).decode("ascii"),
                signed_at=signed_at,
            )
        )

    if not signatures:
        raise BundleError(
            f"no signing key available: set ${SIGNING_KEY_ENV} or provide an ed25519 key"
        )
    return manifest.model_copy(update={"signatures": signatures})


def verify_signature(
    manifest: BundleManifest,
    signature: Signature,
    *,
    hmac_key: bytes | None = None,
    ed25519_public_keys: Iterable[str | Path] | None = None,
) -> bool:
    """Whether *signature* is valid for *manifest* under the trusted key material."""
    payload = manifest.signed_payload()
    if signature.algorithm == "hmac-sha256":
        key = hmac_key if hmac_key is not None else hmac_key_from_env()
        if not key:
            return False
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature.value)
    if signature.algorithm == "ed25519":
        if not ed25519_available():
            return False
        try:
            raw = base64.b64decode(signature.value, validate=True)
        except (ValueError, TypeError):
            return False
        from cryptography.exceptions import InvalidSignature

        for path in _public_key_paths(ed25519_public_keys):
            if not path.is_file():
                continue
            try:
                load_ed25519_public_key(path).verify(raw, payload)
            except (InvalidSignature, BundleError):
                continue
            return True
        return False
    return False


def write_bundle(directory: str | Path, manifest: BundleManifest) -> Path:
    """Write ``evidence-bundle.json``."""
    path = Path(directory) / BUNDLE_FILE
    pkgio.write_json(path, manifest.model_dump(mode="json"))
    return path


def read_bundle(directory: str | Path) -> BundleManifest | None:
    """Read ``evidence-bundle.json`` if present."""
    path = Path(directory) / BUNDLE_FILE
    if not path.is_file():
        return None
    try:
        return BundleManifest.model_validate(pkgio.read_json(path))
    except (ValidationError, pkgio.PackageError) as exc:
        raise BundleError(f"{path}: {exc}") from exc


def verify_bundle(
    directory: str | Path,
    *,
    hmac_key: bytes | None = None,
    ed25519_public_keys: Iterable[str | Path] | None = None,
    head_commit: str | None = None,
    require_head: bool = False,
    now: datetime | None = None,
    max_age_hours: int | None = None,
    min_signatures: int = 1,
    allowed_algorithms: Iterable[str] | None = None,
    min_approvals: int = 0,
    required_roles: Iterable[str] | None = None,
    require_overall: bool = True,
) -> BundleVerification:
    """Verify the signed bundle of the package at *directory*.

    Checks, in order: manifest present and well-formed; every covered file still hashes
    to the recorded digest (tamper detection, missing files included); at least
    ``min_signatures`` signatures verify against the trusted keys using an allowed
    algorithm; ``final-verdict.json`` matches the manifest (gate results, overall,
    fingerprint, commit, ``bundle_digest``); approvals on disk match the manifest and satisfy
    ``min_approvals``/``required_roles``; staleness — the manifest's fingerprint equals
    the package's current fingerprint, its commit equals ``head_commit`` (git ``HEAD`` of
    the package directory when omitted; unknown HEAD fails only with ``require_head``),
    and it is not older than ``max_age_hours``. ``ok`` is ``True`` only when every check
    passes and (with ``require_overall``) the certified verdict is positive.
    """
    root = Path(directory)
    reasons: list[str] = []
    try:
        manifest = read_bundle(root)
    except BundleError as exc:
        return BundleVerification(ok=False, reasons=[str(exc)])
    if manifest is None:
        return BundleVerification(ok=False, reasons=[f"no {BUNDLE_FILE} in {root}"])

    digest = manifest.digest()
    tampered = False
    stale = False

    # -- files -------------------------------------------------------------------------
    recorded = {f.path for f in manifest.files}
    for entry in manifest.files:
        path = root / entry.path
        if not path.is_file():
            tampered = True
            reasons.append(f"missing bundled file {entry.path}")
            continue
        if sha256_file(path) != entry.sha256:
            tampered = True
            reasons.append(f"content of {entry.path} differs from the bundle")
    for current in collect_files(root):
        if current.path not in recorded:
            tampered = True
            reasons.append(f"file {current.path} was added after the bundle was built")

    # -- signatures --------------------------------------------------------------------
    allowed = set(allowed_algorithms) if allowed_algorithms is not None else None
    valid = 0
    invalid = 0
    for signature in manifest.signatures:
        if allowed is not None and signature.algorithm not in allowed:
            invalid += 1
            reasons.append(f"signature by {signature.signer} uses disallowed {signature.algorithm}")
            continue
        if verify_signature(
            manifest, signature, hmac_key=hmac_key, ed25519_public_keys=ed25519_public_keys
        ):
            valid += 1
        else:
            invalid += 1
            reasons.append(f"{signature.algorithm} signature by {signature.signer} is invalid")
    if valid < min_signatures:
        reasons.append(f"{valid} valid signature(s), {min_signatures} required")

    # -- verdict consistency -----------------------------------------------------------
    overall: bool | None = None
    try:
        verdict = read_verdict(root)
    except pkgio.PackageError as exc:
        verdict = None
        reasons.append(str(exc))
    if verdict is None:
        reasons.append(f"no {pkgio.FINAL_VERDICT_FILE} to certify")
    else:
        overall = verdict.overall
        if verdict.change_id != manifest.change_id:
            tampered = True
            reasons.append("verdict change id differs from the bundle")
        if verdict.bundle_digest != digest:
            tampered = True
            reasons.append("verdict bundle_digest does not match the bundle")
        if [g.model_dump() for g in verdict.gate_results] != [
            g.model_dump() for g in manifest.gate_results
        ]:
            tampered = True
            reasons.append("verdict gate results differ from the bundle")
        if verdict.overall != manifest.overall:
            tampered = True
            reasons.append("verdict overall differs from the bundle")
        if verdict.fingerprint and verdict.fingerprint != manifest.fingerprint:
            tampered = True
            reasons.append("verdict was evaluated against a different package fingerprint")
        if verdict.commit_sha and manifest.commit_sha and verdict.commit_sha != manifest.commit_sha:
            tampered = True
            reasons.append("verdict commit differs from the bundle commit")
        if require_overall and not verdict.overall:
            reasons.append("certified verdict is negative (overall=false)")

    # -- approvals ---------------------------------------------------------------------
    try:
        on_disk = read_approvals(root)
    except BundleError as exc:
        on_disk = []
        reasons.append(str(exc))
    if [a.model_dump() for a in on_disk] != [a.model_dump() for a in manifest.approvals]:
        tampered = True
        reasons.append("approvals on disk differ from the bundle")
    if len(manifest.approvals) < min_approvals:
        reasons.append(f"{len(manifest.approvals)} approval(s), {min_approvals} required")
    for role in required_roles or ():
        if not any(a.role == role for a in manifest.approvals):
            reasons.append(f"missing approval for role {role!r}")

    # -- staleness ---------------------------------------------------------------------
    current_fp = fp.compute_fingerprint(root)
    if manifest.fingerprint and manifest.fingerprint != current_fp:
        stale = True
        reasons.append("package content changed since the bundle was built (fingerprint)")
    head = head_commit if head_commit is not None else git_head(root)
    if head is None:
        if require_head:
            stale = True
            reasons.append("git HEAD unknown; commit staleness cannot be verified")
        else:
            reasons.append("note: git HEAD unknown; commit staleness not verified")
    elif not manifest.commit_sha:
        stale = True
        reasons.append("bundle records no commit sha")
    elif manifest.commit_sha != head:
        stale = True
        reasons.append(f"bundle commit {manifest.commit_sha[:12]} is not HEAD {head[:12]}")
    if max_age_hours is not None and manifest.produced_at is not None:
        produced = manifest.produced_at
        if produced.tzinfo is None:
            produced = produced.replace(tzinfo=UTC)
        now_ts = now or utcnow()
        if now_ts - produced > timedelta(hours=max_age_hours):
            stale = True
            reasons.append(f"bundle is older than {max_age_hours}h")

    blocking = [r for r in reasons if not r.startswith("note: ")]
    return BundleVerification(
        ok=not blocking,
        digest=digest,
        reasons=reasons,
        tampered=tampered,
        stale=stale,
        valid_signatures=valid,
        invalid_signatures=invalid,
        approvals=len(manifest.approvals),
        overall=overall,
    )


def publish_bundle(
    directory: str | Path,
    verdict: FinalVerdict,
    *,
    signer: str,
    hmac_key: bytes | None = None,
    ed25519_private_key: str | Path | None = None,
    commit_sha: str | None = None,
    now: datetime | None = None,
) -> tuple[BundleManifest, FinalVerdict]:
    """Build, sign and write the bundle, then write the verdict cross-referencing it.

    Returns the signed manifest and the verdict as written (signatures copied from the
    manifest, ``bundle_digest`` set, ``commit_sha`` aligned with the manifest).
    """
    root = Path(directory)
    manifest = build_bundle(root, verdict, commit_sha=commit_sha, now=now)
    signed = sign_bundle(
        manifest,
        signer=signer,
        hmac_key=hmac_key,
        ed25519_private_key=ed25519_private_key,
        now=now,
    )
    write_bundle(root, signed)
    final = verdict.model_copy(
        update={
            "signatures": list(signed.signatures),
            "bundle_digest": signed.digest(),
            "commit_sha": signed.commit_sha,
            "produced_at": signed.produced_at,
        }
    )
    write_verdict(root, final)
    return signed, final
