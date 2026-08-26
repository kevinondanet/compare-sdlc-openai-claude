"""Tests for aisdlc.gates.verdict: approvals, bundle build/sign/verify, tamper + staleness."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from aisdlc.gates import verdict as v
from aisdlc.gates.gates import evaluate_all
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ChangePackage, FinalVerdict, GateId, GateResult, Signature
from tests.test_gates_fixtures import COMMIT, NOW, context, golden_package, policy

KEY = b"test-signing-key"


@pytest.fixture(autouse=True)
def _no_env_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(v.SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(v.ED25519_PRIVATE_KEY_ENV, raising=False)
    monkeypatch.delenv(v.ED25519_PUBLIC_KEY_ENV, raising=False)


@pytest.fixture
def saved(tmp_path: Path) -> ChangePackage:
    """The golden package written to disk with a positive verdict."""
    pkg = golden_package()
    created = pkgio.create(tmp_path, pkg.change_id, pkg.intent)
    for name in (
        "requirements",
        "assumptions",
        "decisions",
        "threat_model",
        "plan",
        "tasks",
        "evidence",
    ):
        setattr(created, name, getattr(pkg, name))
    created.save()
    v.write_approvals(created.root, context().approvals)  # type: ignore[arg-type]
    ctx = context(
        current_fingerprint=created.base_fingerprint, stored_fingerprint=created.base_fingerprint
    )
    verdict = evaluate_all(created, policy(), context=ctx)
    assert verdict.overall
    assert verdict.fingerprint == created.base_fingerprint
    v.write_verdict(created.root, verdict)  # type: ignore[arg-type]
    return created


def _root(pkg: ChangePackage) -> Path:
    assert pkg.root is not None
    return pkg.root


# --------------------------------------------------------------------------------------
# Approvals
# --------------------------------------------------------------------------------------


def test_approvals_round_trip(tmp_path: Path) -> None:
    assert v.read_approvals(tmp_path) == []
    first = v.Approval(role="owner", approver="kevin", approved_at=NOW)
    v.add_approval(tmp_path, first)
    v.add_approval(tmp_path, v.Approval(role="security", approver="sec", approved_at=NOW))
    replaced = v.add_approval(tmp_path, first.model_copy(update={"note": "again"}))
    assert [a.role for a in replaced] == ["security", "owner"]
    assert v.read_approvals(tmp_path)[1].note == "again"
    (tmp_path / v.APPROVALS_FILE).write_text("{}")
    with pytest.raises(v.BundleError):
        v.read_approvals(tmp_path)


# --------------------------------------------------------------------------------------
# Manifest + signing
# --------------------------------------------------------------------------------------


def test_build_bundle_collects_files_and_state(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    manifest = v.build_bundle(root, verdict, commit_sha=COMMIT, now=NOW)
    assert manifest.change_id == "CHG-login-mfa"
    assert manifest.commit_sha == COMMIT
    assert manifest.fingerprint == saved.base_fingerprint
    assert manifest.overall is True
    assert [g.gate for g in manifest.gate_results] == list(GateId)
    assert len(manifest.approvals) == 2
    paths = [f.path for f in manifest.files]
    assert "evidence/tests.json" in paths and "evidence/security.json" in paths
    assert "approvals.json" in paths
    assert all(len(f.sha256) == 64 for f in manifest.files)
    assert manifest.signatures == []
    # digest is deterministic and ignores signatures
    signed = manifest.model_copy(
        update={"signatures": [Signature(signer="x", value="y", signed_at=NOW)]}
    )
    assert signed.digest() == manifest.digest()


def test_build_bundle_rejects_non_package(tmp_path: Path) -> None:
    with pytest.raises(v.BundleError, match="not a change package"):
        v.build_bundle(tmp_path, FinalVerdict(change_id="CHG-x"))


def test_sign_requires_key_material(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    manifest = v.build_bundle(root, verdict, commit_sha=COMMIT)
    assert v.signing_available() is False
    with pytest.raises(v.BundleError, match="no signing key"):
        v.sign_bundle(manifest, signer="ci")


def test_hmac_sign_and_verify_from_env(
    saved: ChangePackage, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(v.SIGNING_KEY_ENV, KEY.decode())
    assert v.signing_available()
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    manifest, final = v.publish_bundle(root, verdict, signer="ci", commit_sha=COMMIT, now=NOW)
    assert [s.algorithm for s in manifest.signatures] == ["hmac-sha256"]
    assert final.signatures == manifest.signatures
    assert final.bundle_digest == manifest.digest()
    assert (root / v.BUNDLE_FILE).is_file()
    on_disk = v.read_bundle(root)
    assert on_disk == manifest
    result = v.verify_bundle(root, head_commit=COMMIT, now=NOW, max_age_hours=72)
    assert result.ok, result.reasons
    assert result.valid_signatures == 1 and not result.tampered and not result.stale
    assert result.overall is True and result.approvals == 2


def test_verify_with_wrong_key_fails(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    good = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert good.ok, good.reasons
    bad = v.verify_bundle(root, hmac_key=b"other", head_commit=COMMIT)
    assert not bad.ok
    assert bad.invalid_signatures == 1
    assert any("signature by ci is invalid" in r for r in bad.reasons)
    assert any("0 valid signature(s), 1 required" in r for r in bad.reasons)
    disallowed = v.verify_bundle(
        root, hmac_key=KEY, head_commit=COMMIT, allowed_algorithms=["ed25519"]
    )
    assert not disallowed.ok and any("disallowed" in r for r in disallowed.reasons)


def test_tamper_detection(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)

    # 1. evidence file edited after signing
    tests_file = root / "evidence" / "tests.json"
    data = json.loads(tests_file.read_text())
    data[0]["failed"] = 0
    data[0]["passed"] = 9999
    tests_file.write_text(json.dumps(data))
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert result.tampered and not result.ok
    assert any("evidence/tests.json differs" in r for r in result.reasons)

    # 2. manifest itself edited: signatures no longer match the digest
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    manifest = v.read_bundle(root)
    assert manifest is not None
    forged = manifest.model_copy(update={"overall": True, "approvals": []})
    v.write_bundle(root, forged)
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert not result.ok and result.invalid_signatures == 1
    assert any("approvals on disk differ" in r for r in result.reasons)

    # 3. verdict edited independently of the bundle
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    fake = verdict.model_copy(
        update={
            "gate_results": [GateResult(gate=g, passed=True) for g in GateId],
            "overall": True,
            "bundle_digest": "0" * 64,
        }
    )
    v.write_verdict(root, fake)
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert result.tampered
    assert any("bundle_digest does not match" in r for r in result.reasons)
    assert any("gate results differ" in r for r in result.reasons)

    # 4. bundled file removed / new evidence added
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    (root / "evidence" / "cost.json").unlink()
    (root / "evidence" / "extra.json").write_text("{}")
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert any("missing bundled file evidence/cost.json" in r for r in result.reasons)
    assert any("evidence/extra.json was added" in r for r in result.reasons)


def test_staleness(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT, now=NOW)

    other = v.verify_bundle(root, hmac_key=KEY, head_commit="1234567890ab")
    assert other.stale and not other.ok
    assert any("is not HEAD 1234567890ab" in r for r in other.reasons)

    old = v.verify_bundle(
        root, hmac_key=KEY, head_commit=COMMIT, now=NOW + timedelta(hours=100), max_age_hours=72
    )
    assert old.stale and any("older than 72h" in r for r in old.reasons)

    unknown = v.verify_bundle(root, hmac_key=KEY, head_commit=None)
    assert unknown.ok, unknown.reasons
    assert any(r.startswith("note: git HEAD unknown") for r in unknown.reasons)
    strict = v.verify_bundle(root, hmac_key=KEY, head_commit=None, require_head=True)
    assert strict.stale and not strict.ok

    # authored content edited after bundling -> fingerprint mismatch
    (root / "requirements.md").write_text((root / "requirements.md").read_text() + "\nedit\n")
    edited = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert edited.stale and any("fingerprint" in r for r in edited.reasons)


def test_verify_requires_approvals_and_positive_verdict(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    negative = verdict.model_copy(update={"overall": False})
    v.write_verdict(root, negative)
    v.publish_bundle(root, negative, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert not result.ok and any("negative" in r for r in result.reasons)
    lenient = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT, require_overall=False)
    assert lenient.ok, lenient.reasons
    roles = v.verify_bundle(
        root,
        hmac_key=KEY,
        head_commit=COMMIT,
        require_overall=False,
        min_approvals=3,
        required_roles=["release"],
    )
    assert any("2 approval(s), 3 required" in r for r in roles.reasons)
    assert any("missing approval for role 'release'" in r for r in roles.reasons)


def test_verify_without_bundle_or_verdict(saved: ChangePackage, tmp_path: Path) -> None:
    root = _root(saved)
    missing = v.verify_bundle(root, hmac_key=KEY)
    assert not missing.ok and "no evidence-bundle.json" in missing.reasons[0]
    (root / v.BUNDLE_FILE).write_text("not json")
    broken = v.verify_bundle(root, hmac_key=KEY)
    assert not broken.ok
    verdict = v.read_verdict(root)
    assert verdict is not None
    v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    (root / pkgio.FINAL_VERDICT_FILE).unlink()
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert not result.ok and any("no final-verdict.json" in r for r in result.reasons)


def test_ed25519_sign_and_verify(saved: ChangePackage, tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    assert v.ed25519_available()
    priv, pub = v.generate_ed25519_keypair(tmp_path / "keys" / "release.pem")
    assert priv.is_file() and pub == tmp_path / "keys" / "release.pem.pub"
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    assert v.signing_available(ed25519_private_key=priv)
    manifest, _ = v.publish_bundle(
        root, verdict, signer="release-bot", ed25519_private_key=priv, commit_sha=COMMIT
    )
    assert [s.algorithm for s in manifest.signatures] == ["ed25519"]
    ok = v.verify_bundle(root, ed25519_public_keys=[pub], head_commit=COMMIT)
    assert ok.ok, ok.reasons
    # wrong public key -> invalid; no key -> invalid
    _, other_pub = v.generate_ed25519_keypair(tmp_path / "keys" / "other.pem")
    bad = v.verify_bundle(root, ed25519_public_keys=[other_pub], head_commit=COMMIT)
    assert not bad.ok and bad.invalid_signatures == 1
    none = v.verify_bundle(root, head_commit=COMMIT)
    assert not none.ok and none.invalid_signatures == 1
    # both algorithms together
    both, _ = v.publish_bundle(
        root, verdict, signer="ci", hmac_key=KEY, ed25519_private_key=priv, commit_sha=COMMIT
    )
    assert {s.algorithm for s in both.signatures} == {"hmac-sha256", "ed25519"}
    result = v.verify_bundle(
        root, hmac_key=KEY, ed25519_public_keys=[pub], head_commit=COMMIT, min_signatures=2
    )
    assert result.ok and result.valid_signatures == 2
    with pytest.raises(v.BundleError):
        v.load_ed25519_private_key(pub)
    with pytest.raises(v.BundleError):
        v.load_ed25519_public_key(tmp_path / "keys" / "nope.pem")


def test_ed25519_keys_from_env(
    saved: ChangePackage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("cryptography")
    priv, pub = v.generate_ed25519_keypair(tmp_path / "k.pem")
    monkeypatch.setenv(v.ED25519_PRIVATE_KEY_ENV, str(priv))
    monkeypatch.setenv(v.ED25519_PUBLIC_KEY_ENV, str(pub))
    assert v.signing_available()
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    v.publish_bundle(root, verdict, signer="env", commit_sha=COMMIT)
    assert v.verify_bundle(root, head_commit=COMMIT).ok


def test_git_head_in_repo(tmp_repo: Path) -> None:
    head = v.git_head(tmp_repo)
    assert head is not None and len(head) == 40
    assert v.git_head(tmp_repo / "does-not-exist") is None


# --------------------------------------------------------------------------------------
# Stale verdicts are never certified
# --------------------------------------------------------------------------------------


def test_build_bundle_refuses_a_stale_verdict(saved: ChangePackage) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None and verdict.fingerprint
    with pytest.raises(v.BundleError, match="commit"):
        v.build_bundle(root, verdict, commit_sha="deadbeef")
    (root / "requirements.md").write_text((root / "requirements.md").read_text() + "\nedit\n")
    with pytest.raises(v.BundleError, match="stale"):
        v.build_bundle(root, verdict, commit_sha=COMMIT)
    with pytest.raises(v.BundleError, match="stale"):
        v.publish_bundle(root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT)
    assert not (root / v.BUNDLE_FILE).exists()


def test_verify_bundle_flags_verdict_evaluated_against_other_content(
    saved: ChangePackage,
) -> None:
    root = _root(saved)
    verdict = v.read_verdict(root)
    assert verdict is not None
    _manifest, final = v.publish_bundle(
        root, verdict, signer="ci", hmac_key=KEY, commit_sha=COMMIT, now=NOW
    )
    assert v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT).ok
    v.write_verdict(root, final.model_copy(update={"fingerprint": "0" * 64}))
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert result.tampered and not result.ok
    assert any("different package fingerprint" in r for r in result.reasons)
    v.write_verdict(root, final.model_copy(update={"commit_sha": "deadbeef"}))
    result = v.verify_bundle(root, hmac_key=KEY, head_commit=COMMIT)
    assert result.tampered and any("verdict commit differs" in r for r in result.reasons)


def test_local_signing_key_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_dir = tmp_path / "changes" / "CHG-x"
    package_dir.mkdir(parents=True)
    assert v.local_signing_key_path(package_dir) == tmp_path / ".aisdlc" / "signing.key"
    assert v.local_signing_key_path(tmp_path / "elsewhere") is None
    assert v.discover_hmac_key(package_dir) is None
    assert not v.signing_available(package_dir=package_dir)
    key_file = tmp_path / ".aisdlc" / "signing.key"
    key_file.parent.mkdir()
    key_file.write_text("ab" * 32 + "\n")
    assert v.discover_hmac_key(package_dir) == bytes.fromhex("ab" * 32)
    assert v.signing_available(package_dir=package_dir)
    key_file.write_text("not-hex")
    assert v.read_local_signing_key(key_file) == b"not-hex"
    monkeypatch.setenv(v.SIGNING_KEY_ENV, "env-key")
    assert v.discover_hmac_key(package_dir) == b"env-key"
