# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Persistence, signing, and CI CLI tests for release evaluation."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

import agent_sre.sdlc.signing as release_signing
from agent_sre.cli.main import cli
from agent_sre.sdlc import (
    EvaluationConflictError,
    EvaluationLedgerIntegrityError,
    ReasonCode,
    ReleaseEvaluator,
    SQLiteEvaluationLedger,
    canonical_json_bytes,
    parse_pyrit_security_evidence,
    parse_release_policy,
    with_digest,
)
from agent_sre.sdlc.signing import (
    load_signature_bundle,
    load_trusted_public_key,
    sign_release_bundle,
    verify_release_bundle,
    write_signature_bundle,
)
from agent_sre.signing import ArtifactSigner

from .test_release_policy import NOW, evidence_payload, policy_payload


def models():
    policy = parse_release_policy(json.dumps(policy_payload()))
    evidence = parse_pyrit_security_evidence(json.dumps(evidence_payload()))
    return policy, evidence


def test_sqlite_ledger_is_idempotent_and_survives_restart(tmp_path) -> None:
    database = tmp_path / "release-evaluations.db"
    policy, evidence = models()
    first_time = NOW
    second_time = NOW + timedelta(minutes=10)

    with SQLiteEvaluationLedger(database) as ledger:
        first = ReleaseEvaluator(ledger).evaluate(policy, evidence, evaluated_at=first_time)
        second = ReleaseEvaluator(ledger).evaluate(policy, evidence, evaluated_at=second_time)
        assert second == first
        assert ledger.count() == 1

    with SQLiteEvaluationLedger(database) as ledger:
        restored = ledger.get(evidence.evidence_digest)
        assert restored == first
        assert ledger.count() == 1


def test_ledger_re_evaluates_when_evidence_crosses_freshness_boundary(tmp_path) -> None:
    database = tmp_path / "release-evaluations.db"
    policy, evidence = models()

    with SQLiteEvaluationLedger(database) as ledger:
        fresh = ReleaseEvaluator(ledger).evaluate(policy, evidence, evaluated_at=NOW)
        stale_at = NOW + timedelta(minutes=31)
        stale = ReleaseEvaluator(ledger).evaluate(policy, evidence, evaluated_at=stale_at)
        repeated = ReleaseEvaluator(ledger).evaluate(
            policy,
            evidence,
            evaluated_at=stale_at + timedelta(minutes=5),
        )

        assert fresh.status.value == "pass"
        assert ReasonCode.EVIDENCE_STALE in stale.reason_codes
        assert stale.status.value == "fail"
        assert repeated == stale
        assert ledger.count() == 2


def test_ledger_rejects_same_evidence_under_different_policy(tmp_path) -> None:
    database = tmp_path / "release-evaluations.db"
    policy, evidence = models()
    changed = policy_payload()
    changed["policy_version"] = "2.0.0"
    changed = with_digest(changed, field="policy_digest")
    other_policy = parse_release_policy(json.dumps(changed))

    with SQLiteEvaluationLedger(database) as ledger:
        ReleaseEvaluator(ledger).evaluate(policy, evidence, evaluated_at=NOW)
        with pytest.raises(EvaluationConflictError):
            ReleaseEvaluator(ledger).evaluate(other_policy, evidence, evaluated_at=NOW)


def test_sqlite_ledger_concurrently_deduplicates_one_evidence_digest(tmp_path) -> None:
    policy, evidence = models()
    with SQLiteEvaluationLedger(tmp_path / "release-evaluations.db") as ledger:
        evaluator = ReleaseEvaluator(ledger)
        with ThreadPoolExecutor(max_workers=8) as pool:
            verdicts = tuple(
                pool.map(
                    lambda offset: evaluator.evaluate(
                        policy, evidence, evaluated_at=NOW + timedelta(seconds=offset)
                    ),
                    range(16),
                )
            )
        assert len({verdict.verdict_digest for verdict in verdicts}) == 1
        assert ledger.count() == 1


def test_ledger_authenticates_indexed_digests_on_read(tmp_path) -> None:
    database = tmp_path / "release-evaluations.db"
    policy, evidence = models()
    with SQLiteEvaluationLedger(database) as ledger:
        ReleaseEvaluator(ledger).evaluate(policy, evidence, evaluated_at=NOW)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE release_evaluations SET policy_digest=? WHERE evidence_digest=?",
            ("f" * 64, evidence.evidence_digest),
        )

    with (
        SQLiteEvaluationLedger(database) as ledger,
        pytest.raises(EvaluationLedgerIntegrityError, match="ledger index"),
    ):
        ledger.get(evidence.evidence_digest)


def test_release_verdict_signing_checks_digest_signature_and_trust_anchor(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(release_signing, "_now_utc", lambda: NOW)
    policy, evidence = models()
    verdict = ReleaseEvaluator().evaluate(policy, evidence, evaluated_at=NOW)
    verdict_path = tmp_path / "verdict.json"
    verdict_path.write_bytes(canonical_json_bytes(verdict) + b"\n")

    key_owner = ArtifactSigner()
    private_key = tmp_path / "release-key.pem"
    private_key.write_bytes(key_owner.export_private_key_pem())
    signature = sign_release_bundle(
        verdict_path,
        policy=policy,
        evidence=evidence,
        private_key_path=str(private_key),
        signer_did="did:web:release.example",
    )
    signature_path = tmp_path / "verdict.sig.json"
    write_signature_bundle(signature_path, signature)
    restored = load_signature_bundle(signature_path)

    assert restored.signer_did == "did:web:release.example"
    assert verify_release_bundle(
        verdict_path,
        restored,
        trusted_public_key=key_owner.public_key_bytes,
        expected_policy=policy,
        expected_evidence=evidence,
    )
    assert not verify_release_bundle(
        verdict_path,
        restored,
        trusted_public_key=b"x" * 32,
        expected_policy=policy,
        expected_evidence=evidence,
    )
    assert not verify_release_bundle(verdict_path, restored)

    with monkeypatch.context() as clock:
        clock.setattr(
            release_signing,
            "_now_utc",
            lambda: NOW + timedelta(hours=2),
        )
        assert not verify_release_bundle(
            verdict_path,
            restored,
            trusted_public_key=key_owner.public_key_bytes,
            expected_policy=policy,
            expected_evidence=evidence,
        )

    verdict_path.write_bytes(verdict_path.read_bytes() + b" ")
    assert not verify_release_bundle(
        verdict_path,
        restored,
        trusted_public_key=key_owner.public_key_bytes,
        expected_policy=policy,
        expected_evidence=evidence,
    )

    verdict_path.write_bytes(canonical_json_bytes(verdict) + b"\n")
    unsigned_metadata = restored.to_dict()
    unsigned_metadata["signer_did"] = "did:web:attacker.example"
    signature_path.write_text(json.dumps(unsigned_metadata), encoding="utf-8")
    tampered_metadata = load_signature_bundle(signature_path)
    assert not verify_release_bundle(
        verdict_path,
        tampered_metadata,
        trusted_public_key=key_owner.public_key_bytes,
        expected_policy=policy,
        expected_evidence=evidence,
    )

    invalid_time = signature.to_dict()
    invalid_time["timestamp"] = "2026-08-25T13:00:00+01:00"
    signature_path.write_text(json.dumps(invalid_time), encoding="utf-8")
    with pytest.raises(ValueError, match="must use UTC"):
        load_signature_bundle(signature_path)


def test_release_signing_refuses_a_failing_verdict(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(release_signing, "_now_utc", lambda: NOW)
    policy_data = policy_payload()
    policy_data["thresholds"]["max_cost_usd"] = "0.001"
    policy = parse_release_policy(json.dumps(with_digest(policy_data, field="policy_digest")))
    evidence = parse_pyrit_security_evidence(json.dumps(evidence_payload()))
    verdict = ReleaseEvaluator().evaluate(policy, evidence, evaluated_at=NOW)
    assert verdict.status.value == "fail"
    verdict_path = tmp_path / "failed-verdict.json"
    verdict_path.write_bytes(canonical_json_bytes(verdict) + b"\n")
    key_owner = ArtifactSigner()
    private_key = tmp_path / "release-key.pem"
    private_key.write_bytes(key_owner.export_private_key_pem())

    with pytest.raises(ValueError, match="refusing to sign"):
        sign_release_bundle(
            verdict_path,
            policy=policy,
            evidence=evidence,
            private_key_path=str(private_key),
        )


def test_trusted_public_key_hex_cannot_be_shadowed_by_a_relative_file(
    tmp_path, monkeypatch
) -> None:
    trusted_hex = (b"t" * 32).hex()
    monkeypatch.chdir(tmp_path)
    (tmp_path / trusted_hex).write_text((b"a" * 32).hex(), encoding="utf-8")

    assert load_trusted_public_key(trusted_hex) == b"t" * 32
    relative_file = tmp_path / "trusted-key.txt"
    relative_file.write_text(trusted_hex, encoding="utf-8")
    with pytest.raises(ValueError, match="must be absolute"):
        load_trusted_public_key(relative_file.name)
    assert load_trusted_public_key(relative_file) == b"t" * 32


def _write_inputs(tmp_path):
    policy_path = tmp_path / "policy.json"
    evidence_path = tmp_path / "evidence.json"
    policy_path.write_text(json.dumps(policy_payload()), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence_payload()), encoding="utf-8")
    return policy_path, evidence_path


def test_release_evaluate_cli_has_ci_exit_codes_and_idempotent_output(tmp_path, capsys) -> None:
    policy_path, evidence_path = _write_inputs(tmp_path)
    database = tmp_path / "ledger.db"
    output = tmp_path / "verdict.json"
    args = [
        "release",
        "evaluate",
        "--policy",
        str(policy_path),
        "--evidence",
        str(evidence_path),
        "--ledger",
        str(database),
        "--output",
        str(output),
        "--evaluated-at",
        NOW.isoformat(),
    ]
    assert cli(args) == 0
    first_stdout = capsys.readouterr().out
    assert json.loads(first_stdout)["status"] == "pass"
    assert output.read_bytes() == first_stdout.encode()

    later_args = args[:-1] + [(NOW + timedelta(minutes=10)).isoformat()]
    assert cli(later_args) == 0
    assert capsys.readouterr().out == first_stdout

    failing = policy_payload()
    failing["thresholds"]["max_cost_usd"] = "0.001"
    failing = with_digest(failing, field="policy_digest")
    policy_path.write_text(json.dumps(failing), encoding="utf-8")
    without_ledger = [item for item in args if item not in {"--ledger", str(database)}]
    assert cli(without_ledger) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "fail"


def test_release_cli_rejects_invalid_input_with_configuration_exit(tmp_path, capsys) -> None:
    policy_path, evidence_path = _write_inputs(tmp_path)
    evidence_path.write_text('{"schema":"pyrit.security-evidence/v1"}', encoding="utf-8")
    result = cli(
        [
            "release",
            "evaluate",
            "--policy",
            str(policy_path),
            "--evidence",
            str(evidence_path),
        ]
    )
    assert result == 2
    assert "release evaluation error" in capsys.readouterr().err


def test_release_verify_cli_distinguishes_valid_and_invalid_signatures(
    tmp_path, capsys, monkeypatch
) -> None:
    monkeypatch.setattr(release_signing, "_now_utc", lambda: NOW)
    policy, evidence = models()
    policy_path, evidence_path = _write_inputs(tmp_path)
    verdict = ReleaseEvaluator().evaluate(policy, evidence, evaluated_at=NOW)
    verdict_path = tmp_path / "verdict.json"
    verdict_path.write_bytes(canonical_json_bytes(verdict) + b"\n")
    signer = ArtifactSigner()
    private_key = tmp_path / "key.pem"
    private_key.write_bytes(signer.export_private_key_pem())
    signature = sign_release_bundle(
        verdict_path,
        policy=policy,
        evidence=evidence,
        private_key_path=str(private_key),
    )
    signature_path = tmp_path / "signature.json"
    write_signature_bundle(signature_path, signature)

    args = [
        "release",
        "verify",
        "--bundle",
        str(verdict_path),
        "--signature",
        str(signature_path),
        "--policy",
        str(policy_path),
        "--evidence",
        str(evidence_path),
        "--trusted-public-key",
        signer.public_key_bytes.hex(),
    ]
    assert cli(args) == 0
    assert json.loads(capsys.readouterr().out) == {"verified": True}

    args[-1] = (b"x" * 32).hex()
    assert cli(args) == 1
    assert json.loads(capsys.readouterr().out) == {"verified": False}
