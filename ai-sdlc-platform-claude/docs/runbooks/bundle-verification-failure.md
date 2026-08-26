# Runbook — evidence bundle verification fails

**Symptom.** `aisdlc gate verify-bundle CHG-x` exits 1 with `tampered: [...]`,
`invalid signature`, `bundle digest mismatch` or `stale evidence`; or G6 fails with
`missing/stale evidence` or `missing approval`.

**What the bundle is.** `aisdlc gate bundle` hashes every `evidence/*.json`, the
`final-verdict.json` gate results and the effective policy, writes the manifest and
signs its digest (HMAC-SHA256 with `$AISDLC_SIGNING_KEY` / `.aisdlc/signing.key`, or
ed25519). `verify-bundle` recomputes every hash and checks the signature.

## Triage

| Message | Meaning | Action |
| --- | --- | --- |
| `tampered: evidence/tests.json` | The file changed after signing. | Was it a legitimate re-run? Then re-bundle (`gate bundle --force`) so the verdict reflects the new evidence. Otherwise treat as an integrity incident: restore from git and find the writer in the audit log. |
| `invalid signature` / `0 valid signatures` | Wrong key or the manifest was edited. | Verify which key signed (`final-verdict.json` `signatures[].key_id`). CI uses `$AISDLC_SIGNING_KEY`; local runs use `.aisdlc/signing.key`. Re-bundle with the right key. |
| `bundle digest mismatch` | `final-verdict.json` `bundle_digest` differs from the manifest. | Someone re-ran `gate bundle` without `--force` on a stale verdict, or edited the verdict. Regenerate the verdict (`gate verdict --force`) then bundle. |
| `stale evidence: EVD-tests-001 at <sha>` | Evidence commit SHA is older than the current HEAD of the change. | Re-run the producer (`aisdlc test run-evidence`, `run change`, `security campaign run`) on the current commit. Evidence is bound to a commit on purpose. |
| `missing approval (1 of 2)` | G6 needs human approvals for this risk class. | `aisdlc gate approve CHG-x --approver <name>`; approvals are recorded in the verdict and signed. |
| `evidence incomplete` | A producer wrote `status: incomplete`. | Fix the producer run (see the G4 runbook for campaigns; for tests check the junit/coverage parse). Incomplete evidence never passes. |

## Checks before re-signing

1. `git status changes/CHG-x/evidence` — every change to evidence should come from a
   producer command in the audit trail (`aisdlc governance audit export --package CHG-x`).
2. `aisdlc gate evaluate CHG-x` is green for every required gate.
3. Approvals are still valid: an approval is tied to the bundle digest; a re-bundle after
   new evidence needs fresh approvals.

**Exit.** `aisdlc gate verify-bundle CHG-x --json` shows `valid_signatures >= 1` and an
empty `tampered` list.
