# Runbook — G4 fails on a PyRIT campaign or safety regression

**Symptom.** `aisdlc gate evaluate CHG-x` reports G4 failed with one of:
`campaign incomplete`, `ASR 0.12 > threshold 0.05`, `undetermined rate 0.20 > 0.05`,
`safety regression: <category> above threshold`, or `manifest drift: tool X observed but
not declared`.

**Why it fails closed.** G4 (ARCHITECTURE.md §3, §7) only accepts a *complete* campaign:
every scheduled trial produced SUCCESS/FAILURE/UNDETERMINED. A trial that errored, timed
out or never ran makes `complete=false`; a high undetermined rate means the scorer could
not decide and the ASR is not trustworthy either way.

## Triage

1. Read the evidence, not the summary line:
   `python -c "import json;print(json.dumps(json.load(open('changes/CHG-x/evidence/security.json'))['pyrit'],indent=2))"`.
   Fields: `asr`, `undetermined_rate`, `complete`, `trials`, `baseline_delta`.
2. Incomplete (`complete: false`)
   - Re-run the campaign alone with verbose output:
     `aisdlc security campaign run templates/pyrit/campaigns/<id>.yaml --package CHG-x --json`.
     `incomplete_objectives` in the JSON lists the objective and the exception per trial.
   - Common causes: the application-under-test callable raised (fix the target adapter),
     a per-trial timeout (raise `timeout_seconds` in the campaign spec), rate limiting on a
     model-backed scorer (lower `max_concurrency`).
   - Never lower `trials` below `security_baselines.safety_trials_min`; the gate rejects it.
3. High undetermined rate
   - The scorer returned no decision. Calibrate it first:
     `aisdlc security judges calibrate <scorer> --dataset labelled.csv` and check FPR/FNR.
   - Switch a free-text judge for a deterministic scorer (substring/regex) where the
     objective allows, or tighten the judge prompt. Re-run.
4. ASR above threshold
   - This is a real finding. Open the per-scenario table (`--json` -> `scenarios[]`) and
     the conversations in PyRIT memory for the successful attacks.
   - Fix the application (input screening, tool allow-list, approval token — see
     `pilots/ai-agent`), add the attack objective to the regression suite
     (`@safety_case`), re-run until ASR is under the threshold **and** `baseline_delta`
     is not positive.
   - The threshold lives in the org policy (`security_baselines.asr_threshold`); a project
     may only lower it (`aisdlc policy validate` rejects a raise).
5. Manifest drift
   - `aisdlc ci manifest-drift CHG-x` prints observed-but-undeclared tools/data
     sources/egress hosts from `evidence/audit-entries.json`.
   - Either the agent did something it should not (block it: tighten the role's
     allow-list and `allowed_egress_hosts`) or the threat model is stale (declare it in
     `architecture/threat-model.md` `tool_data_manifest` and get the ADR/threat updated).

## Do not

- Do not mark the evidence `complete` by hand, delete `security.json`, or bump the
  threshold in `aisdlc.yaml` — the merge is narrow-only and the bundle records the
  policy digest.
- Do not skip G4 by re-classifying an agentic change as `standard`; `plan risk classify`
  derives the class from the touched paths and the reviewer will see the mismatch.

**Exit.** `aisdlc gate evaluate CHG-x --gate G4` passes; then `aisdlc gate bundle`.
