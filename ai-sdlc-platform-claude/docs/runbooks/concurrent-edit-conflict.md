# Runbook — "changed concurrently" / conflicting edits on a change package

**Symptom.** `aisdlc plan generate`, `intake kernel`, `intake clarify` or a library call
to `ChangePackage.save(base_fingerprint=...)` fails with
`changes/CHG-x changed concurrently: base fingerprint ... ; reload and merge before
saving`, or an intake command exits 2 with `changed while editing and the edits conflict`.

**Why.** Every authored file of a change package (intent, requirements, assumptions,
plan, tasks, `scenarios/`, `architecture/`) is covered by a content fingerprint
(`.fingerprint`). A writer that loaded the package earlier must prove the disk still
matches its base before writing; otherwise nothing is written. Evidence, handoffs and the
verdict are *produced* files and never invalidate a base.

The long-running writers handle this themselves:

- the orchestrator (`aisdlc run ...`) reloads the package and reapplies only its produced
  state — task statuses, plan approval, evidence — on top of the human's version;
- intake commands reload and three-way merge (requirements by id and scenario id, every
  other artifact as a unit) and abort only when both sides edited the same thing.

## Triage

1. `aisdlc change fingerprint CHG-x` shows the stored and current fingerprints and the
   files that differ.
2. Non-conflicting concurrent edit (most cases): re-run the command. It reloads the
   fresh content and merges (intake prints `note: merged concurrent edits`).
3. Conflict reported (`intent`, `tasks`, `bodies[plan.md]`, `REQ-003.text ...`):
   - Both sides changed the same artifact. Open the file, keep the intended version, and
     re-run the command once. Requirement conflicts list the requirement/scenario id.
   - Scenarios are never dropped by a merge, even when one side deleted them; delete
     again deliberately if that was the intent.
4. Library code that saves packages: catch `OptimisticConcurrencyError`, reload, then
   `fingerprint.merge_packages(base, ours, theirs)` (authoring) or
   `package.save_produced_state(pkg)` (producers), and save with the fresh base.

**Exit.** `aisdlc change validate CHG-x` passes and `aisdlc change fingerprint CHG-x`
reports the stored fingerprint equal to the current one.
