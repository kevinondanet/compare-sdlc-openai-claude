---
title: "Enterprise AI-SDLC Evidence Workflow"
last_reviewed: 2026-08-26
owner: agt-maintainers
---

# Enterprise AI-SDLC Evidence Workflow

The [reusable evidence workflow](../../.github/workflows/enterprise-ai-sdlc-evidence.yml)
gives governed repositories a common, source-bound handoff for quality,
security, SBOM, provenance, Agent SRE, and optional PyRIT evidence. It checks
out the exact caller commit, validates the caller's trusted base commit, applies
fixed central checks over the `base...source` patch, validates the mandatory
caller evidence, writes canonical JSON, and uploads the fixed
`agt-ai-sdlc-evidence` artifact.

The workflow does not execute PyRIT. Networked or costly PyRIT campaigns stay
in a separate, protected workflow and are supplied only as validated evidence.

## Consumer workflow

Call the workflow by its full 40-character commit SHA. A branch or tag is not
an adequate trust anchor for an organization-wide required check.

```yaml
name: Governed AI-SDLC evidence

on:
  pull_request:
  push:
    branches: ["main"]

permissions:
  contents: read

jobs:
  canonical-change:
    # Organization-owned job that emits a protected agt.change/v1 identity.
    uses: your-organization/central-governance/.github/workflows/change.yml@<FULL_COMMIT_SHA>

  governed-runtime:
    needs: canonical-change
    # This protected producer executes the governed manifest and uploads the
    # fixed agt-ai-sdlc-caller-evidence artifact in this workflow run.
    uses: your-organization/central-governance/.github/workflows/governed-runtime.yml@<FULL_COMMIT_SHA>
    with:
      base_revision: ${{ github.event.pull_request.base.sha || github.event.before }}
      change_id: ${{ needs.canonical-change.outputs.change_id }}
      change_digest: ${{ needs.canonical-change.outputs.change_digest }}

  evidence:
    needs: [canonical-change, governed-runtime]
    permissions:
      actions: read
      contents: read
    uses: microsoft/agent-governance-toolkit/.github/workflows/enterprise-ai-sdlc-evidence.yml@<FULL_COMMIT_SHA>
    with:
      base_revision: ${{ github.event.pull_request.base.sha || github.event.before }}
      change_id: ${{ needs.canonical-change.outputs.change_id }}
      change_digest: ${{ needs.canonical-change.outputs.change_digest }}
```

Make `evidence` and the organization-managed `canonical-change` job required
checks on protected branches. The caller's `change_id` and lowercase SHA-256
`change_digest` must come from the same protected canonical change record; do
not derive them from pull-request text or other contributor-controlled fields.

`base_revision` is required for every reusable call. The caller is responsible
for selecting the trusted commit that defines the reviewed change range. Use a
GitHub-supplied event SHA or a protected organization-owned resolver, never pull
request text, a workflow-dispatch string from an untrusted operator, or code
from the proposed change. The workflow accepts a 40-character hexadecimal SHA
in either case, normalizes it to lowercase, verifies that it resolves to the
exact commit in the fetched repository, and runs
`git merge-base --is-ancestor base source` before
`git diff --check base...source`. Initial-history pushes and events whose
`before` value is all zeroes need a protected caller job to select a real
commit; the workflow intentionally fails closed instead of guessing a base.

The reusable workflow exposes only typed data inputs. It has no command,
script, URL, target, or shell input, and it never interpolates an input into a
shell program. Remote actions in the workflow are pinned to immutable commit
SHAs, `docker://` actions must use an immutable `sha256` image digest, and
checkout credentials are not persisted.

## Required repository evidence

Every caller must first execute the governed orchestration runtime, then publish
one artifact named `agt-ai-sdlc-caller-evidence` in the same workflow run. The
reusable evidence job must depend on that protected producer job. There is no
input that bypasses this handoff: a central-only diagnostic run is not a
governed execution record, so a missing caller artifact fails closed. Only
these top-level files are accepted:

| File | Contract |
|---|---|
| `quality-details.json` | Canonical `agt.ai-sdlc-quality-gates/v1` handoff containing exact, digest-valid G0, G1, G2, and G3 results for one source, risk class, development policy, and evaluation time |
| `security-details.json` | Canonical `agt.ai-sdlc-security-gates/v1` handoff containing the matching digest-valid G4 result and, when PyRIT is required, its complete canonical release policy and policy-evaluated verdict |
| `orchestration-manifest.json` | Canonical, digest-valid `agt.orchestration-manifest/v1` executed for the exact change, protected policy, source, prompts, routes, Plane-2 tool governance, limits, dependency waves, trusted review attesters, predeclared conditional remediation/re-review rounds, and checkpoint requirements |
| `execution-receipt.json` | Canonical, digest-valid `agt.orchestration-execution-receipt/v1` proving required assignments succeeded, unused conditional work was explicitly skipped, cost and tool audits are complete, and the ordered authenticated review/remediation history ends clean under the exact manifest/change/source/policy binding |
| `agent-sre-execution-evidence.json` | Canonical JSON array of strict `agt.execution-evidence/v1` records bound to the change ID, change digest, and source revision, including exactly one cost record that reconciles the execution receipt |
| `pyrit-security-evidence.json` | Optional strict `pyrit.security-evidence/v1` record whose subject is the exact source revision and canonical change ID, with a matching canonical payload digest |

This workflow assembles evidence; it does not itself issue G6 readiness or a release
signature. The later protected readiness/issuance job must also supply the effective
orchestration policy, a fresh organization-signed `agt.risk-classification/v1`, and
any risk-required signed `agt.human-approval/v1` records. It compares every projected
manifest control with that policy, independently pins the risk-classifier,
review-attester, and approval-issuer keys, and reruns G0-G6. Each approval must bind
the exact source, change digest, enterprise-policy digest, risk tier, role, decision,
issue time, and expiry, and its policy-pinned issuer must authorize that role. A
matching self-digest, embedded key, or a risk class copied into the quality handoff is
not an independent trust anchor.

Upload that artifact from a fixed producer job after its tests and scans pass.
Pin the upload action to a reviewed 40-character commit SHA, use the fixed
artifact name, and grant that job no more than read access to repository
contents. The central workflow rejects missing required reports, unexpected
or non-regular entries (including symlinks), files larger than 16 MiB, aggregate
caller evidence larger than 32 MiB, more than 256 Agent SRE records, duplicate
JSON keys, non-finite numbers, source mismatches, malformed digests, and
duplicate Agent SRE evidence IDs. The orchestration files, quality report,
security report, and Agent SRE command records are mandatory. PyRIT evidence is
optional only for risk profiles that do not require it and when
`require_pyrit_evidence` is disabled; high-risk and tool-enabled-agent G4
handoffs require it regardless of that input.

The orchestration validator mirrors the runtime contract instead of accepting
digest-shaped JSON. Assignment scopes must be allowed by the manifest;
high-risk or privileged assignments must carry their required checkpoints;
independent review must use a distinct model family; routes and price records
must be effective at `planned_at`; limits and grant coverage must match the
receipt; and every receipt prompt identity must exactly match its manifest
assignment. Limits include bounded maximum assignment duration and
`max_review_rounds`. The embedded
Plane-2 `tool_governance` policy must define both role allowlists, canonical
tools, actions, and scopes, approval-gated privileged actions,
command/network/secret allowlists, result-size and screening bounds, relative
workspace paths, and HTTPS-only network access. Assignment scopes must fit both
the manifest-wide and role-specific allowlists. The manifest must copy the
protected remediation path scopes and review-attester identity/key allowlist
exactly, and predeclare every conditional fix/re-review pair up to its round
ceiling. The receipt must be final `succeeded`, include every planned assignment
exactly once as either successful or legitimately skipped, retain one
digest-valid, role-authorized, screened tool-call audit per observed tool call,
and declare complete, reconciled cost. Privileged audit records must bind an
exact checkpoint grant. Its
`release_checkpoint_valid_until` must be later than both the receipt evaluation
time and the workflow's actual assembly time, so an old stored receipt cannot
authorize a new evidence bundle after its release grant expires. A recomputed
digest cannot turn an invalid or incomplete orchestration claim into valid
evidence.

Every successful whole-change review in `review_history` must carry an Ed25519
semantic attestation from a protected policy-pinned attester. The signature
binds the manifest, change, review assignment, report digest, verdict, and
complete finding set, so a valid clean result cannot be replayed across
assignments or manifests. A blocking finding set defines exact task and path
scope; the next remediation record must echo the runtime-derived binding, stay
inside the declared policy path scope, and be followed by a fresh whole-change
review. History must be contiguous, remain within `max_review_rounds`, and end
in an authenticated clean verdict. Host-authored round/fix arrays or
self-digested `clean` strings are not accepted.

The quality and security files are gate handoffs, not four-field CI summaries.
Each nested result uses the canonical Agent SRE development- or enterprise-gate
schema, carries a recomputed result digest, binds the exact change ID, change
digest, source revision, risk class, policy digest, and recent evaluation time,
and contains the exact risk-selected check-code set. G0 must contain the three
intent-readiness checks. G1 must contain either the documentation-only
not-applicable check or the complete architecture, interface, threat, tool, and
task-scope set. G2 and G3 must be passing; G4 must be passing and use the same
risk class and evaluation time as G0-G3. A resealed skeletal result or a result
with an unknown, missing, duplicate, or failed semantic check is rejected.

The assembler resolves every G2, G3, and G4 command-evidence reference by exact
schema, evidence ID, and digest, and then evaluates the pass-critical facts
again from the referenced records. This includes risk-selected build, contract,
format, lint, type, complexity, duplication, coverage, mutation, architecture,
drift, executable-test portfolio and traceability checks; whole-change,
independent, provider-diverse review with zero blockers and a bounded fix loop;
and SAST, SCA, secrets, SBOM, and provenance checks. Standard and high-risk
profiles therefore cannot omit build, test, review, SAST, secrets, or provenance
evidence while retaining a self-claimed passing summary. High-risk and
tool-enabled-agent profiles additionally require the current native,
digest-valid RAMPART report adapted into the source-bound Agent SRE agent-safety
envelope. Its enterprise profile must pin the exact campaign digest and a
per-dimension case minimum; every expected case binds its native pytest node ID,
result index, definition-file hashes, dimension, strategy, and observability.
The adapter requires exact native coverage with retained completed-result turns,
and the run attestation must be signed by a protected issuer/key authorized for
the reported producer and environment. These claims are checked from the retained
native report, campaign, run attestation, and safety envelope—not from summary
counts alone. The same profiles require a declared-versus-observed tool manifest,
human-labelled judge calibration bound to the exact PyRIT scorer, and PyRIT policy
evaluation.
All selected command records must be passed zero-exit CI results, be fresh at
the gate evaluation time, and retain a content-addressed report reference.

Each supplied Agent SRE record must contain exactly these fields, with no
missing or additional keys: `schema_version`, `evidence_id`, `change_id`,
`source_revision`, `change_digest`, `kind`, `status`, `generated_at`,
`producer`, `environment`, `command`, `exit_code`, `requirement_ids`,
`scenario_ids`, `task_ids`, `test_layers`, `metrics`, `artifacts`, and
`evidence_sha256`. The accepted `kind` values are `build`, `format`, `lint`,
`typecheck`, `complexity`, `duplication`, `contract`, `test`, `coverage`,
`mutation`, `architecture`, `drift`, `review`, `sast`, `sca`, `secrets`,
`sbom`, `provenance`, `tool_manifest`, `agent_safety`, `judge_calibration`,
`performance`, and `cost`; statuses are `passed`, `failed`, or `incomplete`.

Records use the same structural contract as Agent SRE `CommandEvidence`:
`generated_at` is a canonical UTC timestamp ending in `Z`; producer,
environment, and command are non-empty canonical strings; `exit_code` is an
integer or null; and a `passed` claim requires exit code `0`. Identifier arrays
are sorted and unique. Test layers are sorted and unique, use only
`documentation`, `unit`, `property`, `integration`, `contract`, `end_to_end`,
`architecture`, `security`, `agent_safety`, or `performance`, and are present
if and only if `kind` is `test`. `metrics` is an object and `artifacts` maps
strings to canonical strings. The file itself must be canonical JSON with one
trailing newline, and `evidence_sha256` must be the lowercase SHA-256 of the
canonical record after excluding that digest field. Recomputing a digest does
not make an invalid pass claim valid.

Exactly one Agent SRE record must have `kind: cost`. It must be a passed,
zero-exit record with no test layers and metrics containing exactly
`change_cost_report`, `cost_complete`, `event_count`, `event_set_digest`,
`orchestration_event_set_digest`, `total_cost_usd`, and `unpriced_events`.
`change_cost_report` is the canonical `agt.change-cost-report/v1` record. It
partitions the whole central ledger into disjoint exact event inventories,
including the risk-required orchestration, CI, and scanner components, and
includes strict external PyRIT and RAMPART usage components. Its orchestration
partition—not the larger whole-change total—must exactly reconcile the final
receipt's unique usage event IDs and actual cost. The workflow recomputes ledger
event-set digests, component sums, external artifact bindings, completeness,
required component kinds, and the accounting digest. Unknown cost,
duplicate/missing events, missing required harnesses, or overlap between ledger
partitions fails closed.

To make a separately generated PyRIT campaign blocking, set both inputs:

```yaml
    with:
      base_revision: ${{ github.event.pull_request.base.sha || github.event.before }}
      change_id: ${{ needs.canonical-change.outputs.change_id }}
      change_digest: ${{ needs.canonical-change.outputs.change_digest }}
      require_pyrit_evidence: true
```

Required PyRIT evidence must declare a complete, terminal campaign with at
least one trial. Its full v1 structure is validated, including the immutable
subject stored before execution, canonical producer-owned trial-plan digest,
exact planned and observed inventories, origin run IDs, observation timestamps,
cache/reuse and missing-provenance counts, oldest-trial freshness anchor,
configuration fingerprint, and completeness flags. A releasable run cannot
contain reused cached trials, omit planned cached rows, or include foreign or
missing trial provenance. Group identities, outcomes, and latency plus overall
mean, nearest-rank p95, maximum, and total latency are recomputed from the exact
observed trials. Complete usage and cost facts remain required when policy says
so; baselines must pass the same inventory/provenance checks and expose only the
exact stable incompatibility reasons derivable from their lifecycle and
configuration. The security handoff must also embed the exact canonical
`agt.release-policy/v1` document and its canonical `agt.release-verdict/v1`.
The assembler recomputes both digests, resolves all three G4 policy, evidence,
and verdict references exactly, and reapplies the policy's subject, allowed
benchmark, required scenarios and groups, minimum trials, freshness window,
ASR, error, undetermined, latency, usage, cost, and baseline rules to the raw
PyRIT facts. A complete PyRIT document whose raw ASR exceeds policy is rejected
even if both the G4 result and release verdict were resealed as passing. Keep
the campaign producer protected from untrusted pull request code, restrict its
credentials and targets, and require human approval for external or
production-like targets.

## Evidence handoff

The `agt-ai-sdlc-evidence` artifact contains:

- explicit non-gating central quality metadata and a security summary;
- an SPDX JSON source SBOM;
- a source- and workflow-bound provenance record;
- the validated `orchestration-manifest.json` and final
  `execution-receipt.json` produced by the governed runtime;
- `evidence-manifest.json`, including byte sizes and SHA-256 hashes;
- `agent-sre-execution-evidence.json` plus one flat
  `agent-sre-EVD-*.json` file per record for repeated Agent SRE ingestion; and
- validated caller quality and security reports, plus PyRIT evidence when
  supplied.

The canonical manifest and generated quality, security, and provenance reports
bind both normalized `base_revision` and exact `source_revision`. The workflow
provenance also binds the orchestration manifest and receipt digests, policy,
run, assignment set, authenticated review history, final status, and complete
orchestration plus whole-change accounting facts. The workflow output
`manifest_sha256` is the SHA-256 of the canonical evidence manifest. The hashes
detect accidental or post-assembly mutation; they do not authenticate the
producer by themselves.

## Optional platform attestation

Set `enable_attestation: true` only on a protected, non-pull-request run. The
caller must allow `attestations: write` and `id-token: write` for the reusable
workflow. Attestation is disabled by default and is skipped for pull requests;
its write permissions exist only in the isolated attestation job.

Assembly happens before that isolated job, so the non-gating
`agt.ci-provenance/v1` metadata says `attested: false` and separately records
whether attestation was requested. The workflow deliberately does not emit that
pre-attestation observation as passed Agent SRE `provenance` evidence. A
successful platform attestation is attached to the manifest by GitHub after
assembly; consumers must verify that platform attestation rather than treating
the in-artifact request flag as proof.

## Trust boundaries and limitations

- Branch protection, required jobs, immutable workflow references, and the
  organization-owned canonical change producer are the trust anchors. A JSON
  digest created by an untrusted producer is not a signature.
- A contributor who can replace the caller-evidence producer can fabricate its
  reports. Protect that workflow with code ownership and required review.
- Keep review-attester, risk-classifier, and approval-issuer private keys outside the
  agent host and contributor-controlled jobs. Embedded public keys are claims until
  matched to the protected orchestration and enterprise policies.
- Plane-2 callbacks authorize exact calls and fence late results, but the Python
  runtime cannot prevent a privileged host adapter from bypassing its callbacks
  or forcibly terminate a non-cooperative thread. Run the adapter with
  least-privilege process/container isolation and OS-enforced workspace, egress,
  redirect/DNS/IP, and secret controls. A valid receipt proves mediated calls;
  it does not prove no ambient bypass path existed.
- The central quality file is metadata, not build evidence or a quality gate. It
  records checkout/base binding and the patch whitespace observation; the
  workflow deliberately emits no `EVD-CENTRAL-BUILD` claim. Symlink containment
  and action pinning remain central security checks. None of these replace
  language-specific tests, builds, lint, type checks, secret scanning, SAST, or
  policy evaluation; publish those raw results as source-bound Agent SRE
  command evidence and publish the corresponding canonical G0-G4 results in
  the quality and security handoffs.
- Dependency review runs on pull requests. Protected push or release workflows
  should retain the organization's dependency and vulnerability scanning gates.
- SBOM generation inventories the checked-out source. Consumers should add
  image or package SBOMs for separately built release artifacts.

Review pinned action commits and the workflow itself on a controlled cadence.
Update consumers only after the replacement commit has passed the same required
checks and security review.
