# Enterprise AI-SDLC release evidence (experimental)

This self-checking, offline example composes the Agent SRE AI-SDLC controls into one
release path: a canonical change contract, dependency-aware planning and durable
execution, model/cost routing, signed risk and review facts, per-call tool governance,
bounded fix/re-review, G0-G6 evidence evaluation, policy-bound signed human approval,
and Ed25519 issuance.
It also authenticates the live PyRIT golden wire fixture and consumes a complete,
synthetic `pyrit.security-evidence/v1` campaign fixture under a strict release policy,
and adapts native current RAMPART output into the source-bound Agent SRE envelope.

> [!IMPORTANT]
> This surface is experimental and may change before Agent SRE reaches GA. The
> synthetic evidence and model catalog are deterministic demonstration fixtures, not
> claims about a production system. Replace every fixture with evidence produced by
> your CI, runtime, scanners, usage ledger, and PyRIT campaign.

## What the demo proves

| Stage | Artifact or control |
|---|---|
| G0 | Intent, assumptions, normative requirements, acceptance scenarios, and reciprocal traceability |
| G1 | Accepted ADR, interface contract, NFR, threat model, task DAG, risk tiers, and tool scopes |
| Plan and execute | Fresh context/workspace identifiers, dependency waves, enabled model/prompt registry bindings, benchmark- and price-backed routing, exact Plane-2 role/tool/action/scope policy, pre-call authorization, untrusted-result screening, signed checkpoints, hard result-commit deadlines, and a different provider family for review |
| G2 | Build, format, lint, type, complexity, duplication, contract, tests, coverage, mutation, architecture, and drift evidence |
| G3 | A separately signed blocking review, runtime-derived path-scoped remediation, and a fresh signed clean re-review from a different model family, all within two predeclared rounds |
| G4 | SAST, SCA, secret scan, SBOM, provenance, strict native RAMPART results adapted into a source-bound envelope, declared-vs-observed tools, human-labelled PyRIT judge calibration, and a passing strict PyRIT verdict |
| G5 | Complete central accounting across orchestration, CI, scanners, PyRIT, and RAMPART; exact ledger event inventories; and observed p95 latency |
| G6 | Organization-signed risk depth, exact protected orchestration-policy projection, authenticated review history, source/policy/model/prompt/execution binding, a fresh policy-pinned signed approval, and release readiness |
| Issue | Trusted-input re-evaluation at signing time, signed change/effective-policy claims, and deployment-context verification against a pinned key |

Unknowns fail closed. The byte-identical PyRIT golden fixture intentionally reports
unavailable cost and usage; the demo proves the release evaluator rejects it before
using a second, explicitly synthetic and complete fixture for the passing path. Its
run timestamps and evidence digest are refreshed in memory so the example exercises
the same real freshness checks used in production. An untrusted public key copied
only from the signature sidecar is also rejected.

## Run it

From the repository root, install Agent SRE in a virtual environment, then choose a
new output directory:

```bash
python -m venv .venv-enterprise-sdlc
. .venv-enterprise-sdlc/bin/activate
python -m pip install -e agent-governance-python/agent-sre
PYTHONPATH=agent-governance-python/agent-sre/src \
  python examples/enterprise-ai-sdlc/demo.py \
  --output /tmp/agt-enterprise-ai-sdlc-demo
```

The command exits nonzero on any failed assertion or strict schema/digest check. A
successful run prints a JSON summary with `G0` through `G6` set to `pass`, readiness
set to `ready`, and pinned-key signature verification set to `true`.

The output contains:

```text
changes/CHG-001/                 canonical change.json plus Markdown projections
orchestration/manifest.json      bounded work, routing, reservations, and review
orchestration/human-checkpoints.json
orchestration/checkpoint-grants.json
orchestration/trusted-checkpoint-public-key.hex
orchestration/trusted-review-attester-public-key.hex
orchestration/execution-receipt.json
workspaces/                         governed relative-path root (empty in this demo)
control-plane/usage-ledger.sqlite3
control-plane/orchestration-runtime.sqlite3
control-plane/catalog.sqlite3       durable model, prompt, price, and benchmark facts
evidence/command-evidence.json   integrity-bound G2-G5 command evidence
evidence/pyrit-security-evidence.json
evidence/golden-fail-closed-verdict.json
evidence/pyrit-release-verdict.json
evidence/risk-classification.json
evidence/human-approval.json
evidence/reports/rampart-native-report.json
evidence/reports/rampart-campaign.json
evidence/reports/rampart-run-attestation.json
evidence/reports/rampart-safety-report.json
evidence/rampart-campaign-root/   retained definition files rehashed by the adapter
evidence/reports/usage-rollup.json
evidence/reports/change-cost-report.json
release/readiness.json           unsigned readiness assessment
release/issued-release.json      issued canonical release artifact
release/issued-release.json.sig.json
release/trusted-release-public-key.hex
release/trusted-approval-issuer-public-key.hex
release/trusted-rampart-issuer-public-key.hex
summary.json
```

Use a new output directory on every run. When finished, remove only the explicit
demo output directory you supplied.

## Produce the PyRIT artifact in CI

Bind the release subject before the scenario starts (the API exposes the same
`evidence_subject` input):

```bash
pyrit_scan run "$SCENARIO_NAME" \
  --application fixture-app \
  --change CHG-001 \
  --commit-sha "$GIT_COMMIT"
```

After that bound scenario completes, export privacy-safe evidence. The three subject
flags below are equality assertions against the stored subject; they cannot attach a
subject to an old run or relabel it:

```bash
pyrit_scan scenario-evidence "$SCENARIO_RESULT_ID" \
  --application fixture-app \
  --change CHG-001 \
  --commit-sha "$GIT_COMMIT" \
  --baseline-scenario-result-id "$BASELINE_RESULT_ID" \
  --output evidence/pyrit-security-evidence.json
```

Provide all three assertion flags together. PyRIT writes atomically. Release-grade
completeness requires the exact producer-owned trial plan to equal the current run's
observed inventory, with every trial carrying its immutable origin, observation time,
cache flag, outcome, and duration. Reused cached trials, omitted cached rows, foreign
origins, or missing provenance fail closed; freshness is anchored to the oldest
included trial. Partial or unknown usage/cost remains explicit for policy evaluation.
Exit `1` means attack-outcome evidence is incomplete or unavailable, and `2` means a
subject assertion is partial. Do not promote the artifact merely because export
succeeded: Agent SRE authenticates its digest, recomputes group and overall counts and
latency from observed trials, and evaluates subject, freshness, cost, and compatible-
baseline regressions. Baselines must satisfy the same exact inventory/provenance
rules. Policy pins the complete benchmark fingerprint—including the PyRIT version,
scenario, target, scorer, datasets, techniques, and objectives—and pins any accepted
baseline by its independently verified digest and age. Project overlays may narrow
but cannot broaden those pins.
For high-risk and tool-agent releases, a separate content-addressed PyRIT
scorer-evaluation report must bind the same scorer evaluation hash and meet policy
for human-labelled sample count, agreement, and false-accept rate. The consumer also
derives baseline compatibility from persisted lifecycle and benchmark facts, so a
comparable baseline cannot be mislabeled to skip regression limits.

## Issuance trust boundary

An unsigned `ready` file is not enough to obtain a signature. `sdlc issue` requires
the canonical change, effective organization/project policies, manifest, final
receipt, signed risk classification, every command and approval artifact, and any
required PyRIT evidence again. The signing job must also supply separately protected
change and effective-policy digests. Human approvals are Ed25519-signed by a
policy-pinned issuer, bind the exact source, change and enterprise-policy digests,
authorize a specific role and risk tier, and carry an expiry; a self-digest or a key
supplied only by the approval is insufficient. Agent SRE reproduces the input
readiness digest, re-runs G0-G6 at the actual signing time, and signs an envelope that
authenticates the artifact hash, signing time, signer identity, and readiness digest.
It also authenticates the earliest expiry across every supporting command report,
PyRIT run and baseline, signed risk classification, review semantic attestation,
final release checkpoint, signed approval, and readiness evaluation.

Deployment verification similarly requires the expected change, active effective
policy and their trust anchors in addition to the pinned Ed25519 key. The enterprise
policy names the release audience (for example, `production`), which is carried in
the signed readiness claims. Verification rejects cross-audience/application/
repository/revision replay, stale readiness, expired approvals, sidecar metadata
tampering, expired supporting evidence, and a key supplied only by the sidecar.

Run that final job under a protected CI workload identity. Read organization policy
and trust-anchor values from protected configuration, and download evidence and
approvals from immutable authenticated CI/IdP records. Artifact self-digests detect
mutation but do not, by themselves, authenticate the `producer` named inside a JSON
document. An approval signature authenticates its approver claim only through the
policy-pinned issuer authorized for that role. Required command reports carry both a
durable URI and their claimed SHA-256 digest; the protected store must authenticate
the producer and match the retained bytes to that claim.

## Runtime enforcement boundary

`OrchestrationPlanner` creates a side-effect-free contract.
`GovernedOrchestrationRuntime` executes it through an injected host, verifies
independently pinned manifest/change/policy digests and Ed25519 checkpoint-authority
keys, rechecks the exact enabled model and prompt registry records, rejects runtime
prices that differ from the effective-dated records in the trusted manifest, and
requires final approval to be issued after and bound to authenticated independent
review output. The protected policy pins review-attester identities and Ed25519 keys;
a host-authored `clean` string or self-digest is insufficient. Each short-lived
attestation also binds the manifest, run, change and policy digests, exact review
assignment/request, context/workspace, model identity/family, round number, report,
verdict, and complete finding set, preventing cross-run or cross-assignment replay.

Plane-2 is an enforceable runtime decision point for cooperating host adapters. The
host submits canonical tool, action, resource, path or URL, scopes, secret reference,
and approval metadata before each call. The runtime applies exact role allowlists,
workspace confinement, command/network/secret policy, checkpoint authorization,
turn/tool/cost ceilings, and deadline/cancellation fences; it durably records the
decision before the side effect. The adapter must then submit the untrusted result for
screening. A successful receipt requires one screened audit for every observed tool
call. The demo exercises network, command, read, and scoped-write decisions without
performing any external action.

This boundary is cooperative by design: the Python runtime cannot stop an adapter
from bypassing its callback and using ambient filesystem or network privileges. A
late synchronous return is fenced from committing, but its Python thread is not
forcibly terminated. Production adapters therefore need least-privilege process or
container isolation, OS-enforced workspace and egress controls, redirect/DNS/IP
policy, and secret brokering. Agent OS can provide that outer enforcement and its
audit export can remain additional G4 evidence; it no longer substitutes for the
runtime's required per-call authorization record.

For review, the manifest predeclares the maximum round count plus each conditional
remediation/re-review pair. A blocking signed finding set identifies exact task IDs
and paths. The runtime—not the host—derives the remediation binding, permits writes
only to those paths inside the policy scope, records the fix, and launches a fresh
whole-change review. Release fails when the round limit is exhausted or the final
authenticated verdict is not clean.

`ControlPlaneCatalog` persists the demo's model, price, and benchmark facts as
canonical records, then rehydrates the router used for planning. Along with the
runtime and `UsageLedger` databases, it rejects path escape, symlink swaps, and
replacement with an older valid SQLite snapshot while a service instance is live.
SQLite record hashes and triggers detect ordinary corruption, but a process with
arbitrary database-write authority remains inside the trust boundary. Production
deployments must protect these directories with a dedicated service identity,
restrictive ACLs, authenticated backups, and single-writer ownership.

The demo also calls `orchestration_policy_violations` against the protected effective
policy and requires no difference in limits, tool governance, remediation paths,
review-attester trust, routes, checkpoints, or conditional rounds. Its central cost
report proves disjoint exact ledger inventories for orchestration, CI, and scanners,
then adds the strict PyRIT and RAMPART external usage records. Unknown or duplicate
usage fails closed instead of being treated as zero.

The RAMPART path is equally inventory-bound. The enterprise profile pins the exact
campaign digest and a per-dimension case minimum. Every campaign case binds its
pytest node ID, result index, dimension, strategy, required observability, and hashes
of retained definition files. A protected producer signs the exact campaign, native
report, usage observation, subject, run, and freshness window; G4 trusts that claim
only through the enterprise policy's issuer ID, Ed25519 key, producer, and environment
allowlist. The adapter then requires exact case coverage and retained turns for every
safe or unsafe result before emitting the source-bound safety report.

## Suggested CI gates

Run the focused implementation checks before the example:

```bash
cd agent-governance-python/agent-sre
PYTHONPATH=src pytest -q tests/unit/sdlc
ruff check src/agent_sre/sdlc tests/unit/sdlc ../../examples/enterprise-ai-sdlc/demo.py
mypy src/agent_sre/sdlc
cd ../..
PYTHONPATH=agent-governance-python/agent-sre/src \
  python examples/enterprise-ai-sdlc/demo.py \
  --output /tmp/agt-enterprise-ai-sdlc-ci
```

The demo never calls a model or the network. In production, keep the same contracts
but replace the offline catalogs and reports with independently retained artifacts;
pin the release public key, canonical change digest, and effective-policy digest
through deployment trust configuration, not from the adjacent release artifacts.
