# ADR-0005: Single gate depth profile and canonical evidence producers

- Status: accepted
- Date: 2026-08-25
- Related: ARCHITECTURE.md §2.4, §3, §9 (Deviations)

## Context

Two engineers independently implemented `GateDepthProfile` — one in `planning/risk.py`
(per-gate depth table, `checks`, human checkpoints) and one in `gates/depth.py` (the
threshold knobs the gates enforce). Their defaults disagreed (coverage floor vs target at
standard depth, approvals for `high`, PyRIT trial minimum, LOW-risk G4/G5). Separately,
three producers wrote `evidence/*.json` in shapes the canonical models could not load:
`governance.audit` emitted an entries-list record where `AuditEvidence.entries` is an int,
the PyRIT/safety runners wrote side files instead of `security.json`, and the ledger's cost
extract was not a `CostEvidence`.

## Decision

1. `gates/depth.py` is the only definition of `GateDepthProfile`; `planning/risk.py`
   re-exports it and `gate_depth_profile()` wraps `GateDepthProfile.from_risk_class`.
   Per-gate depths derive from the org policy's `gates.required_gates` / `gates.depth`
   (the planner's private base table is gone). Gate-enforced knobs win where the two
   implementations disagreed; planning names survive as read-only alias properties.
   `plan_approval_required` (orchestration checkpoint, standard+) and
   `require_plan_approval` (G1 blocks on `approved_by`, deep) are deliberately distinct.
2. Producers write the canonical models: `evidence/audit.json` = `AuditEvidence` summary
   with the per-call detail in `evidence/audit-entries.json` (the manifest drift check
   reads the sidecar, then `report_uri`); `evidence/security.json` is merged in place by
   `supply_chain.update_security_evidence`; `evidence/cost.json` comes from
   `UsageLedger.cost_evidence`. `GateResult.depth` records the per-gate depth.

## Consequences

- One object flows planner → plan checker → gates → CLI; profile changes happen in one file.
- Packages produced by the CLI always load; incomplete or tampered evidence still fails
  the gates closed because status is derived, not asserted, by the producers.
- Tests that pinned the planner's old defaults were updated (documented in §9).
