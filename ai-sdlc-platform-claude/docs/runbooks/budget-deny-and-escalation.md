# Runbook — budget deny, quota hit, or escalation refused

**Symptom.** `aisdlc run change` stops with `blocked` (exit 3) and a message such as
`per-change budget exhausted`, `budget check: deny (team:payments monthly)`,
`max_agent_turns reached`, `escalation not allowed for role implementer`; or
`aisdlc cost budget-check` exits 1 (deny) / 2 (require_approval).

**Where the numbers come from.** The org policy `cost_limits` (budgets per
application/team/environment/change; quotas for agent turns, parallel agents, review
rounds, tool calls, context tokens) narrowed by the project `overrides` — a project can
only lower them. Spend is read from the usage ledger (`.aisdlc/ledger.sqlite` or
`$AISDLC_LEDGER`); forecasts come from the router's cost estimate for the next call.

## Triage

1. See the actual spend and what consumed it:
   `aisdlc cost report --change CHG-x` (per role/model), `aisdlc cost kpis --change CHG-x`
   (turns per success, review rounds per merge, share of high-tier calls a lower tier
   could have served).
2. Decide which of the three cases you are in.
   - **Runaway loop.** Many review rounds or turns on one task: the implement/verify/review
     loop is not converging. Look at `handoffs/` for the task (`aisdlc run status CHG-x`),
     fix the task brief or the verification command, and re-run only that task
     (`aisdlc run task TASK-nnn --change CHG-x`). Do not raise `max_review_rounds`.
   - **Legitimately expensive change.** The forecast is right and the budget is wrong for
     this change. Register a scoped, time-boxed exception in the budgets file
     (`exceptions: [{scope: change:CHG-x, extra_usd: 20, until: 2026-09-01, approver: ...}]`)
     and re-run `aisdlc cost budget-check --budgets budgets.yaml ...`. Exceptions are
     recorded in `evidence/cost.json` and shown at G5.
   - **Escalation refused.** The router wanted a higher tier than
     `models.max_tier_per_role.<role>` allows or `escalation_allowed: false`. Check
     `aisdlc cost route --complexity ... --role ...` for the reason. Either the task is
     mis-scoped (split it so a standard-tier model can do it) or the cap is wrong at the
     org level — that is an org-policy change with its own review, never a project override.
3. `require_approval` decisions surface as an orchestration checkpoint of kind `budget`;
   approve interactively or with `--yes` only after step 1.

## Do not

- Do not point `$AISDLC_LEDGER` at an empty database to "reset" spend; the ledger is the
  system of record for KPIs and the G5 variance.
- Do not re-run with `--ignore-duplicates` to get past a duplicate-run suppression
  unless the inputs really changed; the suppression exists to stop paying twice.

**Exit.** `aisdlc cost budget-check --scope change:CHG-x --forecast <next estimate>`
returns `allow`, and `aisdlc run change CHG-x --resume` continues from the last handoff.
