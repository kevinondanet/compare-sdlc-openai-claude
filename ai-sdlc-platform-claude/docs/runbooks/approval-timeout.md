# Runbook — approval timed out or no approver available

**Symptom.** A tier 3 action (git push, PR creation, backlog update, write outside the
worktree) or a tier 4 request is denied with `Approval rejected by system:auto-reject`,
`approval timed out after 300s`, or `no approvers configured`; the run reports
`blocked` and the audit log shows `policy_decision: deny`.

**Why.** ARCHITECTURE.md §4: approval timeouts and missing approvers **deny**. The
Agent Governance Toolkit resolves `require_approval` rules synchronously through the
platform's approval handler; the orchestrator only approves what a human checkpoint
approved, and `tool_tiers.approval_timeout_seconds` (org policy, project may only
shorten) bounds the wait. Tier 4 is always denied to agents — it happens outside the
agent loop.

## Triage

1. Identify the action: `aisdlc governance audit export --package CHG-x` (or the
   `--audit-log` file) lists tool, action type, resource, tier, matched rule, approvers.
   `aisdlc governance policy check --role implementer '{"tool_name": "Bash",
   "action_type": "git_push", "resource": "origin main"}'` reproduces the decision.
2. Was the denial correct?
   - A tier 4 action (deploy, secrets, IAM, delete data, unlisted egress): yes. Do it
     out of band with the normal change process, or add the host to
     `allowed_egress_hosts` if it was legitimate egress (that makes it tier 2 and audited).
   - A tier 3 action in a non-interactive run: expected. `--non-interactive` (the
     default without a TTY) denies every checkpoint. Re-run interactively, or with
     `--yes` in a trusted pipeline where the pipeline itself is the approval.
   - A tier 3 action that should be rule-approved: run with a rule-based approver
     (`aisdlc governance policy check ... --auto-approve-as ci-bot`) or, in orchestration, approve
     the `tier3` checkpoint. The approver identity lands in the audit entry.
3. Timeout with a real approver: the approver did not answer within
   `approval_timeout_seconds`. Ask, then resume — the run is resumable
   (`aisdlc run change CHG-x --resume`); completed tasks are not repeated.
4. `no approvers configured`: the generated role policy has an empty `approvers` list.
   Set them in the role spec (`aisdlc governance policy generate --approver tech-lead`)
   or the project config and regenerate `templates/agt/<role>.yaml`.

## Do not

- Do not raise `approval_timeout_seconds` in `aisdlc.yaml` — the merge only allows
  shortening it.
- Do not run agents in `--shadow` mode to "see what happens": shadow mode reports
  without enforcing and is for policy authoring only.

**Exit.** The audit entry for the retried action shows `approver_did` set and
`outcome: success`; `aisdlc run status CHG-x` shows the task `done`.
