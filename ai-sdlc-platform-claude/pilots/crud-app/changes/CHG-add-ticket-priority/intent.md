---
id: CHG-add-ticket-priority
title: Add a priority to support tickets
kernel:
  why: Support staff triage tickets by reading titles; urgent problems wait behind
    trivia because the ticket service has no notion of priority.
  capabilities:
  - Store a priority (low, normal, high, urgent) on every ticket
  - Default the priority to normal when none is given
  - List tickets ordered by priority, urgent first
  - Set and change the priority from the tickets command line
  constraints:
  - The JSON store written by earlier versions must keep loading
  - No new third-party dependencies (standard library only)
  - Priorities are a closed vocabulary; free text is rejected
  non_goals:
  - Automatic priority inference from ticket text
  - Notifications or escalation timers
  - Changing the ticket status model
  success_signal: Every ticket carries a valid priority, `tickets list --sort priority`
    returns urgent tickets first, and legacy stores load with priority normal.
owner: tickets-lead
risk_class: standard
stakeholders:
- support staff
- support operations lead
labels:
- crud
- tickets
---
# Intent

Add a `priority` field to the in-memory tickets service and its CLI so that support
staff can triage. The field is a closed set (`low`, `normal`, `high`, `urgent`) with an
explicit rank; listing can sort by it; everything else stays as it is.
