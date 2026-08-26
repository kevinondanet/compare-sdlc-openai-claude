# Pilot 2 — standard web service

Project class: **standard** (`risk_class: standard`; `service/auth/*` would be `high`).
The change package `changes/CHG-add-health-endpoint` adds `GET /health` with dependency
checks, a hard per-check timeout and a 200/503 contract. Gate depth profile: every gate at
standard depth (G0–G6), one human approval for release.

Walk-through (inside a git repository with a commit):

```
aisdlc intake readiness CHG-add-health-endpoint
aisdlc plan check CHG-add-health-endpoint
aisdlc run change CHG-add-health-endpoint --runner dry --yes
aisdlc test run-evidence CHG-add-health-endpoint --command "python3 -m unittest discover -s tests -q"
aisdlc gate evaluate CHG-add-health-endpoint
```
