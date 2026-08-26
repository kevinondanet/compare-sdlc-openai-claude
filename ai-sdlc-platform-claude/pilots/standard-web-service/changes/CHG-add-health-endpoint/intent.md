---
id: CHG-add-health-endpoint
title: Add a /health endpoint with dependency checks
kernel:
  why: Operators cannot tell whether the service or one of its dependencies is down.
  capabilities:
  - GET /health reports each dependency check and an overall status
  - A failing dependency turns the response into HTTP 503 naming the check
  - Checks are bounded by a timeout so a hung dependency cannot hang the probe
  constraints:
  - No web framework is added; the service stays plain WSGI
  - The health body must not expose connection strings or credentials
  non_goals:
  - Readiness/liveness split
  - Metrics export
  success_signal: Load balancer probes flip to 503 within one probe interval of a
    dependency outage; unit tests cover 200, 503 and the timeout path.
owner: service-lead
risk_class: standard
stakeholders:
- platform operations
- on-call engineers
labels:
- observability
---
# Intent

Expose `GET /health` so the load balancer and on-call engineers can see which dependency is failing.
