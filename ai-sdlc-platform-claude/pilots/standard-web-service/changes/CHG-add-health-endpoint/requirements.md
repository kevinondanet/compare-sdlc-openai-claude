---
requirements:
- id: REQ-001
  text: WHEN a client requests GET /health, the service SHALL respond with HTTP 200
    and a JSON body listing each dependency check with its status.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-001-01
    name: all checks pass
    given: every dependency check returns true
    when: GET /health is requested
    then: the status is 200 and checks maps each name to 'ok'
    raw: ''
  tags:
  - api
- id: REQ-002
  text: WHEN any dependency check fails, the service SHALL respond with HTTP 503 and
    the body SHALL name every failing check.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-002-01
    name: database down
    given: the db check returns false
    when: GET /health is requested
    then: the status is 503 and failing equals ['db']
    raw: ''
  tags:
  - api
- id: REQ-003
  text: The service SHALL bound every dependency check to at most 2 seconds and SHALL
    report a check that exceeds the bound as failing.
  kind: non_functional
  priority: must
  scenarios:
  - id: SCN-003-01
    name: hung dependency
    when: a check does not return within 2 seconds
    then: the check is reported as 'fail' and the response still completes
    raw: ''
  tags:
  - resilience
---
# Requirements

Each requirement in the front-matter uses SHALL/MUST or an EARS form and has at
least one WHEN/THEN scenario. Use this body for narrative and rationale.
