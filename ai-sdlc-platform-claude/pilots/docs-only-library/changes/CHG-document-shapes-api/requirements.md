---
requirements:
- id: REQ-001
  text: The documentation SHALL describe every public function of the shapes package
    with its parameters and return value.
  kind: functional
  priority: must
  scenarios:
  - id: SCN-001-01
    name: reference sections
    when: a reader opens docs/api.md
    then: a section titled with the function name exists for area and perimeter
    raw: ''
  tags: []
- id: REQ-002
  text: Every code example in docs/api.md SHALL execute without error against the
    shapes package.
  kind: non_functional
  priority: must
  scenarios:
  - id: SCN-002-01
    name: doctest
    when: python3 -m doctest docs/api.md runs
    then: it exits with status 0
    raw: ''
  tags: []
---
# Requirements

Each requirement in the front-matter uses SHALL/MUST or an EARS form and has at
least one WHEN/THEN scenario. Use this body for narrative and rationale.
