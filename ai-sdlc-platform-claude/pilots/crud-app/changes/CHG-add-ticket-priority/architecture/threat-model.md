---
assets:
- ticket records (titles, status, priority)
- the JSON store file
actors:
- support staff member (CLI user)
- support automation script
threats:
- id: THR-001
  title: Unvalidated priority values corrupt the store and break sorting
  description: A script or a hand-edited store passes an arbitrary string as priority.
  category: tampering
  severity: medium
  assets:
  - ticket records
  - the JSON store file
  mitigation_ids:
  - MIT-001
  status: mitigated
- id: THR-002
  title: Priority-sorted listing becomes a denial-of-service on large stores
  description: Sorting every request on an unbounded list stalls the CLI.
  category: denial_of_service
  severity: low
  assets:
  - ticket records
  mitigation_ids:
  - MIT-002
  status: mitigated
mitigations:
- id: MIT-001
  description: validate_priority runs on create, update and from_rows; invalid values raise
    before any state changes (SCN-001-02, SCN-004-02).
  threat_ids:
  - THR-001
  verified: true
- id: MIT-002
  description: One stable sort keyed on a precomputed rank; REQ-005 bounds 10,000 tickets to
    200 ms and the test suite measures it (SCN-005-01).
  threat_ids:
  - THR-002
  verified: true
tool_data_manifest:
  tools: []
  data_sources: []
  network_egress: []
---
# Threat model

The application has no network surface and no agentic components, so the tool/data
manifest is empty; its only persistent state is the local JSON ticket store.
