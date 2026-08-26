---
assets:
- dependency topology
- service availability
actors:
- anonymous internet client
- on-call engineer
threats:
- id: THR-001
  title: Health body discloses internal hostnames or credentials
  description: ''
  category: information_disclosure
  severity: medium
  assets:
  - dependency topology
  mitigation_ids:
  - MIT-001
  status: mitigated
- id: THR-002
  title: Probe flood exhausts dependency connections
  description: ''
  category: denial_of_service
  severity: low
  assets:
  - service availability
  mitigation_ids:
  - MIT-002
  status: open
mitigations:
- id: MIT-001
  description: The body carries only check names and 'ok'/'fail'; no messages from
    exceptions are serialised.
  threat_ids:
  - THR-001
  verified: true
- id: MIT-002
  description: Checks are cheap pings; the endpoint sits behind the load balancer
    rate limit.
  threat_ids:
  - THR-002
  verified: false
tool_data_manifest:
  tools: []
  data_sources:
  - orders database (ping only)
  network_egress: []
---
# Threat model

Assets, actors, threats (STRIDE + prompt injection), mitigations and the declared
tool/data manifest for agentic changes.
