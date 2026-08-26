---
assets:
- the order table
- the CSV export sent to the caterer
actors:
- team member (submits orders)
- office manager (exports the table)
- caterer (opens the CSV in a spreadsheet)
threats:
- id: THR-001
  title: Spreadsheet formula injection through the free-text notes field
  description: A note starting with '=' or '@' executes as a formula when the caterer
    opens the CSV.
  category: tampering
  severity: medium
  assets:
  - the CSV export sent to the caterer
  mitigation_ids:
  - MIT-001
  status: mitigated
- id: THR-002
  title: Orders slipped in after the Friday cut-off
  description: A team member submits after the cut-off, so the caterer's count is
    wrong.
  category: tampering
  severity: low
  assets:
  - the order table
  mitigation_ids:
  - MIT-002
  status: mitigated
mitigations:
- id: MIT-001
  description: lowcode.table.csv_safe prefixes cells starting with =, +, -, @, tab
    or CR with an apostrophe on export.
  threat_ids:
  - THR-001
  verified: true
- id: MIT-002
  description: The engine checks the cut-off against its own clock on every submission
    and stores nothing when closed; the CLI only accepts an explicit time in tests.
  threat_ids:
  - THR-002
  verified: true
tool_data_manifest:
  tools: []
  data_sources: []
  network_egress: []
---
# Threat model

The application has no network surface and no agentic component; the only untrusted
input is what team members type into the form.
