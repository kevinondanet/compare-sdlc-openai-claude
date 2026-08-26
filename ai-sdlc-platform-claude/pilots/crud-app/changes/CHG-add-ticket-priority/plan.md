---
summary: Field and validation first; sorting and the CLI flag in parallel; whole suite last.
waves:
- index: 0
  task_ids:
  - TASK-001
  checkpoint: false
  description: Priority field, validation, default and legacy-row loading.
- index: 1
  task_ids:
  - TASK-002
  - TASK-003
  checkpoint: false
  description: Priority-sorted listing and the CLI flag (independent of each other).
- index: 2
  task_ids:
  - TASK-004
  checkpoint: true
  description: Full suite, then a human checkpoint before release.
---
# Plan

Wave 0 changes the record shape; waves 1 and 2 build on it. The checkpoint after wave 2
is the release review.
