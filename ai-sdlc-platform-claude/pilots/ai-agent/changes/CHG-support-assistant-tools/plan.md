---
summary: Registry and refund gate first, then screening, then the full test suite.
waves:
- index: 0
  task_ids:
  - TASK-001
  - TASK-002
  checkpoint: false
  description: ''
- index: 1
  task_ids:
  - TASK-003
  checkpoint: false
  description: ''
- index: 2
  task_ids:
  - TASK-004
  checkpoint: true
  description: ''
---
# Plan

Waves group tasks that can run in parallel. `checkpoint: true` requests a human
checkpoint after the wave.
